use std::collections::HashMap;

use digest::Digest;
use md4::Md4;

use super::messages::*;
use super::types::*;

const REPUBLISH_KEYWORD_SECS: i64 = 24 * 3600;
const REPUBLISH_SOURCE_SECS: i64 = 5 * 3600;
const MAX_FILES_PER_KEYWORD_PUBLISH: usize = 150;
const MAX_FILES_PER_KEYWORD_PACKET: usize = 50;

/// Bit set in the `"ember"` source-publish tag when this client speaks
/// the v1 LowID-to-LowID protocol (rendezvous hole-punch + WebSocket
/// relay fallback). See `build_source_publish` for the full rationale.
pub const EMBER_CAP_RELAY_PUNCH_V1: u8 = 0x01;

/// Free-string KAD source tag name carrying the publisher's Ember
/// Noise X25519 static public key (32 bytes, raw). Recipients cache
/// `(ip, port) -> noise_pub` from this tag so they can dial the
/// publisher's Ember-native UDP transport without manual key
/// distribution. Vanilla eMule clients see an unknown blob tag and
/// silently drop it; clients that don't yet speak Ember-native
/// transport simply ignore it.
pub const EMBER_NOISE_PUB_TAG: &str = "ember_npub";

#[derive(Debug, Clone)]
pub struct PublishableFile {
    pub file_hash: KadId,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub complete_sources: u32,
    /// eMule only publishes complete shared files under keywords. Part files
    /// still source-publish by file hash, but must not appear in keyword
    /// search results.
    pub keyword_publishable: bool,
    /// Persisted eMule `FT_KADLASTPUBLISHSRC` timestamp. Used to avoid
    /// republishing every source immediately after a restart.
    pub last_source_publish: i64,
}

#[derive(Debug)]
struct PublishRecord {
    pub file: PublishableFile,
    pub last_source_publish: i64,
}

#[derive(Debug)]
struct KeywordRecord {
    keyword: String,
    last_publish: i64,
    /// eMule tracks hot keyword targets separately from files. Keep the
    /// backoff on the keyword hash so one popular word does not suppress
    /// unrelated keywords from the same file.
    backoff_shift: u32,
}

#[derive(Debug, Clone)]
pub struct KeywordPublishBatch {
    pub keyword_hash: KadId,
    pub keyword: String,
    pub messages: Vec<KadMessage>,
    pub file_hashes: Vec<KadId>,
}

/// Manages publishing files to the KAD network.
#[derive(Debug)]
pub struct PublishManager {
    local_id: KadId,
    user_hash: [u8; 16],
    tcp_port: u16,
    udp_port: u16,
    /// Local Ember Noise X25519 static public key. Emitted in source
    /// publishes via [`EMBER_NOISE_PUB_TAG`] so other Ember peers can
    /// learn how to dial our Ember-native transport without manual
    /// key distribution. All-zero (the default) suppresses emission,
    /// matching the legacy behavior of nodes that pre-date the
    /// Noise-static-key field on `NodeIdentity`.
    pub noise_pub: [u8; 32],
    pub firewalled: bool,
    pub use_extern_kad_port: bool,
    pub direct_udp_callback: bool,
    pub connect_options: u8,
    pub buddy_ip: u32,
    pub buddy_port: u16,
    pub buddy_id: Option<KadId>,
    records: HashMap<KadId, PublishRecord>,
    keyword_records: HashMap<KadId, KeywordRecord>,
}

impl PublishManager {
    pub fn new(local_id: KadId, user_hash: [u8; 16], tcp_port: u16, udp_port: u16) -> Self {
        PublishManager {
            local_id,
            user_hash,
            tcp_port,
            udp_port,
            noise_pub: [0u8; 32],
            firewalled: false,
            use_extern_kad_port: false,
            direct_udp_callback: false,
            connect_options: 0,
            buddy_ip: 0,
            buddy_port: 0,
            buddy_id: None,
            records: HashMap::new(),
            keyword_records: HashMap::new(),
        }
    }

    /// Register a file for publishing.
    pub fn add_file(&mut self, file: PublishableFile) {
        self.ensure_keyword_records_for_file(&file);
        self.records
            .entry(file.file_hash)
            .and_modify(|record| {
                record.file.file_name = file.file_name.clone();
                record.file.file_size = file.file_size;
                record.file.file_type = file.file_type.clone();
                record.file.complete_sources = file.complete_sources;
                record.file.keyword_publishable = file.keyword_publishable;
                record.file.last_source_publish = file.last_source_publish;
                if file.last_source_publish > 0 {
                    record.last_source_publish =
                        record.last_source_publish.max(file.last_source_publish);
                }
            })
            .or_insert_with(|| PublishRecord {
                last_source_publish: file.last_source_publish,
                file,
            });
    }

    /// Remove a file from publishing (e.g. when a download is cancelled).
    pub fn remove_file(&mut self, file_hash: &KadId) {
        self.records.remove(file_hash);
    }

    /// Clear all records and re-add files (for re-indexing).
    pub fn clear_all(&mut self) {
        self.records.clear();
        self.keyword_records.clear();
    }

    /// Add a batch of files for publishing.
    pub fn add_files_batch(&mut self, files: Vec<PublishableFile>) {
        for file in files {
            self.add_file(file);
        }
    }

    /// Number of keyword targets that are currently due for publishing.
    pub fn keywords_needing_publish_count(&self) -> usize {
        let now = chrono::Utc::now().timestamp();
        self.keyword_records
            .values()
            .filter(|record| {
                let shift = record.backoff_shift.min(4);
                let interval = REPUBLISH_KEYWORD_SECS.saturating_mul(1_i64 << shift);
                now.saturating_sub(record.last_publish) > interval
                    && self.keyword_has_publishable_files(&record.keyword)
            })
            .count()
    }

    /// Get files that need source republishing.
    pub fn files_needing_source_publish(&self) -> Vec<&PublishableFile> {
        let now = chrono::Utc::now().timestamp();
        self.records
            .values()
            .filter(|r| now.saturating_sub(r.last_source_publish) > REPUBLISH_SOURCE_SECS)
            .map(|r| &r.file)
            .collect()
    }

    /// Build eMule-style keyword publishes: one store search per keyword,
    /// carrying up to 150 complete shared files and split into 50-entry
    /// `PublishKeyReq` packets.
    pub fn keyword_batches_needing_publish(&self, max_keywords: usize) -> Vec<KeywordPublishBatch> {
        let now = chrono::Utc::now().timestamp();
        let mut batches = Vec::new();

        for (keyword_hash, keyword_record) in &self.keyword_records {
            if batches.len() >= max_keywords {
                break;
            }
            let shift = keyword_record.backoff_shift.min(4);
            let interval = REPUBLISH_KEYWORD_SECS.saturating_mul(1_i64 << shift);
            if now.saturating_sub(keyword_record.last_publish) <= interval {
                continue;
            }

            let mut entries = Vec::new();
            let mut file_hashes = Vec::new();
            for record in self.records.values() {
                if !record.file.keyword_publishable {
                    continue;
                }
                if !extract_keywords(&record.file.file_name)
                    .into_iter()
                    .any(|kw| kw == keyword_record.keyword)
                {
                    continue;
                }
                entries.push(Self::build_keyword_entry(&record.file));
                file_hashes.push(record.file.file_hash);
                if entries.len() >= MAX_FILES_PER_KEYWORD_PUBLISH {
                    break;
                }
            }

            if entries.is_empty() {
                continue;
            }

            let messages = entries
                .chunks(MAX_FILES_PER_KEYWORD_PACKET)
                .map(|chunk| KadMessage::PublishKeyReq {
                    target: *keyword_hash,
                    entries: chunk.to_vec(),
                })
                .collect();

            batches.push(KeywordPublishBatch {
                keyword_hash: *keyword_hash,
                keyword: keyword_record.keyword.clone(),
                messages,
                file_hashes,
            });
        }

        batches
    }

    /// Mark a keyword target as published.
    pub fn mark_keyword_published(&mut self, keyword_hash: &KadId) {
        if let Some(record) = self.keyword_records.get_mut(keyword_hash) {
            record.last_publish = chrono::Utc::now().timestamp();
        }
    }

    /// Mark a file's source as published.
    pub fn mark_source_published(&mut self, file_hash: &KadId) {
        if let Some(record) = self.records.get_mut(file_hash) {
            record.last_source_publish = chrono::Utc::now().timestamp();
        }
    }

    /// K15: record the load value returned by the peer that accepted
    /// our keyword publish. Load >= 90 means the peer's keyword bucket
    /// is effectively full — don't hammer it. Load < 50 means we have
    /// headroom and we can reset backoff.
    pub fn record_keyword_publish_load(&mut self, keyword_hash: &KadId, load: u8) {
        if let Some(record) = self.keyword_records.get_mut(keyword_hash) {
            if load >= 90 {
                record.backoff_shift = (record.backoff_shift + 1).min(4);
            } else if load < 50 {
                record.backoff_shift = 0;
            }
        }
    }

    /// Build a KADEMLIA2_PUBLISH_SOURCE_REQ message for a file.
    /// For firewalled clients, includes buddy information so peers can reach us
    /// via relay (matching eMule's Search.cpp StorePacket STOREFILE case).
    pub fn build_source_publish(&self, file: &PublishableFile) -> Option<KadMessage> {
        let mut tags = Vec::new();

        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEPORT),
            value: TagValue::Uint16(self.tcp_port),
        });
        if !self.use_extern_kad_port {
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCEUPORT),
                value: TagValue::Uint16(self.udp_port),
            });
        }

        if self.firewalled {
            if self.direct_udp_callback {
                tags.push(KadTag {
                    name: TagName::Id(TAG_SOURCETYPE),
                    value: TagValue::Uint8(6),
                });
            } else if self.buddy_id.is_some() {
                // eMule source types:
                // 3 = firewalled with buddy, 5 = same for >4GB files.
                let st = if file.file_size > u32::MAX as u64 {
                    5
                } else {
                    3
                };
                tags.push(KadTag {
                    name: TagName::Id(TAG_SOURCETYPE),
                    value: TagValue::Uint8(st),
                });
                tags.push(KadTag {
                    name: TagName::Id(TAG_SERVERIP),
                    value: TagValue::Uint32(self.buddy_ip),
                });
                tags.push(KadTag {
                    name: TagName::Id(TAG_SERVERPORT),
                    value: TagValue::Uint16(self.buddy_port),
                });
                // eMule publishes the inverse local KadID as a hex string buddy hash.
                let mut buddy_hash_id = self.local_id.0;
                for byte in &mut buddy_hash_id {
                    *byte ^= 0xFF;
                }
                tags.push(KadTag {
                    name: TagName::Id(TAG_BUDDYHASH),
                    value: TagValue::String(hex::encode(buddy_hash_id)),
                });
            } else {
                return None;
            }
        } else {
            // eMule direct source types:
            // 1 = direct high-ID, 4 = same for >4GB files.
            let st = if file.file_size > u32::MAX as u64 {
                4
            } else {
                1
            };
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(st),
            });
        }

        tags.push(KadTag {
            name: TagName::Id(TAG_FILESIZE),
            value: TagValue::Uint64(file.file_size),
        });
        tags.push(KadTag {
            name: TagName::Id(TAG_ENCRYPTION),
            value: TagValue::Uint8(self.connect_options),
        });

        // Ember capability advertisement: tells other Ember clients that we
        // speak the LowID-to-LowID hole-punch / WebSocket-relay protocol
        // (broker.rs + relay.rs + the rendezvous-server). Other Ember peers
        // gate their broker attempts on the presence of this tag, so vanilla
        // eMule peers (which don't speak our relay protocol on the other
        // end) don't get ~46 s of wasted punch+relay before failing.
        //
        // Wire details:
        // - String-named (not a numeric ID) so it lives in eMule's free
        //   string-tag namespace and can never collide with a future
        //   `0xF0..0xFF` source-tag assignment from the upstream protocol.
        // - eMule clients see an unknown string tag and silently drop it.
        // - Value is a Uint8 capability bitfield. Bit 0 means "Ember v1
        //   relay+punch capable". Higher bits are reserved for future
        //   protocol features (e.g. peer-relay support, alt transport)
        //   so we can extend without a breaking change.
        tags.push(KadTag {
            name: TagName::Str("ember".to_string()),
            value: TagValue::Uint8(EMBER_CAP_RELAY_PUNCH_V1),
        });

        // Ember Noise pubkey advertisement. Lets recipients dial our
        // Ember-native UDP transport without copying hex from devtools
        // or running a separate identity exchange — the KAD source
        // record we already publish carries the pubkey alongside the
        // capability bit. Skipped when the pubkey is all-zero (legacy
        // identity that pre-dates the Noise-key field), matching the
        // suppression rule in `extract_kad_sources` for safety.
        if self.noise_pub != [0u8; 32] {
            tags.push(KadTag {
                name: TagName::Str(EMBER_NOISE_PUB_TAG.to_string()),
                // `Bsob` (eMule `TAGTYPE_BSOB`), not `Blob`: the 32-byte key
                // fits in a u8 length and eMule's KAD tag reader rejects the
                // larger `TAGTYPE_BLOB`, which would otherwise make a vanilla
                // eMule peer drop our entire source publish.
                value: TagValue::Bsob(self.noise_pub.to_vec()),
            });
        }

        // eMule Search.cpp STOREFILE uses client hash (user hash), not KadID:
        // CUInt128 uID(CKademlia::GetPrefs()->GetClientHash())
        // user_hash is raw ed2k bytes; wrap in CUInt128 wire format for KAD.
        Some(KadMessage::PublishSourceReq {
            target: file.file_hash,
            sender_id: KadId(cuint128_swap(&self.user_hash)),
            tags,
        })
    }

    fn build_keyword_entry(file: &PublishableFile) -> PublishEntry {
        let complete_sources = file.complete_sources.max(1);
        PublishEntry {
            id: file.file_hash,
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_FILENAME),
                    value: TagValue::String(file.file_name.clone()),
                },
                KadTag {
                    name: TagName::Id(TAG_FILESIZE),
                    value: TagValue::Uint64(file.file_size),
                },
                KadTag {
                    name: TagName::Id(TAG_FILETYPE),
                    value: TagValue::String(file.file_type.clone()),
                },
                KadTag {
                    name: TagName::Id(TAG_SOURCES),
                    value: TagValue::Uint32(complete_sources),
                },
                KadTag {
                    name: TagName::Id(TAG_COMPLETE_SOURCES),
                    value: TagValue::Uint32(complete_sources),
                },
            ],
        }
    }

    pub fn file_count(&self) -> usize {
        self.records.len()
    }

    pub fn reset_source_publish(&mut self, file_hash: &KadId) {
        if let Some(record) = self.records.get_mut(file_hash) {
            record.last_source_publish = 0;
        }
    }

    pub fn reset_keyword_publish(&mut self, file_hash: &KadId) {
        if let Some(record) = self.records.get(file_hash) {
            for keyword in extract_keywords(&record.file.file_name) {
                let keyword_hash = keyword_to_kad_id(&keyword);
                if let Some(keyword_record) = self.keyword_records.get_mut(&keyword_hash) {
                    keyword_record.last_publish = 0;
                    keyword_record.backoff_shift = 0;
                }
            }
        }
    }

    pub fn reset_keyword_target_publish(&mut self, keyword_hash: &KadId) {
        if let Some(keyword_record) = self.keyword_records.get_mut(keyword_hash) {
            keyword_record.last_publish = 0;
            keyword_record.backoff_shift = 0;
        }
    }

    fn ensure_keyword_records_for_file(&mut self, file: &PublishableFile) {
        if !file.keyword_publishable {
            return;
        }
        for keyword in extract_keywords(&file.file_name) {
            let keyword_hash = keyword_to_kad_id(&keyword);
            self.keyword_records
                .entry(keyword_hash)
                .or_insert(KeywordRecord {
                    keyword,
                    last_publish: 0,
                    backoff_shift: 0,
                });
        }
    }

    fn keyword_has_publishable_files(&self, keyword: &str) -> bool {
        self.records.values().any(|record| {
            record.file.keyword_publishable
                && extract_keywords(&record.file.file_name)
                    .into_iter()
                    .any(|kw| kw == keyword)
        })
    }
}

/// Hash a keyword string to a KAD ID using MD4 (eMule convention).
/// eMule loads the MD4 output via CUInt128::SetValueBE, then writes each
/// 32-bit word in little-endian on the wire. This effectively reverses
/// the byte order within each 4-byte word of the raw MD4 digest.
pub fn keyword_to_kad_id(keyword: &str) -> KadId {
    let lower = keyword.to_lowercase();
    let hash = Md4::digest(lower.as_bytes());
    md4_bytes_to_kad_id(&hash)
}

/// Convert raw MD4 output bytes to a KadId matching eMule's CUInt128 wire format.
/// Each 32-bit word has its bytes reversed (big-endian interpretation written as LE).
pub fn md4_bytes_to_kad_id(hash: &[u8]) -> KadId {
    debug_assert!(
        hash.len() >= 16,
        "md4_bytes_to_kad_id expects a 16-byte digest"
    );
    let mut id = [0u8; 16];
    let len = hash.len().min(16);
    let src = &hash[..len];
    for i in 0..4 {
        let base = i * 4;
        if base + 3 < len {
            id[base] = src[base + 3];
            id[base + 1] = src[base + 2];
            id[base + 2] = src[base + 1];
            id[base + 3] = src[base];
        }
    }
    KadId(id)
}

/// Reverse the byte-swap: convert a KadId back to raw MD4 bytes.
/// This is the inverse of `md4_bytes_to_kad_id`.
pub fn kad_id_to_md4_bytes(id: &KadId) -> [u8; 16] {
    let mut raw = [0u8; 16];
    for i in 0..4 {
        let base = i * 4;
        raw[base] = id.0[base + 3];
        raw[base + 1] = id.0[base + 2];
        raw[base + 2] = id.0[base + 1];
        raw[base + 3] = id.0[base];
    }
    raw
}

/// Extract searchable keywords from a filename using eMule's tokenization rules.
/// Matches eMule SearchManager::GetWords:
/// - Split on INV_KAD_KEYWORD_CHARS: ` ()[]{}<>,._-!?:;\\/"`
/// - Keep words where UTF-8 byte length >= 3
/// - Deduplicate (case-insensitive), keeping order of first occurrence
/// - Remove last word if it's exactly 3 chars and 3 bytes (strips file extensions)
pub fn extract_keywords(filename: &str) -> Vec<String> {
    let separator_chars = |c: char| -> bool {
        matches!(
            c,
            '(' | ')'
                | '['
                | ']'
                | '{'
                | '}'
                | '<'
                | '>'
                | ','
                | '.'
                | '_'
                | '-'
                | '!'
                | '?'
                | ':'
                | ';'
                | '\\'
                | '/'
                | '"'
        ) || c.is_whitespace()
    };

    let mut seen = std::collections::HashSet::new();
    let mut result: Vec<String> = Vec::new();
    let mut last_chars = 0usize;
    let mut last_bytes = 0usize;

    for word in filename.split(separator_chars) {
        let bytes = word.len();
        if bytes < 3 {
            continue;
        }
        let lower = word.to_lowercase();
        if seen.insert(lower.clone()) {
            last_chars = word.chars().count();
            last_bytes = bytes;
            result.push(lower);
        }
    }

    // eMule: if last word is 3 chars and 3 bytes and there are >1 words, pop it (extension)
    if result.len() > 1 && last_chars == 3 && last_bytes == 3 {
        result.pop();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_file() -> PublishableFile {
        PublishableFile {
            file_hash: KadId([0x42; 16]),
            file_name: "ember-test.bin".to_string(),
            file_size: 1024,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        }
    }

    fn make_publisher(firewalled: bool) -> PublishManager {
        let mut p = PublishManager::new(KadId([0xAA; 16]), [0xBB; 16], 4662, 4672);
        p.firewalled = firewalled;
        // Fake direct UDP callback so the firewalled branch is allowed to
        // emit a publish (otherwise `build_source_publish` returns None
        // for firewalled clients with no buddy info, which would skip
        // emission of every other tag too).
        p.direct_udp_callback = true;
        p
    }

    /// HighID Ember client must emit the `"ember"` capability tag in
    /// every source publish so the recipient's `extract_kad_sources`
    /// (and via it the broker dispatch gate) can know we're reachable
    /// over the Ember relay/punch protocol.
    #[test]
    fn build_source_publish_includes_ember_capability_tag() {
        let publisher = make_publisher(false);
        let file = sample_file();
        let msg = publisher
            .build_source_publish(&file)
            .expect("HighID publish should not be skipped");
        let tags = match msg {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message type from build_source_publish"),
        };

        let ember_tag = tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Str(s) if s == "ember"))
            .expect("ember capability tag must be present in source publish");
        let value = match ember_tag.value {
            TagValue::Uint8(v) => v,
            _ => panic!("ember tag must be Uint8 (capability bitfield)"),
        };
        assert!(
            value & EMBER_CAP_RELAY_PUNCH_V1 != 0,
            "v1 relay+punch capability bit must be set, got {:#04x}",
            value,
        );
    }

    /// HighID Ember publish must carry the Noise pubkey blob so that
    /// recipients can dial the publisher's Ember-native UDP transport
    /// without a separate key exchange.
    #[test]
    fn build_source_publish_includes_noise_pubkey_blob() {
        let mut publisher = make_publisher(false);
        let mut npub = [0u8; 32];
        for (i, b) in npub.iter_mut().enumerate() {
            *b = i as u8 + 1;
        }
        publisher.noise_pub = npub;

        let msg = publisher
            .build_source_publish(&sample_file())
            .expect("HighID publish should not be skipped");
        let tags = match msg {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message type"),
        };

        let npub_tag = tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Str(s) if s == EMBER_NOISE_PUB_TAG))
            .expect("ember Noise pubkey tag must be present");
        let blob = match &npub_tag.value {
            // eMule-compatible small-blob type; see build_source_publish.
            TagValue::Bsob(b) => b,
            _ => panic!("ember_npub tag must be a Bsob"),
        };
        assert_eq!(blob.len(), 32, "Noise pubkey wire size");
        assert_eq!(blob.as_slice(), &npub);
    }

    /// The Noise pubkey tag is suppressed for legacy identities that
    /// pre-date the keypair field — the all-zero default acts as a
    /// "nothing to publish" sentinel and the recipient also rejects
    /// all-zero on read.
    #[test]
    fn build_source_publish_skips_zero_noise_pubkey() {
        let publisher = make_publisher(false);
        // noise_pub left at its default `[0u8; 32]`.
        let msg = publisher.build_source_publish(&sample_file()).unwrap();
        let tags = match msg {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message type"),
        };
        assert!(
            !tags
                .iter()
                .any(|t| matches!(&t.name, TagName::Str(s) if s == EMBER_NOISE_PUB_TAG)),
            "all-zero Noise pubkey must not be published"
        );
    }

    /// Same emission required when the publisher is firewalled (LowID /
    /// behind NAT) — that's actually the most important case because
    /// those publishes are the only ones the broker dispatch gate
    /// consults to decide "can I reach this peer via Ember".
    #[test]
    fn build_source_publish_firewalled_includes_ember_capability_tag() {
        let publisher = make_publisher(true);
        let file = sample_file();
        let msg = publisher
            .build_source_publish(&file)
            .expect("firewalled-with-direct-udp publish should not be skipped");
        let tags = match msg {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message type from build_source_publish"),
        };
        assert!(
            tags.iter()
                .any(|t| matches!(&t.name, TagName::Str(s) if s == "ember")),
            "firewalled publish must still advertise ember capability — \
             the broker uses this to decide whether to attempt LowID-to-LowID",
        );
    }
}
