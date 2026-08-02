use std::collections::HashMap;

use digest::Digest;
use md4::Md4;

use super::messages::*;
use super::types::*;

const REPUBLISH_KEYWORD_SECS: i64 = 20 * 3600;
const REPUBLISH_SOURCE_SECS: i64 = 5 * 3600;
const MAX_FILES_PER_KEYWORD_PUBLISH: usize = 150;
const MAX_FILES_PER_KEYWORD_PACKET: usize = 50;

/// K15's load-based backoff (see [`PublishManager::record_keyword_publish_load`])
/// doubles the keyword republish interval each time a storing peer reports
/// a near-full bucket, up to `1 << 4` = 16x. Left uncapped, that reaches
/// `20h * 16` = 320h (~13.3 days) — vastly longer than the `KEYWORD_TTL_SECS`
/// (24h) every other KAD node enforces against the entry we published.
/// Once backoff kicks in even once, our keyword entries would expire
/// everywhere and our shared files would drop out of keyword search for
/// days while we're still online, defeating the entire point of
/// publishing. Cap the backoff-adjusted interval so we always renew with
/// at least this much margin before the TTL lapses, regardless of shift —
/// the load-based backoff still meaningfully slows republishing within
/// that ceiling, it just can't blow through the network's own expiry.
const KEYWORD_REPUBLISH_SAFETY_MARGIN_SECS: i64 = 2 * 3600;

/// Backoff-adjusted keyword republish interval for a given `backoff_shift`,
/// clamped so it never exceeds `store::KEYWORD_TTL_SECS` minus a safety
/// margin. See `KEYWORD_REPUBLISH_SAFETY_MARGIN_SECS` for why the cap is
/// necessary and `store::KEYWORD_TTL_SECS`'s doc comment for the other side
/// of this invariant.
fn keyword_republish_interval(backoff_shift: u32) -> i64 {
    let shift = backoff_shift.min(4);
    let uncapped = REPUBLISH_KEYWORD_SECS.saturating_mul(1_i64 << shift);
    uncapped
        .min(super::store::KEYWORD_TTL_SECS.saturating_sub(KEYWORD_REPUBLISH_SAFETY_MARGIN_SECS))
}

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
    pub(crate) tcp_port: u16,
    pub(crate) udp_port: u16,
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
    /// Reverse index (keyword_hash -> file_hashes) kept in sync with
    /// `records`/`keyword_records` by `ensure_keyword_records_for_file` /
    /// `remove_file_from_keyword_index`. Backs [`Self::files_for_keyword`],
    /// which answers inbound `SearchKeyReq` in O(1) + O(matches) instead of
    /// re-running `extract_keywords` over every shared file per request —
    /// see that method's doc comment for why the linear scan was a
    /// remotely-triggerable CPU-amplification vector.
    keyword_index: HashMap<KadId, std::collections::HashSet<KadId>>,
    /// eMule `CSharedFileList::m_currFileSrc`: round-robin cursor over
    /// `records`, advanced by exactly one entry per scheduler tick
    /// regardless of whether that entry turns out to be due. See
    /// `next_source_candidate`.
    source_cursor: Option<KadId>,
    /// eMule `CKnownFile::CPublishKeywordList`'s internal round-robin
    /// cursor (`GetNextKeyword`): same "one candidate per tick" walk as
    /// `source_cursor`, over `keyword_records`.
    keyword_cursor: Option<KadId>,
}

/// eMule `CSharedFileList::Publish()` walks a plain array index
/// (`m_currFileSrc` / `m_currFileNotes`) through its known-file list,
/// examining exactly one candidate per `KADEMLIAPUBLISHTIME` tick regardless
/// of whether it turns out to be due, and wraps back to the start once it
/// runs off the end — so a full sweep of N entries takes N ticks even when
/// none of them are due, rather than jumping straight to whichever entry
/// happens to be due right now. `HashMap` has no stable index, so this walks
/// a deterministic sort of the keys instead; the effect (exactly one
/// candidate considered per call, full sweep before any repeat) is the same.
pub(crate) fn round_robin_next<V>(
    map: &HashMap<KadId, V>,
    cursor: &mut Option<KadId>,
) -> Option<KadId> {
    if map.is_empty() {
        *cursor = None;
        return None;
    }
    let mut keys: Vec<KadId> = map.keys().copied().collect();
    keys.sort();
    let next = match *cursor {
        Some(c) => match keys.iter().position(|k| *k == c) {
            Some(pos) => keys[(pos + 1) % keys.len()],
            // Cursor's previous entry is gone (file unshared / keyword
            // pruned) — eMule's index would now point at whatever shifted
            // into that slot; restarting from the front is the simplest
            // equivalent and still guarantees a full sweep.
            None => keys[0],
        },
        None => keys[0],
    };
    *cursor = Some(next);
    Some(next)
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
            keyword_index: HashMap::new(),
            source_cursor: None,
            keyword_cursor: None,
        }
    }

    /// Register a file for publishing.
    pub fn add_file(&mut self, file: PublishableFile) {
        // A re-add with a different name or `keyword_publishable` flag
        // (rename, or a partial finishing/re-starting a download) can
        // change which keywords this file_hash should be indexed under.
        // Drop the stale associations before re-deriving them below so
        // `keyword_index` never accumulates entries for keywords the file
        // no longer matches.
        if let Some(old) = self.records.get(&file.file_hash) {
            if old.file.file_name != file.file_name
                || old.file.keyword_publishable != file.keyword_publishable
            {
                self.remove_file_from_keyword_index(&old.file.clone());
            }
        }
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
        if let Some(record) = self.records.remove(file_hash) {
            self.remove_file_from_keyword_index(&record.file);
        }
    }

    /// Remove `file`'s entry from every keyword bucket it was indexed
    /// under in `keyword_index`, pruning any bucket left empty. Must be
    /// called with the file's *old* name/publishability whenever it's
    /// about to be replaced or dropped from `records`, so the index never
    /// holds a `file_hash` that `files_for_keyword` would then return
    /// alongside a `records` lookup miss (or, worse, a stale/renamed
    /// file's now-wrong metadata).
    fn remove_file_from_keyword_index(&mut self, file: &PublishableFile) {
        for keyword in extract_keywords(&file.file_name) {
            let keyword_hash = keyword_to_kad_id(&keyword);
            if let Some(set) = self.keyword_index.get_mut(&keyword_hash) {
                set.remove(&file.file_hash);
                if set.is_empty() {
                    self.keyword_index.remove(&keyword_hash);
                }
            }
        }
    }

    /// Add a batch of files for publishing.
    pub fn add_files_batch(&mut self, files: Vec<PublishableFile>) {
        for file in files {
            self.add_file(file);
        }
    }

    /// Reconcile the registered file set to exactly `keep`, dropping
    /// records for files that are no longer shared while preserving the
    /// source AND keyword publish timestamps of files that remain.
    ///
    /// This is the non-destructive replacement for `clear_all()` + re-add
    /// on every shared-file change. `clear_all()` discarded all in-memory
    /// keyword publish times (`keyword_records`); because keyword times —
    /// unlike source times — are not persisted to known.met, every change
    /// (share/unshare, priority edit, a completed download being shared,
    /// etc.) re-queued the entire keyword set, so keyword publishing never
    /// settled to its 24h interval and republished continuously. Callers
    /// should `add_file`/`add_files_batch` the current set first (which
    /// keeps existing keyword timestamps via `or_insert`), then call this
    /// to evict anything no longer present.
    pub fn retain_files(&mut self, keep: &std::collections::HashSet<KadId>) {
        self.records.retain(|hash, _| keep.contains(hash));
        // Prune keyword targets that no longer back any keyword-publishable
        // file so we stop republishing keywords for files that were removed.
        let live_keywords: std::collections::HashSet<String> = self
            .records
            .values()
            .filter(|record| record.file.keyword_publishable)
            .flat_map(|record| extract_keywords(&record.file.file_name))
            .collect();
        self.keyword_records
            .retain(|_, record| live_keywords.contains(&record.keyword));
        // Keep `keyword_index` in lock-step: drop any indexed file_hash
        // that `records.retain` above just dropped, and any now-empty
        // bucket. Cheap full rebuild rather than surgical per-removed-file
        // cleanup — this only runs on share-list reconciliation, not on
        // any network-request path.
        for hashes in self.keyword_index.values_mut() {
            hashes.retain(|h| keep.contains(h));
        }
        self.keyword_index.retain(|_, hashes| !hashes.is_empty());
    }

    /// Number of keyword targets that are currently due for publishing.
    pub fn keywords_needing_publish_count(&self) -> usize {
        let now = chrono::Utc::now().timestamp();
        self.keyword_records
            .values()
            .filter(|record| {
                let interval = keyword_republish_interval(record.backoff_shift);
                now.saturating_sub(record.last_publish) > interval
                    && self.keyword_has_publishable_files(&record.keyword)
            })
            .count()
    }

    /// Whether this node publishes any shared file to KAD.
    ///
    /// Gates the Ember rendezvous advert: a node already running the publish
    /// rotation adds one more record to traffic it was sending anyway, whereas
    /// a pure leecher would be generating KAD publish traffic solely to
    /// advertise itself. Leechers can still look the rendezvous key up.
    pub fn has_publishable_files(&self) -> bool {
        !self.records.is_empty()
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

    /// eMule `CSharedFileList::Publish()` STOREFILE branch: advance the
    /// round-robin cursor by exactly one file and return it only if that
    /// one candidate is actually due. Called at most once per
    /// `KADEMLIAPUBLISHTIME` tick regardless of the outcome — like eMule, a
    /// full sweep of N shared files takes N ticks even when none of them
    /// are due, rather than searching the whole set for whichever file
    /// happens to be due right now.
    pub fn next_source_candidate(&mut self) -> Option<&PublishableFile> {
        let next = round_robin_next(&self.records, &mut self.source_cursor)?;
        let now = chrono::Utc::now().timestamp();
        let record = self.records.get(&next)?;
        if now.saturating_sub(record.last_source_publish) > REPUBLISH_SOURCE_SECS {
            Some(&record.file)
        } else {
            None
        }
    }

    /// eMule `CSharedFileList::Publish()` STOREKEYWORD branch: advance the
    /// keyword round-robin cursor by exactly one target and return its
    /// publish batch only if that one candidate is actually due. See
    /// `next_source_candidate` for why this doesn't just scan for the next
    /// due keyword.
    pub fn next_keyword_candidate(&mut self) -> Option<KeywordPublishBatch> {
        let next = round_robin_next(&self.keyword_records, &mut self.keyword_cursor)?;
        let now = chrono::Utc::now().timestamp();
        let record = self.keyword_records.get(&next)?;
        let interval = keyword_republish_interval(record.backoff_shift);
        if now.saturating_sub(record.last_publish) <= interval {
            return None;
        }
        self.build_batch_for_keyword(next, record)
    }

    /// Gather up to 150 complete, keyword-publishable files backing
    /// `keyword_hash` and split them into 50-entry `PublishKeyReq` packets.
    /// Returns `None` if no live file currently backs this keyword (e.g.
    /// the last one was unshared but the keyword record hasn't been pruned
    /// yet).
    fn build_batch_for_keyword(
        &self,
        keyword_hash: KadId,
        keyword_record: &KeywordRecord,
    ) -> Option<KeywordPublishBatch> {
        // Use `keyword_index` (already the source of truth for
        // `files_for_keyword`) instead of re-tokenizing every shared
        // file's name via `extract_keywords` on every republish. This also
        // fixes a determinism gap: iterating `self.records.values()`
        // directly walked `HashMap` order, so when more than
        // `MAX_FILES_PER_KEYWORD_PUBLISH` files backed one keyword, *which*
        // subset got published could vary between calls/restarts purely
        // from hash-map iteration order, silently starving some files of
        // ever being advertised under a popular keyword. Sorting by file
        // hash gives a stable, repeatable selection.
        let mut file_hashes: Vec<KadId> = match self.keyword_index.get(&keyword_hash) {
            Some(hashes) => hashes.iter().copied().collect(),
            None => return None,
        };
        file_hashes.sort();

        let mut entries = Vec::new();
        let mut selected_hashes = Vec::new();
        for file_hash in file_hashes {
            let Some(record) = self.records.get(&file_hash) else {
                continue;
            };
            if !record.file.keyword_publishable {
                continue;
            }
            entries.push(Self::build_keyword_entry(&record.file));
            selected_hashes.push(record.file.file_hash);
            if entries.len() >= MAX_FILES_PER_KEYWORD_PUBLISH {
                break;
            }
        }
        let file_hashes = selected_hashes;

        if entries.is_empty() {
            return None;
        }

        let messages = entries
            .chunks(MAX_FILES_PER_KEYWORD_PACKET)
            .map(|chunk| KadMessage::PublishKeyReq {
                target: keyword_hash,
                entries: chunk.to_vec(),
            })
            .collect();

        Some(KeywordPublishBatch {
            keyword_hash,
            keyword: keyword_record.keyword.clone(),
            messages,
            file_hashes,
        })
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

    /// MD4 file hashes that have completed at least one KAD source publish
    /// (this session or restored from known.met `last_publish_src`). Used by
    /// the Library KAD badge so it means "published", not merely "connected".
    pub fn source_published_md4_hashes(&self) -> std::collections::HashSet<[u8; 16]> {
        self.records
            .iter()
            .filter(|(_, record)| record.last_source_publish > 0)
            .map(|(id, _)| kad_id_to_md4_bytes(id))
            .collect()
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
        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEUPORT),
            value: TagValue::Uint16(self.udp_port),
        });

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
                    // eMule `md4str` emits uppercase hex; keep wire parity.
                    value: TagValue::String(hex::encode_upper(buddy_hash_id)),
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
            self.keyword_index
                .entry(keyword_hash)
                .or_default()
                .insert(file.file_hash);
        }
    }

    /// Files backing `keyword_hash` right now — an O(1) average-case
    /// lookup via [`Self::keyword_index`] followed by O(matches) record
    /// fetches. Kept for unit tests of the keyword index; inbound
    /// `SearchKeyReq` answers from the DHT store only (eMule parity).
    #[cfg(test)]
    pub fn files_for_keyword(&self, keyword_hash: &KadId) -> Vec<&PublishableFile> {
        match self.keyword_index.get(keyword_hash) {
            Some(hashes) => hashes
                .iter()
                .filter_map(|h| self.records.get(h))
                .map(|record| &record.file)
                .collect(),
            None => Vec::new(),
        }
    }

    /// Same lookup `files_for_keyword` does (`keyword_index` gives the file
    /// hashes for this keyword directly), avoiding a full
    /// `extract_keywords` re-tokenization of every shared file's name on
    /// every republish-due check — the scheduler calls this once per
    /// tracked keyword on every publish tick, so with a large library that
    /// used to add up to an O(keywords × files) sweep per tick.
    fn keyword_has_publishable_files(&self, keyword: &str) -> bool {
        let hash = keyword_to_kad_id(keyword);
        self.keyword_index.get(&hash).is_some_and(|file_hashes| {
            file_hashes
                .iter()
                .filter_map(|h| self.records.get(h))
                .any(|record| record.file.keyword_publishable)
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

/// Seed string behind [`ember_rendezvous_key`]. Versioned so the key space can
/// be sharded later without a flag day: a build that publishes to more than one
/// key derives them from `"...-v2:0"`, `"...-v2:1"`, … and publishes to the old
/// key too for one release so the two generations still find each other.
const EMBER_RENDEZVOUS_SEED: &str = "ember-dht-rendezvous-v1";

/// The KAD key Ember nodes advertise themselves under so a client with no DHT
/// contacts can find some.
///
/// KAD is a large, healthy DHT that Ember is already a full member of, which
/// makes it the one bootstrap channel available without a central server or a
/// hardcoded address. A node publishes an ordinary source record here — the
/// same record shape, carrying the same [`EMBER_NOISE_PUB_TAG`] every source
/// publish already carries — and a node looking to join runs an ordinary source
/// lookup, feeding whatever it finds to the DHT bridge.
///
/// Cost to KAD is one extra source record per node per republish interval,
/// which is a single additional entry in a rotation that already carries one
/// per shared file. Storing peers apply their usual per-key and per-IP caps to
/// it like any other record.
pub fn ember_rendezvous_key() -> KadId {
    md4_bytes_to_kad_id(&Md4::digest(EMBER_RENDEZVOUS_SEED.as_bytes()))
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

    /// Every Ember build has to derive the same rendezvous key or nodes
    /// advertise themselves where nobody is looking. Pinning the value guards
    /// the derivation against an innocent-looking refactor of the seed string
    /// or the MD4 word-order conversion.
    #[test]
    fn ember_rendezvous_key_is_stable() {
        let expected = md4_bytes_to_kad_id(&Md4::digest(b"ember-dht-rendezvous-v1"));
        assert_eq!(ember_rendezvous_key(), expected);
        // Stable across calls, and distinct from the raw digest ordering.
        assert_eq!(ember_rendezvous_key(), ember_rendezvous_key());
    }

    /// The rendezvous advert is gated on already publishing something, so a
    /// pure leecher never starts making KAD publish traffic purely to list
    /// itself. It can still look the key up.
    #[test]
    fn has_publishable_files_tracks_the_shared_set() {
        let mut p = make_publisher(false);
        assert!(!p.has_publishable_files());
        p.add_file(sample_file());
        assert!(p.has_publishable_files());
    }

    /// The advert reuses the ordinary source-publish builder, so it must carry
    /// the Noise key — that tag is the entire payload as far as a bootstrapping
    /// peer is concerned. Without it the record is useless to them.
    #[test]
    fn rendezvous_advert_carries_the_noise_pubkey() {
        let mut publisher = make_publisher(false);
        publisher.noise_pub = [7u8; 32];
        let advert = PublishableFile {
            file_hash: ember_rendezvous_key(),
            file_name: String::new(),
            file_size: 0,
            file_type: String::new(),
            complete_sources: 0,
            keyword_publishable: false,
            last_source_publish: 0,
        };
        let tags = match publisher.build_source_publish(&advert).unwrap() {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message type"),
        };
        let npub = tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Str(s) if s == EMBER_NOISE_PUB_TAG))
            .expect("rendezvous advert must carry the Noise pubkey");
        match &npub.value {
            TagValue::Bsob(b) => assert_eq!(b.as_slice(), &[7u8; 32]),
            _ => panic!("ember_npub tag must be a Bsob"),
        }
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

    #[test]
    fn buddyhash_tag_uses_uppercase_hex_like_emule_md4str() {
        let mut publisher = make_publisher(false);
        publisher.firewalled = true;
        publisher.direct_udp_callback = false;
        publisher.buddy_id = Some(KadId([0x11; 16]));
        publisher.buddy_ip = u32::from_be_bytes([10, 0, 0, 1]);
        publisher.buddy_port = 4662;

        let tags = match publisher.build_source_publish(&sample_file()).unwrap() {
            KadMessage::PublishSourceReq { tags, .. } => tags,
            _ => panic!("unexpected message"),
        };
        let buddyhash = tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Id(TAG_BUDDYHASH)))
            .and_then(|t| match &t.value {
                TagValue::String(s) => Some(s.as_str()),
                _ => None,
            })
            .expect("TAG_BUDDYHASH required for buddy publish");
        assert!(
            buddyhash.chars().all(|c| !c.is_ascii_lowercase()),
            "buddy hash must be uppercase hex like eMule md4str, got {buddyhash}"
        );
        let mut expected = publisher.local_id.0;
        for b in &mut expected {
            *b ^= 0xFF;
        }
        assert_eq!(buddyhash, hex::encode_upper(expected));
    }

    /// eMule `StorePacket`'s STOREFILE guard only refuses a file that has
    /// already been published within `REPUBLISH_SOURCE_SECS`; freshly
    /// registered files must not be re-offered on the very next tick.
    #[test]
    fn next_source_candidate_returns_none_when_not_due() {
        let mut p = make_publisher(false);
        let mut file = sample_file();
        file.last_source_publish = chrono::Utc::now().timestamp();
        p.add_file(file);
        assert!(
            p.next_source_candidate().is_none(),
            "freshly published file should not be due yet"
        );
    }

    /// eMule `CSharedFileList::m_currFileSrc`: a blind round-robin index
    /// that visits every shared file exactly once per sweep, then repeats
    /// in the same order — never re-scanning for "whichever file happens
    /// to be due" the way a `.find()` over the due set would.
    #[test]
    fn next_source_candidate_sweeps_all_files_before_repeating() {
        let mut p = make_publisher(false);
        let mut hashes: Vec<KadId> = Vec::new();
        for i in 0u8..5 {
            let mut file = sample_file();
            file.file_hash = KadId([i; 16]);
            file.file_name = format!("file-{i}.bin");
            file.last_source_publish = 0; // due immediately
            hashes.push(file.file_hash);
            p.add_file(file);
        }

        let first_sweep: Vec<KadId> = (0..hashes.len())
            .map(|_| {
                p.next_source_candidate()
                    .expect("all 5 files are due")
                    .file_hash
            })
            .collect();
        let mut sorted_first = first_sweep.clone();
        sorted_first.sort();
        let mut sorted_expected = hashes.clone();
        sorted_expected.sort();
        assert_eq!(
            sorted_first, sorted_expected,
            "one full sweep must visit every file exactly once"
        );

        let second_sweep: Vec<KadId> = (0..hashes.len())
            .map(|_| {
                p.next_source_candidate()
                    .expect("still due — mark_source_published was never called")
                    .file_hash
            })
            .collect();
        assert_eq!(
            second_sweep, first_sweep,
            "the sweep order must repeat identically, like eMule's wrapping index"
        );
    }

    /// Same "one candidate per call, full sweep before repeating" contract
    /// as `next_source_candidate`, for the keyword round-robin
    /// (`GetNextKeyword` in eMule).
    #[test]
    fn next_keyword_candidate_returns_none_when_not_due() {
        let mut p = make_publisher(false);
        p.add_file(sample_file());
        let hashes: Vec<KadId> = p.keyword_records.keys().copied().collect();
        for h in &hashes {
            p.mark_keyword_published(h);
        }
        assert!(
            p.next_keyword_candidate().is_none(),
            "just-published keyword should not be due yet"
        );
    }

    #[test]
    fn next_keyword_candidate_sweeps_all_keywords_before_repeating() {
        let mut p = make_publisher(false);
        let mut file = sample_file();
        file.file_name = "alpha bravo charlie.dat".to_string();
        p.add_file(file);
        let mut hashes: Vec<KadId> = p.keyword_records.keys().copied().collect();
        hashes.sort();
        assert_eq!(
            hashes.len(),
            3,
            "expected 3 distinct keywords from the sample filename"
        );

        let first_sweep: Vec<KadId> = (0..hashes.len())
            .map(|_| {
                p.next_keyword_candidate()
                    .expect("all keywords are due")
                    .keyword_hash
            })
            .collect();
        let mut sorted_first = first_sweep.clone();
        sorted_first.sort();
        assert_eq!(
            sorted_first, hashes,
            "one full sweep must visit every keyword exactly once"
        );

        let second_sweep: Vec<KadId> = (0..hashes.len())
            .map(|_| p.next_keyword_candidate().expect("still due").keyword_hash)
            .collect();
        assert_eq!(
            second_sweep, first_sweep,
            "sweep order must repeat identically"
        );
    }

    /// Regression guard: K15's load-based backoff must never stretch the
    /// keyword republish interval past what `store::KEYWORD_TTL_SECS`
    /// allows, or our published entries expire on every other node before
    /// we renew them. Check every possible `backoff_shift` value (the
    /// real range, plus a couple past the `.min(4)` clamp) stays under the
    /// TTL with the mandated safety margin.
    #[test]
    fn keyword_republish_interval_never_exceeds_store_ttl_minus_margin() {
        let ceiling = super::super::store::KEYWORD_TTL_SECS - KEYWORD_REPUBLISH_SAFETY_MARGIN_SECS;
        for shift in 0..=10u32 {
            let interval = keyword_republish_interval(shift);
            assert!(
                interval <= ceiling,
                "shift {shift} produced interval {interval}s, exceeding the \
                 {ceiling}s ceiling derived from KEYWORD_TTL_SECS"
            );
        }
        // The backoff must still do something within the ceiling: a higher
        // shift should never republish *more* often than a lower one.
        for shift in 0..10u32 {
            assert!(
                keyword_republish_interval(shift) <= keyword_republish_interval(shift + 1),
                "backoff interval must be monotonically non-decreasing with shift"
            );
        }
    }

    /// Reconciling the shared-file set with `retain_files` must keep the
    /// publish timestamps of files that remain and prune keyword targets
    /// whose only backing file was removed. Regression guard for the bug
    /// where every shared-file change wiped keyword publish times and
    /// caused keywords to republish from scratch indefinitely.
    #[test]
    fn retain_files_preserves_kept_keyword_timestamps_and_prunes_removed() {
        let mut p = PublishManager::new(KadId([0x01; 16]), [0x02; 16], 4662, 4672);
        let file_a = PublishableFile {
            file_hash: KadId([0xA1; 16]),
            file_name: "alpha bravo.dat".to_string(),
            file_size: 100,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        };
        let file_b = PublishableFile {
            file_hash: KadId([0xB2; 16]),
            file_name: "delta echo.dat".to_string(),
            file_size: 200,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        };
        p.add_file(file_a.clone());
        p.add_file(file_b.clone());

        // Mark every keyword target as published so we can prove the kept
        // file's timestamps survive reconciliation.
        let kw_hashes: Vec<KadId> = p.keyword_records.keys().copied().collect();
        for h in &kw_hashes {
            p.mark_keyword_published(h);
        }
        assert!(p.keyword_records.values().all(|r| r.last_publish > 0));

        // Reconcile down to just file A (as if file B was unshared).
        let keep: std::collections::HashSet<KadId> = [file_a.file_hash].into_iter().collect();
        p.retain_files(&keep);

        assert_eq!(p.file_count(), 1, "only the kept file should remain");
        assert!(p.records.contains_key(&file_a.file_hash));
        assert!(!p.records.contains_key(&file_b.file_hash));

        // File A's keyword targets are intact AND keep their publish time
        // (the bug was these being reset to 0 on every change).
        for kw in ["alpha", "bravo"] {
            let kh = keyword_to_kad_id(kw);
            let rec = p
                .keyword_records
                .get(&kh)
                .unwrap_or_else(|| panic!("kept keyword '{kw}' must survive retain"));
            assert!(
                rec.last_publish > 0,
                "kept keyword '{kw}' lost its publish time on reconcile"
            );
        }
        // File B's keyword targets are pruned (no remaining backing file).
        for kw in ["delta", "echo"] {
            let kh = keyword_to_kad_id(kw);
            assert!(
                !p.keyword_records.contains_key(&kh),
                "orphan keyword '{kw}' must be pruned after retain"
            );
        }
    }

    /// Regression coverage for `med-searchkeyreq-dos`: `files_for_keyword`
    /// must return exactly the keyword-publishable files backing a given
    /// keyword hash via the `keyword_index`, without needing to touch
    /// `local_index` or re-derive keywords for unrelated files.
    #[test]
    fn files_for_keyword_finds_matching_publishable_file() {
        let mut p = PublishManager::new(KadId([0x01; 16]), [0x02; 16], 4662, 4672);
        let matching = PublishableFile {
            file_hash: KadId([0xA1; 16]),
            file_name: "ubuntu server iso".to_string(),
            file_size: 100,
            file_type: "Iso".to_string(),
            complete_sources: 3,
            keyword_publishable: true,
            last_source_publish: 0,
        };
        let unrelated = PublishableFile {
            file_hash: KadId([0xB2; 16]),
            file_name: "totally different name".to_string(),
            file_size: 200,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        };
        p.add_file(matching.clone());
        p.add_file(unrelated);

        let hits = p.files_for_keyword(&keyword_to_kad_id("ubuntu"));
        assert_eq!(hits.len(), 1, "only the matching file should be returned");
        assert_eq!(hits[0].file_hash, matching.file_hash);

        let misses = p.files_for_keyword(&keyword_to_kad_id("nonexistent"));
        assert!(
            misses.is_empty(),
            "an unpublished keyword must return no files"
        );
    }

    /// A file registered with `keyword_publishable: false` (e.g. an
    /// in-progress partial download) must never surface via
    /// `files_for_keyword` — eMule only answers keyword search with
    /// complete shared files.
    #[test]
    fn files_for_keyword_excludes_non_publishable_files() {
        let mut p = PublishManager::new(KadId([0x01; 16]), [0x02; 16], 4662, 4672);
        p.add_file(PublishableFile {
            file_hash: KadId([0xC3; 16]),
            file_name: "partial download movie".to_string(),
            file_size: 500,
            file_type: "Video".to_string(),
            complete_sources: 0,
            keyword_publishable: false,
            last_source_publish: 0,
        });

        assert!(
            p.files_for_keyword(&keyword_to_kad_id("movie")).is_empty(),
            "a non-keyword-publishable file must not appear in keyword search"
        );
    }

    /// Renaming a file (re-`add_file` with the same hash but a different
    /// name) must drop the stale keyword association, not leave the
    /// file_hash indexed under both the old and new keyword forever.
    #[test]
    fn files_for_keyword_reflects_rename_not_stale_old_name() {
        let mut p = PublishManager::new(KadId([0x01; 16]), [0x02; 16], 4662, 4672);
        let hash = KadId([0xD4; 16]);
        p.add_file(PublishableFile {
            file_hash: hash,
            file_name: "original name".to_string(),
            file_size: 10,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        });
        assert_eq!(p.files_for_keyword(&keyword_to_kad_id("original")).len(), 1);

        p.add_file(PublishableFile {
            file_hash: hash,
            file_name: "renamed file".to_string(),
            file_size: 10,
            file_type: "Pro".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        });

        assert!(
            p.files_for_keyword(&keyword_to_kad_id("original"))
                .is_empty(),
            "the old keyword must no longer resolve to the renamed file"
        );
        assert_eq!(
            p.files_for_keyword(&keyword_to_kad_id("renamed")).len(),
            1,
            "the new keyword must resolve to the renamed file"
        );
    }

    /// `remove_file` must clean up `keyword_index`, not just `records` —
    /// otherwise a removed file's hash lingers in the index and
    /// `files_for_keyword` would return a dangling entry (silently
    /// filtered by the `records.get` lookup today, but wasted memory and
    /// a latent correctness trap for any future caller that assumes
    /// `keyword_index` entries are always live).
    #[test]
    fn remove_file_prunes_keyword_index() {
        let mut p = PublishManager::new(KadId([0x01; 16]), [0x02; 16], 4662, 4672);
        let hash = KadId([0xE5; 16]);
        p.add_file(PublishableFile {
            file_hash: hash,
            file_name: "removable document".to_string(),
            file_size: 10,
            file_type: "Doc".to_string(),
            complete_sources: 0,
            keyword_publishable: true,
            last_source_publish: 0,
        });
        assert_eq!(
            p.files_for_keyword(&keyword_to_kad_id("removable")).len(),
            1
        );

        p.remove_file(&hash);

        assert!(p
            .files_for_keyword(&keyword_to_kad_id("removable"))
            .is_empty());
        assert!(
            !p.keyword_index
                .contains_key(&keyword_to_kad_id("removable")),
            "an empty keyword bucket must be dropped entirely, not left as an empty Vec/Set"
        );
    }
}
