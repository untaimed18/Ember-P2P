use std::collections::HashMap;

use digest::Digest;
use md4::Md4;

use super::messages::*;
use super::types::*;

const REPUBLISH_KEYWORD_SECS: i64 = 24 * 3600;
const REPUBLISH_SOURCE_SECS: i64 = 5 * 3600;

#[derive(Debug, Clone)]
pub struct PublishableFile {
    pub file_hash: KadId,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub complete_sources: u32,
}

#[derive(Debug)]
struct PublishRecord {
    pub file: PublishableFile,
    pub last_keyword_publish: i64,
    pub last_source_publish: i64,
}

/// Manages publishing files to the KAD network.
#[derive(Debug)]
pub struct PublishManager {
    local_id: KadId,
    tcp_port: u16,
    udp_port: u16,
    pub firewalled: bool,
    pub buddy_ip: u32,
    pub buddy_port: u16,
    pub buddy_id: Option<KadId>,
    records: HashMap<KadId, PublishRecord>,
}

impl PublishManager {
    pub fn new(local_id: KadId, tcp_port: u16, udp_port: u16) -> Self {
        PublishManager {
            local_id,
            tcp_port,
            udp_port,
            firewalled: false,
            buddy_ip: 0,
            buddy_port: 0,
            buddy_id: None,
            records: HashMap::new(),
        }
    }

    /// Register a file for publishing.
    pub fn add_file(&mut self, file: PublishableFile) {
        self.records
            .entry(file.file_hash)
            .or_insert_with(|| PublishRecord {
                file,
                last_keyword_publish: 0,
                last_source_publish: 0,
            });
    }

    /// Remove a file from publishing.
    pub fn remove_file(&mut self, file_hash: &KadId) {
        self.records.remove(file_hash);
    }

    /// Clear all records and re-add files (for re-indexing).
    pub fn clear_all(&mut self) {
        self.records.clear();
    }

    /// Add a batch of files for publishing.
    pub fn add_files_batch(&mut self, files: Vec<PublishableFile>) {
        for file in files {
            self.add_file(file);
        }
    }

    /// Get files that need keyword republishing.
    pub fn files_needing_keyword_publish(&self) -> Vec<&PublishableFile> {
        let now = chrono::Utc::now().timestamp();
        self.records
            .values()
            .filter(|r| now - r.last_keyword_publish > REPUBLISH_KEYWORD_SECS)
            .map(|r| &r.file)
            .collect()
    }

    /// Get files that need source republishing.
    pub fn files_needing_source_publish(&self) -> Vec<&PublishableFile> {
        let now = chrono::Utc::now().timestamp();
        self.records
            .values()
            .filter(|r| now - r.last_source_publish > REPUBLISH_SOURCE_SECS)
            .map(|r| &r.file)
            .collect()
    }

    /// Mark a file's keywords as published.
    pub fn mark_keyword_published(&mut self, file_hash: &KadId) {
        if let Some(record) = self.records.get_mut(file_hash) {
            record.last_keyword_publish = chrono::Utc::now().timestamp();
        }
    }

    /// Mark a file's source as published.
    pub fn mark_source_published(&mut self, file_hash: &KadId) {
        if let Some(record) = self.records.get_mut(file_hash) {
            record.last_source_publish = chrono::Utc::now().timestamp();
        }
    }

    /// Build a KADEMLIA2_PUBLISH_SOURCE_REQ message for a file.
    /// For firewalled clients, includes buddy information so peers can reach us
    /// via relay (matching eMule's Search.cpp StorePacket STOREFILE case).
    pub fn build_source_publish(&self, file: &PublishableFile) -> KadMessage {
        let mut tags = Vec::new();

        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEIP),
            value: TagValue::Uint32(0),
        });
        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEPORT),
            value: TagValue::Uint16(self.tcp_port),
        });
        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEUPORT),
            value: TagValue::Uint16(self.udp_port),
        });

        if self.firewalled {
            if let Some(ref buddy_id) = self.buddy_id {
                // eMule source type 2 = KAD firewalled with buddy
                tags.push(KadTag {
                    name: TagName::Id(TAG_SOURCETYPE),
                    value: TagValue::Uint8(2),
                });
                tags.push(KadTag {
                    name: TagName::Id(TAG_SERVERIP),
                    value: TagValue::Uint32(self.buddy_ip),
                });
                tags.push(KadTag {
                    name: TagName::Id(TAG_SERVERPORT),
                    value: TagValue::Uint16(self.buddy_port),
                });
                // Buddy KAD ID as a binary tag so the downloader can do a callback
                tags.push(KadTag {
                    name: TagName::Id(TAG_BUDDYHASH),
                    value: TagValue::Hash(buddy_id.0),
                });
            } else {
                // Firewalled without a buddy - still publish but mark as type 4
                // (KAD firewalled, no buddy -- peers can try UDP callback)
                tags.push(KadTag {
                    name: TagName::Id(TAG_SOURCETYPE),
                    value: TagValue::Uint8(4),
                });
            }
        } else {
            // Not firewalled - direct connect (eMule source type 3 = KAD)
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCETYPE),
                value: TagValue::Uint8(3),
            });
        }

        tags.push(KadTag {
            name: TagName::Id(TAG_FILESIZE),
            value: TagValue::Uint64(file.file_size),
        });

        KadMessage::PublishSourceReq {
            target: file.file_hash,
            sender_id: self.local_id,
            tags,
        }
    }

    /// Build keyword publish data for a file.
    /// Keywords are extracted from the filename, each hashed with MD4 to get a KAD target.
    pub fn build_keyword_publishes(&self, file: &PublishableFile) -> Vec<(KadId, KadMessage)> {
        let keywords = extract_keywords(&file.file_name);
        let mut messages = Vec::new();

        for keyword in keywords {
            let keyword_hash = keyword_to_kad_id(&keyword);

            let entry = PublishEntry {
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
                        value: TagValue::Uint32(1),
                    },
                    KadTag {
                        name: TagName::Id(TAG_COMPLETE_SOURCES),
                        value: TagValue::Uint32(file.complete_sources.max(1)),
                    },
                ],
            };

            let msg = KadMessage::PublishKeyReq {
                target: keyword_hash,
                entries: vec![entry],
            };

            messages.push((keyword_hash, msg));
        }

        messages
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
        if let Some(record) = self.records.get_mut(file_hash) {
            record.last_keyword_publish = 0;
        }
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
        matches!(c, '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | ',' | '.' | '_' | '-' | '!' | '?' | ':' | ';' | '\\' | '/' | '"')
        || c.is_whitespace()
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
