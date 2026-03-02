use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};
use strsim::normalized_levenshtein;
use tracing::{debug, info, warn};

use crate::types::SearchResult;

const SPAM_FILEHASH_HIT: u32 = 60;
const SPAM_FULLNAME_HIT: u32 = 40;
const SPAM_SMALLFULLNAME_HIT: u32 = 10;
const SPAM_SIMILARNAME_HIT: u32 = 30;
const SPAM_SIMILARNAME_NEARHIT: u32 = 20;
const SPAM_SIMILARNAME_FARHIT: u32 = 10;
const SPAM_SIMILARSIZE_HIT: u32 = 10;
const SPAM_UDPSERVERRES_HIT: u32 = 30;
const SPAM_UDPSERVERRES_NEARHIT: u32 = 15;
const SPAM_UDPSERVERRES_FARHIT: u32 = 5;
const SPAM_ONLYUDPSPAMSERVERS_HIT: u32 = 20;
const SPAM_SOURCE_HIT: u32 = 10;
pub const SEARCH_SPAM_THRESHOLD: u32 = 60;

const SMALL_FILENAME_LEN: usize = 10;
const SIZE_TOLERANCE_BYTES: u64 = 5 * 1024 * 1024;
const SIZE_TOLERANCE_PERCENT: f64 = 0.05;

const TOKEN_DELIMITERS: &[char] = &['.', '[', ']', '(', ')', '!', '-', '\'', '_', ' '];

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpamDatabase {
    pub spam_hashes: HashSet<String>,
    pub not_spam_hashes: HashSet<String>,
    pub spam_filenames: Vec<String>,
    pub spam_similar_names: Vec<String>,
    pub spam_sizes: Vec<u64>,
    pub spam_source_ips: HashSet<String>,
    pub spam_server_ips: HashSet<String>,
    pub udp_server_spam_ratios: HashMap<String, f32>,
}

pub struct SpamFilter {
    db: SpamDatabase,
    data_path: std::path::PathBuf,
    dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamStats {
    pub spam_hashes: usize,
    pub not_spam_hashes: usize,
    pub spam_filenames: usize,
    pub spam_server_ips: usize,
    pub spam_source_ips: usize,
}

impl SpamFilter {
    pub fn load(data_dir: &Path) -> Self {
        let data_path = data_dir.join("search_spam.json");
        let db = if data_path.exists() {
            match std::fs::read_to_string(&data_path) {
                Ok(data) => match serde_json::from_str::<SpamDatabase>(&data) {
                    Ok(db) => {
                        info!(
                            "Loaded spam filter: {} hashes, {} filenames",
                            db.spam_hashes.len(),
                            db.spam_filenames.len()
                        );
                        db
                    }
                    Err(e) => {
                        warn!("Failed to parse search_spam.json, starting fresh: {e}");
                        SpamDatabase::default()
                    }
                },
                Err(e) => {
                    warn!("Failed to read search_spam.json: {e}");
                    SpamDatabase::default()
                }
            }
        } else {
            SpamDatabase::default()
        };
        Self {
            db,
            data_path,
            dirty: false,
        }
    }

    pub fn save(&mut self) {
        if !self.dirty {
            return;
        }
        match serde_json::to_string_pretty(&self.db) {
            Ok(data) => {
                let tmp = self.data_path.with_extension("json.tmp");
                if std::fs::write(&tmp, &data).is_ok() {
                    let _ = std::fs::rename(&tmp, &self.data_path);
                    self.dirty = false;
                    debug!("Spam filter saved");
                }
            }
            Err(e) => warn!("Failed to serialize spam filter: {e}"),
        }
    }

    pub fn stats(&self) -> SpamStats {
        SpamStats {
            spam_hashes: self.db.spam_hashes.len(),
            not_spam_hashes: self.db.not_spam_hashes.len(),
            spam_filenames: self.db.spam_filenames.len(),
            spam_server_ips: self.db.spam_server_ips.len(),
            spam_source_ips: self.db.spam_source_ips.len(),
        }
    }

    pub fn rate_result(
        &self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
    ) -> u32 {
        let hash = &result.file.hash;
        let name = &result.file.name;
        let size = result.file.size;

        if self.db.not_spam_hashes.contains(hash) {
            return 0;
        }

        let mut score: u32 = 0;

        if self.db.spam_hashes.contains(hash) {
            score += SPAM_FILEHASH_HIT;
        }

        let name_lower = name.to_lowercase();
        for spam_name in &self.db.spam_filenames {
            if name_lower == spam_name.to_lowercase() {
                score += if name.len() < SMALL_FILENAME_LEN {
                    SPAM_SMALLFULLNAME_HIT
                } else {
                    SPAM_FULLNAME_HIT
                };
                break;
            }
        }

        let stripped = name_without_keywords(name, search_keywords);
        if !stripped.is_empty() {
            for similar in &self.db.spam_similar_names {
                let sim = normalized_levenshtein(&stripped.to_lowercase(), &similar.to_lowercase());
                if sim > 0.95 {
                    score += SPAM_SIMILARNAME_HIT;
                    break;
                } else if sim > 0.85 {
                    score += SPAM_SIMILARNAME_NEARHIT;
                    break;
                } else if sim > 0.70 {
                    score += SPAM_SIMILARNAME_FARHIT;
                    break;
                }
            }
        }

        for &spam_size in &self.db.spam_sizes {
            let diff = if size > spam_size {
                size - spam_size
            } else {
                spam_size - size
            };
            if diff < SIZE_TOLERANCE_BYTES
                && (spam_size == 0 || (diff as f64 / spam_size as f64) < SIZE_TOLERANCE_PERCENT)
            {
                score += SPAM_SIMILARSIZE_HIT;
                break;
            }
        }

        for addr in &result.source_addresses {
            let ip = addr.split(':').next().unwrap_or("");
            if self.db.spam_source_ips.contains(ip) {
                score += SPAM_SOURCE_HIT;
                break;
            }
        }

        if let Some(sip) = server_ip {
            if self.db.spam_server_ips.contains(sip) {
                let all_from_spam = result
                    .source_addresses
                    .iter()
                    .all(|a| a.is_empty());
                if all_from_spam {
                    score += SPAM_UDPSERVERRES_HIT;
                } else {
                    score += SPAM_UDPSERVERRES_NEARHIT;
                }
            }
            if let Some(&ratio) = self.db.udp_server_spam_ratios.get(sip) {
                if ratio > 0.5 {
                    score += SPAM_ONLYUDPSPAMSERVERS_HIT;
                } else if ratio > 0.3 {
                    score += SPAM_UDPSERVERRES_FARHIT;
                }
            }
        }

        score
    }

    pub fn mark_spam(&mut self, result: &SearchResult, search_keywords: &[String]) {
        self.db.spam_hashes.insert(result.file.hash.clone());
        self.db.not_spam_hashes.remove(&result.file.hash);

        let name = &result.file.name;
        let name_lower = name.to_lowercase();
        if !self.db.spam_filenames.iter().any(|n| n.to_lowercase() == name_lower) {
            self.db.spam_filenames.push(name.clone());
        }

        let stripped = name_without_keywords(name, search_keywords);
        if !stripped.is_empty() {
            let stripped_lower = stripped.to_lowercase();
            if !self
                .db
                .spam_similar_names
                .iter()
                .any(|n| n.to_lowercase() == stripped_lower)
            {
                self.db.spam_similar_names.push(stripped);
            }
        }

        if result.file.size > 0 && !self.db.spam_sizes.contains(&result.file.size) {
            self.db.spam_sizes.push(result.file.size);
        }

        for addr in &result.source_addresses {
            if let Some(ip) = addr.split(':').next() {
                if !ip.is_empty() {
                    self.db.spam_source_ips.insert(ip.to_string());
                }
            }
        }

        self.dirty = true;
        self.save();
        info!("Marked as spam: {} ({})", name, result.file.hash);
    }

    pub fn mark_not_spam(&mut self, file_hash: &str) {
        self.db.not_spam_hashes.insert(file_hash.to_string());
        self.db.spam_hashes.remove(file_hash);
        self.dirty = true;
        self.save();
        info!("Marked as not spam: {file_hash}");
    }

    pub fn is_spam(score: u32) -> bool {
        score >= SEARCH_SPAM_THRESHOLD
    }
}

/// Remove search keywords from a filename to isolate the non-keyword portion.
/// This matches eMule's logic in SearchList.cpp: the filename is tokenized and
/// any token that matches a search keyword is removed. The remaining tokens are
/// the "spam signature" of the filename.
pub fn name_without_keywords(filename: &str, keywords: &[String]) -> String {
    let kw_lower: Vec<String> = keywords.iter().map(|k| k.to_lowercase()).collect();
    let tokens: Vec<&str> = filename.split(|c: char| TOKEN_DELIMITERS.contains(&c))
        .filter(|t| !t.is_empty())
        .collect();

    let remaining: Vec<&str> = tokens
        .into_iter()
        .filter(|t| {
            let t_lower = t.to_lowercase();
            !kw_lower.iter().any(|kw| t_lower == *kw)
        })
        .collect();

    remaining.join(" ")
}
