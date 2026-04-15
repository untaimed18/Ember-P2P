use std::collections::{HashMap, HashSet, VecDeque};
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
const SPAM_FAKE_PATTERN_HIT: u32 = 25;
pub const SEARCH_SPAM_THRESHOLD: u32 = 60;
pub const SEARCH_SPAM_THRESHOLD_AGGRESSIVE: u32 = 45;
pub const SEARCH_SPAM_THRESHOLD_RELAXED: u32 = 80;

const SMALL_FILENAME_LEN: usize = 10;
const MIN_SIMILAR_NAME_LEN: usize = 6;
const MAX_LEVENSHTEIN_LEN: usize = 256;
const SIZE_TOLERANCE_BYTES: u64 = 5 * 1024 * 1024;
const SIZE_TOLERANCE_PERCENT: f64 = 0.05;
const MAX_NOT_SPAM_HASHES: usize = 2000;

const TOKEN_DELIMITERS: &[char] = &['.', '[', ']', '(', ')', '!', '-', '\'', '_', ' '];

/// Known fake/spam filename tokens commonly used to pollute ed2k search results.
/// Matches are case-insensitive against normalized filename tokens.
const FAKE_FILENAME_TOKENS: &[&str] = &[
    "password", "serial", "keygen", "crack", "patch",
    "codec", "install_flash_player", "install_codec",
];

/// Suspicious URL-like patterns in filenames (case-insensitive substring match).
const FAKE_URL_PATTERNS: &[&str] = &[
    "www.", "http:", "https:", ".com/", ".net/", ".org/",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamFilterProfile {
    Relaxed,
    Balanced,
    Aggressive,
}

impl SpamFilterProfile {
    pub fn from_setting(value: &str) -> Self {
        if value.eq_ignore_ascii_case("aggressive") {
            Self::Aggressive
        } else if value.eq_ignore_ascii_case("relaxed") {
            Self::Relaxed
        } else {
            Self::Balanced
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamExplanation {
    pub score: u32,
    pub threshold: u32,
    pub profile: String,
    pub is_spam: bool,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SpamDatabase {
    pub spam_hashes: HashSet<String>,
    pub not_spam_hashes: HashSet<String>,
    pub spam_filenames: Vec<String>,
    pub spam_similar_names: Vec<String>,
    pub spam_sizes: VecDeque<u64>,
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
        let data = match serde_json::to_string_pretty(&self.db) {
            Ok(d) => d,
            Err(e) => { warn!("Failed to serialize spam filter: {e}"); return; }
        };
        let tmp = self.data_path.with_extension("json.tmp");
        if let Err(e) = std::fs::write(&tmp, &data) {
            warn!("Failed to write spam filter temp file: {e}");
            return;
        }
        match std::fs::rename(&tmp, &self.data_path) {
            Ok(()) => {
                self.dirty = false;
                debug!("Spam filter saved");
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                warn!("Failed to save spam filter: {e}");
            }
        }
    }

    pub fn take_save_data(&mut self) -> Option<(String, std::path::PathBuf)> {
        if !self.dirty {
            return None;
        }
        match serde_json::to_string_pretty(&self.db) {
            Ok(data) => {
                self.dirty = false;
                Some((data, self.data_path.clone()))
            }
            Err(e) => {
                warn!("Failed to serialize spam filter: {e}");
                None
            }
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

    pub fn reset(&mut self) {
        self.db = SpamDatabase::default();
        self.dirty = true;
        self.save();
        info!("Spam filter database reset");
    }

    fn threshold_for_profile(profile: SpamFilterProfile) -> u32 {
        match profile {
            SpamFilterProfile::Relaxed => SEARCH_SPAM_THRESHOLD_RELAXED,
            SpamFilterProfile::Balanced => SEARCH_SPAM_THRESHOLD,
            SpamFilterProfile::Aggressive => SEARCH_SPAM_THRESHOLD_AGGRESSIVE,
        }
    }

    pub fn explain_result(
        &self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
        profile: SpamFilterProfile,
    ) -> SpamExplanation {
        let hash = normalize_hash(&result.file.hash);
        let name = &result.file.name;
        let size = result.file.size;
        let threshold = Self::threshold_for_profile(profile);

        if self.db.not_spam_hashes.contains(&hash) {
            return SpamExplanation {
                score: 0,
                threshold,
                profile: profile_name(profile),
                is_spam: false,
                reasons: vec!["Manually marked as not spam".to_string()],
            };
        }

        let mut score: u32 = 0;
        let mut reasons = Vec::new();

        if self.db.spam_hashes.contains(&hash) {
            score += SPAM_FILEHASH_HIT;
            reasons.push(format!("Known spam hash (+{SPAM_FILEHASH_HIT})"));
        }

        let name_norm = normalize_filename(name);
        for spam_name in &self.db.spam_filenames {
            if name_norm == *spam_name {
                let bump = if name.len() < SMALL_FILENAME_LEN {
                    SPAM_SMALLFULLNAME_HIT
                } else {
                    SPAM_FULLNAME_HIT
                };
                score += bump;
                reasons.push(format!("Exact spam filename match (+{bump})"));
                break;
            }
        }

        let stripped = name_without_keywords(name, search_keywords);
        if stripped.len() >= MIN_SIMILAR_NAME_LEN && stripped.len() <= MAX_LEVENSHTEIN_LEN {
            for similar in &self.db.spam_similar_names {
                let sim = normalized_levenshtein(&stripped, similar);
                if sim > 0.95 {
                    score += SPAM_SIMILARNAME_HIT;
                    reasons.push(format!("Very similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_HIT})", sim * 100.0));
                    break;
                } else if sim > 0.85 {
                    score += SPAM_SIMILARNAME_NEARHIT;
                    reasons.push(format!("Similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_NEARHIT})", sim * 100.0));
                    break;
                } else if sim > 0.70 {
                    score += SPAM_SIMILARNAME_FARHIT;
                    reasons.push(format!("Loosely similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_FARHIT})", sim * 100.0));
                    break;
                }
            }
        }

        for &spam_size in &self.db.spam_sizes {
            let diff = size.abs_diff(spam_size);
            if diff < SIZE_TOLERANCE_BYTES
                && (spam_size == 0 || (diff as f64 / spam_size as f64) < SIZE_TOLERANCE_PERCENT)
            {
                score += SPAM_SIMILARSIZE_HIT;
                reasons.push(format!("Matches known spam size signature (+{SPAM_SIMILARSIZE_HIT})"));
                break;
            }
        }

        if has_fake_filename_pattern(name) {
            score += SPAM_FAKE_PATTERN_HIT;
            reasons.push(format!("Contains known fake/suspicious pattern (+{SPAM_FAKE_PATTERN_HIT})"));
        }

        let mut spam_source_count = 0u32;
        for addr in &result.source_addresses {
            if let Some(ip) = extract_ip(addr) {
                if self.db.spam_source_ips.contains(&ip) {
                    spam_source_count += 1;
                }
            }
        }
        if spam_source_count > 0 {
            score += SPAM_SOURCE_HIT;
            reasons.push(format!("Source IP seen in spam hits (+{SPAM_SOURCE_HIT})"));
        }

        if let Some(sip) = server_ip.and_then(|s| extract_ip(s)) {
            if self.db.spam_server_ips.contains(&sip) {
                let total_sources = result.source_addresses.iter()
                    .filter(|a| extract_ip(a).is_some())
                    .count();
                let all_sources_spam = total_sources > 0
                    && total_sources as u32 == spam_source_count;
                if all_sources_spam || total_sources == 0 {
                    score += SPAM_UDPSERVERRES_HIT;
                    reasons.push(format!("Result from spam-heavy server, all sources spam (+{SPAM_UDPSERVERRES_HIT})"));
                } else {
                    score += SPAM_UDPSERVERRES_NEARHIT;
                    reasons.push(format!("Result influenced by spam server (+{SPAM_UDPSERVERRES_NEARHIT})"));
                }
            }
            if let Some(&ratio) = self.db.udp_server_spam_ratios.get(&sip) {
                if ratio > 0.5 {
                    score += SPAM_ONLYUDPSPAMSERVERS_HIT;
                    reasons.push(format!("Server spam ratio is high ({:.0}%, +{SPAM_ONLYUDPSPAMSERVERS_HIT})", ratio * 100.0));
                } else if ratio > 0.3 {
                    score += SPAM_UDPSERVERRES_FARHIT;
                    reasons.push(format!("Server spam ratio is elevated ({:.0}%, +{SPAM_UDPSERVERRES_FARHIT})", ratio * 100.0));
                }
            }
        }

        if profile == SpamFilterProfile::Aggressive {
            let boosted = (score as f32 * 1.2).round() as u32;
            if boosted > score {
                reasons.push(format!("Aggressive profile sensitivity boost (+{})", boosted - score));
                score = boosted;
            }
        }

        if reasons.is_empty() {
            reasons.push("No strong spam signals".to_string());
        }

        SpamExplanation {
            score,
            threshold,
            profile: profile_name(profile),
            is_spam: score >= threshold,
            reasons,
        }
    }

    pub fn rate_result(
        &self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
        profile: SpamFilterProfile,
    ) -> u32 {
        self.explain_result(result, search_keywords, server_ip, profile).score
    }

    pub fn mark_spam(&mut self, result: &SearchResult, search_keywords: &[String], server_ip: Option<&str>) {
        const MAX_SPAM_HASHES: usize = 2000;
        let file_hash = normalize_hash(&result.file.hash);
        if !file_hash.is_empty() {
            if self.db.spam_hashes.len() >= MAX_SPAM_HASHES {
                if let Some(first) = self.db.spam_hashes.iter().next().cloned() {
                    self.db.spam_hashes.remove(&first);
                }
            }
            self.db.spam_hashes.insert(file_hash.clone());
            self.db.not_spam_hashes.remove(&file_hash);
        }

        let name = &result.file.name;
        let name_norm = normalize_filename(name);
        if !name_norm.is_empty() && !self.db.spam_filenames.contains(&name_norm) {
            const MAX_SPAM_FILENAMES: usize = 500;
            if self.db.spam_filenames.len() >= MAX_SPAM_FILENAMES {
                self.db.spam_filenames.remove(0);
            }
            self.db.spam_filenames.push(name_norm);
        }

        let stripped = name_without_keywords(name, search_keywords);
        if stripped.len() >= MIN_SIMILAR_NAME_LEN && stripped.len() <= MAX_LEVENSHTEIN_LEN && !self.db.spam_similar_names.contains(&stripped) {
            const MAX_SPAM_SIMILAR_NAMES: usize = 500;
            if self.db.spam_similar_names.len() >= MAX_SPAM_SIMILAR_NAMES {
                self.db.spam_similar_names.remove(0);
            }
            self.db.spam_similar_names.push(stripped);
        }

        const MAX_SPAM_SIZES: usize = 1000;
        if result.file.size > 0 && !self.db.spam_sizes.contains(&result.file.size) {
            if self.db.spam_sizes.len() >= MAX_SPAM_SIZES {
                self.db.spam_sizes.pop_front();
            }
            self.db.spam_sizes.push_back(result.file.size);
        }

        const MAX_SOURCE_IPS_PER_RESULT: usize = 3;
        const MAX_SPAM_SOURCE_IPS: usize = 2000;
        for addr in result.source_addresses.iter().take(MAX_SOURCE_IPS_PER_RESULT) {
            if let Some(ip) = extract_ip(addr) {
                if self.db.spam_source_ips.len() >= MAX_SPAM_SOURCE_IPS {
                    if let Some(first) = self.db.spam_source_ips.iter().next().cloned() {
                        self.db.spam_source_ips.remove(&first);
                    }
                }
                self.db.spam_source_ips.insert(ip);
            }
        }

        if let Some(sip) = server_ip.and_then(|s| extract_ip(s)) {
            const MAX_SPAM_SERVER_IPS: usize = 500;
            if self.db.spam_server_ips.len() >= MAX_SPAM_SERVER_IPS {
                if let Some(first) = self.db.spam_server_ips.iter().next().cloned() {
                    self.db.spam_server_ips.remove(&first);
                }
            }
            self.db.spam_server_ips.insert(sip.clone());

            let entry = self.db.udp_server_spam_ratios.entry(sip).or_insert(0.0);
            *entry = (*entry * 0.9 + 0.1).min(1.0);
            const MAX_SERVER_RATIOS: usize = 500;
            if self.db.udp_server_spam_ratios.len() > MAX_SERVER_RATIOS {
                if let Some(lowest_key) = self.db.udp_server_spam_ratios.iter()
                    .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(k, _)| k.clone())
                {
                    self.db.udp_server_spam_ratios.remove(&lowest_key);
                }
            }
        }

        self.dirty = true;
        info!("Marked as spam: {} ({})", name, result.file.hash);
    }

    pub fn mark_not_spam(&mut self, file_hash: &str) {
        let file_hash = normalize_hash(file_hash);
        if self.db.not_spam_hashes.len() >= MAX_NOT_SPAM_HASHES {
            if let Some(first) = self.db.not_spam_hashes.iter().next().cloned() {
                self.db.not_spam_hashes.remove(&first);
            }
        }
        self.db.not_spam_hashes.insert(file_hash.clone());
        self.db.spam_hashes.remove(&file_hash);
        self.dirty = true;
        info!("Marked as not spam: {file_hash}");
    }

    /// Silently add a hash to the not-spam whitelist (e.g. on completed download).
    /// Does not save immediately; caller should ensure periodic save happens.
    pub fn auto_mark_not_spam(&mut self, file_hash: &str) {
        let file_hash = normalize_hash(file_hash);
        if file_hash.is_empty() {
            return;
        }
        if self.db.not_spam_hashes.contains(&file_hash) {
            return;
        }
        if self.db.not_spam_hashes.len() >= MAX_NOT_SPAM_HASHES {
            if let Some(first) = self.db.not_spam_hashes.iter().next().cloned() {
                self.db.not_spam_hashes.remove(&first);
            }
        }
        self.db.not_spam_hashes.insert(file_hash.clone());
        self.db.spam_hashes.remove(&file_hash);
        self.dirty = true;
        debug!("Auto-marked completed download as not spam: {file_hash}");
    }

    pub fn is_spam(score: u32, profile: SpamFilterProfile) -> bool {
        let threshold = Self::threshold_for_profile(profile);
        score >= threshold
    }
}

fn profile_name(profile: SpamFilterProfile) -> String {
    match profile {
        SpamFilterProfile::Relaxed => "relaxed".to_string(),
        SpamFilterProfile::Balanced => "balanced".to_string(),
        SpamFilterProfile::Aggressive => "aggressive".to_string(),
    }
}

/// Check if a filename contains known fake/spam patterns.
fn has_fake_filename_pattern(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();

    for pattern in FAKE_URL_PATTERNS {
        if lower.contains(pattern) {
            return true;
        }
    }

    let tokens: Vec<String> = filename
        .split(|c: char| TOKEN_DELIMITERS.contains(&c))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect();

    for token in &tokens {
        for fake in FAKE_FILENAME_TOKENS {
            if token == fake {
                return true;
            }
        }
    }

    false
}

/// Remove search keywords from a filename to isolate the non-keyword portion.
/// This matches eMule's logic in SearchList.cpp: the filename is tokenized and
/// any token that matches a search keyword is removed. The remaining tokens are
/// the "spam signature" of the filename.
pub fn name_without_keywords(filename: &str, keywords: &[String]) -> String {
    let kw_tokens = keyword_tokens(keywords);
    filename
        .split(|c: char| TOKEN_DELIMITERS.contains(&c))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .filter(|t| !kw_tokens.contains(t))
        .collect::<Vec<_>>()
        .join(" ")
}

fn normalize_hash(hash: &str) -> String {
    hash.trim().to_ascii_lowercase()
}

fn normalize_filename(name: &str) -> String {
    name.split(|c: char| TOKEN_DELIMITERS.contains(&c))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

fn extract_ip(addr: &str) -> Option<String> {
    if addr.is_empty() {
        return None;
    }

    if let Ok(ip) = addr.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if let Ok(sock) = addr.parse::<std::net::SocketAddr>() {
        return Some(sock.ip().to_string());
    }

    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let ip = &rest[..end];
            if ip.parse::<std::net::IpAddr>().is_ok() {
                return Some(ip.to_string());
            }
        }
    }

    if addr.matches(':').count() == 1 {
        if let Some((ip, _port)) = addr.split_once(':') {
            if ip.parse::<std::net::IpAddr>().is_ok() {
                return Some(ip.to_string());
            }
        }
    }

    None
}

fn keyword_tokens(keywords: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    for kw in keywords {
        for token in kw
            .split(|c: char| TOKEN_DELIMITERS.contains(&c))
            .filter(|t| !t.is_empty())
        {
            out.insert(token.to_ascii_lowercase());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let unique = format!(
            "ember-spam-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_result(hash: &str, name: &str) -> SearchResult {
        SearchResult {
            file: crate::types::FileInfo {
                id: hash.to_string(),
                name: name.to_string(),
                path: String::new(),
                size: 123,
                hash: hash.to_string(),
                aich_hash: String::new(),
                extension: "bin".to_string(),
                modified_at: 0,
                priority: "normal".to_string(),
                requests: 0,
                accepted: 0,
                bytes_transferred: 0,
                alltime_requests: 0,
                alltime_accepted: 0,
                alltime_transferred: 0,
                complete_sources: 0,
                folder: String::new(),
                shared: false,
                shared_kad: false,
                shared_ed2k: false,
            },
            peer_id: String::new(),
            peer_name: String::new(),
            availability: 1,
            file_type: String::new(),
            source_addresses: Vec::new(),
            rating: None,
            comment: None,
            spam_rating: 0,
            is_spam: false,
            clean_name: String::new(),
            result_origin: String::new(),
        }
    }

    #[test]
    fn save_overwrites_existing_database() {
        let dir = temp_dir("overwrite");
        let mut filter = SpamFilter::load(&dir);
        let hash_a = "a".repeat(32);
        let hash_b = "b".repeat(32);

        filter.mark_spam(&sample_result(&hash_a, "first.bin"), &[], None);
        filter.save();

        let mut reloaded = SpamFilter::load(&dir);
        assert!(reloaded.db.spam_hashes.contains(&hash_a));

        reloaded.mark_spam(&sample_result(&hash_b, "second.bin"), &[], None);
        reloaded.save();

        let latest = SpamFilter::load(&dir);
        assert!(latest.db.spam_hashes.contains(&hash_a));
        assert!(latest.db.spam_hashes.contains(&hash_b));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn name_without_keywords_normalizes_tokens() {
        let out = name_without_keywords(
            "My.Movie-2026[1080p]_X264.mkv",
            &["movie".to_string(), "1080p".to_string()],
        );
        assert_eq!(out, "my 2026 x264 mkv");
    }

    #[test]
    fn hash_match_is_case_insensitive() {
        let dir = temp_dir("hash-case");
        let mut filter = SpamFilter::load(&dir);
        let result = sample_result("ABCDEF0123456789ABCDEF0123456789", "sample.bin");
        filter.mark_spam(&result, &[], None);

        let score = filter.rate_result(
            &sample_result("abcdef0123456789abcdef0123456789", "other.bin"),
            &[],
            None,
            SpamFilterProfile::Balanced,
        );
        assert!(score >= SPAM_FILEHASH_HIT);

        let _ = std::fs::remove_dir_all(dir);
    }
}
