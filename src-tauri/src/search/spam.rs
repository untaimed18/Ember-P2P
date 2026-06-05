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

// Filename-token signals, split into two confidence tiers. STRONG tokens are
// almost exclusively seen on fake/pollution uploads, while WEAK tokens
// ("patch", "codec", "crack", ...) appear constantly in legitimate software,
// games and release filenames. The old single +25 weight for the weak set was
// a genuine false-positive source, so weak tokens now contribute only a small
// nudge and rely on corroborating signals to cross the threshold.
const SPAM_STRONG_TOKEN_HIT: u32 = 25;
const SPAM_WEAK_TOKEN_HIT: u32 = 8;
const SPAM_FAKE_URL_HIT: u32 = 25;
/// Cap on the total filename-pattern contribution so a name stuffed with many
/// weak tokens can't dominate the score on its own.
const SPAM_PATTERN_MAX: u32 = 30;

// Community-rating signals (peer / KAD notes). A file the network has voted
// "fake" is one of the strongest spam indicators eMule uses.
const SPAM_FAKE_RATING_HIT: u32 = 40;
const SPAM_FAKE_RATING_NEARHIT: u32 = 20;
const FAKE_RATING_MIN_VOTES: u32 = 2;
const FAKE_RATING_MAJORITY: f32 = 0.5;
const FAKE_RATING_SOME: f32 = 0.25;

// Intra-result-set (batch) statistical signals — coordinated index poisoning
// that's only visible across the whole result set, not in any single entry.
const SPAM_BATCH_NAME_MANY_HASHES_HIT: u32 = 25;
const SPAM_BATCH_HASH_MANY_NAMES_HIT: u32 = 25;
const SPAM_BATCH_SOURCE_CONCENTRATION_HIT: u32 = 15;
/// Don't run statistical detection on tiny result sets (insufficient signal).
const BATCH_MIN_RESULTS_FOR_STATS: usize = 8;
/// Distinct hashes sharing one exact (specific) filename before it's suspicious.
const BATCH_NAME_DISTINCT_HASHES_MIN: usize = 3;
/// Distinct filenames advertised for one hash before it's suspicious.
const BATCH_HASH_DISTINCT_NAMES_MIN: usize = 3;
/// A normalized filename must be at least this many chars to be "specific"
/// enough that many-hashes-per-name is meaningful (avoids flagging generic
/// names like "setup exe").
const BATCH_MIN_NAME_LEN_FOR_COLLISION: usize = 8;
/// A source IP referenced by at least this fraction of the batch is "hot"
/// (likely an index-poisoning node).
const BATCH_SOURCE_HOT_SHARE: f64 = 0.5;
/// Only treat a source IP as hot once the batch is at least this large, so a
/// handful of legitimate results that happen to share a seeder don't trip it.
const BATCH_SOURCE_MIN_HITS: usize = 4;

pub const SEARCH_SPAM_THRESHOLD: u32 = 60;
pub const SEARCH_SPAM_THRESHOLD_AGGRESSIVE: u32 = 45;
pub const SEARCH_SPAM_THRESHOLD_RELAXED: u32 = 80;

const SMALL_FILENAME_LEN: usize = 10;
const MIN_SIMILAR_NAME_LEN: usize = 6;
const MAX_LEVENSHTEIN_LEN: usize = 256;
const SIZE_TOLERANCE_BYTES: u64 = 5 * 1024 * 1024;
const SIZE_TOLERANCE_PERCENT: f64 = 0.05;
/// Token-set (Jaccard) similarity at or above this flags reordered-token spam
/// that edit distance scores poorly (e.g. "free movie hd" vs "hd movie free").
const SIMILAR_NAME_JACCARD_HIT: f64 = 0.85;

const TOKEN_DELIMITERS: &[char] = &['.', '[', ']', '(', ')', '!', '-', '\'', '_', ' '];

/// High-confidence fake filename tokens — rarely if ever legitimate.
const STRONG_FAKE_FILENAME_TOKENS: &[&str] = &[
    "install_flash_player",
    "install_codec",
    "setup_codec",
    "downloadmanager",
    "freedownload",
    "fulldownload",
];

/// Ambiguous tokens that *also* appear in plenty of legitimate filenames.
/// Weighted low; meant to corroborate, not convict on their own.
const WEAK_FAKE_FILENAME_TOKENS: &[&str] = &[
    "password", "serial", "keygen", "crack", "patch", "codec",
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

/// Aggregate community verdict for a single file, derived from peer/KAD notes.
/// `fake_votes` is the number of "fake" ratings among `total_votes` rated
/// comments. Passed into scoring so a file the network has flagged as fake is
/// penalised even before the user has ever seen it.
#[derive(Debug, Clone, Copy, Default)]
pub struct CommunityRating {
    pub fake_votes: u32,
    pub total_votes: u32,
}

/// Statistical context computed once over a whole result set, used to detect
/// coordinated poisoning that no single result reveals:
///   * one exact (specific) filename carried by many distinct hashes,
///   * one hash advertised under many different filenames,
///   * results funnelled through a single dominant source IP.
///
/// Disabled (`enabled = false`) for batches below `BATCH_MIN_RESULTS_FOR_STATS`
/// so we never draw conclusions from too little data.
#[derive(Debug, Clone, Default)]
pub struct BatchSpamContext {
    enabled: bool,
    /// normalized filename -> number of distinct file hashes carrying it
    name_hash_counts: HashMap<String, usize>,
    /// file hash -> number of distinct normalized filenames advertised
    hash_name_counts: HashMap<String, usize>,
    /// source IPs referenced by a suspiciously large share of the batch
    hot_source_ips: HashSet<String>,
}

impl BatchSpamContext {
    /// Analyse a batch of search results into reusable statistical signals.
    pub fn analyze(results: &[SearchResult]) -> Self {
        let total = results.len();
        if total < BATCH_MIN_RESULTS_FOR_STATS {
            return Self::default();
        }

        let mut name_hashes: HashMap<String, HashSet<String>> = HashMap::new();
        let mut hash_names: HashMap<String, HashSet<String>> = HashMap::new();
        let mut source_hits: HashMap<String, usize> = HashMap::new();

        for r in results {
            let name_norm = normalize_filename(&r.file.name);
            let hash = normalize_hash(&r.file.hash);
            if !name_norm.is_empty() && !hash.is_empty() {
                name_hashes.entry(name_norm.clone()).or_default().insert(hash.clone());
                hash_names.entry(hash).or_default().insert(name_norm);
            }
            // Count each distinct source IP at most once per result so a single
            // result listing the same IP twice doesn't inflate the share.
            let mut seen: HashSet<String> = HashSet::new();
            for addr in &r.source_addresses {
                if let Some(ip) = extract_ip(addr) {
                    if seen.insert(ip.clone()) {
                        *source_hits.entry(ip).or_insert(0) += 1;
                    }
                }
            }
        }

        let name_hash_counts = name_hashes
            .into_iter()
            .map(|(k, v)| (k, v.len()))
            .collect();
        let hash_name_counts = hash_names
            .into_iter()
            .map(|(k, v)| (k, v.len()))
            .collect();

        let threshold = ((total as f64) * BATCH_SOURCE_HOT_SHARE).ceil() as usize;
        let min_hits = threshold.max(BATCH_SOURCE_MIN_HITS);
        let hot_source_ips = source_hits
            .into_iter()
            .filter(|(_, c)| *c >= min_hits)
            .map(|(ip, _)| ip)
            .collect();

        Self {
            enabled: true,
            name_hash_counts,
            hash_name_counts,
            hot_source_ips,
        }
    }

    fn name_collision(&self, name_norm: &str) -> bool {
        name_norm.chars().count() >= BATCH_MIN_NAME_LEN_FOR_COLLISION
            && self
                .name_hash_counts
                .get(name_norm)
                .copied()
                .unwrap_or(0)
                >= BATCH_NAME_DISTINCT_HASHES_MIN
    }

    fn hash_collision(&self, hash: &str) -> bool {
        self.hash_name_counts.get(hash).copied().unwrap_or(0) >= BATCH_HASH_DISTINCT_NAMES_MIN
    }

    fn source_concentrated(&self, result: &SearchResult) -> bool {
        if self.hot_source_ips.is_empty() {
            return false;
        }
        result
            .source_addresses
            .iter()
            .filter_map(|a| extract_ip(a))
            .any(|ip| self.hot_source_ips.contains(&ip))
    }
}

/// A string set with FIFO eviction. Replaces the previous `HashSet` fields
/// whose over-cap eviction dropped an *arbitrary* element (so a hot, recently
/// seen spam hash could be evicted while stale ones lingered). Insertion order
/// is tracked so the *oldest* entry is dropped first. Serialized as a flat JSON
/// array (oldest first), keeping it wire-compatible with the old `HashSet`
/// on-disk representation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(from = "Vec<String>", into = "Vec<String>")]
pub struct FifoSet {
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl FifoSet {
    fn contains(&self, key: &str) -> bool {
        self.set.contains(key)
    }

    fn len(&self) -> usize {
        self.set.len()
    }

    /// Insert `key`, evicting the oldest entries first until the set is below
    /// `cap`. No-op if already present (does not refresh recency — FIFO, not
    /// LRU, matching the simple aging eMule uses for these caches).
    fn insert(&mut self, key: String, cap: usize) {
        if cap == 0 || self.set.contains(&key) {
            return;
        }
        while self.set.len() >= cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.set.remove(&old);
                }
                None => break,
            }
        }
        self.set.insert(key.clone());
        self.order.push_back(key);
    }

    fn remove(&mut self, key: &str) -> bool {
        if self.set.remove(key) {
            if let Some(pos) = self.order.iter().position(|x| x == key) {
                self.order.remove(pos);
            }
            true
        } else {
            false
        }
    }

    /// Drop oldest entries until at or below `cap` (used on load to enforce
    /// caps against a hand-edited or migrated file).
    fn truncate_oldest(&mut self, cap: usize) {
        while self.set.len() > cap {
            match self.order.pop_front() {
                Some(old) => {
                    self.set.remove(&old);
                }
                None => break,
            }
        }
    }
}

impl From<Vec<String>> for FifoSet {
    fn from(items: Vec<String>) -> Self {
        let mut s = FifoSet::default();
        for item in items {
            if s.set.insert(item.clone()) {
                s.order.push_back(item);
            }
        }
        s
    }
}

impl From<FifoSet> for Vec<String> {
    fn from(f: FifoSet) -> Self {
        f.order.into_iter().collect()
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
#[serde(default)]
pub struct SpamDatabase {
    pub spam_hashes: FifoSet,
    pub not_spam_hashes: FifoSet,
    pub spam_filenames: Vec<String>,
    pub spam_similar_names: Vec<String>,
    pub spam_sizes: VecDeque<u64>,
    pub spam_source_ips: FifoSet,
    pub spam_server_ips: FifoSet,
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

// Per-set caps. Enforced identically at write time (`mark_spam`) and on load,
// so a hand-edited `search_spam.json` can't produce a runtime db larger than
// the app would build on its own.
const MAX_SPAM_HASHES: usize = 2_000;
/// Unified cap for the not-spam whitelist, used by both the runtime insert path
/// and the load path (previously 2000 at runtime vs 10000 on load).
const NOT_SPAM_HASHES_CAP: usize = 10_000;
const MAX_SPAM_FILENAMES: usize = 500;
const MAX_SPAM_SIMILAR_NAMES: usize = 500;
const MAX_SPAM_SIZES: usize = 1_000;
const MAX_SPAM_SERVER_IPS: usize = 500;
const MAX_SPAM_SOURCE_IPS: usize = 2_000;
const MAX_SOURCE_IPS_PER_RESULT: usize = 3;
// Match the runtime cap enforced by `mark_spam` for the server-ratio map.
const MAX_SERVER_RATIOS: usize = 500;

/// Maximum decoded JSON file size (bytes) we'll attempt to parse.
/// At >50 MB of `search_spam.json` something is broken or malicious.
const LOAD_MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;

impl SpamFilter {
    pub fn load(data_dir: &Path) -> Self {
        let data_path = data_dir.join("search_spam.json");
        let db = if data_path.exists() {
            // Pre-flight size check so a large file doesn't OOM us at startup.
            match std::fs::metadata(&data_path) {
                Ok(meta) if meta.len() > LOAD_MAX_FILE_BYTES => {
                    warn!(
                        "search_spam.json is {} bytes (> {} cap); refusing to load",
                        meta.len(),
                        LOAD_MAX_FILE_BYTES
                    );
                    SpamDatabase::default()
                }
                _ => match std::fs::read_to_string(&data_path) {
                    Ok(data) => match serde_json::from_str::<SpamDatabase>(&data) {
                        Ok(mut db) => {
                            // Truncate to per-set caps so a corrupted or
                            // hand-edited file can't produce a runtime db
                            // larger than `mark_spam` would ever produce.
                            db.spam_hashes.truncate_oldest(MAX_SPAM_HASHES);
                            db.not_spam_hashes.truncate_oldest(NOT_SPAM_HASHES_CAP);
                            if db.spam_filenames.len() > MAX_SPAM_FILENAMES {
                                db.spam_filenames.truncate(MAX_SPAM_FILENAMES);
                            }
                            if db.spam_similar_names.len() > MAX_SPAM_SIMILAR_NAMES {
                                db.spam_similar_names.truncate(MAX_SPAM_SIMILAR_NAMES);
                            }
                            if db.spam_sizes.len() > MAX_SPAM_SIZES {
                                db.spam_sizes.truncate(MAX_SPAM_SIZES);
                            }
                            db.spam_server_ips.truncate_oldest(MAX_SPAM_SERVER_IPS);
                            db.spam_source_ips.truncate_oldest(MAX_SPAM_SOURCE_IPS);
                            if db.udp_server_spam_ratios.len() > MAX_SERVER_RATIOS {
                                let to_drop: Vec<String> = db
                                    .udp_server_spam_ratios
                                    .keys()
                                    .skip(MAX_SERVER_RATIOS)
                                    .cloned()
                                    .collect();
                                for k in to_drop {
                                    db.udp_server_spam_ratios.remove(&k);
                                }
                            }
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
                },
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
        match crate::security::atomic_write(&self.data_path, data.as_bytes(), false) {
            Ok(()) => {
                self.dirty = false;
                debug!("Spam filter saved");
            }
            Err(e) => warn!("Failed to save spam filter: {e}"),
        }
    }

    pub fn take_save_data(&mut self) -> Option<(String, std::path::PathBuf)> {
        if !self.dirty {
            return None;
        }
        match serde_json::to_string_pretty(&self.db) {
            Ok(data) => {
                Some((data, self.data_path.clone()))
            }
            Err(e) => {
                warn!("Failed to serialize spam filter: {e}");
                None
            }
        }
    }

    pub fn clear_dirty(&mut self) {
        self.dirty = false;
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
        community: CommunityRating,
        batch: &BatchSpamContext,
    ) -> SpamExplanation {
        let hash = normalize_hash(&result.file.hash);
        let name = &result.file.name;
        let size = result.file.size;
        let threshold = Self::threshold_for_profile(profile);
        // The `relaxed` profile is deliberately local-only: it scores against
        // the user's own learned database and filename heuristics, but skips
        // the network-influenced signals (community "fake" votes and
        // intra-result-set statistical detection). Those are enabled from
        // `balanced` upward. This makes the profile a meaningful "how much do I
        // trust network-derived signals" dial rather than just a threshold.
        let network_signals = profile != SpamFilterProfile::Relaxed;

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
            // `strsim::normalized_levenshtein` works on chars, so prefilter on
            // char counts. Similarity is bounded by 1 - |Δlen| / max(len): the
            // lowest scoring threshold below is 0.70, so any candidate whose
            // length differs by ≥30% can't score on edit distance — but it can
            // still match by token set (reordered tokens), so we keep it for
            // the Jaccard check.
            let stripped_chars = stripped.chars().count();
            let stripped_tokens = token_set(&stripped);
            for similar in &self.db.spam_similar_names {
                let similar_chars = similar.chars().count();
                let max_chars = stripped_chars.max(similar_chars);
                let length_ok = max_chars > 0
                    && (stripped_chars.abs_diff(similar_chars) as f64) / (max_chars as f64) < 0.30;
                let sim = if length_ok {
                    normalized_levenshtein(&stripped, similar)
                } else {
                    0.0
                };
                if sim > 0.95 {
                    score += SPAM_SIMILARNAME_HIT;
                    reasons.push(format!("Very similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_HIT})", sim * 100.0));
                    break;
                } else if sim > 0.85 {
                    score += SPAM_SIMILARNAME_NEARHIT;
                    reasons.push(format!("Similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_NEARHIT})", sim * 100.0));
                    break;
                } else {
                    let jac = jaccard(&stripped_tokens, &token_set(similar));
                    if jac >= SIMILAR_NAME_JACCARD_HIT {
                        score += SPAM_SIMILARNAME_NEARHIT;
                        reasons.push(format!("Reordered spam pattern ({:.0}% token match, +{SPAM_SIMILARNAME_NEARHIT})", jac * 100.0));
                        break;
                    } else if sim > 0.70 {
                        score += SPAM_SIMILARNAME_FARHIT;
                        reasons.push(format!("Loosely similar spam pattern ({:.0}% match, +{SPAM_SIMILARNAME_FARHIT})", sim * 100.0));
                        break;
                    }
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

        let pattern_score = fake_pattern_score(name);
        if pattern_score > 0 {
            score += pattern_score;
            reasons.push(format!("Contains known fake/suspicious pattern (+{pattern_score})"));
        }

        // Community verdict: a file the network has voted "fake".
        if network_signals && community.total_votes >= FAKE_RATING_MIN_VOTES {
            let frac = community.fake_votes as f32 / community.total_votes as f32;
            if frac >= FAKE_RATING_MAJORITY {
                score += SPAM_FAKE_RATING_HIT;
                reasons.push(format!(
                    "Majority of community ratings are 'fake' ({}/{}, +{SPAM_FAKE_RATING_HIT})",
                    community.fake_votes, community.total_votes
                ));
            } else if frac >= FAKE_RATING_SOME {
                score += SPAM_FAKE_RATING_NEARHIT;
                reasons.push(format!(
                    "Several community ratings are 'fake' ({}/{}, +{SPAM_FAKE_RATING_NEARHIT})",
                    community.fake_votes, community.total_votes
                ));
            }
        }

        // Intra-result-set statistical signals (coordinated poisoning).
        if network_signals && batch.enabled {
            if batch.name_collision(&name_norm) {
                score += SPAM_BATCH_NAME_MANY_HASHES_HIT;
                reasons.push(format!(
                    "Same filename advertised under {} different hashes in this search (+{SPAM_BATCH_NAME_MANY_HASHES_HIT})",
                    batch.name_hash_counts.get(&name_norm).copied().unwrap_or(0)
                ));
            }
            if batch.hash_collision(&hash) {
                score += SPAM_BATCH_HASH_MANY_NAMES_HIT;
                reasons.push(format!(
                    "Same file advertised under {} different names in this search (+{SPAM_BATCH_HASH_MANY_NAMES_HIT})",
                    batch.hash_name_counts.get(&hash).copied().unwrap_or(0)
                ));
            }
            if batch.source_concentrated(result) {
                score += SPAM_BATCH_SOURCE_CONCENTRATION_HIT;
                reasons.push(format!("Sources dominated by a result-flooding IP (+{SPAM_BATCH_SOURCE_CONCENTRATION_HIT})"));
            }
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
        community: CommunityRating,
        batch: &BatchSpamContext,
    ) -> u32 {
        self.explain_result(result, search_keywords, server_ip, profile, community, batch)
            .score
    }

    pub fn mark_spam(&mut self, result: &SearchResult, search_keywords: &[String], server_ip: Option<&str>) {
        let file_hash = normalize_hash(&result.file.hash);
        if !file_hash.is_empty() {
            self.db.spam_hashes.insert(file_hash.clone(), MAX_SPAM_HASHES);
            self.db.not_spam_hashes.remove(&file_hash);
        }

        let name = &result.file.name;
        let name_norm = normalize_filename(name);
        if !name_norm.is_empty() && !self.db.spam_filenames.contains(&name_norm) {
            if self.db.spam_filenames.len() >= MAX_SPAM_FILENAMES {
                self.db.spam_filenames.remove(0);
            }
            self.db.spam_filenames.push(name_norm);
        }

        let stripped = name_without_keywords(name, search_keywords);
        if stripped.len() >= MIN_SIMILAR_NAME_LEN && stripped.len() <= MAX_LEVENSHTEIN_LEN && !self.db.spam_similar_names.contains(&stripped) {
            if self.db.spam_similar_names.len() >= MAX_SPAM_SIMILAR_NAMES {
                self.db.spam_similar_names.remove(0);
            }
            self.db.spam_similar_names.push(stripped);
        }

        if result.file.size > 0 && !self.db.spam_sizes.contains(&result.file.size) {
            if self.db.spam_sizes.len() >= MAX_SPAM_SIZES {
                self.db.spam_sizes.pop_front();
            }
            self.db.spam_sizes.push_back(result.file.size);
        }

        for addr in result.source_addresses.iter().take(MAX_SOURCE_IPS_PER_RESULT) {
            if let Some(ip) = extract_ip(addr) {
                self.db.spam_source_ips.insert(ip, MAX_SPAM_SOURCE_IPS);
            }
        }

        if let Some(sip) = server_ip.and_then(|s| extract_ip(s)) {
            self.db.spam_server_ips.insert(sip.clone(), MAX_SPAM_SERVER_IPS);

            let entry = self.db.udp_server_spam_ratios.entry(sip).or_insert(0.0);
            *entry = (*entry * 0.9 + 0.1).min(1.0);
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
        self.db.not_spam_hashes.insert(file_hash.clone(), NOT_SPAM_HASHES_CAP);
        self.db.spam_hashes.remove(&file_hash);
        self.dirty = true;
        info!("Marked as not spam: {file_hash}");
    }

    /// Silently add a hash to the not-spam whitelist (e.g. on completed download).
    /// Does not save immediately; caller should ensure periodic save happens.
    pub fn auto_mark_not_spam(&mut self, file_hash: &str) {
        let file_hash = normalize_hash(file_hash);
        if file_hash.is_empty() || self.db.not_spam_hashes.contains(&file_hash) {
            return;
        }
        self.db.not_spam_hashes.insert(file_hash.clone(), NOT_SPAM_HASHES_CAP);
        self.db.spam_hashes.remove(&file_hash);
        self.dirty = true;
        debug!("Auto-marked completed download as not spam: {file_hash}");
    }

    /// Auto-redemption after scoring a search batch: fold the per-server
    /// outcome back into the learned reputation. We only ever *decay* a
    /// server's spam ratio here (when its results came back mostly clean) and
    /// never auto-escalate — escalation stays user-driven via `mark_spam` to
    /// avoid heuristic feedback loops. A server whose ratio decays below the
    /// floor is fully redeemed (dropped from the spam-server set), so a server
    /// that cleaned up its act is no longer penalised forever.
    pub fn record_server_clean_batch(&mut self, server_ip: &str, clean: usize, total: usize) {
        if total == 0 {
            return;
        }
        let sip = match extract_ip(server_ip) {
            Some(s) => s,
            None => return,
        };
        let clean_frac = clean as f32 / total as f32;
        if clean_frac < 0.7 {
            return;
        }
        let mut changed = false;
        let mut redeem = false;
        if let Some(r) = self.db.udp_server_spam_ratios.get_mut(&sip) {
            if *r > 0.0 {
                *r *= 0.8;
                changed = true;
            }
            if *r < 0.05 {
                redeem = true;
            }
        }
        if redeem {
            self.db.udp_server_spam_ratios.remove(&sip);
            if self.db.spam_server_ips.remove(&sip) {
                info!("Redeemed spam server {sip}: results clean again");
            }
            changed = true;
        }
        if changed {
            self.dirty = true;
        }
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

/// Score a filename's fake/suspicious-pattern signal. URL-like patterns and
/// high-confidence ("strong") tokens contribute a meaningful bump; ambiguous
/// ("weak") tokens contribute only a small nudge because they also appear in
/// many legitimate filenames. The total is capped at `SPAM_PATTERN_MAX` so a
/// keyword-stuffed name can't dominate the overall score by itself.
fn fake_pattern_score(filename: &str) -> u32 {
    let lower = canonical_lower(filename);

    let mut score = 0u32;
    for pattern in FAKE_URL_PATTERNS {
        if lower.contains(pattern) {
            score += SPAM_FAKE_URL_HIT;
            break;
        }
    }

    let tokens: HashSet<String> = filename
        .split(|c: char| TOKEN_DELIMITERS.contains(&c))
        .filter(|t| !t.is_empty())
        .map(canonical_lower)
        .collect();

    let mut strong = false;
    for token in &tokens {
        if STRONG_FAKE_FILENAME_TOKENS.iter().any(|t| t == token) {
            strong = true;
            break;
        }
    }
    if strong {
        score += SPAM_STRONG_TOKEN_HIT;
    }

    // Also catch strong tokens that appear as substrings (e.g. without our
    // exact delimiters), since they're specific enough to be safe.
    if !strong {
        for t in STRONG_FAKE_FILENAME_TOKENS {
            if lower.contains(t) {
                score += SPAM_STRONG_TOKEN_HIT;
                break;
            }
        }
    }

    let weak_hits = tokens
        .iter()
        .filter(|token| WEAK_FAKE_FILENAME_TOKENS.iter().any(|t| t == *token))
        .count() as u32;
    score += weak_hits.saturating_mul(SPAM_WEAK_TOKEN_HIT);

    score.min(SPAM_PATTERN_MAX)
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
        .map(canonical_lower)
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
        .map(canonical_lower)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Unicode-aware lowercasing plus confusable folding. Spam frequently swaps
/// Latin letters for visually identical Cyrillic/Greek code points or uses
/// full-width forms to dodge exact and edit-distance matching; folding them to
/// a canonical Latin form closes that evasion path. ASCII input is unaffected.
fn canonical_lower(s: &str) -> String {
    s.to_lowercase().chars().map(fold_char).collect()
}

fn fold_char(c: char) -> char {
    // Full-width ASCII variants (U+FF01..U+FF5E) -> ASCII.
    let c = if ('\u{FF01}'..='\u{FF5E}').contains(&c) {
        char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
    } else {
        c
    };
    match c {
        // Cyrillic look-alikes (lowercase, post to_lowercase()).
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c',
        'х' => 'x', 'у' => 'y', 'к' => 'k', 'м' => 'm', 'т' => 't',
        'в' => 'b', 'н' => 'h',
        // Greek look-alikes.
        'ο' => 'o', 'α' => 'a', 'ρ' => 'p', 'ν' => 'v', 'τ' => 't',
        'ι' => 'i', 'κ' => 'k',
        _ => c,
    }
}

/// Tokenize a (already space-joined, lowercased) string into a set of tokens
/// for set-similarity comparison.
fn token_set(s: &str) -> HashSet<String> {
    s.split(|c: char| TOKEN_DELIMITERS.contains(&c) || c == ' ')
        .filter(|t| !t.is_empty())
        .map(|t| t.to_string())
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count();
    let union = a.len() + b.len() - inter;
    if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    }
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
            out.insert(canonical_lower(token));
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
            media: None,
            spam_rating: 0,
            is_spam: false,
            clean_name: String::new(),
            result_origin: String::new(),
        }
    }

    fn sized_result(hash: &str, name: &str, size: u64, sources: &[&str]) -> SearchResult {
        let mut r = sample_result(hash, name);
        r.file.size = size;
        r.source_addresses = sources.iter().map(|s| s.to_string()).collect();
        r
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
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );
        assert!(score >= SPAM_FILEHASH_HIT);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fifo_set_evicts_oldest_first() {
        let mut s = FifoSet::default();
        s.insert("a".to_string(), 2);
        s.insert("b".to_string(), 2);
        s.insert("c".to_string(), 2); // evicts "a"
        assert!(!s.contains("a"));
        assert!(s.contains("b"));
        assert!(s.contains("c"));
        assert_eq!(s.len(), 2);

        // round-trips through the array serialization preserving order
        let v: Vec<String> = s.clone().into();
        assert_eq!(v, vec!["b".to_string(), "c".to_string()]);
        let back: FifoSet = v.into();
        assert!(back.contains("b") && back.contains("c"));
    }

    #[test]
    fn weak_token_alone_is_not_spam() {
        let dir = temp_dir("weak-token");
        let filter = SpamFilter::load(&dir);
        // "patch" is a weak token; a plausible legit game-patch filename must
        // not be flagged as spam on the token alone.
        let score = filter.rate_result(
            &sample_result(&"1".repeat(32), "Awesome.Game.v1.2.patch.exe"),
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );
        assert!(score < SEARCH_SPAM_THRESHOLD, "weak token scored {score}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn community_fake_majority_flags_spam() {
        let dir = temp_dir("fake-rating");
        let filter = SpamFilter::load(&dir);
        let explanation = filter.explain_result(
            &sample_result(&"2".repeat(32), "totally_legit_movie.avi"),
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating { fake_votes: 4, total_votes: 5 },
            &BatchSpamContext::default(),
        );
        assert!(explanation.score >= SPAM_FAKE_RATING_HIT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn relaxed_profile_ignores_network_signals() {
        // Both a strong community-fake verdict and a poisoned batch must be
        // ignored under the local-only `relaxed` profile.
        let mut results = Vec::new();
        for i in 0..10 {
            let hash = format!("{:032x}", i);
            results.push(sized_result(&hash, "Popular Movie 2026 1080p BluRay.mkv", 1000 + i, &[]));
        }
        let ctx = BatchSpamContext::analyze(&results);
        let dir = temp_dir("relaxed-skip");
        let filter = SpamFilter::load(&dir);

        let batch_score = filter.rate_result(
            &results[0],
            &[],
            None,
            SpamFilterProfile::Relaxed,
            CommunityRating { fake_votes: 9, total_votes: 10 },
            &ctx,
        );
        assert_eq!(batch_score, 0, "relaxed should ignore batch + community signals");

        // Same inputs under balanced must score (sanity check the gate, not
        // the absence of any DB entries).
        let balanced_score = filter.rate_result(
            &results[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating { fake_votes: 9, total_votes: 10 },
            &ctx,
        );
        assert!(balanced_score > 0, "balanced should apply network signals");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn batch_detects_same_name_many_hashes() {
        // 10 results sharing one specific filename but all distinct hashes:
        // classic index poisoning.
        let mut results = Vec::new();
        for i in 0..10 {
            let hash = format!("{:032x}", i);
            results.push(sized_result(&hash, "Popular Movie 2026 1080p BluRay.mkv", 1000 + i, &[]));
        }
        let ctx = BatchSpamContext::analyze(&results);
        let dir = temp_dir("batch-name");
        let filter = SpamFilter::load(&dir);
        let score = filter.rate_result(
            &results[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &ctx,
        );
        assert!(score >= SPAM_BATCH_NAME_MANY_HASHES_HIT, "batch score {score}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn confusable_lookalikes_fold_to_ascii() {
        // 'о' here is Cyrillic U+043E, not ASCII 'o'; folding + lowercasing
        // must collapse it to the ASCII form so spam can't dodge matching.
        let folded = canonical_lower("Mоvie");
        assert_eq!(folded, "movie");
    }

    #[test]
    fn server_redemption_decays_ratio() {
        let dir = temp_dir("redeem");
        let mut filter = SpamFilter::load(&dir);
        let mut r = sample_result(&"3".repeat(32), "junk.exe");
        r.source_addresses = vec!["1.2.3.4:1000".to_string()];
        // Escalate the server reputation via repeated spam marks.
        for _ in 0..30 {
            filter.mark_spam(&r, &[], Some("9.9.9.9:4242"));
        }
        assert!(filter.db.spam_server_ips.contains("9.9.9.9"));
        // Now feed many clean batches; the server should eventually be redeemed.
        for _ in 0..60 {
            filter.record_server_clean_batch("9.9.9.9:4242", 10, 10);
        }
        assert!(!filter.db.spam_server_ips.contains("9.9.9.9"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
