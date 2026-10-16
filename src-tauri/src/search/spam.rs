use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;

use serde::{Deserialize, Serialize};
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
const FAKE_RATING_MIN_VOTES: u32 = 3;
/// Distinct voters who must have said "fake" before any community signal
/// fires, so one voter cannot carry a verdict however few others rated.
const FAKE_RATING_MIN_FAKE_VOTERS: u32 = 2;
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
/// Honest re-encodes and re-rips of one popular title routinely reach three or
/// four, so the bar sits above that.
const BATCH_NAME_DISTINCT_HASHES_MIN: usize = 5;
/// Distinct names advertised for one hash before it's suspicious. Names are
/// compared as signatures (release metadata stripped) and near-identical
/// signatures count once (see [`HashNames`]), so the bar counts different
/// titles, not the release-tag and release-group variants every popular file
/// is seen under.
const BATCH_HASH_DISTINCT_NAMES_MIN: usize = 4;
/// Signatures at or above this token-set similarity are one name for
/// many-names counting ("inception" / "inception yts").
const BATCH_SAME_NAME_JACCARD: f64 = 0.5;
/// Signatures kept per hash for many-names counting. Far above the bar, so it
/// only bounds the clustering work and the count a reason can show.
const MAX_HASH_NAME_SIGNATURES: usize = 64;
/// A normalized filename must be at least this many chars, and carry a
/// distinctive token (see [`is_distinctive_token`]), to be "specific" enough
/// that many-hashes-per-name is meaningful — "setup exe" and "01 intro mp3"
/// are shared by countless unrelated files.
const BATCH_MIN_NAME_LEN_FOR_COLLISION: usize = 8;
/// A source IP referenced by at least this fraction of the batch is "hot"
/// (likely an index-poisoning node).
const BATCH_SOURCE_HOT_SHARE: f64 = 0.5;
/// Only treat a source IP as hot once the batch is at least this large, so a
/// handful of legitimate results that happen to share a seeder don't trip it.
const BATCH_SOURCE_MIN_HITS: usize = 4;
/// Caps so a pathological all-servers search cannot grow these maps unboundedly.
const MAX_BATCH_NAME_KEYS: usize = 4_096;
const MAX_BATCH_HASH_KEYS: usize = 4_096;
const MAX_BATCH_SOURCE_KEYS: usize = 2_048;
const MAX_BATCH_SNAPSHOTS: usize = 1_024;
/// Cap on the *values* behind one `name_hashes` key (`hash_names` has its own,
/// [`MAX_HASH_NAME_SIGNATURES`]).
///
/// The key counts above are capped but the sets they hold were not, so a flood
/// advertising one filename under an unbounded number of distinct hashes grew a
/// single bucket for the life of the search context. Set to
/// [`MAX_BATCH_SNAPSHOTS`] because that is the most rows `upgrade_rows` can
/// ever act on: a hash with no snapshot behind it cannot be emitted, and the
/// collision bars are `>=` against single digits, so nothing above this bound
/// changes a decision — only the count shown in a `BatchNameManyHashes` reason.
const MAX_BATCH_KEY_MEMBERS: usize = MAX_BATCH_SNAPSHOTS;

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

/// Release metadata that names no particular file: containers, resolutions,
/// codecs, sources, language tags. Stripped from a name before it is learned
/// or compared as a similar-name signature, so "1080p mkv" left over after the
/// search keywords is not learned as spam. Every all-digit token (track
/// numbers, years) is a stop token too, see [`is_stop_token`].
const SIGNATURE_STOP_TOKENS: &[&str] = &[
    // containers / extensions
    "mkv", "avi", "mp4", "m4v", "mov", "wmv", "flv", "webm", "mpg", "mpeg", "ts", "m2ts", "vob",
    "ogm", "rmvb", "iso", "img", "bin", "cue", "nrg", "mdf", "mds", "rar", "zip", "7z", "gz",
    "tar", "exe", "msi", "dmg", "apk", "pdf", "epub", "mobi", "doc", "txt", "nfo", "srt", "sub",
    "idx", "ass", "mp3", "flac", "ogg", "wav", "m4a", "wma", "ape", "opus", "jpg", "png", "gif",
    // resolutions
    "4k", "8k", "uhd", "fhd", "hd", "sd", "hdr", "hdr10", "dv",
    // codecs
    "x264", "x265", "h264", "h265", "hevc", "avc", "xvid", "divx", "aac", "ac3", "eac3", "dts",
    "ddp", "dd", "truehd", "atmos", "10bit", "8bit",
    // sources
    "bluray", "blu", "ray", "bdrip", "brrip", "bdremux", "remux", "webrip", "webdl", "web", "dl",
    "hdtv", "pdtv", "dvdrip", "dvdscr", "dvd", "hdrip", "cam", "hdcam", "telesync", "tc", "scr",
    "r5", "proper", "repack", "internal", "limited", "extended", "unrated",
    // languages / subtitles
    "eng", "english", "ger", "german", "deu", "fre", "french", "fra", "spa", "spanish", "esp",
    "ita", "italian", "rus", "russian", "jpn", "japanese", "jap", "chi", "chinese", "kor",
    "korean", "por", "portuguese", "pol", "polish", "dut", "dutch", "multi", "dual", "subs",
    "subbed", "dubbed", "vostfr", "vo", "vf",
];

/// Words shared by unrelated files of one kind. Not stripped from signatures,
/// but never what makes a name distinctive.
const GENERIC_NAME_TOKENS: &[&str] = &[
    "the", "and", "for", "setup", "install", "installer", "intro", "outro", "track", "readme",
    "sample", "trailer", "video", "audio", "movie", "film", "music", "song", "album", "file",
    "files", "new", "part", "disc", "disk", "full", "version", "final", "update", "various",
    "artist", "artists", "unknown", "untitled", "episode", "season", "chapter", "vol", "volume",
];

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
const WEAK_FAKE_FILENAME_TOKENS: &[&str] =
    &["password", "serial", "keygen", "crack", "patch", "codec"];

/// Suspicious URL-like patterns in filenames (case-insensitive substring match).
const FAKE_URL_PATTERNS: &[&str] = &["www.", "http:", "https:", ".com/", ".net/", ".org/"];

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
/// `fake_votes` is the number of distinct voters who rated it "fake" among
/// `total_votes` distinct voters who rated it (see
/// `CommentManager::fake_rating_stats` for what makes voters distinct). Passed
/// into scoring so a file the network has flagged as fake is penalised even
/// before the user has ever seen it.
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
    /// normalized filename -> distinct file hashes carrying it
    name_hashes: HashMap<String, HashSet<String>>,
    /// file hash -> the names it was advertised under
    hash_names: HashMap<String, HashNames>,
    /// source IPs referenced by results (Kad publisher-only rows skipped)
    source_hits: HashMap<String, usize>,
    result_count: usize,
    /// source IPs referenced by a suspiciously large share of the batch
    hot_source_ips: HashSet<String>,
    /// Last-seen row fields for hashes already absorbed, so a later packet that
    /// newly crosses a collision bar can upgrade earlier streamed rows.
    snapshots: HashMap<String, StreamedSpamSnapshot>,
    /// Hashes of files this library already holds, for the whole search.
    ///
    /// Carried here rather than passed alongside because this context is
    /// already threaded to every scoring call — the network task moves it in
    /// and out of `ActiveSearchRequest` per packet, and the IPC paths pass one
    /// directly — so the exemption reaches the scorer without a `local_index`
    /// read on the network loop or a new argument on four call chains.
    owned_hashes: HashSet<String>,
    /// Batch-signal verdicts rows already carry, by hash. See
    /// [`Self::carry_batch_signals`].
    carried: HashMap<String, CarriedBatchSignals>,
    /// Re-sighted rows waiting for the next [`Self::absorb`]. See
    /// [`Self::note_resighted`].
    pending_resights: Vec<RowNames>,
}

/// The forms of one row's name the batch statistics key on.
#[derive(Debug, Clone)]
struct RowNames {
    hash: String,
    /// [`normalize_filename`]: same-name/many-hashes compares exact names.
    normalized: String,
    /// [`similar_name_signature`] without keywords: many-names compares titles.
    signature: String,
}

impl RowNames {
    fn of(result: &SearchResult) -> Option<Self> {
        let hash = normalize_hash(&result.file.hash);
        let canonical = canonical_lower(&result.file.name);
        let normalized = normalized_from_canonical(&canonical);
        if hash.is_empty() || normalized.is_empty() {
            return None;
        }
        let signature = signature_from_canonical(&canonical, &HashSet::new());
        Some(Self {
            hash,
            normalized,
            signature,
        })
    }
}

/// The distinct names one hash was advertised under, for many-names counting.
///
/// Signatures whose token sets are at least [`BATCH_SAME_NAME_JACCARD`]
/// similar are one name, transitively, so "inception", "inception yts" and
/// "inception sparks" count once however they arrive; titles that share only
/// a search keyword ("matrix crack keygen", "matrix free movie") stay apart.
#[derive(Debug, Clone, Default)]
struct HashNames {
    seen: HashSet<String>,
    groups: Vec<Vec<HashSet<String>>>,
}

impl HashNames {
    fn insert(&mut self, signature: &str) {
        if signature.is_empty()
            || self.seen.len() >= MAX_HASH_NAME_SIGNATURES
            || !self.seen.insert(signature.to_string())
        {
            return;
        }
        let mut joined = vec![token_set(signature)];
        let mut apart = Vec::with_capacity(self.groups.len() + 1);
        for group in std::mem::take(&mut self.groups) {
            if group
                .iter()
                .any(|member| jaccard(member, &joined[0]) >= BATCH_SAME_NAME_JACCARD)
            {
                joined.extend(group);
            } else {
                apart.push(group);
            }
        }
        apart.push(joined);
        self.groups = apart;
    }

    fn count(&self) -> usize {
        self.groups.len()
    }
}

/// The batch signals one row was scored with by the pass that saw its batch.
#[derive(Debug, Clone, Copy, Default)]
struct CarriedBatchSignals {
    /// The distinct-hash count its `BatchNameManyHashes` reason reported.
    name_many_hashes: Option<u32>,
    /// The distinct-name count its `BatchHashManyNames` reason reported.
    hash_many_names: Option<u32>,
    source_concentration: bool,
}

#[derive(Debug, Clone)]
struct StreamedSpamSnapshot {
    hash: String,
    name: String,
    size: u64,
    source_addresses: Vec<String>,
    result_origin: String,
    origin_server_ip: Option<String>,
    rating: Option<u8>,
    /// Carried so the rebuilt row still answers the search's own filters.
    ///
    /// An upgrade is a re-emit of a row the user is already looking at, and
    /// `enrich_and_emit_search_results` runs every streamed row past
    /// `result_matches_client_filters` on the way out. Leaving these at their
    /// defaults meant the rebuilt row claimed no extension, no file type and a
    /// single source — so a search narrowed to `Video`, to an extension, or to
    /// two-plus sources dropped every upgrade it produced, and the poisoned
    /// rows already on screen stayed unflagged. Silently, and exactly in the
    /// searches where coordinated poisoning is worth catching.
    extension: String,
    file_type: String,
    availability: u32,
}

impl BatchSpamContext {
    /// Analyse a batch of search results into reusable statistical signals.
    pub fn analyze(results: &[SearchResult]) -> Self {
        let mut ctx = Self::default();
        ctx.absorb(results);
        ctx
    }

    /// A context that carries nothing but the owned-file exemption.
    ///
    /// Every statistical signal stays off (`enabled` is false until
    /// [`Self::absorb`] has seen `BATCH_MIN_RESULTS_FOR_STATS` rows), so this
    /// behaves exactly like `default()` apart from the exemption — which is what
    /// the IPC paths want: they deliberately score without batch heuristics.
    pub fn for_owned_hashes(hashes: impl IntoIterator<Item = String>) -> Self {
        let mut ctx = Self::default();
        ctx.set_owned_hashes(hashes);
        ctx
    }

    pub fn set_owned_hashes(&mut self, hashes: impl IntoIterator<Item = String>) {
        self.owned_hashes = hashes
            .into_iter()
            .map(|h| normalize_hash(&h))
            .filter(|h| !h.is_empty())
            .collect();
    }

    /// Keep the batch signals `results` were already flagged with, for a pass
    /// that re-scores them without the batch that produced them.
    ///
    /// A re-score after Mark spam / Mark not spam hands back rows one at a time,
    /// so it cannot rebuild the search-wide context the stream scored them
    /// against — and scoring without it, then adopting the result outright,
    /// cleared every flag that context had raised. One unmark un-flagged the
    /// whole coordinated flood beside it. What a re-score exists to move is the
    /// learned-data signals; the batch ones are facts about the search, which
    /// the re-score has not seen change, so they are re-applied as they were.
    /// Read from `spam_reason_details`, the only place a row records them.
    ///
    /// Still gated like the live signals: a profile without network signals
    /// drops them, and an explicit Mark not spam or an owned file outranks them.
    pub fn carry_batch_signals(&mut self, results: &[SearchResult]) {
        let name_code = SpamReasonCode::BatchNameManyHashes.as_code();
        let hash_code = SpamReasonCode::BatchHashManyNames.as_code();
        let source_code = SpamReasonCode::BatchSourceConcentration.as_code();
        for r in results {
            let hash = normalize_hash(&r.file.hash);
            if hash.is_empty() {
                continue;
            }
            let mut signals = CarriedBatchSignals::default();
            // Held to today's bars: a row flagged under a lower one carries
            // nothing the live signal would not raise now.
            for reason in &r.spam_reason_details {
                if reason.code == name_code {
                    let count = reason.count.unwrap_or(BATCH_NAME_DISTINCT_HASHES_MIN as u32);
                    if count as usize >= BATCH_NAME_DISTINCT_HASHES_MIN
                        && has_distinctive_token(&normalize_filename(&r.file.name))
                    {
                        signals.name_many_hashes = Some(count);
                    }
                } else if reason.code == hash_code {
                    let count = reason.count.unwrap_or(BATCH_HASH_DISTINCT_NAMES_MIN as u32);
                    if count as usize >= BATCH_HASH_DISTINCT_NAMES_MIN {
                        signals.hash_many_names = Some(count);
                    }
                } else if reason.code == source_code {
                    signals.source_concentration = true;
                }
            }
            if signals.name_many_hashes.is_some()
                || signals.hash_many_names.is_some()
                || signals.source_concentration
            {
                self.carried.insert(hash, signals);
            }
        }
    }

    /// Whether `hash` is a file this library already holds.
    pub fn is_owned(&self, hash: &str) -> bool {
        !self.owned_hashes.is_empty() && self.owned_hashes.contains(hash)
    }

    /// Queue the names of rows dropped as re-sightings of a hash this search
    /// already streamed.
    ///
    /// Repeats never reach [`Self::absorb`], so they are not scored twice, but
    /// the name a hash is re-advertised under is exactly what many-names
    /// counts. Folded in at the start of the next `absorb`, after the caller
    /// has taken its `colliding_hashes` baseline, so a collision they complete
    /// upgrades the row already on screen. Not counted toward `result_count`:
    /// a re-sighting is not another result.
    pub fn note_resighted(&mut self, results: &[SearchResult]) {
        for r in results {
            if self.pending_resights.len() >= MAX_BATCH_SNAPSHOTS {
                return;
            }
            if let Some(names) = RowNames::of(r) {
                self.pending_resights.push(names);
            }
        }
    }

    pub fn has_pending_resights(&self) -> bool {
        !self.pending_resights.is_empty()
    }

    pub fn clear_pending_resights(&mut self) {
        self.pending_resights.clear();
    }

    fn record_names(&mut self, names: &RowNames) {
        if self.name_hashes.contains_key(&names.normalized)
            || self.name_hashes.len() < MAX_BATCH_NAME_KEYS
        {
            let bucket = self.name_hashes.entry(names.normalized.clone()).or_default();
            if bucket.len() < MAX_BATCH_KEY_MEMBERS {
                bucket.insert(names.hash.clone());
            }
        }
        if self.hash_names.contains_key(&names.hash) || self.hash_names.len() < MAX_BATCH_HASH_KEYS
        {
            self.hash_names
                .entry(names.hash.clone())
                .or_default()
                .insert(&names.signature);
        }
    }

    /// Fold another packet into this context so same-name/many-hashes can be
    /// seen across the whole search, not only inside one UDP/Kad emit.
    pub fn absorb(&mut self, results: &[SearchResult]) {
        for names in std::mem::take(&mut self.pending_resights) {
            self.record_names(&names);
        }
        for r in results {
            self.result_count = self.result_count.saturating_add(1);
            if let Some(names) = RowNames::of(r) {
                self.record_names(&names);
                let hash = names.hash;
                if self.snapshots.contains_key(&hash) || self.snapshots.len() < MAX_BATCH_SNAPSHOTS
                {
                    self.snapshots.insert(
                        hash.clone(),
                        StreamedSpamSnapshot {
                            hash: hash.clone(),
                            name: r.file.name.clone(),
                            size: r.file.size,
                            source_addresses: r.source_addresses.clone(),
                            result_origin: r.result_origin.clone(),
                            origin_server_ip: r.origin_server_ip.clone(),
                            rating: r.rating,
                            extension: r.file.extension.clone(),
                            file_type: r.file_type.clone(),
                            availability: r.availability,
                        },
                    );
                }
            }
            // Kad keyword hits often list the publishing node as the source.
            // Counting that IP as "hot" flags a whole contact's honest results.
            if origin_is_kad_publisher_only(&r.result_origin) {
                continue;
            }
            let mut seen: HashSet<String> = HashSet::new();
            for addr in &r.source_addresses {
                if let Some(ip) = extract_ip(addr) {
                    if !is_globally_routable_ip(&ip) {
                        continue;
                    }
                    if self.source_hits.contains_key(&ip)
                        || self.source_hits.len() < MAX_BATCH_SOURCE_KEYS
                    {
                        if seen.insert(ip.clone()) {
                            *self.source_hits.entry(ip).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
        self.recompute();
    }

    /// Hashes that currently participate in a name-many-hashes or hash-many-names
    /// collision. Empty while `enabled` is false.
    pub fn colliding_hashes(&self) -> HashSet<String> {
        if !self.enabled {
            return HashSet::new();
        }
        let mut out = HashSet::new();
        for (name, hashes) in &self.name_hashes {
            if self.name_collision(name) {
                out.extend(hashes.iter().cloned());
            }
        }
        for (hash, names) in &self.hash_names {
            if names.count() >= BATCH_HASH_DISTINCT_NAMES_MIN {
                out.insert(hash.clone());
            }
        }
        out
    }

    /// Earlier streamed rows whose name/hash just crossed a collision bar.
    /// `skip` is the current packet (already scored against this context).
    pub fn upgrade_rows(
        &self,
        prev_colliding: &HashSet<String>,
        skip: &HashSet<String>,
    ) -> Vec<SearchResult> {
        let now = self.colliding_hashes();
        let mut out = Vec::new();
        for hash in now.difference(prev_colliding) {
            if skip.contains(hash) {
                continue;
            }
            if let Some(snap) = self.snapshots.get(hash) {
                out.push(snap.to_search_result());
            }
        }
        out
    }

    fn recompute(&mut self) {
        self.enabled = self.result_count >= BATCH_MIN_RESULTS_FOR_STATS;
        if !self.enabled {
            self.hot_source_ips.clear();
            return;
        }
        let threshold = ((self.result_count as f64) * BATCH_SOURCE_HOT_SHARE).ceil() as usize;
        let min_hits = threshold.max(BATCH_SOURCE_MIN_HITS);
        self.hot_source_ips = self
            .source_hits
            .iter()
            .filter(|(_, c)| **c >= min_hits)
            .map(|(ip, _)| ip.clone())
            .collect();
    }

    fn name_collision(&self, name_norm: &str) -> bool {
        name_norm.chars().count() >= BATCH_MIN_NAME_LEN_FOR_COLLISION
            && self.name_hashes.get(name_norm).map(|s| s.len()).unwrap_or(0)
                >= BATCH_NAME_DISTINCT_HASHES_MIN
            && has_distinctive_token(name_norm)
    }

    fn hash_collision(&self, hash: &str) -> bool {
        self.hash_name_count(hash) >= BATCH_HASH_DISTINCT_NAMES_MIN
    }

    fn name_hash_count(&self, name_norm: &str) -> usize {
        self.name_hashes.get(name_norm).map(|s| s.len()).unwrap_or(0)
    }

    fn hash_name_count(&self, hash: &str) -> usize {
        self.hash_names.get(hash).map(HashNames::count).unwrap_or(0)
    }

    fn source_concentrated(&self, result: &SearchResult) -> bool {
        if self.hot_source_ips.is_empty() || origin_is_kad_publisher_only(&result.result_origin)
        {
            return false;
        }
        result
            .source_addresses
            .iter()
            .filter_map(|a| extract_ip(a))
            .any(|ip| self.hot_source_ips.contains(&ip))
    }
}

fn origin_is_kad_publisher_only(origin: &str) -> bool {
    let upper = origin.to_ascii_uppercase();
    upper.contains("KAD") && !upper.contains("SERVER") && !upper.contains("UDP")
}

/// Whether a UDP global search contributed this row. Server reputation is a
/// signal about the UDP server that answered (eMule `CSearchList` applies it
/// to UDP results only): the connected server's TCP replies carry no source
/// addresses and come from the server the user chose, so scoring or stamping
/// them with it would make one Mark spam a penalty on every result it returns.
pub(crate) fn origin_has_udp_server(origin: &str) -> bool {
    origin
        .split('·')
        .any(|part| part.trim() == crate::search::merge::ORIGIN_SERVER_UDP)
}

/// Reasons that come from learned server reputation.
const SERVER_REASON_CODES: [SpamReasonCode; 4] = [
    SpamReasonCode::SpamServerAllSources,
    SpamReasonCode::SpamServerInfluence,
    SpamReasonCode::ServerRatioHigh,
    SpamReasonCode::ServerRatioElevated,
];

/// The score `reasons` add up to without any server-reputation signal,
/// re-applying the aggressive boost the same way scoring does (it never
/// depends on the server signals).
fn score_without_server_signals(reasons: &[SpamReason]) -> u32 {
    let boost_code = SpamReasonCode::AggressiveBoost.as_code();
    let mut score = 0u32;
    let mut boosted = false;
    for reason in reasons {
        if reason.code == boost_code {
            boosted = true;
        } else if !SERVER_REASON_CODES
            .iter()
            .any(|code| code.as_code() == reason.code)
        {
            score = score.saturating_add(reason.weight.unwrap_or(0));
        }
    }
    if boosted {
        score = score.max((score as f32 * 1.2).round() as u32);
    }
    score
}

impl StreamedSpamSnapshot {
    fn to_search_result(&self) -> SearchResult {
        SearchResult {
            file: crate::types::FileInfo {
                id: self.hash.clone(),
                name: self.name.clone(),
                path: String::new(),
                size: self.size,
                hash: self.hash.clone(),
                aich_hash: String::new(),
                ember_file_hash: String::new(),
                extension: self.extension.clone(),
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
                friends_only: false,
                shared_kad: false,
                shared_ed2k: false,
                shared_ember: false,
            },
            peer_id: String::new(),
            peer_name: String::new(),
            availability: self.availability,
            file_type: self.file_type.clone(),
            source_addresses: self.source_addresses.clone(),
            rating: self.rating,
            comment: None,
            media: None,
            spam_rating: 0,
            is_spam: false,
            clean_name: String::new(),
            result_origin: self.result_origin.clone(),
            origin_server_ip: self.origin_server_ip.clone(),
            spam_reasons: Vec::new(),
            spam_reason_details: Vec::new(),
        }
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

    /// Entries oldest first.
    fn iter(&self) -> impl Iterator<Item = &String> {
        self.order.iter()
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

/// One named number a spam reason interpolates. A closed set rather than free
/// strings so the placeholder names in the English below are the same names the
/// UI's Paraglide messages declare, and a test can hold the two together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpamParam {
    Weight,
    Percent,
    Count,
    Votes,
    Total,
}

impl SpamParam {
    fn name(self) -> &'static str {
        match self {
            Self::Weight => "weight",
            Self::Percent => "percent",
            Self::Count => "count",
            Self::Votes => "votes",
            Self::Total => "total",
        }
    }
}

/// Declares every reason the spam scorer can give for a verdict, each bound to
/// a stable code and an English template.
///
/// The English is what logs and the `explain_spam_result` diagnostics read, and
/// what a UI older than the backend falls back to. The code plus its numeric
/// parameters are what the UI translates, so the eight non-English locales stop
/// reading English in the spam tooltip.
///
/// One table for both halves is what keeps them honest: a variant cannot
/// compile without a code and a template, and `scripts/backend-codes.test.mjs`
/// parses this table to require both a translation in all nine locales and the
/// same `{placeholders}` on each side.
macro_rules! spam_reason_codes {
    ($($variant:ident => $code:literal, $message:literal;)+) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SpamReasonCode {
            $($variant,)+
        }

        impl SpamReasonCode {
            /// Every variant, in declaration order. Only the exhaustiveness
            /// tests walk the set, so it stays out of the shipped binary.
            #[cfg(test)]
            pub const ALL: &'static [SpamReasonCode] = &[$(SpamReasonCode::$variant,)+];

            /// Stable identifier carried to the UI as `SpamReason::code`.
            pub fn as_code(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }

            /// English template; `{name}` placeholders are filled from the
            /// [`SpamParam`]s the producer supplies.
            pub fn message(self) -> &'static str {
                match self {
                    $(Self::$variant => $message,)+
                }
            }
        }
    };
}

spam_reason_codes! {
    NotSpamMarked => "not_spam_marked", "Manually marked as not spam";
    OwnedFile => "owned_file", "Already in your library";
    KnownHash => "known_hash", "Known spam hash (+{weight})";
    ExactFilename => "exact_filename", "Exact spam filename match (+{weight})";
    VerySimilarName => "very_similar_name", "Very similar spam pattern ({percent}% match, +{weight})";
    SimilarName => "similar_name", "Similar spam pattern ({percent}% match, +{weight})";
    ReorderedName => "reordered_name", "Reordered spam pattern ({percent}% token match, +{weight})";
    LooselySimilarName => "loosely_similar_name", "Loosely similar spam pattern ({percent}% match, +{weight})";
    SizeSignature => "size_signature", "Matches known spam size signature (+{weight})";
    FakePattern => "fake_pattern", "Contains known fake/suspicious pattern (+{weight})";
    CommunityFakeMajority => "community_fake_majority",
        "Majority of community ratings are 'fake' ({votes}/{total}, +{weight})";
    CommunityFakeSome => "community_fake_some",
        "Several community ratings are 'fake' ({votes}/{total}, +{weight})";
    ResultRatedFake => "result_rated_fake", "Search result rated fake (+{weight})";
    BatchNameManyHashes => "batch_name_many_hashes",
        "Same filename advertised under {count} different hashes in this search (+{weight})";
    BatchHashManyNames => "batch_hash_many_names",
        "Same file advertised under {count} different names in this search (+{weight})";
    BatchSourceConcentration => "batch_source_concentration",
        "Sources dominated by a result-flooding IP (+{weight})";
    SpamSourceIp => "spam_source_ip", "Source IP seen in spam hits (+{weight})";
    SpamServerAllSources => "spam_server_all_sources",
        "Result from spam-heavy server, all sources spam (+{weight})";
    SpamServerInfluence => "spam_server_influence", "Result influenced by spam server (+{weight})";
    ServerRatioHigh => "server_ratio_high", "Server spam ratio is high ({percent}%, +{weight})";
    ServerRatioElevated => "server_ratio_elevated",
        "Server spam ratio is elevated ({percent}%, +{weight})";
    AggressiveBoost => "aggressive_boost", "Aggressive profile sensitivity boost (+{weight})";
    NoSignals => "no_signals", "No strong spam signals";
}

/// One scored spam signal: a stable code, the numbers its message interpolates,
/// and the English the code renders to.
///
/// `text` is redundant with `code` for any UI that knows the code, and is kept
/// anyway — it is what the tooltip shows on a frontend that predates the code,
/// and what makes a logged explanation readable without a message catalog.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpamReason {
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub votes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u32>,
    pub text: String,
}

impl SpamReason {
    fn new(code: SpamReasonCode, params: &[(SpamParam, u32)]) -> Self {
        let mut reason = SpamReason {
            code: code.as_code().to_string(),
            weight: None,
            percent: None,
            count: None,
            votes: None,
            total: None,
            text: code.message().to_string(),
        };
        for &(param, value) in params {
            reason.text = reason
                .text
                .replace(&format!("{{{}}}", param.name()), &value.to_string());
            match param {
                SpamParam::Weight => reason.weight = Some(value),
                SpamParam::Percent => reason.percent = Some(value),
                SpamParam::Count => reason.count = Some(value),
                SpamParam::Votes => reason.votes = Some(value),
                SpamParam::Total => reason.total = Some(value),
            }
        }
        reason
    }
}

/// A similarity or share expressed as a whole percent, matching the `{:.0}`
/// these messages used before they carried the number as a parameter.
fn as_percent(fraction: f64) -> u32 {
    (fraction * 100.0).round().clamp(0.0, 100.0) as u32
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpamExplanation {
    pub score: u32,
    pub threshold: u32,
    pub profile: String,
    pub is_spam: bool,
    pub reasons: Vec<String>,
    /// The same reasons, each with the discriminator and numbers the UI needs
    /// to render them in the active locale. Additive: `reasons` above stays the
    /// authoritative English for logs and for older frontends.
    #[serde(default)]
    pub reason_details: Vec<SpamReason>,
}

/// Per-hash undo record so Mark Not Spam can reverse the collateral that
/// `mark_spam` wrote (filename, similar-name, size, source IPs). Absent on
/// databases written before this field existed; those hashes can still be
/// un-whitelisted by hash only.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SpamMarkEntry {
    pub hash: String,
    pub filename: String,
    pub similar_name: String,
    pub size: u64,
    pub source_ips: Vec<String>,
    pub server_ip: Option<String>,
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
    pub spam_marks: Vec<SpamMarkEntry>,
}

pub struct SpamFilter {
    db: SpamDatabase,
    /// Runtime-only features aligned with `db.spam_similar_names`; avoids
    /// tokenizing every learned name once per search result.
    similar_name_features: Vec<NameFeatures>,
    data_path: std::path::PathBuf,
    dirty: bool,
    /// Set when `search_spam.json` exists but could neither be read nor set
    /// aside. Saving would replace the user's learned data with whatever this
    /// session holds, so nothing is saved until [`Self::begin_user_change`]
    /// gets the file read or preserved.
    persist_blocked: bool,
    /// Deliberate changes made while `persist_blocked`, replayed onto the file
    /// once it can be read.
    held_changes: Vec<HeldUserChange>,
    /// Monotonic mutation counter. Bumped on every change that sets `dirty`.
    /// `take_save_data` captures the value at snapshot time so `mark_saved`
    /// can refuse to clear the dirty flag if a concurrent mutation landed
    /// between the snapshot and the post-write acknowledgement (otherwise that
    /// mutation would be silently dropped from the next save).
    gen: u64,
}

/// A similar-name signature prepared for comparison.
struct NameFeatures {
    chars: Vec<char>,
    /// `chars` sorted, for the multiset bound in [`similar_name_match`].
    sorted_chars: Vec<char>,
    tokens: HashSet<String>,
}

impl NameFeatures {
    fn new(signature: &str) -> Self {
        let chars: Vec<char> = signature.chars().collect();
        let mut sorted_chars = chars.clone();
        sorted_chars.sort_unstable();
        Self {
            chars,
            sorted_chars,
            tokens: token_set(signature),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct SimilarNameMatch {
    code: SpamReasonCode,
    weight: u32,
    fraction: f64,
}

enum LoadOutcome {
    Loaded(Box<SpamDatabase>),
    Missing,
    Corrupt(String),
    Unreadable(std::io::Error),
}

enum HeldUserChange {
    MarkSpam {
        result: Box<SearchResult>,
        keywords: Vec<String>,
        server_ip: Option<String>,
    },
    MarkNotSpam(String),
    Reset,
}

/// Search keywords prepared once for scoring many rows of one search.
pub struct SpamKeywords(HashSet<String>);

impl SpamKeywords {
    pub fn new(keywords: &[String]) -> Self {
        Self(keyword_tokens(keywords))
    }
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

/// Maximum byte length of a single learned filename / similar-name entry on
/// load. Runtime inserts are already bounded (similar names to
/// `MAX_LEVENSHTEIN_LEN`), but a hand-edited or corrupted file could contain
/// pathologically long entries that make the per-result `token_set` / Jaccard
/// / edit-distance scan expensive. Over-length entries are dropped on load.
const MAX_NAME_ENTRY_BYTES: usize = 1024;

impl SpamFilter {
    pub fn load(data_dir: &Path) -> Self {
        let data_path = data_dir.join("search_spam.json");
        // Saves go through `atomic_write`, whose Windows replace-fallback can
        // leave the only copy under its backup name; without this that reads
        // as "no data yet" and the next save makes the loss permanent.
        crate::security::recover_interrupted_replace(&data_path);
        let mut persist_blocked = false;
        let db = match Self::read_database(&data_path) {
            LoadOutcome::Loaded(db) => {
                info!(
                    "Loaded spam filter: {} hashes, {} filenames",
                    db.spam_hashes.len(),
                    db.spam_filenames.len()
                );
                *db
            }
            LoadOutcome::Missing => {
                if crate::security::interrupted_replace_backup_exists(&data_path) {
                    warn!("search_spam.json is parked by an interrupted save that could not be restored; not saving over it");
                    persist_blocked = true;
                }
                SpamDatabase::default()
            }
            LoadOutcome::Corrupt(reason) => {
                match quarantine_corrupt(&data_path) {
                    Ok(moved) => warn!(
                        "search_spam.json {reason}; starting fresh. Original preserved at {}",
                        moved.display()
                    ),
                    Err(e) => {
                        warn!("search_spam.json {reason} and could not be moved aside ({e}); not saving over it");
                        persist_blocked = true;
                    }
                }
                SpamDatabase::default()
            }
            LoadOutcome::Unreadable(e) => {
                warn!("Failed to read search_spam.json ({e}); not saving over it");
                persist_blocked = true;
                SpamDatabase::default()
            }
        };
        let mut filter = Self {
            db,
            similar_name_features: Vec::new(),
            data_path,
            dirty: false,
            persist_blocked,
            held_changes: Vec::new(),
            gen: 0,
        };
        filter.rebuild_similar_name_features();
        filter
    }

    fn read_database(data_path: &Path) -> LoadOutcome {
        // Pre-flight size check so a large file doesn't OOM us at startup.
        match std::fs::metadata(data_path) {
            Ok(meta) if meta.len() > LOAD_MAX_FILE_BYTES => {
                return LoadOutcome::Corrupt(format!(
                    "is {} bytes (> {LOAD_MAX_FILE_BYTES} cap)",
                    meta.len()
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LoadOutcome::Missing,
            Err(e) => return LoadOutcome::Unreadable(e),
        }
        let data = match std::fs::read(data_path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return LoadOutcome::Missing,
            Err(e) => return LoadOutcome::Unreadable(e),
        };
        match serde_json::from_slice::<SpamDatabase>(&data) {
            Ok(mut db) => {
                Self::sanitize_loaded(&mut db);
                LoadOutcome::Loaded(Box::new(db))
            }
            Err(e) => LoadOutcome::Corrupt(format!("could not be parsed ({e})")),
        }
    }

    fn sanitize_loaded(db: &mut SpamDatabase) {
        // Truncate to per-set caps so a corrupted or hand-edited file can't
        // produce a runtime db larger than `mark_spam` would ever produce.
        db.spam_hashes.truncate_oldest(MAX_SPAM_HASHES);
        db.not_spam_hashes.truncate_oldest(NOT_SPAM_HASHES_CAP);
        // Drop pathologically long entries before the count-based truncation
        // so a hand-edited file can't load megabyte-sized names that bog down
        // every search's similarity scan.
        db.spam_filenames.retain(|s| s.len() <= MAX_NAME_ENTRY_BYTES);
        db.spam_similar_names.retain(|s| s.len() <= MAX_NAME_ENTRY_BYTES);
        // Re-derive learned names with the current normalization, so entries
        // an older build wrote (different separators, no NFKC, a smaller
        // look-alike map, release metadata left in) still compare equal to
        // names normalized today.
        db.spam_filenames = dedup_in_order(
            db.spam_filenames
                .iter()
                .map(|n| normalize_filename(n))
                .filter(|n| !n.is_empty()),
        );
        db.spam_similar_names = dedup_in_order(
            db.spam_similar_names
                .iter()
                .map(|n| similar_name_signature(n, &[]))
                .filter(|n| is_learnable_signature(n)),
        );
        for mark in &mut db.spam_marks {
            mark.filename = normalize_filename(&mark.filename);
            let signature = similar_name_signature(&mark.similar_name, &[]);
            mark.similar_name = if is_learnable_signature(&signature) {
                signature
            } else {
                String::new()
            };
        }
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
        let known_hashes = db.spam_hashes.clone();
        db.spam_marks.retain(|m| {
            let hash = normalize_hash(&m.hash);
            !hash.is_empty() && known_hashes.contains(&hash)
        });
        if db.spam_marks.len() > MAX_SPAM_HASHES {
            db.spam_marks.truncate(MAX_SPAM_HASHES);
        }
        if db.udp_server_spam_ratios.len() > MAX_SERVER_RATIOS {
            let mut ranked: Vec<(String, f32)> = db
                .udp_server_spam_ratios
                .iter()
                .map(|(k, v)| (k.clone(), *v))
                .collect();
            ranked.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            let drop_n = ranked.len().saturating_sub(MAX_SERVER_RATIOS);
            for (k, _) in ranked.into_iter().take(drop_n) {
                db.udp_server_spam_ratios.remove(&k);
            }
        }
    }

    fn rebuild_similar_name_features(&mut self) {
        self.similar_name_features = self
            .db
            .spam_similar_names
            .iter()
            .map(|name| NameFeatures::new(name))
            .collect();
    }

    /// Mark the database dirty and advance the mutation counter so an
    /// in-flight save can detect that newer changes have landed.
    fn mark_dirty(&mut self) {
        self.dirty = true;
        self.gen = self.gen.wrapping_add(1);
    }

    /// Writes inline without [`Self::save_gate`]; production saves go through
    /// [`Self::drain_saves`].
    #[cfg(test)]
    pub fn save(&mut self) {
        if !self.is_dirty() {
            return;
        }
        let data = match serde_json::to_string_pretty(&self.db) {
            Ok(d) => d,
            Err(e) => {
                warn!("Failed to serialize spam filter: {e}");
                return;
            }
        };
        match crate::security::atomic_write(&self.data_path, data.as_bytes(), false) {
            Ok(()) => {
                self.dirty = false;
                debug!("Spam filter saved");
            }
            Err(e) => warn!("Failed to save spam filter: {e}"),
        }
    }

    /// Snapshot the current database for an off-lock write. Returns the
    /// serialized JSON, the destination path, and the mutation generation the
    /// snapshot reflects. Pass that generation back to `mark_saved` so a
    /// mutation that lands while the write is in flight isn't marked clean.
    pub fn take_save_data(&mut self) -> Option<(String, std::path::PathBuf, u64)> {
        if !self.is_dirty() {
            return None;
        }
        match serde_json::to_string_pretty(&self.db) {
            Ok(data) => Some((data, self.data_path.clone(), self.gen)),
            Err(e) => {
                warn!("Failed to serialize spam filter: {e}");
                None
            }
        }
    }

    /// Clear the dirty flag, but only if no mutation occurred since the
    /// snapshot identified by `gen` was taken. If the database changed while
    /// the corresponding write was in flight, the flag stays set so the newer
    /// state is persisted on the next save. If an *older* write completes
    /// after a newer generation, re-dirty so a stale on-disk snapshot is
    /// rewritten.
    pub fn mark_saved(&mut self, gen: u64) {
        if self.gen == gen {
            self.dirty = false;
        } else if gen < self.gen {
            self.dirty = true;
        }
    }

    /// Whether there are changes a save should write. False while saving is
    /// held back over an unreadable file (see `persist_blocked`).
    pub fn is_dirty(&self) -> bool {
        self.dirty && !self.persist_blocked
    }

    /// Run before every deliberate change (Mark spam, Mark not spam, reset).
    ///
    /// While saving is held back the file is tried again first, since what
    /// kept it unreadable at startup (an antivirus scan, a sync client) is
    /// often gone by now. If it reads, it becomes this session's database with
    /// this session's changes folded in, and saving resumes. If it still
    /// cannot be read, a copy is set aside so the save this change triggers
    /// cannot destroy it. Only when neither works does saving stay held, the
    /// change kept in memory and replayed when a later attempt succeeds.
    fn begin_user_change(&mut self) {
        if !self.persist_blocked {
            return;
        }
        crate::security::recover_interrupted_replace(&self.data_path);
        let resolved = match Self::read_database(&self.data_path) {
            LoadOutcome::Loaded(db) => {
                self.adopt_loaded(*db);
                true
            }
            LoadOutcome::Missing => {
                let parked = parked_replace_path(&self.data_path);
                if !parked.exists() {
                    true
                } else if let LoadOutcome::Loaded(db) = Self::read_database(&parked) {
                    self.adopt_loaded(*db);
                    true
                } else {
                    set_aside_copy(&parked, "unreadable")
                }
            }
            LoadOutcome::Corrupt(reason) => match quarantine_corrupt(&self.data_path) {
                Ok(moved) => {
                    warn!("search_spam.json {reason}; preserved at {}", moved.display());
                    true
                }
                Err(e) => {
                    warn!("search_spam.json {reason} and still cannot be moved aside ({e}); not saving yet");
                    false
                }
            },
            LoadOutcome::Unreadable(_) => set_aside_copy(&self.data_path, "unreadable"),
        };
        if resolved {
            self.persist_blocked = false;
            self.held_changes.clear();
        }
    }

    /// Make `loaded` the database, keeping what this session learned since
    /// startup: completed downloads it whitelisted, then every deliberate
    /// change made while saving was held, in order. Server-ratio decay from
    /// this session is not carried over.
    fn adopt_loaded(&mut self, loaded: SpamDatabase) {
        let session = std::mem::replace(&mut self.db, loaded);
        for hash in session.not_spam_hashes.iter() {
            if !self.db.spam_hashes.contains(hash) {
                self.db
                    .not_spam_hashes
                    .insert(hash.clone(), NOT_SPAM_HASHES_CAP);
            }
        }
        self.rebuild_similar_name_features();
        for change in std::mem::take(&mut self.held_changes) {
            match change {
                HeldUserChange::MarkSpam {
                    result,
                    keywords,
                    server_ip,
                } => self.apply_mark_spam(&result, &keywords, server_ip.as_deref()),
                HeldUserChange::MarkNotSpam(hash) => self.apply_mark_not_spam(&hash),
                HeldUserChange::Reset => self.apply_reset(),
            }
        }
        self.mark_dirty();
        info!("search_spam.json is readable again; merged this session's spam changes into it");
    }

    fn hold(&mut self, change: HeldUserChange) {
        if self.held_changes.len() >= MAX_SPAM_HASHES {
            self.held_changes.remove(0);
        }
        self.held_changes.push(change);
    }

    /// Serialize background spam-filter saves across IPC and the network loop
    /// so concurrent `atomic_write`s cannot leave a stale snapshot on disk.
    pub fn save_gate() -> &'static tokio::sync::Mutex<()> {
        static GATE: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        GATE.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Drain dirty spam-filter snapshots to disk under [`Self::save_gate`].
    /// Safe to call from multiple tasks; writers serialize on the gate.
    pub async fn drain_saves(
        spam_filter: &std::sync::Arc<tokio::sync::RwLock<Self>>,
    ) -> Result<(), String> {
        let _guard = Self::save_gate().lock().await;
        loop {
            let Some((data, path, gen)) = ({
                let mut spam = spam_filter.write().await;
                spam.take_save_data()
            }) else {
                return Ok(());
            };
            let write_result = tokio::task::spawn_blocking(move || {
                crate::security::atomic_write(&path, data.as_bytes(), false)
            })
            .await
            .map_err(|e| format!("spam filter save task failed: {e}"))?;
            match write_result {
                Ok(()) => {
                    spam_filter.write().await.mark_saved(gen);
                }
                Err(e) => {
                    return Err(e.to_string());
                }
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

    /// Clear all learned data. Does not write to disk — callers persist via
    /// `take_save_data` + `mark_saved` so the (blocking) file write happens on
    /// a blocking thread rather than under the async lock.
    pub fn reset(&mut self) {
        self.begin_user_change();
        if self.persist_blocked {
            self.hold(HeldUserChange::Reset);
        }
        self.apply_reset();
    }

    fn apply_reset(&mut self) {
        self.db = SpamDatabase::default();
        self.similar_name_features.clear();
        self.mark_dirty();
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
        self.explain_result_with_keywords(
            result,
            &SpamKeywords::new(search_keywords),
            server_ip,
            profile,
            community,
            batch,
        )
    }

    /// [`Self::explain_result`] with the keywords prepared once, for callers
    /// scoring many rows of one search.
    ///
    /// `server_ip` is the UDP server whose packet carried the row. The row's
    /// own `origin_server_ip` wins over it: a row re-scored later (an upgrade,
    /// a re-score pass) belongs to the server that first sent it, not to
    /// whichever packet triggered the re-score.
    pub fn explain_result_with_keywords(
        &self,
        result: &SearchResult,
        keywords: &SpamKeywords,
        server_ip: Option<&str>,
        profile: SpamFilterProfile,
        community: CommunityRating,
        batch: &BatchSpamContext,
    ) -> SpamExplanation {
        let hash = normalize_hash(&result.file.hash);
        let name = &result.file.name;
        let size = result.file.size;
        let server_ip = if origin_has_udp_server(&result.result_origin) {
            result.origin_server_ip.as_deref().or(server_ip)
        } else {
            None
        };
        let threshold = Self::threshold_for_profile(profile);
        // The `relaxed` profile is deliberately local-only: it scores against
        // the user's own learned database and filename heuristics, but skips
        // the network-influenced signals (community "fake" votes and
        // intra-result-set statistical detection). Those are enabled from
        // `balanced` upward. This makes the profile a meaningful "how much do I
        // trust network-derived signals" dial rather than just a threshold.
        let network_signals = profile != SpamFilterProfile::Relaxed;

        if self.db.not_spam_hashes.contains(&hash) {
            return Self::explanation(
                0,
                threshold,
                profile,
                vec![SpamReason::new(SpamReasonCode::NotSpamMarked, &[])],
            );
        }

        // A file this library already holds cannot be fake: the bytes are on
        // disk and hash to exactly this id. The same argument `auto_mark_not_spam`
        // makes for a completed download, applied to the library at large —
        // without writing tens of thousands of hashes into a 10,000-entry
        // learned set that exists to remember the user's own decisions.
        //
        // This is not cosmetic. The batch heuristics score a *result set*, not a
        // file, so a flood advertising many hashes under a name that collides
        // with something you share was enough to push your own copy over the
        // threshold and hide it under "hide spam" — in your own search, for a
        // file you are seeding. An attacker choosing the colliding name decides
        // which of your files disappears.
        //
        // An explicit Mark spam still wins, exactly as it does over
        // `auto_mark_not_spam`: if the user has judged this hash, that judgement
        // is the answer.
        if batch.is_owned(&hash) && !self.db.spam_hashes.contains(&hash) {
            return Self::explanation(
                0,
                threshold,
                profile,
                vec![SpamReason::new(SpamReasonCode::OwnedFile, &[])],
            );
        }

        let mut score: u32 = 0;
        let mut reasons: Vec<SpamReason> = Vec::new();
        // Aggressive ×1.2 is for corroborated spam (hash, exact name, URL /
        // strong token, batch name/hash collision). Similar-name + size of
        // two legitimate ISOs must not cross the Aggressive threshold alone.
        let mut strong_local = false;

        if self.db.spam_hashes.contains(&hash) {
            score += SPAM_FILEHASH_HIT;
            reasons.push(SpamReason::new(
                SpamReasonCode::KnownHash,
                &[(SpamParam::Weight, SPAM_FILEHASH_HIT)],
            ));
            strong_local = true;
        }

        let canonical = canonical_lower(name);
        let name_norm = normalized_from_canonical(&canonical);
        let mut exact_name_hit = false;
        for spam_name in &self.db.spam_filenames {
            if name_norm == *spam_name {
                exact_name_hit = true;
                let bump = if name.chars().count() < SMALL_FILENAME_LEN {
                    SPAM_SMALLFULLNAME_HIT
                } else {
                    SPAM_FULLNAME_HIT
                };
                score += bump;
                reasons.push(SpamReason::new(
                    SpamReasonCode::ExactFilename,
                    &[(SpamParam::Weight, bump)],
                ));
                if bump >= SPAM_FULLNAME_HIT {
                    strong_local = true;
                }
                break;
            }
        }

        // An exact learned name already says everything a similar one would,
        // and a genuine file sharing the name must not take both weights.
        if !exact_name_hit {
            let signature = signature_from_canonical(&canonical, &keywords.0);
            if let Some(hit) = self.best_similar_name(&signature) {
                score += hit.weight;
                reasons.push(SpamReason::new(
                    hit.code,
                    &[
                        (SpamParam::Percent, as_percent(hit.fraction)),
                        (SpamParam::Weight, hit.weight),
                    ],
                ));
            }
        }

        for &spam_size in &self.db.spam_sizes {
            let diff = size.abs_diff(spam_size);
            if diff < SIZE_TOLERANCE_BYTES
                && (spam_size == 0 || (diff as f64 / spam_size as f64) < SIZE_TOLERANCE_PERCENT)
            {
                score += SPAM_SIMILARSIZE_HIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::SizeSignature,
                    &[(SpamParam::Weight, SPAM_SIMILARSIZE_HIT)],
                ));
                break;
            }
        }

        let pattern_score = fake_pattern_score_canonical(&canonical);
        if pattern_score > 0 {
            score += pattern_score;
            reasons.push(SpamReason::new(
                SpamReasonCode::FakePattern,
                &[(SpamParam::Weight, pattern_score)],
            ));
            if fake_pattern_is_strong_canonical(&canonical) {
                strong_local = true;
            }
        }

        // Community verdict: a file the network has voted "fake".
        let mut community_applied = false;
        if network_signals
            && community.total_votes >= FAKE_RATING_MIN_VOTES
            && community.fake_votes >= FAKE_RATING_MIN_FAKE_VOTERS
        {
            let frac = community.fake_votes as f32 / community.total_votes as f32;
            if frac >= FAKE_RATING_MAJORITY {
                score += SPAM_FAKE_RATING_HIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::CommunityFakeMajority,
                    &[
                        (SpamParam::Votes, community.fake_votes),
                        (SpamParam::Total, community.total_votes),
                        (SpamParam::Weight, SPAM_FAKE_RATING_HIT),
                    ],
                ));
                community_applied = true;
                // ≥3-vote majority is enough corroboration for Aggressive ×1.2
                // so a well-voted fake can hide; two sybils never reach here.
                strong_local = true;
            } else if frac >= FAKE_RATING_SOME {
                score += SPAM_FAKE_RATING_NEARHIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::CommunityFakeSome,
                    &[
                        (SpamParam::Votes, community.fake_votes),
                        (SpamParam::Total, community.total_votes),
                        (SpamParam::Weight, SPAM_FAKE_RATING_NEARHIT),
                    ],
                ));
                community_applied = true;
            }
        }
        // Search-result FT_FILERATING / Kad note tag on the hit itself — a
        // weak prior, not enough to hide a row on its own.
        if network_signals && !community_applied && result.rating == Some(1) {
            score += SPAM_FAKE_RATING_NEARHIT;
            reasons.push(SpamReason::new(
                SpamReasonCode::ResultRatedFake,
                &[(SpamParam::Weight, SPAM_FAKE_RATING_NEARHIT)],
            ));
        }

        // Intra-result-set statistical signals (coordinated poisoning), live
        // from this batch or carried by a row whose batch is not here — see
        // `BatchSpamContext::carry_batch_signals`.
        if network_signals {
            let carried = batch.carried.get(&hash).copied().unwrap_or_default();
            let name_hashes = if batch.enabled && batch.name_collision(&name_norm) {
                Some(batch.name_hash_count(&name_norm) as u32)
            } else {
                carried.name_many_hashes
            };
            let hash_names = if batch.enabled && batch.hash_collision(&hash) {
                Some(batch.hash_name_count(&hash) as u32)
            } else {
                carried.hash_many_names
            };
            if let Some(count) = name_hashes {
                score += SPAM_BATCH_NAME_MANY_HASHES_HIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::BatchNameManyHashes,
                    &[
                        (SpamParam::Count, count),
                        (SpamParam::Weight, SPAM_BATCH_NAME_MANY_HASHES_HIT),
                    ],
                ));
                strong_local = true;
            }
            if let Some(count) = hash_names {
                score += SPAM_BATCH_HASH_MANY_NAMES_HIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::BatchHashManyNames,
                    &[
                        (SpamParam::Count, count),
                        (SpamParam::Weight, SPAM_BATCH_HASH_MANY_NAMES_HIT),
                    ],
                ));
                strong_local = true;
            }
            if (batch.enabled && batch.source_concentrated(result)) || carried.source_concentration
            {
                score += SPAM_BATCH_SOURCE_CONCENTRATION_HIT;
                reasons.push(SpamReason::new(
                    SpamReasonCode::BatchSourceConcentration,
                    &[(SpamParam::Weight, SPAM_BATCH_SOURCE_CONCENTRATION_HIT)],
                ));
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
            reasons.push(SpamReason::new(
                SpamReasonCode::SpamSourceIp,
                &[(SpamParam::Weight, SPAM_SOURCE_HIT)],
            ));
        }

        if let Some(sip) = server_ip.and_then(extract_ip) {
            if self.db.spam_server_ips.contains(&sip) {
                let total_sources = result
                    .source_addresses
                    .iter()
                    .filter(|a| extract_ip(a).is_some())
                    .count();
                // A row listing no sources says nothing about them, so it
                // gets the near-hit weight, never the all-sources-spam one.
                let all_sources_spam =
                    total_sources > 0 && total_sources as u32 == spam_source_count;
                if all_sources_spam {
                    score += SPAM_UDPSERVERRES_HIT;
                    reasons.push(SpamReason::new(
                        SpamReasonCode::SpamServerAllSources,
                        &[(SpamParam::Weight, SPAM_UDPSERVERRES_HIT)],
                    ));
                } else {
                    score += SPAM_UDPSERVERRES_NEARHIT;
                    reasons.push(SpamReason::new(
                        SpamReasonCode::SpamServerInfluence,
                        &[(SpamParam::Weight, SPAM_UDPSERVERRES_NEARHIT)],
                    ));
                }
            }
            if let Some(&ratio) = self.db.udp_server_spam_ratios.get(&sip) {
                if ratio > 0.5 {
                    score += SPAM_ONLYUDPSPAMSERVERS_HIT;
                    reasons.push(SpamReason::new(
                        SpamReasonCode::ServerRatioHigh,
                        &[
                            (SpamParam::Percent, as_percent(ratio as f64)),
                            (SpamParam::Weight, SPAM_ONLYUDPSPAMSERVERS_HIT),
                        ],
                    ));
                } else if ratio > 0.3 {
                    score += SPAM_UDPSERVERRES_FARHIT;
                    reasons.push(SpamReason::new(
                        SpamReasonCode::ServerRatioElevated,
                        &[
                            (SpamParam::Percent, as_percent(ratio as f64)),
                            (SpamParam::Weight, SPAM_UDPSERVERRES_FARHIT),
                        ],
                    ));
                }
            }
        }

        if profile == SpamFilterProfile::Aggressive && strong_local {
            let boosted = (score as f32 * 1.2).round() as u32;
            if boosted > score {
                reasons.push(SpamReason::new(
                    SpamReasonCode::AggressiveBoost,
                    &[(SpamParam::Weight, boosted - score)],
                ));
                score = boosted;
            }
        }

        if reasons.is_empty() {
            reasons.push(SpamReason::new(SpamReasonCode::NoSignals, &[]));
        }

        Self::explanation(score, threshold, profile, reasons)
    }

    /// Wrap a scored reason list, deriving the English `reasons` from the coded
    /// ones so the two lists cannot fall out of step.
    fn explanation(
        score: u32,
        threshold: u32,
        profile: SpamFilterProfile,
        reason_details: Vec<SpamReason>,
    ) -> SpamExplanation {
        SpamExplanation {
            score,
            threshold,
            profile: profile_name(profile),
            is_spam: Self::is_spam(score, profile),
            reasons: reason_details.iter().map(|r| r.text.clone()).collect(),
            reason_details,
        }
    }

    #[cfg(test)]
    pub fn rate_result(
        &self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
        profile: SpamFilterProfile,
        community: CommunityRating,
        batch: &BatchSpamContext,
    ) -> u32 {
        self.explain_result(
            result,
            search_keywords,
            server_ip,
            profile,
            community,
            batch,
        )
        .score
    }

    /// The strongest similar-name signal `name` earns against every learned
    /// signature, not merely the first one over a threshold.
    fn best_similar_name(&self, signature: &str) -> Option<SimilarNameMatch> {
        let len = signature.chars().count();
        if !(MIN_SIMILAR_NAME_LEN..=MAX_LEVENSHTEIN_LEN).contains(&len) {
            return None;
        }
        let probe = NameFeatures::new(signature);
        let mut rows = LevenshteinRows::default();
        let mut best: Option<SimilarNameMatch> = None;
        for candidate in &self.similar_name_features {
            let Some(hit) = similar_name_match(&probe, candidate, &mut rows) else {
                continue;
            };
            let better = best.is_none_or(|b| {
                hit.weight > b.weight || (hit.weight == b.weight && hit.fraction > b.fraction)
            });
            if better {
                best = Some(hit);
                if hit.weight == SPAM_SIMILARNAME_HIT && hit.fraction >= 1.0 {
                    break;
                }
            }
        }
        best
    }

    pub fn mark_spam(
        &mut self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
    ) {
        self.begin_user_change();
        if self.persist_blocked {
            self.hold(HeldUserChange::MarkSpam {
                result: Box::new(result.clone()),
                keywords: search_keywords.to_vec(),
                server_ip: server_ip.map(str::to_string),
            });
        }
        self.apply_mark_spam(result, search_keywords, server_ip);
    }

    fn apply_mark_spam(
        &mut self,
        result: &SearchResult,
        search_keywords: &[String],
        server_ip: Option<&str>,
    ) {
        let file_hash = normalize_hash(&result.file.hash);
        if !file_hash.is_empty() {
            self.db
                .spam_hashes
                .insert(file_hash.clone(), MAX_SPAM_HASHES);
            self.db.not_spam_hashes.remove(&file_hash);
            // Reverse collateral for the previous mark of this hash (re-mark)
            // and for hashes FIFO-evicted by the insert above, *before* we
            // learn this row's filename/IPs so a shared name is not dropped.
            if let Some(pos) = self.db.spam_marks.iter().position(|m| m.hash == file_hash) {
                let old = self.db.spam_marks.remove(pos);
                self.drop_mark_collateral(&old);
            }
            self.drop_orphaned_marks();
        }

        let name = &result.file.name;
        let canonical = canonical_lower(name);
        let name_norm = normalized_from_canonical(&canonical);
        if !name_norm.is_empty() && !self.db.spam_filenames.contains(&name_norm) {
            if self.db.spam_filenames.len() >= MAX_SPAM_FILENAMES {
                self.db.spam_filenames.remove(0);
            }
            self.db.spam_filenames.push(name_norm.clone());
        }

        let signature = signature_from_canonical(&canonical, &keyword_tokens(search_keywords));
        let stripped = if is_learnable_signature(&signature) {
            signature
        } else {
            String::new()
        };
        if !stripped.is_empty() && !self.db.spam_similar_names.contains(&stripped) {
            if self.db.spam_similar_names.len() >= MAX_SPAM_SIMILAR_NAMES {
                self.db.spam_similar_names.remove(0);
            }
            self.db.spam_similar_names.push(stripped.clone());
        }

        if result.file.size > 0 && !self.db.spam_sizes.contains(&result.file.size) {
            if self.db.spam_sizes.len() >= MAX_SPAM_SIZES {
                self.db.spam_sizes.pop_front();
            }
            self.db.spam_sizes.push_back(result.file.size);
        }

        let mut learned_ips: Vec<String> = Vec::new();
        for addr in result
            .source_addresses
            .iter()
            .take(MAX_SOURCE_IPS_PER_RESULT)
        {
            if let Some(ip) = extract_ip(addr) {
                if !is_globally_routable_ip(&ip) {
                    continue;
                }
                self.db
                    .spam_source_ips
                    .insert(ip.clone(), MAX_SPAM_SOURCE_IPS);
                if !learned_ips.contains(&ip) {
                    learned_ips.push(ip);
                }
            }
        }

        // Only a UDP global-search answer trains server reputation, keyed by
        // the server that sent it. An empty origin comes from an IPC caller
        // that does not send one; the search page only sends a server IP for
        // UDP rows, and the streaming path only stamps UDP rows with one.
        let server_ip_owned = if result.result_origin.is_empty()
            || origin_has_udp_server(&result.result_origin)
        {
            result
                .origin_server_ip
                .as_deref()
                .or(server_ip)
                .and_then(extract_ip)
                .filter(|ip| is_globally_routable_ip(ip))
        } else {
            None
        };
        if let Some(ref sip) = server_ip_owned {
            self.db
                .spam_server_ips
                .insert(sip.clone(), MAX_SPAM_SERVER_IPS);

            let entry = self.db.udp_server_spam_ratios.entry(sip.clone()).or_insert(0.0);
            *entry = (*entry * 0.9 + 0.1).min(1.0);
            if self.db.udp_server_spam_ratios.len() > MAX_SERVER_RATIOS {
                if let Some(lowest_key) = self
                    .db
                    .udp_server_spam_ratios
                    .iter()
                    .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                    .map(|(k, _)| k.clone())
                {
                    self.db.udp_server_spam_ratios.remove(&lowest_key);
                }
            }
        }

        if !file_hash.is_empty() {
            self.db.spam_marks.push(SpamMarkEntry {
                hash: file_hash,
                filename: name_norm,
                similar_name: stripped,
                size: result.file.size,
                source_ips: learned_ips,
                server_ip: server_ip_owned,
            });
            while self.db.spam_marks.len() > MAX_SPAM_HASHES {
                let mark = self.db.spam_marks.remove(0);
                self.drop_mark_collateral(&mark);
            }
        }

        self.rebuild_similar_name_features();
        self.mark_dirty();
        info!("Marked as spam: {} ({})", name, result.file.hash);
    }

    pub fn mark_not_spam(&mut self, file_hash: &str) {
        self.begin_user_change();
        if self.persist_blocked {
            self.hold(HeldUserChange::MarkNotSpam(file_hash.to_string()));
        }
        self.apply_mark_not_spam(file_hash);
    }

    fn apply_mark_not_spam(&mut self, file_hash: &str) {
        let file_hash = normalize_hash(file_hash);
        self.db
            .not_spam_hashes
            .insert(file_hash.clone(), NOT_SPAM_HASHES_CAP);
        self.db.spam_hashes.remove(&file_hash);
        if let Some(pos) = self.db.spam_marks.iter().position(|m| m.hash == file_hash) {
            let mark = self.db.spam_marks.remove(pos);
            self.drop_mark_collateral(&mark);
            self.rebuild_similar_name_features();
        }
        self.mark_dirty();
        info!("Marked as not spam: {file_hash}");
    }

    /// Drop filename / similar-name / size / source IPs / server IP that this
    /// mark added, but only when no remaining mark still references them.
    fn drop_mark_collateral(&mut self, mark: &SpamMarkEntry) {
        if !mark.filename.is_empty()
            && !self
                .db
                .spam_marks
                .iter()
                .any(|m| m.filename == mark.filename)
        {
            self.db.spam_filenames.retain(|n| n != &mark.filename);
        }
        if !mark.similar_name.is_empty()
            && !self
                .db
                .spam_marks
                .iter()
                .any(|m| m.similar_name == mark.similar_name)
        {
            self.db.spam_similar_names.retain(|n| n != &mark.similar_name);
        }
        if mark.size > 0 && !self.db.spam_marks.iter().any(|m| m.size == mark.size) {
            self.db.spam_sizes.retain(|s| *s != mark.size);
        }
        for ip in &mark.source_ips {
            if !self
                .db
                .spam_marks
                .iter()
                .any(|m| m.source_ips.iter().any(|o| o == ip))
            {
                self.db.spam_source_ips.remove(ip);
            }
        }
        if let Some(sip) = &mark.server_ip {
            let still_used = self
                .db
                .spam_marks
                .iter()
                .any(|m| m.server_ip.as_deref() == Some(sip.as_str()));
            if !still_used {
                self.db.udp_server_spam_ratios.remove(sip);
                self.db.spam_server_ips.remove(sip);
            }
        }
    }

    /// Reverse collateral for marks whose hash left `spam_hashes` (FIFO cap).
    fn drop_orphaned_marks(&mut self) {
        let known = self.db.spam_hashes.clone();
        let mut i = 0;
        while i < self.db.spam_marks.len() {
            if known.contains(&self.db.spam_marks[i].hash) {
                i += 1;
                continue;
            }
            let mark = self.db.spam_marks.remove(i);
            self.drop_mark_collateral(&mark);
        }
    }

    /// Silently add a hash to the not-spam whitelist (e.g. on completed download).
    /// Does not save immediately; caller should ensure periodic save happens.
    /// Does not override an explicit Mark Spam — finishing a fake must not
    /// un-train the hash.
    pub fn auto_mark_not_spam(&mut self, file_hash: &str) {
        let file_hash = normalize_hash(file_hash);
        if file_hash.is_empty()
            || self.db.not_spam_hashes.contains(&file_hash)
            || self.db.spam_hashes.contains(&file_hash)
        {
            return;
        }
        self.db
            .not_spam_hashes
            .insert(file_hash.clone(), NOT_SPAM_HASHES_CAP);
        self.mark_dirty();
        debug!("Auto-marked completed download as not spam: {file_hash}");
    }

    /// Auto-redemption after scoring a search batch: fold the per-server
    /// outcome back into the learned reputation. We only ever *decay* a
    /// server's spam ratio here (when its results came back mostly clean) and
    /// never auto-escalate — escalation stays user-driven via `mark_spam` to
    /// avoid heuristic feedback loops. A server whose ratio decays below the
    /// floor is fully redeemed (dropped from the spam-server set), so a server
    /// that cleaned up its act is no longer penalised forever.
    ///
    /// A row counts as clean if it would be clean without the server's own
    /// reputation signals. Those land on every row a flagged server returns,
    /// so counting them would let the reputation vouch for itself and keep a
    /// server from ever being redeemed.
    pub fn record_server_clean_batch(
        &mut self,
        server_ip: &str,
        results: &[SearchResult],
        profile: SpamFilterProfile,
    ) {
        let total = results.len();
        if total == 0 {
            return;
        }
        let sip = match extract_ip(server_ip) {
            Some(s) => s,
            None => return,
        };
        let clean = results
            .iter()
            .filter(|r| {
                !Self::is_spam(score_without_server_signals(&r.spam_reason_details), profile)
            })
            .count();
        if clean == 0 {
            return;
        }
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
            self.mark_dirty();
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
pub(crate) fn fake_pattern_score(filename: &str) -> u32 {
    fake_pattern_score_canonical(&canonical_lower(filename))
}

fn fake_pattern_score_canonical(lower: &str) -> u32 {
    let mut score = 0u32;
    for pattern in FAKE_URL_PATTERNS {
        if lower.contains(pattern) {
            score += SPAM_FAKE_URL_HIT;
            break;
        }
    }

    let tokens: HashSet<&str> = name_tokens(lower).collect();

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

fn fake_pattern_is_strong_canonical(lower: &str) -> bool {
    if FAKE_URL_PATTERNS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    let tokens: HashSet<&str> = name_tokens(lower).collect();
    STRONG_FAKE_FILENAME_TOKENS
        .iter()
        .any(|t| tokens.contains(*t) || lower.contains(t))
}

/// The part of a filename the similar-name signal learns and compares. As in
/// eMule's `SearchList.cpp`, the name is tokenized and the search keywords are
/// dropped; release metadata ([`is_stop_token`]) goes too, since it says
/// nothing about which file this is.
fn similar_name_signature(filename: &str, keywords: &[String]) -> String {
    signature_from_canonical(&canonical_lower(filename), &keyword_tokens(keywords))
}

/// [`similar_name_signature`] of an already canonical name.
fn signature_from_canonical(canonical: &str, keywords: &HashSet<String>) -> String {
    name_tokens(canonical)
        .filter(|t| !keywords.contains(*t) && !is_stop_token(t))
        .collect::<Vec<_>>()
        .join(" ")
}

/// [`normalize_filename`] of an already canonical name.
fn normalized_from_canonical(canonical: &str) -> String {
    name_tokens(canonical).collect::<Vec<_>>().join(" ")
}

/// Whether a signature is specific enough to learn: within the comparable
/// length range and carrying at least one distinctive token.
fn is_learnable_signature(signature: &str) -> bool {
    let len = signature.chars().count();
    (MIN_SIMILAR_NAME_LEN..=MAX_LEVENSHTEIN_LEN).contains(&len) && has_distinctive_token(signature)
}

/// A token (already canonical) that identifies nothing on its own: release
/// metadata, a number or year, a resolution, an episode or bit-depth tag.
fn is_stop_token(token: &str) -> bool {
    if SIGNATURE_STOP_TOKENS.contains(&token) {
        return true;
    }
    let digits = token.chars().take_while(|c| c.is_ascii_digit()).count();
    let rest = &token[digits..];
    if digits == token.len() {
        return true;
    }
    if digits > 0 && matches!(rest, "p" | "i" | "bit" | "ch" | "fps" | "k") {
        return true;
    }
    if digits > 0 {
        if let Some(tail) = rest.strip_prefix('x') {
            if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) {
                return true;
            }
        }
    }
    if let Some(tail) = token.strip_prefix('s') {
        if let Some((season, episode)) = tail.split_once('e') {
            let numeric = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_digit());
            if numeric(season) && numeric(episode) {
                return true;
            }
        }
    }
    false
}

/// A token that tells one file from another: not a stop token, not a generic
/// word, and at least three characters — or two when not plain ASCII, since a
/// pair of CJK ideographs carries as much as a short Latin word.
fn is_distinctive_token(token: &str) -> bool {
    if is_stop_token(token) || GENERIC_NAME_TOKENS.contains(&token) {
        return false;
    }
    let chars = token.chars().count();
    chars >= 3 || (chars >= 2 && !token.is_ascii())
}

fn has_distinctive_token(name: &str) -> bool {
    name_tokens(name).any(is_distinctive_token)
}

fn dedup_in_order(items: impl Iterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    items.filter(|item| seen.insert(item.clone())).collect()
}

/// Where an interrupted [`crate::security::atomic_write`] parks the previous
/// file (`security::interrupted_replace_backup_path`).
fn parked_replace_path(path: &Path) -> std::path::PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ember-replace-bak");
    path.with_file_name(name)
}

/// A free `<file name>.<stamp>.<kind>` path beside `path`, the naming the
/// other quarantined JSON stores use.
fn aside_path(path: &Path, kind: &str) -> std::path::PathBuf {
    let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
    let base = path.file_name().unwrap_or_default().to_string_lossy().into_owned();
    let mut destination = path.with_file_name(format!("{base}.{stamp}.{kind}"));
    let mut suffix = 0u32;
    while destination.exists() {
        suffix = suffix.saturating_add(1);
        destination = path.with_file_name(format!("{base}.{stamp}.{suffix}.{kind}"));
    }
    destination
}

/// An earlier `<file name>.*.<kind>` copy beside `path` holding exactly `data`.
fn identical_aside_copy(path: &Path, kind: &str, data: &[u8]) -> Option<std::path::PathBuf> {
    let base = path.file_name()?.to_string_lossy().into_owned();
    let prefix = format!("{base}.");
    let suffix = format!(".{kind}");
    std::fs::read_dir(path.parent()?)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            name.starts_with(&prefix) && name.ends_with(&suffix)
        })
        .filter(|entry| entry.metadata().is_ok_and(|m| m.len() == data.len() as u64))
        .map(|entry| entry.path())
        .find(|candidate| std::fs::read(candidate).is_ok_and(|bytes| bytes == data))
}

/// Copy `path` aside as `<file name>.<stamp>.<kind>`, so a save may replace
/// it. Returns whether a copy now exists.
fn set_aside_copy(path: &Path, kind: &str) -> bool {
    let destination = aside_path(path, kind);
    match std::fs::copy(path, &destination) {
        Ok(_) => {
            warn!(
                "{} could not be read; a copy is preserved at {}",
                path.display(),
                destination.display()
            );
            true
        }
        Err(e) => {
            warn!("{} could not be read or copied ({e}); not saving over it", path.display());
            false
        }
    }
}

/// Move an unparseable `search_spam.json` aside, beside the original, so the
/// user's learned data stays recoverable and the next save does not land on
/// it.
///
/// When the file cannot be moved (another process holds it open) it is
/// copied instead. A copy is a quarantine even if the original then cannot be
/// deleted: the next save replaces the original, and the data is safe in the
/// copy. An identical copy left by an earlier run is reused rather than made
/// again on every start.
fn quarantine_corrupt(path: &Path) -> std::io::Result<std::path::PathBuf> {
    let destination = aside_path(path, "corrupt");
    if std::fs::rename(path, &destination).is_ok() {
        return Ok(destination);
    }
    let data = std::fs::read(path)?;
    let copy = match identical_aside_copy(path, "corrupt", &data) {
        Some(existing) => existing,
        None => {
            std::fs::write(&destination, &data)?;
            destination
        }
    };
    if let Err(e) = std::fs::remove_file(path) {
        warn!(
            "{} is preserved at {} but could not be removed ({e}); the next save replaces it",
            path.display(),
            copy.display()
        );
    }
    Ok(copy)
}

/// Score one learned signature against a probe.
///
/// Edit similarity is `strsim::normalized_levenshtein` — `1 - d / max_len`
/// over chars — but only computed where it can reach the lowest threshold
/// (0.70): the length difference and the character-multiset difference are
/// both lower bounds on `d`, and the banded distance gives up once `d` passes
/// the bound. A candidate that fails those could only score ≤ 0.70, where no
/// edit-based weight applies, so skipping it cannot change a score.
fn similar_name_match(
    probe: &NameFeatures,
    candidate: &NameFeatures,
    rows: &mut LevenshteinRows,
) -> Option<SimilarNameMatch> {
    let (a, b) = (probe.chars.len(), candidate.chars.len());
    let max_chars = a.max(b);
    let length_ok = max_chars > 0 && (a.abs_diff(b) as f64) / (max_chars as f64) < 0.30;
    let mut sim = 0.0;
    if length_ok {
        let limit = max_chars * 3 / 10 + 1;
        if multiset_distance_bound(&probe.sorted_chars, &candidate.sorted_chars) <= limit {
            if let Some(d) = levenshtein_within(&probe.chars, &candidate.chars, limit, rows) {
                sim = 1.0 - (d as f64) / (max_chars as f64);
            }
        }
    }
    let (code, weight, fraction) = if sim > 0.95 {
        (SpamReasonCode::VerySimilarName, SPAM_SIMILARNAME_HIT, sim)
    } else if sim > 0.85 {
        (SpamReasonCode::SimilarName, SPAM_SIMILARNAME_NEARHIT, sim)
    } else {
        let jac = jaccard(&probe.tokens, &candidate.tokens);
        if jac >= SIMILAR_NAME_JACCARD_HIT {
            (SpamReasonCode::ReorderedName, SPAM_SIMILARNAME_NEARHIT, jac)
        } else if sim > 0.70 {
            (SpamReasonCode::LooselySimilarName, SPAM_SIMILARNAME_FARHIT, sim)
        } else {
            return None;
        }
    };
    Some(SimilarNameMatch {
        code,
        weight,
        fraction,
    })
}

/// Lower bound on the edit distance between two strings, from their sorted
/// characters: every character one has beyond the other costs an edit.
fn multiset_distance_bound(a: &[char], b: &[char]) -> usize {
    let (mut i, mut j, mut common) = (0, 0, 0);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Equal => {
                common += 1;
                i += 1;
                j += 1;
            }
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
        }
    }
    (a.len() - common).max(b.len() - common)
}

/// Row buffers for [`levenshtein_within`], reused across the candidates of
/// one scan.
#[derive(Default)]
struct LevenshteinRows {
    prev: Vec<usize>,
    cur: Vec<usize>,
}

/// Levenshtein distance over chars if it is at most `max`, else `None`.
/// Only the diagonal band of width `max` is filled, and a row whose every cell
/// already exceeds `max` ends the search.
fn levenshtein_within(
    a: &[char],
    b: &[char],
    max: usize,
    rows: &mut LevenshteinRows,
) -> Option<usize> {
    let (a, b) = if a.len() > b.len() { (b, a) } else { (a, b) };
    let (n, m) = (a.len(), b.len());
    if m - n > max {
        return None;
    }
    if n == 0 {
        return Some(m);
    }
    const FAR: usize = usize::MAX / 2;
    let LevenshteinRows { prev, cur } = rows;
    prev.clear();
    prev.extend((0..=m).map(|j| if j <= max { j } else { FAR }));
    cur.clear();
    cur.resize(m + 1, FAR);
    for i in 1..=n {
        let lo = i.saturating_sub(max).max(1);
        let hi = (i + max).min(m);
        cur[0] = if i <= max { i } else { FAR };
        cur[lo - 1] = if lo == 1 { cur[0] } else { FAR };
        let mut row_min = cur[lo - 1];
        for j in lo..=hi {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let value = (prev[j - 1] + cost).min(prev[j] + 1).min(cur[j - 1] + 1);
            cur[j] = value;
            row_min = row_min.min(value);
        }
        if hi < m {
            cur[hi + 1] = FAR;
        }
        if row_min > max {
            return None;
        }
        std::mem::swap(prev, cur);
    }
    (prev[m] <= max).then_some(prev[m])
}

fn normalize_hash(hash: &str) -> String {
    hash.trim().to_ascii_lowercase()
}

fn normalize_filename(name: &str) -> String {
    normalized_from_canonical(&canonical_lower(name))
}

/// Word separators in a canonical name. Characters NFKC already maps to ASCII
/// (full-width punctuation, half-width CJK brackets) arrive as ASCII here.
fn is_token_delimiter(c: char) -> bool {
    c.is_whitespace()
        || c.is_ascii_punctuation()
        || matches!(
            c,
            // Latin-1 punctuation
            '¡' | '§' | '«' | '¶' | '·' | '»' | '¿'
            // General Punctuation: dashes, quotes, bullets, leaders, ellipsis
            | '\u{2010}'..='\u{2027}'
            // CJK Symbols and Punctuation, minus the letters and marks in the
            // block (々 〆 〇, Hangzhou numerals, tone marks, kana repeats, 〻)
            | '\u{3000}'..='\u{3004}'
            | '\u{3008}'..='\u{3020}'
            | '\u{3030}'
            | '\u{3036}'..='\u{3037}'
            | '\u{303D}'..='\u{303F}'
            // Katakana middle dot
            | '・'
        )
}

/// Non-empty words of an already canonical string.
fn name_tokens(canonical: &str) -> impl Iterator<Item = &str> {
    canonical.split(is_token_delimiter).filter(|t| !t.is_empty())
}

/// The comparison form of a name: invisible characters dropped, NFKC
/// normalized (full-width forms, ligatures, circled and compatibility
/// characters to their plain equivalents), lowercased, and Latin look-alikes
/// folded to Latin. Spam pads names with zero-width characters and swaps in
/// Cyrillic/Greek homoglyphs to dodge exact and edit-distance matching.
fn canonical_lower(s: &str) -> String {
    // Lunate sigma looks like `c` but NFKC turns it into a sigma, which does
    // not, so it is folded before normalizing.
    let visible: String = s
        .chars()
        .filter(|c| !is_default_ignorable(*c))
        .map(|c| if matches!(c, 'Ϲ' | 'ϲ') { 'c' } else { c })
        .collect();
    let normalized = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(&visible);
    let mut out = String::with_capacity(normalized.len());
    for c in normalized.chars() {
        for lower in c.to_lowercase() {
            out.push(fold_confusable(lower).unwrap_or(lower));
        }
    }
    out
}

/// Unicode `Default_Ignorable_Code_Point`s: rendered as nothing, so free to
/// insert anywhere in a name without changing how it looks.
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// The Latin letter a lowercase Cyrillic or Greek letter is folded to.
///
/// Applied after lowercasing, so both cases of a letter fold the same way.
/// Where the two cases look like different Latin letters (Greek Η/η read as
/// H/n, Μ/μ as M/u, Ν/ν as N/v, Υ/υ as Y/u) the uppercase reading wins:
/// capitals are what spam swaps in to pass for Latin. Letters that pass for
/// Latin in one case only and would mangle real text in the other (Γ/γ, Ω/ω)
/// are not folded.
fn fold_confusable(c: char) -> Option<char> {
    Some(match c {
        // Cyrillic
        'а' => 'a',
        'в' | 'ь' => 'b',
        'с' => 'c',
        'ԁ' => 'd',
        'е' | 'ё' => 'e',
        'һ' | 'н' => 'h',
        'і' | 'ї' => 'i',
        'ј' => 'j',
        'к' => 'k',
        'ӏ' => 'l',
        'м' => 'm',
        'о' => 'o',
        'р' => 'p',
        'ԛ' => 'q',
        'ѕ' => 's',
        'т' => 't',
        'ԝ' => 'w',
        'х' => 'x',
        'у' | 'ү' => 'y',
        // Greek
        'α' => 'a',
        'β' => 'b',
        'ε' => 'e',
        'η' => 'h',
        'ι' => 'i',
        'ϳ' => 'j',
        'κ' => 'k',
        'μ' => 'm',
        'ν' => 'n',
        'ο' => 'o',
        'ρ' => 'p',
        'τ' => 't',
        'χ' => 'x',
        'υ' => 'y',
        'ζ' => 'z',
        // Latin letters outside ASCII that pass for ASCII ones
        'ı' => 'i',
        'ɑ' => 'a',
        'ɡ' => 'g',
        _ => return None,
    })
}

/// Tokenize a (canonical) string into a set of tokens for set-similarity
/// comparison.
fn token_set(s: &str) -> HashSet<String> {
    name_tokens(s).map(str::to_string).collect()
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

fn is_globally_routable_ip(ip: &str) -> bool {
    let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    match addr {
        std::net::IpAddr::V4(v) => {
            !v.is_unspecified()
                && !v.is_loopback()
                && !v.is_private()
                && !v.is_link_local()
                && !v.is_broadcast()
                && !v.is_documentation()
                && !is_shared_v4(v)
                && !is_benchmarking_v4(v)
                && !v.is_multicast()
        }
        std::net::IpAddr::V6(v) => {
            !v.is_unspecified()
                && !v.is_loopback()
                && !v.is_multicast()
                && !v.is_unique_local()
                && !v.is_unicast_link_local()
                && !is_documentation_v6(v)
        }
    }
}

/// RFC 6598 CGNAT `100.64.0.0/10`. `Ipv4Addr::is_shared` is still unstable here.
fn is_shared_v4(v: std::net::Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// RFC 2544 benchmarking `198.18.0.0/15`. `Ipv4Addr::is_benchmarking` is still unstable here.
fn is_benchmarking_v4(v: std::net::Ipv4Addr) -> bool {
    let o = v.octets();
    o[0] == 198 && (o[1] & 0xfe) == 18
}

/// `2001:db8::/32` and RFC 9637 `3fff::/20`. `Ipv6Addr::is_documentation` is still unstable here.
///
/// The `/20` covers all 16 bits of the first group plus the top four of the
/// second, so it is the *second* group that carries the mask. Masking the
/// first group instead made the test unsatisfiable — `x & 0xfff0` clears the
/// low nibble that `0x3fff` needs — so the whole range read as ordinary
/// global unicast.
fn is_documentation_v6(v: std::net::Ipv6Addr) -> bool {
    let s = v.segments();
    (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x3fff && (s[1] & 0xf000) == 0)
}

fn keyword_tokens(keywords: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    for kw in keywords {
        out.extend(name_tokens(&canonical_lower(kw)).map(str::to_string));
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
                ember_file_hash: String::new(),
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
                friends_only: false,
                shared_kad: false,
                shared_ed2k: false,
                shared_ember: false,
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
            origin_server_ip: None,
            spam_reasons: Vec::new(),
            spam_reason_details: Vec::new(),
        }
    }

    fn sized_result(hash: &str, name: &str, size: u64, sources: &[&str]) -> SearchResult {
        let mut r = sample_result(hash, name);
        r.file.size = size;
        r.source_addresses = sources.iter().map(|s| s.to_string()).collect();
        r
    }

    const ALL_SPAM_PARAMS: [SpamParam; 5] = [
        SpamParam::Weight,
        SpamParam::Percent,
        SpamParam::Count,
        SpamParam::Votes,
        SpamParam::Total,
    ];

    /// The parameters a code's English template asks for, with distinct stand-in
    /// values so a message that interpolates the wrong one is visible.
    fn declared_params(code: SpamReasonCode) -> Vec<(SpamParam, u32)> {
        ALL_SPAM_PARAMS
            .iter()
            .filter(|param| code.message().contains(&format!("{{{}}}", param.name())))
            .enumerate()
            .map(|(index, param)| (*param, 11 + index as u32))
            .collect()
    }

    fn field(reason: &SpamReason, param: SpamParam) -> Option<u32> {
        match param {
            SpamParam::Weight => reason.weight,
            SpamParam::Percent => reason.percent,
            SpamParam::Count => reason.count,
            SpamParam::Votes => reason.votes,
            SpamParam::Total => reason.total,
        }
    }

    /// The codes are an IPC contract: the search tooltip looks each one up in a
    /// table keyed by exactly this string.
    #[test]
    fn every_spam_reason_code_is_a_distinct_identifier() {
        let mut seen = std::collections::HashSet::new();
        for code in SpamReasonCode::ALL {
            let text = code.as_code();
            assert!(
                !text.is_empty()
                    && text
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{text} is not a snake_case identifier"
            );
            assert!(seen.insert(text), "{text} is used by two variants");
            assert!(!code.message().is_empty(), "{text} has no English");
        }
        assert_eq!(seen.len(), SpamReasonCode::ALL.len());
    }

    /// The numbers are carried as named parameters rather than baked into the
    /// text, because the UI re-interpolates them into a translated sentence. A
    /// template slot with no matching field, or a field the template never
    /// asks for, means the tooltip renders a hole or drops a number.
    #[test]
    fn every_spam_reason_renders_the_parameters_its_template_declares() {
        for code in SpamReasonCode::ALL {
            let params = declared_params(*code);
            let reason = SpamReason::new(*code, &params);
            assert_eq!(reason.code, code.as_code());
            assert!(
                !reason.text.contains('{'),
                "{} left a placeholder unfilled: {}",
                code.as_code(),
                reason.text
            );
            for param in ALL_SPAM_PARAMS {
                let declared = params.iter().find(|(p, _)| *p == param);
                assert_eq!(
                    field(&reason, param),
                    declared.map(|(_, value)| *value),
                    "{} disagrees with its template about {}",
                    code.as_code(),
                    param.name()
                );
            }
        }
    }

    /// Scoring is the only producer of a spam reason, and the tooltip is the
    /// surface that used to read English in all nine locales. Every reason it
    /// emits has to arrive with a code and the numbers to re-render it.
    #[test]
    fn scoring_reports_a_code_and_parameters_beside_the_english() {
        let dir = temp_dir("coded-reasons");
        let mut filter = SpamFilter::load(&dir);
        let hash = "d".repeat(32);
        filter.db.spam_hashes.insert(hash.clone(), MAX_SPAM_HASHES);

        let explanation = filter.explain_result(
            &sample_result(&hash, "install_codec www.example.com/movie.exe"),
            &[],
            None,
            SpamFilterProfile::Aggressive,
            CommunityRating {
                fake_votes: 4,
                total_votes: 5,
            },
            &BatchSpamContext::default(),
        );

        let known: std::collections::HashSet<&str> =
            SpamReasonCode::ALL.iter().map(|c| c.as_code()).collect();
        assert_eq!(
            explanation.reasons.len(),
            explanation.reason_details.len(),
            "the English list and the coded list describe the same verdict"
        );
        for (english, detail) in explanation
            .reasons
            .iter()
            .zip(explanation.reason_details.iter())
        {
            assert_eq!(english, &detail.text);
            assert!(known.contains(detail.code.as_str()), "{} is not a declared code", detail.code);
            assert!(!detail.text.contains('{'), "{} rendered a hole", detail.code);
        }

        let codes: Vec<&str> = explanation
            .reason_details
            .iter()
            .map(|r| r.code.as_str())
            .collect();
        assert!(codes.contains(&"known_hash"));
        assert!(codes.contains(&"fake_pattern"));
        assert!(codes.contains(&"community_fake_majority"));
        assert!(
            codes.contains(&"aggressive_boost"),
            "corroborated spam on the aggressive profile boosts, and says so"
        );

        let hash_hit = explanation
            .reason_details
            .iter()
            .find(|r| r.code == "known_hash")
            .expect("the known-hash signal is present");
        assert_eq!(hash_hit.weight, Some(SPAM_FILEHASH_HIT));
        let votes = explanation
            .reason_details
            .iter()
            .find(|r| r.code == "community_fake_majority")
            .expect("the community signal is present");
        assert_eq!((votes.votes, votes.total), (Some(4), Some(5)));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A whitelisted hash takes an early return of its own, which is exactly
    /// the sort of path that keeps returning a bare sentence after the rest of
    /// the function has been converted.
    #[test]
    fn the_not_spam_verdict_is_coded_too() {
        let dir = temp_dir("coded-not-spam");
        let mut filter = SpamFilter::load(&dir);
        let hash = "e".repeat(32);
        filter.mark_not_spam(&hash);

        let explanation = filter.explain_result(
            &sample_result(&hash, "anything.bin"),
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );

        assert!(!explanation.is_spam);
        assert_eq!(
            explanation
                .reason_details
                .iter()
                .map(|r| r.code.as_str())
                .collect::<Vec<_>>(),
            ["not_spam_marked"]
        );
        assert_eq!(explanation.reasons, ["Manually marked as not spam"]);

        let _ = std::fs::remove_dir_all(dir);
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

    #[tokio::test]
    async fn drain_saves_waits_for_a_save_already_holding_the_gate() {
        let dir = temp_dir("drain-gate");
        let hash = "c".repeat(32);
        let filter = std::sync::Arc::new(tokio::sync::RwLock::new(SpamFilter::load(&dir)));
        filter
            .write()
            .await
            .mark_spam(&sample_result(&hash, "gated.bin"), &[], None);

        let gate = SpamFilter::save_gate().lock().await;
        let drain = tokio::spawn({
            let filter = filter.clone();
            async move { SpamFilter::drain_saves(&filter).await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!drain.is_finished());
        assert!(filter.read().await.is_dirty());

        drop(gate);
        drain.await.unwrap().unwrap();
        assert!(!filter.read().await.is_dirty());
        assert!(SpamFilter::load(&dir).db.spam_hashes.contains(&hash));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn similar_name_signature_drops_keywords_and_release_metadata() {
        let out = similar_name_signature(
            "My.Movie-2026[1080p]_X264.Director's.Cut.mkv",
            &["movie".to_string(), "1080p".to_string()],
        );
        assert_eq!(out, "my director s cut");
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
            CommunityRating {
                fake_votes: 4,
                total_votes: 5,
            },
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
            results.push(sized_result(
                &hash,
                "Popular Movie 2026 1080p BluRay.mkv",
                1000 + i,
                &[],
            ));
        }
        let ctx = BatchSpamContext::analyze(&results);
        let dir = temp_dir("relaxed-skip");
        let filter = SpamFilter::load(&dir);

        let batch_score = filter.rate_result(
            &results[0],
            &[],
            None,
            SpamFilterProfile::Relaxed,
            CommunityRating {
                fake_votes: 9,
                total_votes: 10,
            },
            &ctx,
        );
        assert_eq!(
            batch_score, 0,
            "relaxed should ignore batch + community signals"
        );

        // Same inputs under balanced must score (sanity check the gate, not
        // the absence of any DB entries).
        let balanced_score = filter.rate_result(
            &results[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating {
                fake_votes: 9,
                total_votes: 10,
            },
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
            results.push(sized_result(
                &hash,
                "Popular Movie 2026 1080p BluRay.mkv",
                1000 + i,
                &[],
            ));
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
        assert!(
            score >= SPAM_BATCH_NAME_MANY_HASHES_HIT,
            "batch score {score}"
        );
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
        let clean: Vec<SearchResult> = (0..10)
            .map(|i| sample_result(&format!("{i:032x}"), "clean.bin"))
            .collect();
        for _ in 0..60 {
            filter.record_server_clean_batch("9.9.9.9:4242", &clean, SpamFilterProfile::Balanced);
        }
        assert!(!filter.db.spam_server_ips.contains("9.9.9.9"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn two_fake_votes_are_not_enough() {
        let dir = temp_dir("two-fakes");
        let filter = SpamFilter::load(&dir);
        let score = filter.rate_result(
            &sample_result(&"4".repeat(32), "movie.avi"),
            &[],
            None,
            SpamFilterProfile::Aggressive,
            CommunityRating {
                fake_votes: 2,
                total_votes: 2,
            },
            &BatchSpamContext::default(),
        );
        assert!(
            score < SEARCH_SPAM_THRESHOLD_AGGRESSIVE,
            "two sybil fakes scored {score}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// RFC 9637 reserved `3fff::/20` for documentation, and the mask that was
    /// supposed to match it could never be satisfied, so those addresses were
    /// treated as ordinary global unicast and learned as spam sources.
    #[test]
    fn documentation_ipv6_ranges_are_not_globally_routable() {
        for doc in [
            "2001:db8::1",
            "3fff::1",
            "3fff:0fff:ffff:ffff:ffff:ffff:ffff:ffff",
        ] {
            assert!(
                !is_globally_routable_ip(doc),
                "{doc} is documentation space"
            );
        }
        // Just outside the /20, and a plain global address, must still pass.
        for real in ["3fff:1000::1", "2606:4700:4700::1111"] {
            assert!(is_globally_routable_ip(real), "{real} is routable");
        }
    }

    #[test]
    fn unmark_reverses_filename_and_source_learning() {
        let dir = temp_dir("unmark");
        let mut filter = SpamFilter::load(&dir);
        let hash = "5".repeat(32);
        let mut r = sample_result(&hash, "UniqueSpamNameXYZ.bin");
        r.source_addresses = vec![
            "8.8.8.8:4662".to_string(),
            "192.168.1.9:4662".to_string(),
            "100.64.1.1:4662".to_string(),
            "198.18.1.1:4662".to_string(),
        ];
        filter.mark_spam(&r, &[], Some("9.9.9.9"));
        assert!(filter.db.spam_filenames.iter().any(|n| n.contains("uniquespamnamexyz")));
        assert!(filter.db.spam_source_ips.contains("8.8.8.8"));
        assert!(
            !filter.db.spam_source_ips.contains("192.168.1.9"),
            "LAN source must not be learned"
        );
        assert!(
            !filter.db.spam_source_ips.contains("100.64.1.1"),
            "CGNAT source must not be learned"
        );
        assert!(
            !filter.db.spam_source_ips.contains("198.18.1.1"),
            "benchmarking-range source must not be learned"
        );
        filter.mark_not_spam(&hash);
        assert!(!filter.db.spam_hashes.contains(&hash));
        assert!(!filter.db.spam_filenames.iter().any(|n| n.contains("uniquespamnamexyz")));
        assert!(!filter.db.spam_source_ips.contains("8.8.8.8"));
        assert!(
            !filter.db.spam_server_ips.contains("9.9.9.9"),
            "unmark must drop the origin server when no other mark references it"
        );
        assert!(
            !filter.db.udp_server_spam_ratios.contains_key("9.9.9.9"),
            "unmark must drop the origin server ratio when no other mark references it"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn auto_mark_does_not_override_explicit_spam() {
        let dir = temp_dir("auto-skip");
        let mut filter = SpamFilter::load(&dir);
        let hash = "6".repeat(32);
        filter.mark_spam(&sample_result(&hash, "fake.bin"), &[], None);
        filter.auto_mark_not_spam(&hash);
        assert!(filter.db.spam_hashes.contains(&hash));
        assert!(!filter.db.not_spam_hashes.contains(&hash));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn aggressive_similar_name_and_size_do_not_convict() {
        let dir = temp_dir("agg-fp");
        let mut filter = SpamFilter::load(&dir);
        let marked = sized_result(
            &"7".repeat(32),
            "ubuntu-22.04-live-server-amd64.iso",
            2_000_000_000,
            &[],
        );
        filter.mark_spam(&marked, &["ubuntu".to_string()], None);

        let sibling = sized_result(
            &"8".repeat(32),
            "ubuntu-24.04-live-server-amd64.iso",
            2_000_000_000 + 1024,
            &[],
        );
        let score = filter.rate_result(
            &sibling,
            &["ubuntu".to_string()],
            None,
            SpamFilterProfile::Aggressive,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );
        assert!(
            score < SEARCH_SPAM_THRESHOLD_AGGRESSIVE,
            "related ISO scored {score} under aggressive"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn origin_server_ip_on_the_row_trains_server_reputation() {
        let dir = temp_dir("origin-sip");
        let mut filter = SpamFilter::load(&dir);
        let mut r = sample_result(&"9".repeat(32), "junk.bin");
        r.origin_server_ip = Some("93.184.216.34".to_string());
        filter.mark_spam(&r, &[], None);
        assert!(filter.db.spam_server_ips.contains("93.184.216.34"));

        let mut doc = sample_result(&"a".repeat(32), "doc.bin");
        doc.origin_server_ip = Some("203.0.113.10".to_string());
        filter.mark_spam(&doc, &[], None);
        assert!(
            !filter.db.spam_server_ips.contains("203.0.113.10"),
            "IETF documentation-range IPs must not train server reputation"
        );

        let mut bench = sample_result(&"aa".repeat(16), "bench.bin");
        bench.origin_server_ip = Some("198.18.0.1".to_string());
        filter.mark_spam(&bench, &[], None);
        assert!(
            !filter.db.spam_server_ips.contains("198.18.0.1"),
            "benchmarking-range IPs must not train server reputation"
        );

        let mut v6doc = sample_result(&"ab".repeat(16), "v6doc.bin");
        v6doc.origin_server_ip = Some("2001:db8::1".to_string());
        filter.mark_spam(&v6doc, &[], None);
        assert!(
            !filter.db.spam_server_ips.contains("2001:db8::1"),
            "IPv6 documentation-range IPs must not train server reputation"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn three_fake_votes_flag_on_aggressive_not_balanced() {
        let dir = temp_dir("three-fakes");
        let filter = SpamFilter::load(&dir);
        let community = CommunityRating {
            fake_votes: 3,
            total_votes: 3,
        };
        let result = sample_result(&"b".repeat(32), "movie.avi");
        let agg = filter.explain_result(
            &result,
            &[],
            None,
            SpamFilterProfile::Aggressive,
            community,
            &BatchSpamContext::default(),
        );
        assert!(
            agg.is_spam,
            "majority fake should hide on aggressive, score {}",
            agg.score
        );
        let bal = filter.explain_result(
            &result,
            &[],
            None,
            SpamFilterProfile::Balanced,
            community,
            &BatchSpamContext::default(),
        );
        assert!(
            !bal.is_spam,
            "majority fake alone must stay under balanced, score {}",
            bal.score
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn hash_fifo_eviction_reverses_mark_collateral() {
        let dir = temp_dir("orphan-marks");
        let mut filter = SpamFilter::load(&dir);
        let hash = "c".repeat(32);
        filter.mark_spam(&sample_result(&hash, "OrphanNameXYZ.bin"), &[], None);
        assert!(filter.db.spam_filenames.iter().any(|n| n.contains("orphannamexyz")));
        filter.db.spam_hashes.remove(&hash);
        filter.drop_orphaned_marks();
        assert!(!filter.db.spam_filenames.iter().any(|n| n.contains("orphannamexyz")));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn later_packet_upgrades_earlier_same_name_hashes() {
        let poison = "Poisoned Movie Title 2026.mkv";
        let mut ctx = BatchSpamContext::default();
        let first = vec![
            sized_result(&"1".repeat(32), poison, 1000, &[]),
            sized_result(&"2".repeat(32), poison, 1001, &[]),
        ];
        ctx.absorb(&first);
        let prev = ctx.colliding_hashes();
        assert!(prev.is_empty(), "two rows are below the batch stats bar");

        let mut rest = Vec::new();
        for i in 2..8 {
            rest.push(sized_result(&format!("{:032x}", i), poison, 1000 + i as u64, &[]));
        }
        ctx.absorb(&rest);
        let skip: HashSet<String> = rest.iter().map(|r| r.file.hash.clone()).collect();
        let upgrades = ctx.upgrade_rows(&prev, &skip);
        let upgraded: HashSet<_> = upgrades.iter().map(|r| r.file.hash.clone()).collect();
        assert!(upgraded.contains(&"1".repeat(32)));
        assert!(upgraded.contains(&"2".repeat(32)));
        assert!(!upgraded.contains(&format!("{:032x}", 2)));
    }

    /// A file the library holds cannot be fake — the bytes are on disk and hash
    /// to exactly this id. Without the exemption a flood advertising many hashes
    /// under a name that collides with something you share pushed your own copy
    /// over the threshold: your file, hidden from your own search, with the
    /// attacker choosing which one by choosing the name.
    #[test]
    fn a_file_we_already_hold_is_never_batch_spam() {
        let dir = temp_dir("owned-exempt");
        let filter = SpamFilter::load(&dir);
        // One advertised name carried by many hashes, with the URL such names
        // usually carry, and one hash re-advertised under several names. Both
        // collision bars plus the filename pattern — and one of those hashes is
        // a file we are seeding.
        let poison = "www.poison.to Movie Title 2026.mkv";
        let mine = "1".repeat(32);

        let mut rows = vec![
            sized_result(&mine, poison, 1000, &[]),
            sized_result(&mine, "www.poison.to Garden Planner 2026.mkv", 1000, &[]),
            sized_result(&mine, "www.poison.to Ocean Documentary 2026.mkv", 1000, &[]),
            sized_result(&mine, "www.poison.to Jazz Piano 2026.mkv", 1000, &[]),
        ];
        for i in 2..10 {
            rows.push(sized_result(&format!("{i:032x}"), poison, 1000 + i as u64, &[]));
        }

        let plain = BatchSpamContext::analyze(&rows);
        let convicted = filter.explain_result(
            &rows[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &plain,
        );
        assert!(
            convicted.is_spam,
            "the batch really does convict it (score {}); that is what the \
             exemption has to override",
            convicted.score
        );

        let mut owned = BatchSpamContext::analyze(&rows);
        owned.set_owned_hashes([mine.clone()]);
        let verdict = filter.explain_result(
            &rows[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &owned,
        );
        assert_eq!(verdict.score, 0);
        assert!(!verdict.is_spam);
        assert_eq!(verdict.reason_details[0].code, "owned_file");

        // The flood around it is still judged on its own merits — the exemption
        // is per hash, not a licence for the batch it arrived in.
        let neighbour = filter.explain_result(
            &rows[4],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &owned,
        );
        assert!(neighbour.score > 0, "exempting our copy exempted the flood");
        assert!(neighbour
            .reason_details
            .iter()
            .all(|r| r.code != "owned_file"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A re-score after Mark not spam sends rows back one by one, with no batch
    /// to rebuild the collision statistics from, and the UI adopts its verdict
    /// outright — so one unmark cleared every row the batch had flagged. The
    /// marked row clears; its siblings keep what the batch said about them.
    #[test]
    fn a_rescore_keeps_the_batch_signals_rows_were_flagged_with() {
        let dir = temp_dir("carry-batch");
        let mut filter = SpamFilter::load(&dir);
        // Five hashes, each advertised under the same four unrelated titles
        // from one flooding IP: both collision bars and the source bar, which
        // together convict under `balanced` while no single row signal does.
        let names = [
            "Popular Movie 2026 1080p BluRay.mkv",
            "Garden Planner Deluxe.mkv",
            "Ocean Documentary Series.mkv",
            "Jazz Piano Collection.mkv",
        ];
        let hashes: Vec<String> = (0..5).map(|i| format!("{:032x}", i + 1)).collect();
        let mut stream = Vec::new();
        for hash in &hashes {
            for name in names {
                stream.push(sized_result(hash, name, 1000, &["93.184.216.34:4662"]));
            }
        }
        let live = BatchSpamContext::analyze(&stream);
        let mut shown: Vec<SearchResult> = hashes
            .iter()
            .map(|hash| {
                let mut row = sized_result(hash, names[0], 1000, &["93.184.216.34:4662"]);
                let verdict = filter.explain_result(
                    &row,
                    &[],
                    None,
                    SpamFilterProfile::Balanced,
                    CommunityRating::default(),
                    &live,
                );
                assert!(verdict.is_spam, "the stream flags it (score {})", verdict.score);
                row.is_spam = verdict.is_spam;
                row.spam_rating = verdict.score;
                row.spam_reason_details = verdict.reason_details;
                row
            })
            .collect();
        let streamed_score = shown[1].spam_rating;

        filter.mark_not_spam(&hashes[0]);
        let bare = BatchSpamContext::default();
        let uncarried = filter.explain_result(
            &shown[1],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &bare,
        );
        assert!(
            !uncarried.is_spam,
            "without the batch the sibling reads clean, which is what the UI then adopted"
        );

        let mut carried = BatchSpamContext::default();
        carried.carry_batch_signals(&shown);
        let rescore = |row: &SearchResult, profile| {
            filter.explain_result(row, &[], None, profile, CommunityRating::default(), &carried)
        };
        let unmarked = rescore(&shown[0], SpamFilterProfile::Balanced);
        assert!(!unmarked.is_spam, "the row the user unmarked clears");
        assert_eq!(unmarked.reason_details[0].code, "not_spam_marked");
        for row in &shown[1..] {
            let verdict = rescore(row, SpamFilterProfile::Balanced);
            assert!(verdict.is_spam, "a sibling flagged only by the batch was cleared");
            assert_eq!(verdict.score, streamed_score);
            assert!(verdict
                .reason_details
                .iter()
                .any(|r| r.code == "batch_name_many_hashes" && r.count == Some(5)));
        }

        // Carried signals are still network signals.
        assert!(!rescore(&shown[1], SpamFilterProfile::Relaxed).is_spam);

        // And carry nothing for a row that was not flagged by them.
        shown[2].spam_reason_details.clear();
        let mut carried = BatchSpamContext::default();
        carried.carry_batch_signals(&shown[2..3]);
        assert!(!filter
            .explain_result(
                &shown[2],
                &[],
                None,
                SpamFilterProfile::Balanced,
                CommunityRating::default(),
                &carried,
            )
            .is_spam);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The user's own verdict outranks "we have it", exactly as it outranks
    /// `auto_mark_not_spam` on a completed download.
    #[test]
    fn an_explicit_mark_spam_still_wins_over_owning_the_file() {
        let dir = temp_dir("owned-vs-mark");
        let mut filter = SpamFilter::load(&dir);
        let hash = "a".repeat(32);
        let row = sample_result(&hash, "Something I Shared.bin");
        filter.mark_spam(&row, &[], None);

        let owned = BatchSpamContext::for_owned_hashes([hash.clone()]);
        let verdict = filter.explain_result(
            &row,
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &owned,
        );
        assert!(verdict.is_spam, "an explicit mark is the user's answer");
        assert!(verdict.reason_details.iter().any(|r| r.code == "known_hash"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An upgrade is a re-emit of a row the user is already looking at, and
    /// every streamed row is put past `result_matches_client_filters` on the way
    /// out. So a rebuilt row has to answer that filter the same way the row it
    /// replaces did — otherwise narrowing a search to `Video`, to an extension,
    /// or to two-plus sources threw away every upgrade the batch produced, and
    /// the poisoned rows on screen were never flagged.
    #[test]
    fn an_upgraded_row_still_answers_the_searchs_own_filters() {
        let poison = "Poisoned Movie Title 2026.mkv";
        let with_fields = |hash: &str, size: u64| {
            let mut r = sized_result(hash, poison, size, &[]);
            r.file.extension = "mkv".to_string();
            r.file_type = "Video".to_string();
            r.availability = 12;
            r
        };

        let mut ctx = BatchSpamContext::default();
        let first = vec![
            with_fields(&"1".repeat(32), 1000),
            with_fields(&"2".repeat(32), 1001),
        ];
        ctx.absorb(&first);
        let prev = ctx.colliding_hashes();

        let rest: Vec<SearchResult> = (2..8)
            .map(|i| with_fields(&format!("{i:032x}"), 1000 + i as u64))
            .collect();
        ctx.absorb(&rest);
        let skip: HashSet<String> = rest.iter().map(|r| r.file.hash.clone()).collect();

        let upgrades = ctx.upgrade_rows(&prev, &skip);
        assert!(!upgrades.is_empty(), "the collision bar was crossed");
        for row in &upgrades {
            assert_eq!(row.file.extension, "mkv");
            assert_eq!(row.file_type, "Video");
            assert_eq!(row.availability, 12);
            assert!(
                crate::search::merge::result_matches_client_filters(
                    row,
                    Some("Video"),
                    None,
                    None,
                    Some("mkv"),
                    Some(2),
                ),
                "upgrade for {} was dropped by the filter its own row passed",
                row.file.hash
            );
        }
    }

    fn codes(explanation: &SpamExplanation) -> Vec<&str> {
        explanation
            .reason_details
            .iter()
            .map(|r| r.code.as_str())
            .collect()
    }

    fn explain(filter: &SpamFilter, row: &SearchResult, keywords: &[String]) -> SpamExplanation {
        filter.explain_result(
            row,
            keywords,
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        )
    }

    /// Marking a row the connected server returned must not put that server in
    /// `spam_server_ips`: every TCP row it returns lists no sources, and would
    /// carry the server's reputation from then on.
    #[test]
    fn server_reputation_applies_to_udp_rows_only() {
        let dir = temp_dir("udp-only");
        let mut filter = SpamFilter::load(&dir);
        let server = "93.184.216.34";

        let mut tcp_row = sample_result(&"1".repeat(32), "junk one.bin");
        tcp_row.result_origin = crate::search::merge::ORIGIN_SERVER_TCP.to_string();
        tcp_row.origin_server_ip = Some(server.to_string());
        filter.mark_spam(&tcp_row, &[], Some(server));
        assert!(
            !filter.db.spam_server_ips.contains(server),
            "a TCP row must not train the connected server as a spam server"
        );

        let mut udp_row = sample_result(&"2".repeat(32), "junk two.bin");
        udp_row.result_origin = crate::search::merge::ORIGIN_SERVER_UDP.to_string();
        udp_row.origin_server_ip = Some(server.to_string());
        filter.mark_spam(&udp_row, &[], None);
        assert!(filter.db.spam_server_ips.contains(server));

        let mut later_tcp = sample_result(&"3".repeat(32), "honest file.bin");
        later_tcp.result_origin = crate::search::merge::ORIGIN_SERVER_TCP.to_string();
        let verdict = filter.explain_result(
            &later_tcp,
            &[],
            Some(server),
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );
        assert!(
            verdict.reason_details.iter().all(|r| !r.code.starts_with("spam_server")
                && !r.code.starts_with("server_ratio")),
            "TCP rows are not scored against server reputation: {:?}",
            codes(&verdict)
        );

        // A UDP row with no source addresses carries no evidence about its
        // sources: near-hit at most, never the all-sources weight.
        let mut udp_unsourced = sample_result(&"4".repeat(32), "honest file.bin");
        udp_unsourced.result_origin = crate::search::merge::ORIGIN_SERVER_UDP.to_string();
        udp_unsourced.origin_server_ip = Some(server.to_string());
        let verdict = explain(&filter, &udp_unsourced, &[]);
        let server_hit = verdict
            .reason_details
            .iter()
            .find(|r| r.code.starts_with("spam_server"))
            .expect("the UDP row is scored against its server");
        assert_eq!(server_hit.code, "spam_server_influence");
        assert_eq!(server_hit.weight, Some(SPAM_UDPSERVERRES_NEARHIT));

        // All listed sources known spam is still the full hit.
        filter
            .db
            .spam_source_ips
            .insert("8.8.8.8".to_string(), MAX_SPAM_SOURCE_IPS);
        udp_unsourced.source_addresses = vec!["8.8.8.8:4662".to_string()];
        let verdict = explain(&filter, &udp_unsourced, &[]);
        assert!(codes(&verdict).contains(&"spam_server_all_sources"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Server signals land on every row a flagged server returns, so counting
    /// them as "spam" in the redemption tally meant the reputation vouched for
    /// itself and the server was never redeemed.
    #[test]
    fn redemption_ignores_the_servers_own_reputation_signals() {
        let dir = temp_dir("redeem-self");
        let mut filter = SpamFilter::load(&dir);
        let server = "93.184.216.34";
        let mut marked = sample_result(&"5".repeat(32), "junk.bin");
        marked.result_origin = crate::search::merge::ORIGIN_SERVER_UDP.to_string();
        filter.mark_spam(&marked, &[], Some(server));
        filter
            .db
            .udp_server_spam_ratios
            .insert(server.to_string(), 0.9);
        filter
            .db
            .spam_source_ips
            .insert("8.8.8.8".to_string(), MAX_SPAM_SOURCE_IPS);

        let mut rows: Vec<SearchResult> = (0..10)
            .map(|i| {
                let mut r = sized_result(
                    &format!("{:032x}", 100 + i),
                    &format!("honest title {i}.bin"),
                    10_000 + i,
                    &["8.8.8.8:4662"],
                );
                r.result_origin = crate::search::merge::ORIGIN_SERVER_UDP.to_string();
                r.origin_server_ip = Some(server.to_string());
                r
            })
            .collect();
        for row in &mut rows {
            let verdict = explain(&filter, row, &[]);
            assert!(verdict.is_spam, "server signals alone flag it (score {})", verdict.score);
            row.is_spam = verdict.is_spam;
            row.spam_reason_details = verdict.reason_details;
        }
        for _ in 0..60 {
            filter.record_server_clean_batch(server, &rows, SpamFilterProfile::Balanced);
        }
        assert!(!filter.db.spam_server_ips.contains(server));

        // A batch that is spam on its own merits redeems nothing.
        let mut filter = SpamFilter::load(&dir);
        filter.mark_spam(&marked, &[], Some(server));
        for row in &mut rows {
            row.spam_reason_details.push(SpamReason::new(
                SpamReasonCode::KnownHash,
                &[(SpamParam::Weight, SPAM_FILEHASH_HIT)],
            ));
        }
        for _ in 0..60 {
            filter.record_server_clean_batch(server, &rows, SpamFilterProfile::Balanced);
        }
        assert!(filter.db.spam_server_ips.contains(server));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn score_without_server_signals_reapplies_the_aggressive_boost() {
        let reasons = vec![
            SpamReason::new(SpamReasonCode::KnownHash, &[(SpamParam::Weight, 60)]),
            SpamReason::new(SpamReasonCode::SpamServerAllSources, &[(SpamParam::Weight, 30)]),
            SpamReason::new(SpamReasonCode::AggressiveBoost, &[(SpamParam::Weight, 18)]),
        ];
        assert_eq!(score_without_server_signals(&reasons), 72);
    }

    /// An exact learned name is also its own "very similar" name; a genuine
    /// file sharing the name must take only the exact-name weight.
    #[test]
    fn an_exact_name_hit_is_not_scored_again_as_a_similar_name() {
        let dir = temp_dir("exact-not-similar");
        let mut filter = SpamFilter::load(&dir);
        let name = "Distinctive Spam Title Here.avi";
        filter.mark_spam(&sample_result(&"6".repeat(32), name), &[], None);
        let genuine = sized_result(&"7".repeat(32), name, 700_000_000, &[]);
        let verdict = explain(&filter, &genuine, &[]);
        assert_eq!(verdict.score, SPAM_FULLNAME_HIT, "{:?}", codes(&verdict));
        assert!(codes(&verdict).contains(&"exact_filename"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// "1080p mkv" left over after the keywords must not be learned, or it
    /// penalises every unrelated 1080p mkv.
    #[test]
    fn release_metadata_leftovers_are_not_learned_as_similar_names() {
        let dir = temp_dir("stop-list");
        let mut filter = SpamFilter::load(&dir);
        let keywords = vec!["movie".to_string(), "title".to_string()];
        filter.mark_spam(
            &sample_result(&"8".repeat(32), "Movie.Title.2026.1080p.x264.AAC.ENG.mkv"),
            &keywords,
            None,
        );
        assert!(filter.db.spam_similar_names.is_empty(), "{:?}", filter.db.spam_similar_names);
        let unrelated = sample_result(&"9".repeat(32), "Another.Film.2025.1080p.x264.mkv");
        let verdict = explain(&filter, &unrelated, &["another".to_string()]);
        assert!(!codes(&verdict).iter().any(|c| c.contains("similar")), "{:?}", codes(&verdict));

        // A distinctive leftover is learned, without the metadata around it.
        filter.mark_spam(
            &sample_result(&"a".repeat(32), "Movie.Title.FREE.GIFTCARD.1080p.mkv"),
            &keywords,
            None,
        );
        assert_eq!(filter.db.spam_similar_names, vec!["free giftcard".to_string()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn stop_and_distinctive_tokens() {
        for stop in ["1080p", "2160p", "4k", "x265", "hevc", "dts", "webrip", "1999", "2026", "07", "s01e02", "1920x1080", "10bit", "eng", "mkv"] {
            assert!(is_stop_token(stop), "{stop}");
            assert!(!is_distinctive_token(stop), "{stop}");
        }
        for word in ["setup", "intro", "track"] {
            assert!(!is_distinctive_token(word), "{word}");
        }
        for word in ["giftcard", "popular", "东京", "東京物語"] {
            assert!(is_distinctive_token(word), "{word}");
        }
    }

    /// A 79% match listed first must not shadow a 96% match after it: a scan
    /// that stopped at the first candidate over a threshold scored the loose
    /// match (+10) and never saw the very similar one (+30).
    #[test]
    fn the_strongest_similar_name_wins_not_the_first() {
        let dir = temp_dir("best-similar");
        let mut filter = SpamFilter::load(&dir);
        // 5 of 24 characters differ (79%), then 1 of 24 (96%).
        filter.db.spam_similar_names = vec![
            "wxndxrful zxbra crxssxng".to_string(),
            "wonderful zebra crossinx".to_string(),
        ];
        filter.rebuild_similar_name_features();
        let probe = NameFeatures::new("wonderful zebra crossing");
        let mut rows = LevenshteinRows::default();
        let first = similar_name_match(&probe, &filter.similar_name_features[0], &mut rows).unwrap();
        assert_eq!((first.code, as_percent(first.fraction)), (SpamReasonCode::LooselySimilarName, 79));

        let verdict = explain(
            &filter,
            &sample_result(&"b".repeat(32), "wonderful zebra crossing"),
            &[],
        );
        let hit = verdict
            .reason_details
            .iter()
            .find(|r| r.code.contains("similar"))
            .expect("a similar-name reason");
        assert_eq!(hit.code, "very_similar_name");
        assert_eq!((hit.percent, hit.weight), (Some(96), Some(SPAM_SIMILARNAME_HIT)));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn bounded_levenshtein_agrees_with_strsim() {
        let words = [
            "", "a", "ab", "abc", "kitten", "sitting", "free movie hd", "hd movie free",
            "wonderful zebra crossing", "wonderfal zebre crossung", "東京物語 特別版", "東京物語",
            "spam title here", "spam title hera", "completely different",
        ];
        for a in words {
            for b in words {
                let ac: Vec<char> = a.chars().collect();
                let bc: Vec<char> = b.chars().collect();
                let exact = strsim::levenshtein(a, b);
                let mut rows = LevenshteinRows::default();
                for max in 0..=exact + 2 {
                    let got = levenshtein_within(&ac, &bc, max, &mut rows);
                    let want = (exact <= max).then_some(exact);
                    assert_eq!(got, want, "{a:?} vs {b:?} within {max}");
                }
                let mut sa = ac.clone();
                sa.sort_unstable();
                let mut sb = bc.clone();
                sb.sort_unstable();
                assert!(multiset_distance_bound(&sa, &sb) <= exact, "{a:?} vs {b:?}");
            }
        }
    }

    /// The prefilters may skip work, never change a score.
    #[test]
    fn prefiltered_similar_name_scores_match_the_unfiltered_ones() {
        let names = [
            "wonderful zebra crossing", "wonderfal zebre crossung", "zebra crossing wonderful",
            "wonderful zebra", "spam title here", "spam title hera", "free giftcard now",
            "giftcard free now", "東京物語 特別版", "東京物語 特別", "completely different words",
        ];
        let naive = |probe: &str, cand: &str| -> Option<(SpamReasonCode, u32)> {
            let (a, b) = (probe.chars().count(), cand.chars().count());
            let m = a.max(b);
            let length_ok = m > 0 && (a.abs_diff(b) as f64) / (m as f64) < 0.30;
            let sim = if length_ok { strsim::normalized_levenshtein(probe, cand) } else { 0.0 };
            if sim > 0.95 {
                Some((SpamReasonCode::VerySimilarName, as_percent(sim)))
            } else if sim > 0.85 {
                Some((SpamReasonCode::SimilarName, as_percent(sim)))
            } else {
                let jac = jaccard(&token_set(probe), &token_set(cand));
                if jac >= SIMILAR_NAME_JACCARD_HIT {
                    Some((SpamReasonCode::ReorderedName, as_percent(jac)))
                } else if sim > 0.70 {
                    Some((SpamReasonCode::LooselySimilarName, as_percent(sim)))
                } else {
                    None
                }
            }
        };
        let mut rows = LevenshteinRows::default();
        for probe in names {
            for cand in names {
                let got = similar_name_match(&NameFeatures::new(probe), &NameFeatures::new(cand), &mut rows)
                    .map(|m| (m.code, as_percent(m.fraction)));
                assert_eq!(got, naive(probe, cand), "{probe:?} vs {cand:?}");
            }
        }
    }

    /// A corrupt file is not "no data": it is moved aside before the next save
    /// could replace it with an almost empty database.
    #[test]
    fn a_corrupt_file_is_quarantined_not_overwritten() {
        let dir = temp_dir("corrupt");
        let path = dir.join("search_spam.json");
        std::fs::write(&path, b"{ this is not json").unwrap();
        let mut filter = SpamFilter::load(&dir);
        assert_eq!(filter.stats().spam_hashes, 0);
        assert!(!path.exists(), "the corrupt file was moved aside");
        let quarantined: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("search_spam.json.") && n.ends_with(".corrupt"))
            .collect();
        assert_eq!(quarantined.len(), 1, "{quarantined:?}");
        assert_eq!(
            std::fs::read(dir.join(&quarantined[0])).unwrap(),
            b"{ this is not json"
        );
        // Saving goes ahead: the original is safe beside it.
        filter.auto_mark_not_spam(&"c".repeat(32));
        assert!(filter.take_save_data().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    fn saved_database(hashes: &[&str]) -> Vec<u8> {
        let dir = temp_dir("saved-db");
        let mut source = SpamFilter::load(&dir);
        for hash in hashes {
            source.mark_spam(&sample_result(hash, &format!("{hash} name.bin")), &[], None);
        }
        let (data, _, _) = source.take_save_data().unwrap();
        let _ = std::fs::remove_dir_all(dir);
        data.into_bytes()
    }

    fn files_ending(dir: &Path, suffix: &str) -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.to_string_lossy().ends_with(suffix))
            .collect()
    }

    /// A file that exists but cannot be read is not "no data". Nothing saves
    /// over it — not a background change, and not a deliberate one while it
    /// can neither be read nor copied. Once it reads again, it becomes the
    /// database with every change this session made folded in.
    #[test]
    fn an_unreadable_file_is_merged_not_overwritten_once_it_reads_again() {
        let dir = temp_dir("unreadable");
        let path = dir.join("search_spam.json");
        // A directory where the file should be: exists, cannot be read or copied.
        std::fs::create_dir_all(&path).unwrap();
        let mut filter = SpamFilter::load(&dir);
        let auto = "d".repeat(32);
        filter.auto_mark_not_spam(&auto);
        assert!(!filter.is_dirty());
        assert!(filter.take_save_data().is_none());

        let held = "e".repeat(32);
        filter.mark_spam(&sample_result(&held, "held choice.bin"), &[], None);
        assert!(filter.db.spam_hashes.contains(&held), "the change applies in memory");
        assert!(filter.take_save_data().is_none(), "still unreadable: nothing may replace it");

        // Whatever held it is gone, and the user's data is there to read.
        std::fs::remove_dir(&path).unwrap();
        let on_disk = "f".repeat(32);
        std::fs::write(&path, saved_database(&[&on_disk])).unwrap();

        let now = "1".repeat(32);
        filter.mark_not_spam(&now);
        assert!(filter.db.spam_hashes.contains(&on_disk), "the file's data is kept");
        assert!(filter.db.spam_hashes.contains(&held), "the held change is re-applied");
        assert!(filter.db.not_spam_hashes.contains(&auto), "background learning is kept");
        assert!(filter.db.not_spam_hashes.contains(&now));
        assert!(filter.take_save_data().is_some(), "saving resumes");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_oversized_file_is_quarantined() {
        let dir = temp_dir("oversized");
        let path = dir.join("search_spam.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(LOAD_MAX_FILE_BYTES + 1)
            .unwrap();
        let mut filter = SpamFilter::load(&dir);
        assert!(!path.exists());
        let moved = files_ending(&dir, ".corrupt");
        assert_eq!(moved.len(), 1);
        assert_eq!(std::fs::metadata(&moved[0]).unwrap().len(), LOAD_MAX_FILE_BYTES + 1);
        filter.auto_mark_not_spam(&"2".repeat(32));
        assert!(filter.take_save_data().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Another process holding the corrupt file (no delete sharing) cannot
    /// stop the quarantine: a copy preserves it, saving goes ahead, and the
    /// next start reuses that copy instead of making another.
    #[cfg(windows)]
    #[test]
    fn a_corrupt_file_that_cannot_be_moved_is_quarantined_by_copy() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = temp_dir("corrupt-held");
        let path = dir.join("search_spam.json");
        std::fs::write(&path, b"{ not json").unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .unwrap();

        let mut filter = SpamFilter::load(&dir);
        filter.auto_mark_not_spam(&"3".repeat(32));
        assert!(filter.take_save_data().is_some(), "a copy is a quarantine");
        let copies = files_ending(&dir, ".corrupt");
        assert_eq!(copies.len(), 1);
        assert_eq!(std::fs::read(&copies[0]).unwrap(), b"{ not json");

        let _ = SpamFilter::load(&dir);
        assert_eq!(files_ending(&dir, ".corrupt").len(), 1, "no second copy");
        drop(holder);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file that can be neither moved nor read (held exclusively, and too
    /// large to be a real database) cannot be quarantined: saving is held.
    #[cfg(windows)]
    #[test]
    fn a_file_that_cannot_be_quarantined_holds_saving() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = temp_dir("corrupt-locked");
        let path = dir.join("search_spam.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(LOAD_MAX_FILE_BYTES + 1)
            .unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&path)
            .unwrap();

        let mut filter = SpamFilter::load(&dir);
        filter.auto_mark_not_spam(&"4".repeat(32));
        assert!(filter.take_save_data().is_none());
        filter.mark_spam(&sample_result(&"5".repeat(32), "while locked.bin"), &[], None);
        assert!(filter.take_save_data().is_none(), "still neither movable nor readable");
        assert!(files_ending(&dir, ".corrupt").is_empty());

        drop(holder);
        filter.mark_spam(&sample_result(&"6".repeat(32), "after unlock.bin"), &[], None);
        assert!(!path.exists());
        assert_eq!(files_ending(&dir, ".corrupt").len(), 1);
        assert!(filter.take_save_data().is_some());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// An interrupted save whose backup could not be restored is the user's
    /// data, not a first run: it is read and merged before anything replaces
    /// it.
    #[cfg(windows)]
    #[test]
    fn a_parked_backup_that_cannot_be_restored_is_merged_before_saving() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = temp_dir("parked-held");
        let parked = dir.join("search_spam.json.ember-replace-bak");
        let parked_hash = "7".repeat(32);
        std::fs::write(&parked, saved_database(&[&parked_hash])).unwrap();
        let holder = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&parked)
            .unwrap();

        let mut filter = SpamFilter::load(&dir);
        assert!(!filter.db.spam_hashes.contains(&parked_hash));
        filter.auto_mark_not_spam(&"8".repeat(32));
        assert!(filter.take_save_data().is_none());

        let mine = "9".repeat(32);
        filter.mark_spam(&sample_result(&mine, "mine.bin"), &[], None);
        assert!(filter.db.spam_hashes.contains(&parked_hash));
        assert!(filter.db.spam_hashes.contains(&mine));
        assert!(filter.take_save_data().is_some());
        drop(holder);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_interrupted_save_is_recovered_before_loading() {
        let dir = temp_dir("interrupted");
        let hash = "f".repeat(32);
        let mut source = SpamFilter::load(&dir);
        source.mark_spam(&sample_result(&hash, "parked.bin"), &[], None);
        let (data, _, _) = source.take_save_data().unwrap();
        std::fs::write(dir.join("search_spam.json.ember-replace-bak"), data).unwrap();

        let filter = SpamFilter::load(&dir);
        assert!(filter.db.spam_hashes.contains(&hash));
        assert!(dir.join("search_spam.json").exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Data an older build saved — old separators, no NFKC, metadata left in
    /// similar names — still loads and still matches.
    #[test]
    fn a_database_from_an_older_build_still_loads_and_matches() {
        let dir = temp_dir("legacy");
        let hash = "1a".repeat(16);
        let legacy = serde_json::json!({
            "spam_hashes": [hash],
            "not_spam_hashes": [],
            "spam_filenames": ["ac/dc+live mkv"],
            "spam_similar_names": ["free giftcard 1080p mkv", "2026 x264 mkv"],
            "spam_sizes": [1234],
            "spam_source_ips": ["8.8.8.8"],
            "spam_server_ips": [],
            "udp_server_spam_ratios": {},
            "spam_marks": [{
                "hash": hash,
                "filename": "ac/dc+live mkv",
                "similar_name": "free giftcard 1080p mkv",
                "size": 1234,
                "source_ips": ["8.8.8.8"],
                "server_ip": null
            }]
        });
        std::fs::write(dir.join("search_spam.json"), legacy.to_string()).unwrap();
        let mut filter = SpamFilter::load(&dir);
        assert_eq!(filter.db.spam_filenames, vec!["ac dc live mkv".to_string()]);
        assert_eq!(filter.db.spam_similar_names, vec!["free giftcard".to_string()]);

        let verdict = explain(&filter, &sample_result(&"2b".repeat(16), "AC-DC Live.mkv"), &[]);
        assert!(codes(&verdict).contains(&"exact_filename"), "{:?}", codes(&verdict));
        let verdict = explain(
            &filter,
            &sample_result(&"3c".repeat(16), "Free Giftcard 720p.avi"),
            &[],
        );
        assert!(codes(&verdict).contains(&"very_similar_name"), "{:?}", codes(&verdict));

        // The mark still reverses what it learned.
        filter.mark_not_spam(&hash);
        assert!(filter.db.spam_filenames.is_empty());
        assert!(filter.db.spam_similar_names.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Re-sighted rows are dropped before scoring, but their names are what
    /// "same file, many names" counts, so they still reach the context.
    #[test]
    fn resighted_names_complete_a_many_names_collision_and_upgrade_the_row() {
        let mut ctx = BatchSpamContext::default();
        let target = "1".repeat(32);
        let mut first = vec![sized_result(&target, "Original Name Alpha.mkv", 1000, &[])];
        for i in 2..10 {
            first.push(sized_result(&format!("{i:032x}"), &format!("Unrelated Title {i}.mkv"), 1000, &[]));
        }
        ctx.absorb(&first);
        assert!(ctx.colliding_hashes().is_empty());

        ctx.note_resighted(&[
            sized_result(&target, "Garden Planner Deluxe.mkv", 1000, &[]),
            sized_result(&target, "Ocean Documentary Series.mkv", 1000, &[]),
            sized_result(&target, "Jazz Piano Collection.mkv", 1000, &[]),
        ]);
        assert!(ctx.has_pending_resights());
        let prev = ctx.colliding_hashes();
        assert!(prev.is_empty(), "queued names are not counted before absorb");
        ctx.absorb(&[]);
        assert!(!ctx.has_pending_resights());
        let upgrades = ctx.upgrade_rows(&prev, &HashSet::new());
        assert_eq!(upgrades.len(), 1);
        assert_eq!(upgrades[0].file.hash, target);
        assert_eq!(ctx.result_count, 9, "a re-sighting is not another result");
    }

    /// "Setup.exe" and "01 - Intro.mp3" are carried by countless unrelated
    /// files; many hashes sharing them is not poisoning.
    #[test]
    fn generic_names_shared_by_many_hashes_are_not_a_collision() {
        for generic in ["Setup.exe", "01 - Intro.mp3", "Track 01 1080p.mkv"] {
            let rows: Vec<SearchResult> = (0..10)
                .map(|i| sized_result(&format!("{i:032x}"), generic, 1000 + i, &[]))
                .collect();
            let ctx = BatchSpamContext::analyze(&rows);
            assert!(ctx.colliding_hashes().is_empty(), "{generic} collided");
        }
        // Four hashes on a specific name is still below the bar.
        let rows: Vec<SearchResult> = (0..8)
            .map(|i| {
                let name = if i < 4 { "Popular Movie 2026.mkv".to_string() } else { format!("Other {i}.mkv") };
                sized_result(&format!("{i:032x}"), &name, 1000 + i, &[])
            })
            .collect();
        assert!(BatchSpamContext::analyze(&rows).colliding_hashes().is_empty());
    }

    #[test]
    fn one_fake_voter_cannot_raise_the_community_signal() {
        let dir = temp_dir("one-voter");
        let filter = SpamFilter::load(&dir);
        let verdict = filter.explain_result(
            &sample_result(&"4d".repeat(16), "movie.avi"),
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating {
                fake_votes: 1,
                total_votes: 3,
            },
            &BatchSpamContext::default(),
        );
        assert!(
            verdict.reason_details.iter().all(|r| !r.code.starts_with("community")),
            "{:?}",
            codes(&verdict)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unicode_names_normalize_before_comparison() {
        // Zero-width characters, soft hyphens and variation selectors vanish.
        assert_eq!(
            normalize_filename("Sp\u{200B}am\u{00AD}Na\u{FE0F}me\u{FEFF}.avi"),
            "spamname avi"
        );
        // NFKC: full-width forms and ligatures.
        assert_eq!(normalize_filename("ＳＰＡＭ　ﬁle．ａｖｉ"), "spam file avi");
        // CJK punctuation separates words.
        assert_eq!(
            normalize_filename("東京物語「特別版」【1080p】・完全版.mkv"),
            "東京物語 特別版 1080p 完全版 mkv"
        );
        // Cyrillic and Greek look-alikes, either case.
        assert_eq!(canonical_lower("РАУРАL Ѕеtuр"), "paypal setup");
        assert_eq!(canonical_lower("ΑΒΕΚΜΟΡΤΧ"), "abekmoptx");
        assert_eq!(canonical_lower("Mоvie"), "movie");
    }

    #[test]
    fn evasion_by_invisible_characters_and_homoglyphs_still_matches() {
        let dir = temp_dir("unicode-evasion");
        let mut filter = SpamFilter::load(&dir);
        filter.mark_spam(&sample_result(&"5e".repeat(16), "Free Giftcard Generator.exe"), &[], None);
        let disguised = "Frее\u{200D} Gіftсаrd Gеnеrаtоr.exe";
        let verdict = explain(&filter, &sample_result(&"6f".repeat(16), disguised), &[]);
        assert!(codes(&verdict).contains(&"exact_filename"), "{:?}", codes(&verdict));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Thresholds count characters. "映画映画.avi" is 8 characters but 16
    /// bytes, so a byte count puts it over the small-name bar (10) and its
    /// 4-character signature over the learnable minimum (6).
    #[test]
    fn length_thresholds_count_characters_not_bytes() {
        let name = "映画映画.avi";
        assert!(name.chars().count() < SMALL_FILENAME_LEN && name.len() >= SMALL_FILENAME_LEN);
        let dir = temp_dir("char-thresholds");
        let mut filter = SpamFilter::load(&dir);
        filter.mark_spam(&sample_result(&"7a".repeat(16), name), &[], None);
        assert!(filter.db.spam_similar_names.is_empty(), "four characters is too short to learn");
        let verdict = explain(&filter, &sample_result(&"8b".repeat(16), name), &[]);
        let exact = verdict
            .reason_details
            .iter()
            .find(|r| r.code == "exact_filename")
            .expect("exact match");
        assert_eq!(exact.weight, Some(SPAM_SMALLFULLNAME_HIT));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Popular files are seen under many release names. Release tags,
    /// containers and years are not a different name, and neither is a
    /// release group's tag on the same title.
    #[test]
    fn release_name_variants_of_one_title_are_not_many_names() {
        let hash = "c1".repeat(16);
        let variants = [
            "Inception.2010.DVDRip.XviD-GRP.avi",
            "Inception 2010",
            "Inception (2010) [1080p] [YTS].mp4",
            "Inception.2010.720p.BluRay.x264-SPARKS.mkv",
            "inception.2010.mkv",
            "Inception 2010 1080p BluRay x265 HEVC 10bit AAC 5.1-RARBG.mkv",
            "Inception [2010] ENG SUBS.mkv",
        ];
        let mut rows: Vec<SearchResult> = variants
            .iter()
            .map(|name| sized_result(&hash, name, 1_500_000_000, &[]))
            .collect();
        for i in 0..8 {
            rows.push(sized_result(&format!("{i:032x}"), &format!("Unrelated Title {i}.mkv"), 1000, &[]));
        }
        let ctx = BatchSpamContext::analyze(&rows);
        assert!(!ctx.hash_collision(&hash), "{} names", ctx.hash_name_count(&hash));
        assert!(ctx.colliding_hashes().is_empty());
    }

    /// One hash advertised as unrelated titles — even ones that all carry the
    /// search keyword — is the poisoning the signal exists for.
    #[test]
    fn one_hash_under_unrelated_titles_is_many_names() {
        let hash = "c2".repeat(16);
        let titles = [
            "Matrix Crack Keygen.exe",
            "Matrix Free Movie Download.avi",
            "Matrix Soundtrack Album.mp3",
            "Matrix Game Trainer.zip",
        ];
        let mut rows: Vec<SearchResult> = titles
            .iter()
            .map(|name| sized_result(&hash, name, 700_000, &[]))
            .collect();
        for i in 0..8 {
            rows.push(sized_result(&format!("{i:032x}"), &format!("Unrelated Title {i}.mkv"), 1000, &[]));
        }
        let ctx = BatchSpamContext::analyze(&rows);
        assert!(ctx.hash_collision(&hash));
        let dir = temp_dir("many-names");
        let filter = SpamFilter::load(&dir);
        let verdict = filter.explain_result(
            &rows[0],
            &[],
            None,
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &ctx,
        );
        let reason = verdict
            .reason_details
            .iter()
            .find(|r| r.code == "batch_hash_many_names")
            .expect("many-names reason");
        assert_eq!(reason.count, Some(4));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A re-score carries batch reasons only where today's bars would raise
    /// them: an older row flagged at three names, or for a generic name, is
    /// not re-flagged on the strength of that reason.
    #[test]
    fn carried_batch_signals_are_held_to_the_current_bars() {
        let flagged = |hash: &str, name: &str, code: SpamReasonCode, count: u32| {
            let mut row = sample_result(hash, name);
            row.spam_reason_details = vec![SpamReason::new(
                code,
                &[(SpamParam::Count, count), (SpamParam::Weight, 25)],
            )];
            row
        };
        let rows = vec![
            flagged(&"d1".repeat(16), "Popular Movie 2026.mkv", SpamReasonCode::BatchNameManyHashes, 3),
            flagged(&"d2".repeat(16), "Setup.exe", SpamReasonCode::BatchNameManyHashes, 9),
            flagged(&"d3".repeat(16), "Popular Movie 2026.mkv", SpamReasonCode::BatchNameManyHashes, 5),
            flagged(&"d4".repeat(16), "Anything.bin", SpamReasonCode::BatchHashManyNames, 3),
            flagged(&"d5".repeat(16), "Anything.bin", SpamReasonCode::BatchHashManyNames, 4),
        ];
        let mut ctx = BatchSpamContext::default();
        ctx.carry_batch_signals(&rows);
        let carried: Vec<bool> = rows
            .iter()
            .map(|r| ctx.carried.contains_key(&normalize_hash(&r.file.hash)))
            .collect();
        assert_eq!(carried, [false, false, true, false, true]);
    }

    /// The UDP server a row arrived from owns it. Re-scored alongside a later
    /// packet from another server, it is still judged by its own server.
    #[test]
    fn a_rows_own_server_wins_over_the_packet_it_is_rescored_with() {
        let dir = temp_dir("own-server");
        let mut filter = SpamFilter::load(&dir);
        filter
            .db
            .spam_server_ips
            .insert("93.184.216.34".to_string(), MAX_SPAM_SERVER_IPS);
        let mut row = sample_result(&"e1".repeat(16), "earlier row.bin");
        row.result_origin = crate::search::merge::ORIGIN_SERVER_UDP.to_string();
        row.origin_server_ip = Some("198.51.100.20".to_string());
        let verdict = filter.explain_result(
            &row,
            &[],
            Some("93.184.216.34"),
            SpamFilterProfile::Balanced,
            CommunityRating::default(),
            &BatchSpamContext::default(),
        );
        assert!(
            verdict.reason_details.iter().all(|r| !r.code.starts_with("spam_server")),
            "{:?}",
            codes(&verdict)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Both cases of a Greek or Cyrillic look-alike fold to the same Latin
    /// letter, so a name typed in capitals and one in lowercase still match.
    #[test]
    fn both_cases_of_a_look_alike_fold_the_same() {
        for (upper, lower) in [
            ('Η', 'η'), ('Μ', 'μ'), ('Ν', 'ν'), ('Υ', 'υ'), ('Ζ', 'ζ'), ('Ι', 'ι'),
            ('Α', 'α'), ('Ρ', 'ρ'), ('Χ', 'χ'), ('Н', 'н'), ('В', 'в'), ('Ѕ', 'ѕ'),
            ('Ӏ', 'ӏ'), ('Ү', 'ү'), ('Ԛ', 'ԛ'), ('Ϳ', 'ϳ'), ('Ϲ', 'ϲ'),
        ] {
            let (u, l) = (canonical_lower(&upper.to_string()), canonical_lower(&lower.to_string()));
            assert_eq!(u, l, "{upper} and {lower}");
            assert!(u.is_ascii(), "{upper} folds to Latin, got {u}");
        }
        assert_eq!(canonical_lower("ΗΟΤΕΛ"), canonical_lower("ηοτελ"));
        // Lunate sigma survives NFKC as `c`.
        assert_eq!(canonical_lower("ϹODEϲ"), "codec");
        // Pairs that pass for Latin in one case only are left alone.
        for keep in ['γ', 'ω', 'Γ', 'Ω'] {
            assert!(!canonical_lower(&keep.to_string()).is_ascii(), "{keep}");
        }
    }

    #[test]
    fn unicode_punctuation_separates_words() {
        assert_eq!(normalize_filename("Title—Subtitle"), "title subtitle");
        assert_eq!(normalize_filename("“Quoted” • Name…Here"), "quoted name here");
        assert_eq!(normalize_filename("«Titre» ¿Qué? ¡Sí!"), "titre qué sí");
        assert_eq!(normalize_filename("映画〈特別〉〜完全版〜"), "映画 特別 完全版");
        // Letters inside the CJK punctuation block stay inside their word.
        assert_eq!(normalize_filename("人々の〇〇"), "人々の〇〇");
    }
}
