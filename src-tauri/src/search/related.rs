//! "Find related files" — turning one file the user pointed at into the search
//! that finds the *rest* of what they want.
//!
//! eMule has this feature as `Search Related Files`: it sends the literal
//! string `related::<md4>` to the connected eD2k server, and the server — which
//! knows every client's whole shared list — answers with files that tend to be
//! shared alongside that hash. Two things make that unsatisfying in practice:
//!
//! 1. It only works on a server advertising `SRV_TCPFLG_RELATEDSEARCH`, and the
//!    seed file has to be shared by at least ~5 clients on it. Off such a
//!    server eMule simply greys the menu item out, so the feature does nothing
//!    at all most of the time.
//! 2. Server co-share data answers "what do people who have this also have",
//!    which is *not* the question a user asks when they right-click episode 2
//!    of a series. They want episodes 1 and 3.
//!
//! So this module keeps the eD2k co-share request (it is genuinely good data
//! when it is available — see [`co_share_term`]) but treats it as one signal
//! among several, and adds the signal eMule never had: reading the filename.
//! Release names are highly structured — `Title.S01E02.1080p.WEB-DL.x264-GRP`
//! — so [`analyze`] can recover the title, the series/episode marker, the
//! disc/part marker and the year, and [`plan`] can turn those into probes that
//! find the other episodes, the other discs, or other releases of the same
//! title. Those work on every network, with no server support and no protocol
//! change.
//!
//! The output of [`plan`] is deliberately just *a query string plus some
//! hashes*: it feeds the ordinary search pipeline
//! (`NetworkCommand::SearchFiles`), so a related search gets result streaming,
//! spam scoring, dedup, cancellation and tabs for free, and each network does
//! what it is best at within one request — capable eD2k servers get the native
//! co-share request, Kad/Ember/local get the derived keyword query.

use std::sync::LazyLock;

use regex::Regex;

/// Upper bound on derived keyword probes. Each extra probe is another `OR`
/// branch, and Kad can only ever look up *one* keyword hash per search
/// (eMule's design), so a long OR chain buys progressively less while making
/// the query harder for a server to answer usefully.
const MAX_PROBES: usize = 3;

/// Upper bound on seed hashes in one native co-share request. eMule has sent
/// several since eserver 17.14, but the request is one string term on the wire
/// and servers reject over-long expressions, so this stays conservative.
const MAX_CO_SHARE_HASHES: usize = 8;

/// Shortest derived title we will search for. Below this the query is noise
/// (and the eD2k tokenizer drops sub-3-byte words anyway).
const MIN_TITLE_LEN: usize = 3;

/// Why a related search believes a file is related to the seed.
///
/// Serialized in the plan so the UI can label the search and explain itself;
/// the frontend owns the localized wording, this is only the discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    /// Files the network reports as commonly shared *alongside* the seed.
    /// eMule's original signal; needs a `SRV_TCPFLG_RELATEDSEARCH` server.
    CoShare,
    /// Other episodes of the same series (seed had a season/episode marker).
    Series,
    /// Other tracks from the same artist/album (from media metadata).
    Album,
    /// Other discs/parts of the same multi-part set (`CD2`, `Part 3`, ...).
    Volume,
    /// Other releases of the same title (different rip, quality, language).
    Title,
}

impl RelationKind {
    /// Ranking among probes: a lower number is a more specific claim about why
    /// the results are related, and wins when two probes derive the same query.
    fn priority(self) -> u8 {
        match self {
            RelationKind::CoShare => 0,
            RelationKind::Series => 1,
            RelationKind::Album => 2,
            RelationKind::Volume => 3,
            RelationKind::Title => 4,
        }
    }
}

/// A season/episode marker recovered from a filename.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeriesMarker {
    pub season: Option<u32>,
    pub episode: u32,
}

/// A disc/part marker recovered from a filename (`CD1`, `Part 2`, `Vol 3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeMarker {
    pub number: u32,
}

/// What [`analyze`] recovered from a filename.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameAnalysis {
    /// Filename with the extension removed.
    pub stem: String,
    /// Lowercased extension without the dot, empty when there is none.
    pub extension: String,
    pub series: Option<SeriesMarker>,
    pub volume: Option<VolumeMarker>,
    pub year: Option<u16>,
    /// The title with release metadata removed: bracketed segments dropped,
    /// separators normalized to spaces, everything from the first release
    /// marker onward cut, and any surviving noise words removed. Lowercased,
    /// space-collapsed, possibly empty.
    pub title: String,
}

/// One signal a related search will actually use.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelatedProbe {
    pub kind: RelationKind,
    /// The query this signal contributes, in the ordinary user-facing search
    /// grammar ([`crate::search::query::parse`]).
    ///
    /// `None` for [`RelationKind::CoShare`], which is not a keyword search at
    /// all — it rides on [`RelatedPlan::co_share_hashes`] and is answered by the
    /// server from its own index. Keeping it in the same list lets the UI
    /// explain every signal in one place.
    pub query: Option<String>,
}

/// The full plan for one related search.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelatedPlan {
    /// Combined keyword query to run on every network, or `None` when the
    /// filename yielded nothing searchable (then only [`Self::co_share_hashes`]
    /// can produce results).
    pub query: Option<String>,
    /// Every signal this search uses, in priority order — for explaining the
    /// search in the UI.
    pub probes: Vec<RelatedProbe>,
    /// Seed hashes (lowercase hex) for the native eD2k co-share request. Empty
    /// when no seed had a usable hash, or when the connected server cannot
    /// answer a co-share request — there is no point sending hashes a server
    /// will read as a filename substring.
    pub co_share_hashes: Vec<String>,
    /// Seed hashes to hide from the results: a file is not related to itself.
    pub exclude_hashes: Vec<String>,
    /// Display name for the search tab (the seed filename, or a joined list).
    pub seed_label: String,
}

impl RelatedPlan {
    /// True when this plan cannot produce any results and should not be run.
    pub fn is_empty(&self) -> bool {
        self.query.is_none() && self.co_share_hashes.is_empty()
    }
}

/// A file the user pointed at, as much of it as the caller knows.
#[derive(Debug, Clone, Default)]
pub struct SeedFile {
    /// eD2k MD4 hash, lowercase hex. Empty when unknown.
    pub hash: String,
    pub name: String,
    pub artist: Option<String>,
    pub album: Option<String>,
}

// Markers are matched on the raw stem, where the original separators still
// disambiguate (`S01E02`, `S01 E02`, `1x02`, `- 2019 -`).
static RE_SERIES_SE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bs(\d{1,2})[\s._-]?e(\d{1,3})\b").unwrap());
static RE_SERIES_X: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:^|[\s._-])(\d{1,2})x(\d{2,3})(?:$|[\s._-])").unwrap());
static RE_SERIES_WORDY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bseason[\s._-]*(\d{1,2})[\s._-]*(?:episode|ep)[\s._-]*(\d{1,3})\b").unwrap()
});
static RE_SERIES_EP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\bep(?:isode)?[\s._-]?(\d{1,3})\b").unwrap());
static RE_VOLUME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:cd|disc|disk|part|pt|vol|volume)[\s._-]*(\d{1,3})\b").unwrap()
});
/// A bracketed segment: `[Group]`, `(2019)`, `{CRC}`. In release names these
/// are essentially always metadata, so they are dropped wholesale.
static RE_BRACKETED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\[[^\]]*\]|\([^)]*\)|\{[^}]*\}").unwrap());
/// Channel-layout / dotted-codec tokens (`5.1`, `7.1`, `2.0`, `h.264`) that the
/// separator pass would otherwise split into meaningless digit words.
static RE_DOTTED_AUDIO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:dd[p+]?|dts|ac3|eac3|h)?\s?\d\.\d\b").unwrap());

/// Tokens that mark the start of release metadata. Hitting one of these means
/// the title has ended.
///
/// Every entry has to be a word that effectively never appears in a real title,
/// because one false positive here truncates the title and the related search
/// looks for the wrong thing. Words that are only *usually* noise (language
/// tags, tracker names) go in [`WEAK_NOISE_TOKENS`] instead, and multi-token
/// markers like `Part 2` are handled by [`boundary_at`].
const BOUNDARY_TOKENS: &[&str] = &[
    // Resolution / dynamic range
    "480p",
    "576p",
    "720p",
    "1080p",
    "1080i",
    "1440p",
    "2160p",
    "4320p",
    "4k",
    "8k",
    "uhd",
    "hdr",
    "hdr10",
    "sdr",
    // Source
    "bluray",
    "bdrip",
    "brrip",
    "bdremux",
    "remux",
    "webrip",
    "webdl",
    "hdtv",
    "pdtv",
    "dvdrip",
    "dvdscr",
    "dvdr",
    "dvd5",
    "dvd9",
    "hdrip",
    "hdcam",
    "hdts",
    "camrip",
    "telesync",
    "telecine",
    "screener",
    "vhsrip",
    "satrip",
    "tvrip",
    "workprint",
    // Codec / encode
    "x264",
    "x265",
    "h264",
    "h265",
    "hevc",
    "xvid",
    "divx",
    "av1",
    "vp9",
    "mpeg2",
    "10bit",
    "10bits",
    "8bit",
    "hi10p",
    // Audio
    "aac",
    "ac3",
    "eac3",
    "dts",
    "dtshd",
    "truehd",
    "atmos",
    "flac",
    "opus",
    "ddp",
    // Edition / status flags
    "repack",
    "proper",
    "rerip",
    "readnfo",
    "internal",
    "limited",
    "unrated",
    "uncut",
    "remastered",
    "imax",
    "dubbed",
    "subbed",
    "multisub",
    "vostfr",
    "truefrench",
];

/// Tokens that are noise wherever they appear, but too weak to end a title —
/// a film really can be called "The Trust" or "Multi". These are removed from
/// the title without truncating at them.
const WEAK_NOISE_TOKENS: &[&str] = &[
    "www", "com", "net", "org", "info", "torrent", "rarbg", "yts", "yify", "ettv", "eztv", "nzb",
    "ita", "eng", "spa", "ger", "fre", "rus", "jpn", "kor", "chi", "por", "pol", "sub", "subs",
    "hardsub", "softsub", "multi", "dual", "retail", "custom",
];

/// Words that introduce a numbered volume. Only a boundary when a number
/// follows, so `Part of Me` keeps its title but `Part 2` does not.
const VOLUME_WORDS: &[&str] = &["cd", "disc", "disk", "part", "pt", "vol", "volume"];

/// Split a filename into `(stem, lowercase_extension)`.
///
/// A trailing segment only counts as an extension when it is short,
/// alphanumeric and contains a letter — four characters at most, which covers
/// everything real (`mkv`, `mp3`, `flac`, `r00`, `7z`) while leaving the last
/// word of a dotted release name alone. Five characters would swallow the
/// `1080p` off `Some.Movie.2019.1080p`, and requiring a letter keeps `.2019`
/// from being read as an extension.
fn split_stem_ext(name: &str) -> (String, String) {
    match name.rfind('.') {
        Some(idx) if idx > 0 => {
            let ext = &name[idx + 1..];
            let plausible = (1..=4).contains(&ext.len())
                && ext.chars().all(|c| c.is_ascii_alphanumeric())
                && ext.chars().any(|c| c.is_ascii_alphabetic());
            if plausible {
                (name[..idx].to_string(), ext.to_lowercase())
            } else {
                (name.to_string(), String::new())
            }
        }
        _ => (name.to_string(), String::new()),
    }
}

/// Recover structure from a release-style filename.
pub fn analyze(name: &str) -> NameAnalysis {
    let (stem, extension) = split_stem_ext(name.trim());
    let series = detect_series(&stem);
    let volume = detect_volume(&stem);
    let year = detect_year(&stem);
    let title = derive_title(&stem);

    NameAnalysis {
        stem,
        extension,
        series,
        volume,
        year,
        title,
    }
}

fn detect_series(stem: &str) -> Option<SeriesMarker> {
    let from = |c: regex::Captures<'_>| {
        Some(SeriesMarker {
            season: c.get(1).and_then(|m| m.as_str().parse().ok()),
            episode: c.get(2).and_then(|m| m.as_str().parse().ok())?,
        })
    };
    if let Some(c) = RE_SERIES_SE.captures(stem) {
        return from(c);
    }
    if let Some(c) = RE_SERIES_WORDY.captures(stem) {
        return from(c);
    }
    if let Some(c) = RE_SERIES_X.captures(stem) {
        return from(c);
    }
    // `Ep05` with no season. Deliberately last and deliberately requires the
    // `ep` prefix: a bare two-digit run in a release name is far more often a
    // year fragment, a codec level or a track number than an episode.
    RE_SERIES_EP.captures(stem).and_then(|c| {
        Some(SeriesMarker {
            season: None,
            episode: c.get(1).and_then(|m| m.as_str().parse().ok())?,
        })
    })
}

fn detect_volume(stem: &str) -> Option<VolumeMarker> {
    RE_VOLUME.captures(stem).and_then(|c| {
        c.get(1)
            .and_then(|m| m.as_str().parse().ok())
            .map(|number| VolumeMarker { number })
    })
}

fn detect_year(stem: &str) -> Option<u16> {
    year_tokens(&normalize(stem)).last().copied()
}

/// Lowercase a stem into space-separated alphanumeric tokens, after removing
/// the segments that must not be split on separators.
fn normalize(stem: &str) -> String {
    let without_brackets = RE_BRACKETED.replace_all(stem, " ");
    let without_audio = RE_DOTTED_AUDIO.replace_all(&without_brackets, " ");
    without_audio
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '\'' {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                ' '
            }
        })
        .collect()
}

fn year_tokens(normalized: &str) -> Vec<u16> {
    normalized
        .split_whitespace()
        .filter(|t| is_year_shaped(t))
        .filter_map(|t| t.parse().ok())
        .collect()
}

fn is_year_shaped(tok: &str) -> bool {
    tok.len() == 4 && is_all_digits(tok) && matches!(&tok[..2], "19" | "20")
}

fn is_all_digits(tok: &str) -> bool {
    !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit())
}

/// Reduce a stem to just its title: cut at the first release marker, then drop
/// any weak noise that survived inside it.
fn derive_title(stem: &str) -> String {
    let normalized = normalize(stem);
    let tokens: Vec<&str> = normalized.split_whitespace().collect();

    // Which year token is the *release* year: the last one. Earlier years
    // belong to the title (`Blade Runner 2049 2017 2160p`), so only the last
    // one ends it.
    let release_year_idx = tokens.iter().rposition(|t| is_year_shaped(t));

    let cut = (0..tokens.len())
        .find(|&i| boundary_at(&tokens, i, release_year_idx))
        .unwrap_or(tokens.len());

    let mut title: Vec<&str> = tokens[..cut].to_vec();

    // A name that opens with release metadata (`[Group] Show - 05`, or
    // `S01E02 - Title.mkv`) leaves nothing before the cut. Rather than give up,
    // keep every non-marker token from the whole name.
    if title.is_empty() {
        title = (0..tokens.len())
            .filter(|&i| !boundary_at(&tokens, i, release_year_idx))
            .map(|i| tokens[i])
            .collect();
    }

    title.retain(|t| !WEAK_NOISE_TOKENS.contains(t));
    // A short bare number at either end is an index, not part of the title
    // (`03 - Song`, `Album 2`). Four-digit runs are left alone: a year can be
    // part of the title, as in `Blade Runner 2049`.
    while title.last().is_some_and(|t| is_index_number(t)) {
        title.pop();
    }
    while title.first().is_some_and(|t| is_index_number(t)) {
        title.remove(0);
    }

    title.join(" ")
}

fn is_index_number(tok: &str) -> bool {
    is_all_digits(tok) && tok.len() <= 3
}

/// Whether the token at `i` begins release metadata rather than title.
///
/// Takes the whole token slice because several markers span two tokens once
/// separators are gone: `S01 E02`, `Season 2`, `Part 3`.
fn boundary_at(tokens: &[&str], i: usize, release_year_idx: Option<usize>) -> bool {
    let tok = tokens[i];
    let next = tokens.get(i + 1).copied();

    if BOUNDARY_TOKENS.contains(&tok) {
        return true;
    }
    if release_year_idx == Some(i) {
        return true;
    }
    // `web` / `web dl` — "web" alone is a plausible title word, so it only
    // counts when the release suffix follows.
    if tok == "web" && matches!(next, Some("dl") | Some("rip")) {
        return true;
    }
    // `s01e02`, and the split form `s01` + `e02`.
    if RE_SERIES_SE.is_match(tok) {
        return true;
    }
    if is_season_token(tok) && next.is_some_and(is_episode_token) {
        return true;
    }
    // `1x02` (series marker) and `1920x1080` (resolution) — both end the title.
    // `b` needs two digits so a title like `3x3` survives.
    if let Some((a, b)) = tok.split_once('x') {
        if is_all_digits(a) && is_all_digits(b) && a.len() <= 4 && (2..=4).contains(&b.len()) {
            return true;
        }
    }
    // `season 2`, `episode 11`
    if matches!(tok, "season" | "episode") && next.is_some_and(is_all_digits) {
        return true;
    }
    // `cd1`, and the split form `cd` + `1`.
    if let Some(word) = VOLUME_WORDS.iter().find(|w| tok.starts_with(**w)) {
        let rest = &tok[word.len()..];
        if !rest.is_empty() && is_all_digits(rest) {
            return true;
        }
        if rest.is_empty() && next.is_some_and(is_all_digits) {
            return true;
        }
    }
    false
}

fn is_season_token(tok: &str) -> bool {
    tok.len() >= 2
        && tok.starts_with('s')
        && is_all_digits(&tok[1..])
        && (1..=2).contains(&(tok.len() - 1))
}

fn is_episode_token(tok: &str) -> bool {
    tok.len() >= 2
        && tok.starts_with('e')
        && is_all_digits(&tok[1..])
        && (1..=3).contains(&(tok.len() - 1))
}

/// Build the native eD2k co-share search term for one or more seed hashes.
///
/// eMule's wire syntax is the literal string `related` followed by `::<hash>`
/// per file, with the hash in uppercase base16 (`CAbstractFile::GetFileHash` →
/// `md4str` → `EncodeBase16`). The server special-cases the `related:` prefix
/// instead of treating it as a filename substring.
///
/// This must never go through [`crate::search::query::parse`]: `:` is an eD2k
/// keyword separator, so the parser would shred the term into `related` plus
/// hash fragments. Callers wrap the returned string in a
/// [`crate::search::query::QueryExpr::Term`] directly.
pub fn co_share_term(hashes: &[String]) -> Option<String> {
    let mut term = String::from("related");
    let mut used = 0usize;
    for hash in hashes {
        if used >= MAX_CO_SHARE_HASHES {
            break;
        }
        if !is_md4_hex(hash) {
            continue;
        }
        term.push_str("::");
        term.push_str(&hash.to_uppercase());
        used += 1;
    }
    (used > 0).then_some(term)
}

fn is_md4_hex(hash: &str) -> bool {
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

/// Derive the keyword probes for one seed.
fn probes_for(seed: &SeedFile) -> Vec<RelatedProbe> {
    let analysis = analyze(&seed.name);
    let mut probes: Vec<RelatedProbe> = Vec::new();
    let title_usable = analysis.title.len() >= MIN_TITLE_LEN;

    // Other episodes: search the series title *without* the episode marker.
    // This is the case eMule's server co-share data answers worst and users
    // ask for most.
    if analysis.series.is_some() && title_usable {
        probes.push(RelatedProbe {
            kind: RelationKind::Series,
            query: Some(analysis.title.clone()),
        });
    }

    // Other tracks: prefer the tagged artist/album over the filename, which for
    // music is usually just the track title.
    if let Some(query) = album_probe(seed) {
        probes.push(RelatedProbe {
            kind: RelationKind::Album,
            query: Some(query),
        });
    }

    // Other discs/parts of the same set.
    if analysis.volume.is_some() && title_usable {
        probes.push(RelatedProbe {
            kind: RelationKind::Volume,
            query: Some(analysis.title.clone()),
        });
    }

    // Other releases of the same title. Always worth running: it is the only
    // probe that fires for a plain movie or a one-off file.
    if title_usable {
        probes.push(RelatedProbe {
            kind: RelationKind::Title,
            query: Some(analysis.title.clone()),
        });
    }

    probes
}

fn album_probe(seed: &SeedFile) -> Option<String> {
    let artist = seed.artist.as_deref().map(str::trim).unwrap_or_default();
    let album = seed.album.as_deref().map(str::trim).unwrap_or_default();
    let combined = match (artist.is_empty(), album.is_empty()) {
        (true, true) => return None,
        (true, false) => album.to_string(),
        (false, true) => artist.to_string(),
        (false, false) => format!("{artist} {album}"),
    };
    let cleaned = derive_title(&combined);
    (cleaned.len() >= MIN_TITLE_LEN).then_some(cleaned)
}

/// Keep the highest-priority probe per distinct query, in priority order, and
/// drop any query the search grammar cannot turn into a lookup.
fn dedupe_probes(mut probes: Vec<RelatedProbe>) -> Vec<RelatedProbe> {
    probes.retain(|p| {
        p.query
            .as_deref()
            .is_some_and(|q| crate::search::query::parse(q).is_some())
    });
    probes.sort_by_key(|p| p.kind.priority());

    let mut kept: Vec<RelatedProbe> = Vec::new();
    for probe in probes {
        if kept.iter().any(|k| k.query == probe.query) {
            continue;
        }
        kept.push(probe);
        if kept.len() >= MAX_PROBES {
            break;
        }
    }
    kept
}

/// Combine probe queries into one query for the search pipeline.
///
/// A single probe is emitted bare so it parses to a plain AND-tree — that
/// matters because Kad strips the looked-up keyword from an AND-only tree but
/// keeps the whole tree once an `OR` appears. Multiple probes become
/// parenthesized `OR` branches, which the grammar reads as
/// `Or(And(a, b), And(c, d))`.
fn combine_probe_queries(probes: &[RelatedProbe]) -> Option<String> {
    let queries: Vec<&str> = probes.iter().filter_map(|p| p.query.as_deref()).collect();
    match queries[..] {
        [] => None,
        [only] => Some(only.to_string()),
        ref many => Some(
            many.iter()
                .map(|q| format!("({q})"))
                .collect::<Vec<_>>()
                .join(" OR "),
        ),
    }
}

/// Build the plan for a related search over one or more seed files.
///
/// `co_share_available` is whether the connected eD2k server advertises
/// `SRV_TCPFLG_RELATEDSEARCH` (see
/// [`crate::network::ed2k::server::related_search_supported`]). When it does,
/// the plan adds the co-share signal and carries the seed hashes; when it does
/// not, the hashes are withheld so nothing sends a co-share term to a server
/// that would read it as a filename.
///
/// Multi-seed is supported because eMule allows it and because "related to
/// these files" is a reasonable ask, but note the asymmetry: the co-share
/// request takes every hash, while keyword probes are derived from the *first*
/// seed only. Two unrelated filenames have no common title, so OR-ing their
/// titles would just run two searches in one tab and call the results related.
pub fn plan(seeds: &[SeedFile], co_share_available: bool) -> RelatedPlan {
    let hashes: Vec<String> = seeds
        .iter()
        .map(|s| s.hash.trim().to_lowercase())
        .filter(|h| is_md4_hex(h))
        .collect();

    let keyword_probes = seeds
        .first()
        .map(|seed| dedupe_probes(probes_for(seed)))
        .unwrap_or_default();
    let query = combine_probe_queries(&keyword_probes);

    let co_share = co_share_available && !hashes.is_empty();
    let mut probes = Vec::with_capacity(keyword_probes.len() + 1);
    if co_share {
        probes.push(RelatedProbe {
            kind: RelationKind::CoShare,
            query: None,
        });
    }
    probes.extend(keyword_probes);

    RelatedPlan {
        query,
        probes,
        co_share_hashes: if co_share { hashes.clone() } else { Vec::new() },
        exclude_hashes: hashes,
        seed_label: seeds
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(name: &str) -> SeedFile {
        SeedFile {
            hash: "0".repeat(32),
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn music_seed() -> SeedFile {
        SeedFile {
            hash: "a".repeat(32),
            name: "03 - Some Song.mp3".to_string(),
            artist: Some("The Band".to_string()),
            album: Some("Greatest Hits".to_string()),
        }
    }

    #[test]
    fn splits_extension_only_when_plausible() {
        assert_eq!(
            split_stem_ext("Some.Movie.2019.1080p.mkv"),
            ("Some.Movie.2019.1080p".to_string(), "mkv".to_string())
        );
        // A dotted release name must not lose its last word to a fake
        // extension.
        assert_eq!(
            split_stem_ext("Some.Movie.2019.1080p"),
            ("Some.Movie.2019.1080p".to_string(), String::new())
        );
        assert_eq!(
            split_stem_ext("archive.part1.rar"),
            ("archive.part1".to_string(), "rar".to_string())
        );
    }

    #[test]
    fn recovers_series_marker_in_every_common_notation() {
        for (name, season, episode) in [
            ("Show.Name.S01E02.1080p.WEB-DL.x264-GRP.mkv", Some(1), 2),
            ("Show Name - 1x02 - Title.avi", Some(1), 2),
            ("Show.Name.Season.2.Episode.11.mkv", Some(2), 11),
            ("Show Name S03 E04.mkv", Some(3), 4),
            ("Show Name Ep07.mkv", None, 7),
        ] {
            let marker = analyze(name)
                .series
                .unwrap_or_else(|| panic!("no series marker found in {name}"));
            assert_eq!(marker.season, season, "season for {name}");
            assert_eq!(marker.episode, episode, "episode for {name}");
        }
    }

    #[test]
    fn plain_movie_has_no_series_marker() {
        assert!(analyze("Some.Movie.2019.1080p.BluRay.x264.mkv")
            .series
            .is_none());
        // "deep" must not read as an `ep` marker.
        assert!(analyze("Deep.Water.2022.1080p.mkv").series.is_none());
    }

    #[test]
    fn title_stops_at_release_metadata() {
        for (name, expected) in [
            ("Some.Movie.Name.2019.1080p.BluRay.x264-GRP.mkv", "some movie name"),
            ("Show.Name.S01E02.1080p.WEB-DL.x264-GRP.mkv", "show name"),
            ("Show Name S03 E04 720p HDTV.mkv", "show name"),
            ("Show.Name.Season.2.Episode.11.mkv", "show name"),
            ("Another Film (2004) [1080p] {AC3} x265.mkv", "another film"),
            ("Concert.Film.2011.720p.BluRay.DTS.5.1.x264.mkv", "concert film"),
            ("Long.Movie.2001.CD2.avi", "long movie"),
            ("Audiobook Title - Part 3.mp3", "audiobook title"),
        ] {
            assert_eq!(analyze(name).title, expected, "title for {name}");
        }
    }

    /// The resolution `1920x1080` must not read as season 19 episode 20, and
    /// `web` must stay in a title unless the release suffix follows.
    #[test]
    fn title_does_not_cut_on_lookalike_tokens() {
        assert_eq!(analyze("Some Movie 1920x1080 x264.mkv").title, "some movie");
        assert!(analyze("Some Movie 1920x1080.mkv").series.is_none());
        assert_eq!(analyze("The Web We Weave.mkv").title, "the web we weave");
        assert_eq!(analyze("The Web.2019.WEB-DL.mkv").title, "the web");
    }

    /// `Part` / `Vol` are only markers when a number follows, so titles that
    /// merely contain the word survive.
    #[test]
    fn volume_words_need_a_number_to_end_a_title() {
        assert_eq!(analyze("Part of Me.mp3").title, "part of me");
        assert!(analyze("Part of Me.mp3").volume.is_none());
        assert_eq!(analyze("Movie.Name.Part.2.1080p.mkv").title, "movie name");
    }

    #[test]
    fn title_survives_a_name_that_opens_with_metadata() {
        // Nothing precedes the cut, so the fallback keeps the non-marker
        // remainder instead of returning an empty title.
        assert_eq!(
            analyze("[HorribleSubs] Show Name - 05.mkv").title,
            "show name"
        );
        assert_eq!(analyze("1080p.Some.Movie.mkv").title, "some movie");
        assert_eq!(analyze("S01E02 - The Episode Title.mkv").title, "the episode title");
    }

    #[test]
    fn title_keeps_a_year_that_belongs_to_the_title() {
        // Only the *last* year-shaped token is the release year, so an earlier
        // one stays in the title.
        assert_eq!(
            analyze("Blade.Runner.2049.2017.2160p.UHD.BluRay.x265.mkv").title,
            "blade runner 2049"
        );
        assert_eq!(analyze("Blade.Runner.2049.2017.2160p.mkv").year, Some(2017));
    }

    #[test]
    fn detects_release_year_or_none() {
        assert_eq!(analyze("Some.Movie.1999.DVDRip.avi").year, Some(1999));
        assert_eq!(analyze("No Year Here.mkv").year, None);
        // A resolution must not be mistaken for a year.
        assert_eq!(analyze("Some.Movie.1080p.mkv").year, None);
    }

    #[test]
    fn detects_volume_marker() {
        assert_eq!(
            analyze("Long.Movie.2001.CD2.avi").volume,
            Some(VolumeMarker { number: 2 })
        );
        assert_eq!(
            analyze("Audiobook - Part 3.mp3").volume,
            Some(VolumeMarker { number: 3 })
        );
        assert!(analyze("Some.Movie.2019.mkv").volume.is_none());
    }

    #[test]
    fn weak_noise_is_removed_without_truncating_the_title() {
        assert_eq!(
            analyze("Some.Movie.2019.ITA.ENG.1080p.mkv").title,
            "some movie"
        );
        // Tracker spam ahead of the title is dropped, not treated as the title.
        let title = analyze("www.rarbg.to.Some.Movie.2019.1080p.mkv").title;
        assert!(title.contains("some movie"), "got {title:?}");
        assert!(!title.contains("rarbg"), "got {title:?}");
    }

    #[test]
    fn series_seed_probes_the_show_not_the_episode() {
        let plan = plan(&[seed("Show.Name.S01E02.1080p.WEB-DL.x264-GRP.mkv")], false);
        assert_eq!(
            plan.probes.len(),
            1,
            "series and title derive the same query and collapse"
        );
        assert_eq!(plan.probes[0].kind, RelationKind::Series);
        assert_eq!(plan.probes[0].query.as_deref(), Some("show name"));
        // A single probe stays bare so Kad gets a plain AND-tree.
        assert_eq!(plan.query.as_deref(), Some("show name"));
    }

    #[test]
    fn album_metadata_adds_a_second_or_branch() {
        let plan = plan(&[music_seed()], false);
        let kinds: Vec<_> = plan.probes.iter().map(|p| p.kind).collect();
        assert_eq!(kinds, vec![RelationKind::Album, RelationKind::Title]);
        assert_eq!(
            plan.query.as_deref(),
            Some("(the band greatest hits) OR (some song)")
        );
    }

    #[test]
    fn combined_query_parses_to_an_or_of_and_trees() {
        let plan = plan(&[music_seed()], false);
        let expr = crate::search::query::parse(plan.query.as_deref().unwrap())
            .expect("combined query must parse");
        assert!(expr.contains_or(), "branches must stay alternatives");
        assert!(expr.matches("the band - greatest hits - 07 - other song"));
        assert!(expr.matches("some song (live)"));
        assert!(!expr.matches("something entirely different"));
    }

    #[test]
    fn probes_are_capped_and_deduplicated_by_priority() {
        // Series, volume and title all derive the same title here, so only the
        // most specific kind survives.
        let plan = plan(&[seed("Show.Name.S01E02.CD1.720p.HDTV.x264.avi")], false);
        assert_eq!(plan.probes.len(), 1);
        assert_eq!(plan.probes[0].kind, RelationKind::Series);
        assert!(plan.probes.len() <= MAX_PROBES);
    }

    /// A capable server contributes the co-share signal on top of the keyword
    /// probes, and it leads because it is the most specific claim.
    #[test]
    fn co_share_is_listed_first_when_the_server_supports_it() {
        let plan = plan(&[seed("Show.Name.S01E02.1080p.mkv")], true);
        assert_eq!(plan.probes[0].kind, RelationKind::CoShare);
        assert!(
            plan.probes[0].query.is_none(),
            "co-share is not a keyword search"
        );
        assert_eq!(plan.co_share_hashes.len(), 1);
        // It must not leak into the keyword query.
        assert_eq!(plan.query.as_deref(), Some("show name"));
    }

    /// Without server support the hashes are withheld, so nothing can send a
    /// co-share term the server would read as a filename substring.
    #[test]
    fn co_share_hashes_are_withheld_when_the_server_cannot_answer() {
        let plan = plan(&[seed("Show.Name.S01E02.1080p.mkv")], false);
        assert!(plan.co_share_hashes.is_empty());
        assert!(plan.probes.iter().all(|p| p.kind != RelationKind::CoShare));
        // The seed is still hidden from its own results.
        assert_eq!(plan.exclude_hashes.len(), 1);
    }

    #[test]
    fn unsearchable_name_yields_no_keyword_query_but_keeps_co_share() {
        // Every token is under the eD2k 3-byte minimum, so nothing is
        // searchable by keyword — the native co-share request is all that is
        // left, and the plan must still be runnable.
        let plan = plan(&[seed("a.b.mkv")], true);
        assert!(plan.query.is_none());
        assert_eq!(plan.co_share_hashes.len(), 1);
        assert!(!plan.is_empty());
    }

    /// The same unsearchable name with no capable server has nothing left to
    /// try, so the caller must be told rather than shown an empty tab.
    #[test]
    fn unsearchable_name_without_co_share_is_empty() {
        assert!(plan(&[seed("a.b.mkv")], false).is_empty());
    }

    #[test]
    fn plan_with_no_hash_and_no_title_is_empty() {
        let plan = plan(
            &[SeedFile {
                hash: String::new(),
                name: "a.b".to_string(),
                ..Default::default()
            }],
            true,
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn seed_hashes_are_normalized_and_excluded() {
        let plan = plan(
            &[SeedFile {
                hash: "AABBCCDDEEFF00112233445566778899".to_string(),
                name: "Show.Name.S01E02.mkv".to_string(),
                ..Default::default()
            }],
            true,
        );
        assert_eq!(
            plan.exclude_hashes,
            vec!["aabbccddeeff00112233445566778899".to_string()]
        );
        assert_eq!(plan.co_share_hashes, plan.exclude_hashes);
    }

    #[test]
    fn invalid_hashes_are_dropped_from_the_plan() {
        let plan = plan(
            &[SeedFile {
                hash: "not-a-hash".to_string(),
                name: "Show.Name.S01E02.mkv".to_string(),
                ..Default::default()
            }],
            true,
        );
        assert!(plan.co_share_hashes.is_empty());
        assert!(plan.exclude_hashes.is_empty());
        // The keyword probe still works, so the search is still worth running.
        assert!(!plan.is_empty());
    }

    #[test]
    fn co_share_term_matches_emule_wire_syntax() {
        let a = "aabbccddeeff00112233445566778899".to_string();
        let b = "00112233445566778899aabbccddeeff".to_string();
        assert_eq!(
            co_share_term(std::slice::from_ref(&a)).unwrap(),
            "related::AABBCCDDEEFF00112233445566778899"
        );
        assert_eq!(
            co_share_term(&[a, b]).unwrap(),
            "related::AABBCCDDEEFF00112233445566778899::00112233445566778899AABBCCDDEEFF"
        );
    }

    #[test]
    fn co_share_term_rejects_junk_and_caps_hash_count() {
        assert!(co_share_term(&[]).is_none());
        assert!(co_share_term(&["zzzz".to_string()]).is_none());

        let many: Vec<String> = (0..MAX_CO_SHARE_HASHES + 4)
            .map(|i| format!("{i:032x}"))
            .collect();
        let term = co_share_term(&many).unwrap();
        assert_eq!(term.matches("::").count(), MAX_CO_SHARE_HASHES);
    }

    /// The co-share term has to survive as one wire string. Routing it through
    /// the query parser splits it on `:`, and the server then sees a keyword
    /// search for "related" instead of a co-share request.
    #[test]
    fn co_share_term_must_not_be_routed_through_the_query_parser() {
        let term = co_share_term(&["aa".repeat(16)]).unwrap();
        let parsed = crate::search::query::parse(&term).expect("parses, but wrongly");
        assert!(
            parsed.positive_terms().len() > 1,
            "parser splits the term on ':' — callers must build a Term directly"
        );
    }

    #[test]
    fn multi_seed_takes_all_hashes_but_only_the_first_filename() {
        let plan = plan(
            &[
                SeedFile {
                    hash: "a".repeat(32),
                    name: "Show.Name.S01E02.mkv".to_string(),
                    ..Default::default()
                },
                SeedFile {
                    hash: "b".repeat(32),
                    name: "Totally.Different.Movie.2019.mkv".to_string(),
                    ..Default::default()
                },
            ],
            true,
        );
        assert_eq!(plan.co_share_hashes.len(), 2);
        assert_eq!(plan.query.as_deref(), Some("show name"));
        assert_eq!(
            plan.seed_label,
            "Show.Name.S01E02.mkv, Totally.Different.Movie.2019.mkv"
        );
    }

    #[test]
    fn empty_seed_list_produces_an_empty_plan() {
        let plan = plan(&[], true);
        assert!(plan.is_empty());
        assert!(plan.probes.is_empty());
        assert!(plan.seed_label.is_empty());
    }
}
