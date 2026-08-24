//! Anti-leech client filter — eMule-style `AntiLeech.dat` equivalent.
//!
//! The filter matches a haystack of the peer's rendered client-software
//! string (the upload-pane "Software" column from
//! `messages::client_software_from_caps`) plus the CT_MODVERSION /
//! ET_MOD_VERSION tag when that tag is not already in the label. Brand-name
//! defaults (VeryCD, easyMule, …) live in the mod tag; the software column
//! alone is usually just "eMule 0.50". Connections from peers whose haystack
//! matches any pattern are closed at handshake time, before any slot is
//! granted, queue position is held, or upload bytes flow.
//!
//! Patterns are user-controlled via
//! `~/AppData/Roaming/com.ember.p2p/antileech.dat` (or the platform
//! equivalent).
//!
//! ## File format
//!
//! UTF-8, one regex per line. `#` introduces a comment to end-of-line.
//! Blank lines and comment-only lines are ignored. Patterns are
//! Rust-flavour regex (the `regex` crate's syntax) with case-insensitive
//! matching enabled implicitly (the leading `(?i)` is added if absent).
//!
//! ## Default list
//!
//! The defaults below are the small subset of patterns the eMule
//! community has historically converged on as "always block". They do
//! NOT match Ember itself — every regex is anchored or specific enough
//! that "Ember 0.9.0" / "eMule Compat 0.50" cannot trigger. See the
//! self-test in the unit-test module at the bottom of this file.
//!
//! ## Why regex (and not glob / substring)
//!
//! Matches the format of every public AntiLeech.dat in circulation, so
//! a user who already curates one for their existing eMule install can
//! drop it in unchanged. Compile cost is one-time at load (we cache the
//! `RegexSet` for the lifetime of each reload).

use std::path::Path;
use std::sync::Arc;

use parking_lot::RwLock;
use regex::RegexSetBuilder;
use tracing::{info, warn};

/// Default file name written into and read from the user data directory.
pub const DEFAULT_FILE_NAME: &str = "antileech.dat";

/// Hard cap on the number of patterns we'll compile at once. The
/// upload hot path runs `RegexSet::is_match` on every incoming
/// connection; a runaway pattern list (intentional or accidental)
/// would slow handshakes for every peer. 500 is comfortably above any
/// realistic curated AntiLeech.dat (the public ones top out around 60).
pub const MAX_PATTERNS: usize = 500;

/// Hard cap on a single pattern's source length. Real patterns are
/// short brand-name regexes (the longest default is ~12 chars). 256
/// is generous and bounds the worst-case compile time.
pub const MAX_PATTERN_LEN: usize = 256;

/// Maximum AntiLeech.dat size accepted from disk. Real curated lists are
/// kilobytes; this keeps a corrupted local file from being read fully into
/// memory during startup or settings reload.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// Memory budget passed to the `regex` crate when compiling a pattern.
/// 1 MiB is the crate's default, named here so it's auditable in one
/// place. Patterns whose compiled DFA exceeds this are rejected
/// (returned in the per-pattern error list) rather than allowed to
/// blow the memory budget on the hot path.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Text the filter is matched against: the UI software label plus the
/// peer's CT_MODVERSION / ET_MOD_VERSION tag when that tag is not already
/// contained in the label. Brand-name defaults (VeryCD, easyMule, …) live
/// in the mod tag; `client_software_from_caps` does not append it.
pub fn match_haystack(client_software: &str, mod_version: &str) -> String {
    let software = client_software.trim();
    let modv = mod_version.trim();
    if modv.is_empty() {
        return software.to_string();
    }
    if software.is_empty() {
        return modv.to_string();
    }
    if software
        .to_ascii_lowercase()
        .contains(&modv.to_ascii_lowercase())
    {
        software.to_string()
    } else {
        format!("{software} {modv}")
    }
}

fn is_unmodified_legacy_defaults(loaded: &[String]) -> bool {
    loaded.len() == LEGACY_DEFAULT_PATTERNS.len()
        && loaded
            .iter()
            .zip(LEGACY_DEFAULT_PATTERNS.iter())
            .all(|(a, b)| a == b)
}

/// Built-in patterns — the well-known leech mods + a few that target
/// clients that explicitly identify as broken. Kept conservative on
/// purpose; a too-aggressive default would create silent connectivity
/// regressions for users who never realise the filter is on.
///
/// Every entry has been cross-checked NOT to match Ember's own client
/// strings (see the `defaults_do_not_block_ember` unit test).
///
/// `\b(LEECHER|LEECH)\b` is intentionally absent: once the haystack
/// includes mod tags, it hits legitimate DLP/Xtreme-style "Anti-Leech"
/// strings. Brand names below do the real work.
const DEFAULT_PATTERNS: &[&str] = &[
    // VeryCD eMule (Chinese mod, widely deployed, well-documented credit
    // gaming and excessive request behaviour). Lives in ET_MOD_VERSION.
    r"VeryCD",
    // easyMule — VeryCD's later product, same family and rationale.
    r"easyMule",
    // MagicMule — known credit-forging fork.
    r"MagicMule",
    // Sivka — broken upload accounting mod.
    r"\bSivka\b",
    // Old xMule (abandoned eMule fork; the surviving versions
    // mis-implement queue scoring). The `\b` boundaries avoid matching
    // benign substrings like "exMule" that some other mod might use.
    r"\bxMule\b",
    // eMule v0.29 and older predate SecIdent entirely; they can't be
    // credited and consume slots with no upload reciprocity. Rare in
    // 2026, but still occasionally seen on long-tail networks. The
    // pattern matches "eMule 0.0X" through "eMule 0.2X" anchored at
    // the start of the label so "eMule 0.30+" / "eMule 0.50.1" /
    // "Compat" variants stay allowed. Version-suffix letters
    // (e.g. "0.20a") work because we don't require a word boundary
    // after the digits — the leading anchor + `0.[0-2]\d` is enough
    // to scope the match to the early-2.x release line.
    r"^eMule 0\.[0-2]\d",
];

/// Pattern list shipped before the haystack/easyMule change. An on-disk
/// file whose loaded patterns equal this exact list (order included) is
/// treated as an unmodified factory file and rewritten with
/// [`DEFAULT_PATTERNS`]. Customized files are left alone.
const LEGACY_DEFAULT_PATTERNS: &[&str] = &[
    r"VeryCD",
    r"MagicMule",
    r"\bSivka\b",
    r"\bxMule\b",
    r"\b(LEECHER|LEECH)\b",
    r"^eMule 0\.[0-2]\d",
];

/// Compiled, hot-swappable filter. Cheap to read on the upload hot path
/// (one `RegexSet::is_match` call), expensive only on (re)load.
#[derive(Default)]
pub struct AntiLeechFilter {
    /// Lowercase-normalised set of patterns for fast batch matching.
    /// `RegexSet::matches` returns the indices of *every* pattern that
    /// matched in a single pass over the input — much cheaper than
    /// looping per-`Regex` when the pattern list grows past a handful.
    set: Option<regex::RegexSet>,
    /// The raw pattern strings, in load order. Index-aligned with
    /// `set` so we can map a `RegexSet::matches` hit back to the
    /// original user-readable pattern for logs and the settings UI.
    raw_patterns: Vec<String>,
    /// `true` when the user has explicitly disabled the filter via the
    /// settings UI. We keep the compiled patterns around so re-enabling
    /// is instant.
    enabled: bool,
}

/// Result of a match check. `None` means the peer is allowed through.
#[derive(Debug, Clone)]
pub struct LeechMatch {
    pub pattern: String,
}

impl AntiLeechFilter {
    /// Build a filter from a list of pattern strings. Returns the
    /// filter and any per-pattern compile errors so the caller can
    /// log them without aborting the whole load.
    pub fn from_patterns(
        patterns: impl IntoIterator<Item = String>,
        enabled: bool,
    ) -> (Self, Vec<(String, regex::Error)>) {
        // Pre-trim and de-noise once. `take(MAX_PATTERNS + 1)` so we
        // can detect overflow without iterating an unbounded source.
        let raw: Vec<String> = patterns
            .into_iter()
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty() && !p.starts_with('#'))
            .take(MAX_PATTERNS + 1)
            .collect();
        let mut errors: Vec<(String, regex::Error)> = Vec::new();
        let mut accepted: Vec<String> = Vec::with_capacity(raw.len().min(MAX_PATTERNS));
        for pat in &raw {
            // Hard cap on count. Anything past MAX_PATTERNS is dropped
            // with a synthetic error so the user sees it in the UI's
            // "Patterns rejected" list rather than silently losing
            // patterns. `regex::Error` is `#[non_exhaustive]` but its
            // public `Syntax(String)` variant is constructible from
            // outside the crate, so we use it as a typed carrier for
            // a human-readable rejection reason instead of compiling
            // an intentionally invalid pattern (which clippy correctly
            // flags as `invalid_regex` and would surface a confusing
            // "empty capture group name" message in the UI).
            if accepted.len() >= MAX_PATTERNS {
                errors.push((
                    pat.clone(),
                    regex::Error::Syntax(format!(
                        "Too many patterns (limit {MAX_PATTERNS}); pattern dropped",
                    )),
                ));
                continue;
            }
            // Hard cap on per-pattern length. A 4 KiB regex isn't a
            // brand name, it's a denial-of-service waiting to happen.
            if pat.len() > MAX_PATTERN_LEN {
                errors.push((
                    pat.clone(),
                    regex::Error::Syntax(format!(
                        "Pattern exceeds {MAX_PATTERN_LEN}-byte limit ({} bytes)",
                        pat.len(),
                    )),
                ));
                continue;
            }
            // Force case-insensitive matching at the builder level. Inline
            // groups such as `(?:...)` and `(?P<name>...)` are structural,
            // not flag declarations, and must not accidentally disable the
            // default. An explicit `(?-i:...)` can still opt a subexpression
            // back into case-sensitive matching. Most user patterns are
            // brand names ("VeryCD", "MagicMule") and the user shouldn't
            // have to remember to add the flag. We compile each pattern
            // standalone with an explicit `size_limit` so a pathological
            // regex that would compile to a multi-MB DFA is rejected
            // here instead of slowing the upload hot path.
            let compile_result = regex::RegexBuilder::new(pat)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build();
            match compile_result {
                Ok(_) => accepted.push(pat.clone()),
                Err(e) => errors.push((pat.clone(), e)),
            }
        }
        let set = if accepted.is_empty() {
            None
        } else {
            // Same size cap on the combined RegexSet. If the overall
            // automaton would be huge despite each individual pattern
            // fitting, we'd rather warn and run with no filter than
            // burn a peer-facing CPU budget.
            let build_result = RegexSetBuilder::new(&accepted)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build();
            match build_result {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!("AntiLeech: RegexSet build failed unexpectedly: {e}");
                    None
                }
            }
        };
        // Fail closed: if the user expected the filter to be active
        // (`enabled = true`) but the RegexSet failed to build, force
        // `enabled = false`. The previous behavior left `enabled =
        // true` with `set = None` so `check()` returned `None` (=
        // allow) for every peer — i.e. the filter silently
        // disappeared while the UI still claimed it was on.
        let effective_enabled = enabled && set.is_some();
        if enabled && !effective_enabled {
            warn!(
                "AntiLeech: disabling filter at runtime because RegexSet build failed; \
                 user-facing setting still reads enabled=true and the next save/reload \
                 will retry the build with the current pattern list",
            );
        }
        (
            Self {
                set,
                raw_patterns: accepted,
                enabled: effective_enabled,
            },
            errors,
        )
    }

    /// Build a filter pre-loaded with the built-in default pattern list.
    pub fn with_defaults(enabled: bool) -> Self {
        let (filter, errors) =
            Self::from_patterns(DEFAULT_PATTERNS.iter().map(|p| (*p).to_string()), enabled);
        for (pat, err) in &errors {
            warn!("AntiLeech default pattern failed to compile: {pat:?}: {err}");
        }
        filter
    }

    /// Read the filter from `path`. Missing file → empty filter (NOT
    /// the defaults — defaults are seeded explicitly the first time we
    /// create the file). Unreadable file → log + empty.
    pub fn load_from_file(path: &Path, enabled: bool) -> Self {
        match std::fs::metadata(path) {
            Ok(meta) if meta.len() > MAX_FILE_BYTES => {
                warn!(
                    "AntiLeech: refusing to read {} ({} bytes > {} byte cap)",
                    path.display(),
                    meta.len(),
                    MAX_FILE_BYTES
                );
                return Self::default();
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self::default();
            }
            Err(e) => {
                warn!("AntiLeech: failed to stat {}: {e}", path.display());
                return Self::default();
            }
        }
        let data = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Self::default();
            }
            Err(e) => {
                warn!("AntiLeech: failed to read {}: {e}", path.display());
                return Self::default();
            }
        };
        let patterns = data
            .lines()
            .map(|line| line.split('#').next().unwrap_or("").to_string());
        let (filter, errors) = Self::from_patterns(patterns, enabled);
        for (pat, err) in &errors {
            warn!(
                "AntiLeech: pattern {pat:?} in {} failed to compile: {err}",
                path.display()
            );
        }
        info!(
            "AntiLeech: loaded {} pattern(s) from {} (enabled={enabled})",
            filter.raw_patterns.len(),
            path.display()
        );
        filter
    }

    /// Write the current pattern list to disk in the canonical
    /// human-editable format (one regex per line, blank trailing line).
    /// The file is written via `atomic_write` so a crash mid-flush
    /// can't leave a half-truncated file behind.
    pub fn save_to_file(&self, path: &Path) -> std::io::Result<()> {
        let mut buf = String::with_capacity(self.raw_patterns.len() * 32);
        buf.push_str("# Ember anti-leech client filter — one regex per line.\n");
        buf.push_str("# Lines starting with `#` and blank lines are ignored.\n");
        buf.push_str("# Patterns are matched case-insensitively against the rendered\n");
        buf.push_str("# client-software string plus the peer's mod tag when present\n");
        buf.push_str("# (e.g. \"eMule 0.50 VeryCD 080828\", \"eMule 0.48 easyMule\").\n");
        buf.push_str("# Save and reload via Settings to apply.\n\n");
        for pat in &self.raw_patterns {
            buf.push_str(pat);
            buf.push('\n');
        }
        crate::security::atomic_write(path, buf.as_bytes(), false).map_err(std::io::Error::other)
    }

    /// Hot-path matcher. Returns the first matching pattern (for log
    /// + UI), or `None` if the peer is allowed through.
    pub fn check(&self, client_software: &str) -> Option<LeechMatch> {
        if !self.enabled {
            return None;
        }
        let set = self.set.as_ref()?;
        let matches = set.matches(client_software);
        let first = matches.into_iter().next()?;
        let pattern = self
            .raw_patterns
            .get(first)
            .cloned()
            .unwrap_or_else(|| String::from("(unknown pattern)"));
        Some(LeechMatch { pattern })
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Toggle the filter on or off.
    ///
    /// Returns `Err` when the caller asks to enable the filter but the
    /// pattern set has not been compiled (e.g. every pattern in the
    /// on-disk file failed to compile). Without this guard the filter
    /// would report `enabled = true` while `check()` returns `None` for
    /// every peer — i.e. silently allow-all while the UI claims it is
    /// blocking. Callers should surface the error to the user so they
    /// can fix or repopulate the pattern list before re-enabling.
    pub fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        if enabled && self.set.is_none() {
            warn!(
                "AntiLeech: refusing to enable — no compiled pattern set is loaded \
                 (load patterns or restore defaults first)"
            );
            return Err(
                "Anti-leech filter has no compiled patterns; load or restore defaults first"
                    .to_string(),
            );
        }
        self.enabled = enabled;
        Ok(())
    }

    pub fn pattern_count(&self) -> usize {
        self.raw_patterns.len()
    }

    pub fn patterns(&self) -> &[String] {
        &self.raw_patterns
    }

    /// Replace the pattern list, recompiling on the spot. Returns the
    /// compile errors (if any) for the caller to surface to the UI.
    pub fn replace_patterns(
        &mut self,
        patterns: impl IntoIterator<Item = String>,
    ) -> Vec<(String, regex::Error)> {
        let was_enabled = self.enabled;
        let (new_self, errors) = Self::from_patterns(patterns, was_enabled);
        *self = new_self;
        errors
    }
}

/// Shared, hot-reloadable handle. Reads on the upload hot path acquire
/// a read lock (uncontended in steady state); reloads / pattern edits
/// take a write lock.
pub type SharedAntiLeechFilter = Arc<RwLock<AntiLeechFilter>>;

/// Convenience helper for the common boot-time path: load the filter
/// from `data_dir/antileech.dat`; if that file doesn't exist yet, write
/// out the default list so the user has something to edit. An on-disk
/// file that still holds the pre-haystack factory list (including the
/// old `LEECH` token) is rewritten with the current defaults so existing
/// installs pick up `easyMule` without a manual Restore. Customized files
/// are left unchanged.
pub fn load_or_seed_defaults(data_dir: &Path, enabled: bool) -> AntiLeechFilter {
    let path = data_dir.join(DEFAULT_FILE_NAME);
    // `save_to_file` publishes through `atomic_write`, whose Windows
    // replace-fallback can park the only copy under the backup name. Without
    // this, that absence reads as "never seeded" and the seed write below
    // replaces a hand-edited pattern list with the factory defaults.
    crate::security::recover_interrupted_replace(&path);
    if path.exists() {
        let loaded = AntiLeechFilter::load_from_file(&path, enabled);
        if is_unmodified_legacy_defaults(loaded.patterns()) {
            let next = AntiLeechFilter::with_defaults(enabled);
            if let Err(e) = next.save_to_file(&path) {
                warn!(
                    "AntiLeech: could not migrate factory patterns at {}: {e}",
                    path.display()
                );
                return loaded;
            }
            info!(
                "AntiLeech: migrated unmodified factory list at {} to {} pattern(s)",
                path.display(),
                next.pattern_count()
            );
            return next;
        }
        return loaded;
    }
    let filter = AntiLeechFilter::with_defaults(enabled);
    if let Err(e) = filter.save_to_file(&path) {
        warn!(
            "AntiLeech: could not seed default patterns at {}: {e}",
            path.display()
        );
    } else {
        info!(
            "AntiLeech: seeded {} default pattern(s) at {}",
            filter.pattern_count(),
            path.display()
        );
    }
    filter
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRITICAL: every default pattern must NOT block strings Ember
    /// itself emits. If a future addition to `DEFAULT_PATTERNS`
    /// regresses this, the whole Ember mesh would blacklist itself
    /// the moment a peer enabled the filter.
    #[test]
    fn defaults_do_not_block_ember() {
        let filter = AntiLeechFilter::with_defaults(true);
        let labels = [
            "Ember 0.9.0".to_string(),
            "Ember 1.0".to_string(),
            "Ember 1.5.5".to_string(),
            "Ember Compat 0.50".to_string(),
            "eMule Compat 0.50".to_string(),
            "eMule Compat 0.50.1".to_string(),
            // The `client_software_from_caps` output for our own peers
            // (with mod_version = "Ember X.Y.Z") preferred path:
            "Ember".to_string(),
            match_haystack("Ember 1.5.5", "Ember 1.5.5"),
            match_haystack("Ember", "Ember 1.5.5"),
        ];
        for label in labels {
            assert!(
                filter.check(&label).is_none(),
                "default filter unexpectedly blocked our own client string {label:?} \
                 — every default regex must avoid matching Ember's identity"
            );
        }
    }

    /// Defaults must match the well-known leech-mod strings they're
    /// designed for. Without this, a "no-op default list" regression
    /// (e.g. someone making the patterns too restrictive) would leave
    /// users unprotected against the only known-bad clients we
    /// hard-code against.
    #[test]
    fn defaults_block_known_leeches() {
        let filter = AntiLeechFilter::with_defaults(true);
        let blocked = [
            "VeryCD eMule v1.0".to_string(),
            "verycd emule v1.0".to_string(),
            match_haystack("eMule 0.50", "VeryCD 080828"),
            match_haystack("eMule 0.48", "easyMule"),
            "MagicMule 1.4".to_string(),
            match_haystack("eMule 0.50", "MagicMule"),
            "Sivka 17b".to_string(),
            match_haystack("eMule 0.42e", "sivka v12e8"),
            "xMule 1.10.0".to_string(),
            "eMule 0.20a".to_string(),
            "eMule 0.15".to_string(),
        ];
        for label in blocked {
            assert!(
                filter.check(&label).is_some(),
                "expected default filter to block {label:?}"
            );
        }
        // Software column alone must NOT be enough for a brand that only
        // lives in the mod tag — that was the pre-haystack miss.
        assert!(
            filter.check("eMule 0.50").is_none(),
            "plain eMule 0.50 is not a leech"
        );
    }

    /// The old LEECH token must not fire on legitimate anti-leech mods
    /// once the haystack includes mod tags.
    #[test]
    fn defaults_do_not_block_antileech_mod_tags() {
        let filter = AntiLeechFilter::with_defaults(true);
        let allowed = [
            match_haystack("eMule 0.50", "Xtreme 8.1"),
            match_haystack("eMule 0.50a", "MorphXT 12.7"),
            match_haystack("eMule 0.50", "StulleMule"),
            match_haystack("eMule 0.50", "Anti-Leech"),
            "eMule 0.50 Anti-Leech".to_string(),
        ];
        for label in allowed {
            assert!(
                filter.check(&label).is_none(),
                "default filter unexpectedly blocked legitimate mod {label:?}"
            );
        }
        assert!(
            filter.check("eMule 0.29c LEECHER mod").is_some(),
            "ancient eMule 0.29 still blocked by the version pattern, not LEECH"
        );
    }

    /// A disabled filter must let *everything* through, including the
    /// strings it would otherwise block. The settings toggle has to be
    /// a real kill switch.
    #[test]
    fn disabled_filter_lets_everything_through() {
        let filter = AntiLeechFilter::with_defaults(false);
        for label in ["VeryCD eMule v1.0", "MagicMule", "anything"] {
            assert!(
                filter.check(label).is_none(),
                "disabled filter must not match {label:?}"
            );
        }
    }

    /// Unrelated mainstream clients must NOT match the defaults — the
    /// most common false-positive risk is matching legitimate aMule /
    /// MLDonkey / Shareaza / mainline-eMule strings.
    #[test]
    fn defaults_do_not_block_mainstream_clients() {
        let filter = AntiLeechFilter::with_defaults(true);
        let allowed = [
            "eMule",
            "eMule 0.50",
            "eMule 0.50a",
            "eMule 0.49c",
            "aMule 2.3.3",
            "aMule 2.3.1",
            "MLDonkey",
            "MLDonkey 3.1.6",
            "Shareaza",
            "Shareaza 2.7.10.2",
            "lphant 0.57",
            "Hydranode 0.3.1",
            "iMule 1.4.6",
            "eMule Plus",
            "eMule Plus 1.2.5", // the model citizen of buggy-but-not-malicious clients
            "cDonkey",
            "eD2k",
            "eMule Compat",
            "eMule Compat 0.50",
            "eMule 0.50 Xtreme 8.1",
            "eMule 0.50a MorphXT 12.7",
        ];
        for label in allowed {
            assert!(
                filter.check(label).is_none(),
                "default filter unexpectedly blocked mainstream client {label:?}"
            );
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let raw = "
# header comment
\t

VeryCD
   # indented comment
MagicMule
"
        .lines()
        .map(|s| s.split('#').next().unwrap_or("").to_string());
        let (filter, errors) = AntiLeechFilter::from_patterns(raw, true);
        assert!(errors.is_empty(), "no compile errors expected");
        assert_eq!(filter.pattern_count(), 2);
        assert!(filter.check("VeryCD eMule v1.0").is_some());
        assert!(filter.check("MagicMule 2.0").is_some());
    }

    #[test]
    fn invalid_pattern_is_skipped_not_fatal() {
        let raw = vec!["VeryCD".to_string(), "[invalid(regex".to_string()];
        let (filter, errors) = AntiLeechFilter::from_patterns(raw, true);
        // The valid pattern still works; the invalid one is reported but doesn't
        // poison the rest of the list. Critical for hot-reload UX.
        assert_eq!(filter.pattern_count(), 1);
        assert_eq!(errors.len(), 1);
        assert!(filter.check("VeryCD eMule").is_some());
    }

    #[test]
    fn replace_patterns_swaps_atomically() {
        let mut filter = AntiLeechFilter::with_defaults(true);
        assert!(filter.check("VeryCD").is_some());
        let errors = filter.replace_patterns(vec!["NewLeechMod".to_string()]);
        assert!(errors.is_empty());
        assert!(filter.check("VeryCD").is_none(), "old pattern must be gone");
        assert!(
            filter.check("NewLeechMod 1.0").is_some(),
            "new pattern must take effect"
        );
        assert!(
            filter.enabled(),
            "enabled flag must be preserved across replace"
        );
    }

    #[test]
    fn case_insensitive_by_default() {
        let (filter, _) = AntiLeechFilter::from_patterns(vec!["BadMod".to_string()], true);
        assert!(filter.check("BADMOD 1.0").is_some());
        assert!(filter.check("badmod 2.0").is_some());
        assert!(filter.check("BaDmOd").is_some());
    }

    /// `set_enabled(true)` must refuse to enable when no compiled
    /// pattern set exists. Without this guard the filter would silently
    /// allow every peer through while the UI claimed it was active.
    #[test]
    fn set_enabled_refuses_without_pattern_set() {
        let (mut filter, _) = AntiLeechFilter::from_patterns(Vec::<String>::new(), false);
        // Empty pattern list compiles fine but produces an empty
        // RegexSet — which still counts as "has a set". Build a state
        // explicitly without one by simulating a build failure: pass a
        // single pattern that is invalid as a regex so RegexSet::new
        // fails and `set` becomes None.
        let (mut bad_filter, errors) =
            AntiLeechFilter::from_patterns(vec!["[invalid".to_string()], true);
        assert!(!errors.is_empty(), "invalid regex must surface in errors");
        assert!(
            !bad_filter.enabled(),
            "enabled must be forced off when set is None"
        );
        let res = bad_filter.set_enabled(true);
        assert!(res.is_err(), "must refuse to enable without a compiled set");
        assert!(
            !bad_filter.enabled(),
            "state must remain disabled after refusal"
        );
        // Disabling should always succeed regardless of set state.
        let _ = filter.set_enabled(false);
        assert!(filter.set_enabled(false).is_ok());
    }

    #[test]
    fn match_haystack_appends_distinct_mod_tag() {
        assert_eq!(match_haystack("eMule 0.50", ""), "eMule 0.50");
        assert_eq!(match_haystack("", "VeryCD 080828"), "VeryCD 080828");
        assert_eq!(
            match_haystack("eMule 0.50", "VeryCD 080828"),
            "eMule 0.50 VeryCD 080828"
        );
        assert_eq!(
            match_haystack("Ember 1.5.5", "Ember 1.5.5"),
            "Ember 1.5.5",
            "identical mod tag must not be duplicated"
        );
        assert_eq!(
            match_haystack("Ember 1.5.5", "ember 1.5.5"),
            "Ember 1.5.5",
            "containment is case-insensitive"
        );
        assert_eq!(
            match_haystack("Ember", "Ember 1.5.5"),
            "Ember Ember 1.5.5",
            "shorter software label does not swallow a longer mod tag"
        );
    }

    #[test]
    fn version_pattern_stays_anchored_when_mod_tag_is_appended() {
        let (filter, errors) =
            AntiLeechFilter::from_patterns(vec![r"^eMule 0\.[0-2]\d".to_string()], true);
        assert!(errors.is_empty());
        assert!(
            filter
                .check(&match_haystack("eMule 0.50", "VeryCD 080828"))
                .is_none(),
            "0.50 must not match the 0.0x–0.2x version pattern just because a mod tag follows"
        );
        assert!(filter.check("eMule 0.29c").is_some());
    }

    #[test]
    fn load_or_seed_migrates_unmodified_legacy_defaults() {
        let dir = std::env::temp_dir().join(format!(
            "ember-antileech-migrate-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DEFAULT_FILE_NAME);
        let (old, errors) = AntiLeechFilter::from_patterns(
            LEGACY_DEFAULT_PATTERNS.iter().map(|p| (*p).to_string()),
            true,
        );
        assert!(errors.is_empty());
        old.save_to_file(&path).unwrap();

        let migrated = load_or_seed_defaults(&dir, true);
        assert!(
            migrated.patterns().iter().any(|p| p == "easyMule"),
            "migration must add easyMule: {:?}",
            migrated.patterns()
        );
        assert!(
            !migrated.patterns().iter().any(|p| p.contains("LEECH")),
            "migration must drop the LEECH token: {:?}",
            migrated.patterns()
        );
        assert_eq!(
            migrated.patterns(),
            &DEFAULT_PATTERNS
                .iter()
                .map(|s| (*s).to_string())
                .collect::<Vec<_>>(),
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_or_seed_leaves_customized_file_alone() {
        let dir = std::env::temp_dir().join(format!(
            "ember-antileech-custom-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DEFAULT_FILE_NAME);
        let (custom, _) =
            AntiLeechFilter::from_patterns(vec!["VeryCD".to_string(), "MyMod".to_string()], true);
        custom.save_to_file(&path).unwrap();

        let loaded = load_or_seed_defaults(&dir, true);
        assert_eq!(
            loaded.patterns(),
            &["VeryCD".to_string(), "MyMod".to_string()]
        );
        assert!(
            !loaded.patterns().iter().any(|p| p == "easyMule"),
            "custom lists must not be rewritten"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crash inside `atomic_write`'s Windows replace-fallback leaves nothing at
    /// `antileech.dat` and the only copy parked under the fixed
    /// `.ember-replace-bak` name. Without a `recover_interrupted_replace` on the
    /// load path that absence reads as "never seeded", so the seed write replaces
    /// a hand-edited pattern list with the factory defaults and then overwrites
    /// the parked copy — the user's edits are unrecoverable.
    #[test]
    fn load_or_seed_recovers_a_file_parked_by_an_interrupted_replace() {
        let dir = std::env::temp_dir().join(format!(
            "ember-antileech-interrupted-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(DEFAULT_FILE_NAME);
        let (custom, _) =
            AntiLeechFilter::from_patterns(vec!["HandEdited".to_string()], true);
        custom.save_to_file(&path).unwrap();

        // Reproduce the crash window: the destination has been moved aside and
        // the replacement never landed.
        let mut backup_name = path.file_name().unwrap().to_os_string();
        backup_name.push(".ember-replace-bak");
        let backup = path.with_file_name(backup_name);
        std::fs::rename(&path, &backup).unwrap();
        assert!(!path.exists());

        let recovered = load_or_seed_defaults(&dir, true);
        assert_eq!(
            recovered.patterns(),
            &["HandEdited".to_string()],
            "the hand-edited list must be recovered, not replaced by factory defaults"
        );
        assert!(path.exists(), "the parked copy should be restored in place");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
