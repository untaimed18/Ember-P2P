//! Anti-leech client filter — eMule-style `AntiLeech.dat` equivalent.
//!
//! The filter matches a peer's rendered client-software string (the same
//! string the UI displays in the upload-pane "Software" column, produced
//! by `messages::client_software_from_caps`) against a list of regexes
//! the user controls via `~/AppData/Roaming/com.ember.p2p/antileech.dat`
//! (or the platform equivalent). Connections from peers whose label
//! matches any pattern are closed at handshake time, before any slot is
//! granted, queue position is held, or upload bytes flow.
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

/// Memory budget passed to the `regex` crate when compiling a pattern.
/// 1 MiB is the crate's default, named here so it's auditable in one
/// place. Patterns whose compiled DFA exceeds this are rejected
/// (returned in the per-pattern error list) rather than allowed to
/// blow the memory budget on the hot path.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Built-in patterns — the well-known leech mods + a few that target
/// clients that explicitly identify as broken. Kept conservative on
/// purpose; a too-aggressive default would create silent connectivity
/// regressions for users who never realise the filter is on.
///
/// Every entry has been cross-checked NOT to match Ember's own client
/// strings (see the `defaults_do_not_block_ember` unit test).
const DEFAULT_PATTERNS: &[&str] = &[
    // VeryCD eMule (Chinese mod, widely deployed, well-documented credit
    // gaming and excessive request behaviour). Matches the mod tag
    // anywhere in the rendered software string.
    r"VeryCD",
    // MagicMule — known credit-forging fork.
    r"MagicMule",
    // Sivka — broken upload accounting mod.
    r"\bSivka\b",
    // Old xMule (abandoned eMule fork; the surviving versions
    // mis-implement queue scoring). The `\b` boundaries avoid matching
    // benign substrings like "exMule" that some other mod might use.
    r"\bxMule\b",
    // "LEECHER" or "LEECH" tokens — a small number of mods literally
    // brand themselves this way. Anchored with word boundaries so a
    // client called "LeecherProtector" or similar isn't caught.
    r"\b(LEECHER|LEECH)\b",
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
            .take(MAX_PATTERNS + 1)
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty() && !p.starts_with('#'))
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
            // Force case-insensitive matching unless the pattern already
            // has its own `(?i)` / inline flag. Most user patterns are
            // brand names ("VeryCD", "MagicMule") and the user shouldn't
            // have to remember to add the flag. We compile each pattern
            // standalone with an explicit `size_limit` so a pathological
            // regex that would compile to a multi-MB DFA is rejected
            // here instead of slowing the upload hot path.
            let normalised = if pat.starts_with("(?") {
                pat.clone()
            } else {
                format!("(?i){pat}")
            };
            let compile_result = regex::RegexBuilder::new(&normalised)
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
            // We rebuild the (?i)-prefixed list here because `RegexSet`
            // compiles its own copy of the patterns; re-using the
            // already-prefixed strings keeps `set` and `individual` in
            // sync index-for-index.
            let prefixed: Vec<String> = accepted
                .iter()
                .map(|p| {
                    if p.starts_with("(?") {
                        p.clone()
                    } else {
                        format!("(?i){p}")
                    }
                })
                .collect();
            // Same size cap on the combined RegexSet. If the overall
            // automaton would be huge despite each individual pattern
            // fitting, we'd rather warn and run with no filter than
            // burn a peer-facing CPU budget.
            let build_result = RegexSetBuilder::new(&prefixed)
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
        (
            Self {
                set,
                raw_patterns: accepted,
                enabled,
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
        buf.push_str("# client-software string (e.g. \"eMule 0.50\", \"aMule 2.3.3\",\n");
        buf.push_str("# \"VeryCD eMule v1.0\"). Save and reload via Settings to apply.\n\n");
        for pat in &self.raw_patterns {
            buf.push_str(pat);
            buf.push('\n');
        }
        crate::security::atomic_write(path, buf.as_bytes(), false)
            .map_err(std::io::Error::other)
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

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
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
/// out the default list so the user has something to edit.
pub fn load_or_seed_defaults(data_dir: &Path, enabled: bool) -> AntiLeechFilter {
    let path = data_dir.join(DEFAULT_FILE_NAME);
    if path.exists() {
        return AntiLeechFilter::load_from_file(&path, enabled);
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
            "Ember 0.9.0",
            "Ember 1.0",
            "Ember Compat 0.50",
            "eMule Compat 0.50",
            "eMule Compat 0.50.1",
            // The `client_software_from_caps` output for our own peers
            // (with mod_version = "Ember X.Y.Z") preferred path:
            "Ember",
        ];
        for label in labels {
            assert!(
                filter.check(label).is_none(),
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
            "VeryCD eMule v1.0",
            "verycd emule v1.0", // case-insensitive
            "MagicMule 1.4",
            "Sivka 17b",
            "xMule 1.10.0",
            "eMule 0.20a",
            "eMule 0.15",
            "eMule 0.29c LEECHER mod",
        ];
        for label in blocked {
            assert!(
                filter.check(label).is_some(),
                "expected default filter to block {label:?}"
            );
        }
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
        assert!(filter.enabled(), "enabled flag must be preserved across replace");
    }

    #[test]
    fn case_insensitive_by_default() {
        let (filter, _) =
            AntiLeechFilter::from_patterns(vec!["BadMod".to_string()], true);
        assert!(filter.check("BADMOD 1.0").is_some());
        assert!(filter.check("badmod 2.0").is_some());
        assert!(filter.check("BaDmOd").is_some());
    }
}
