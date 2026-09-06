//! User-facing search-query parsing (boolean keyword grammar).
//!
//! eMule/eD2k searches support a boolean keyword grammar: implicit AND between
//! adjacent words, explicit `AND` / `OR` / `NOT`, a leading `-` for negation,
//! `"quoted phrases"`, and parentheses for grouping. Historically Ember only
//! ever built a flat AND-tree of a query's keywords, so `matrix OR reloaded`
//! or `movie -cam` were treated as "must contain every word" — the opposite of
//! what the user meant. (The *inbound* parser already evaluates all of these
//! operators; only the outbound side was limited.)
//!
//! [`QueryExpr`] turns a raw query string into a boolean tree that can be
//! 1. serialized to the eD2k wire format ([`QueryExpr::to_wire_bytes`]) so the
//!    remote server / Kad node filters with the correct boolean semantics, and
//! 2. evaluated locally against a filename ([`QueryExpr::matches`]) so the Kad
//!    result set — which is only ever looked up by a single keyword hash — is
//!    narrowed to true matches on our side.
//!
//! An operator-free query is tokenized by
//! [`extract_query_keywords`](crate::network::kad::publish::extract_query_keywords)
//! and folded into a left-leaning AND-tree; the boolean parser only engages
//! when the query actually contains operators, quotes, parentheses, or a `-`
//! negation. Both paths use the eMule separator set and 3-byte minimum, so the
//! terms are the same words the publisher indexed the filename under.
//!
//! Note the query tokenizer, unlike the filename one, does **not** drop a
//! trailing three-character word. That rule exists to strip `.mkv` off a
//! filename; applied to a query it deleted the last word typed, so `linux mint
//! iso` searched for `linux AND mint` on every network at once — and the
//! boolean path never stripped, so quoting one word changed whether another
//! was searched at all.

use crate::network::kad::publish::extract_query_keywords;

const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_PARSE_DEPTH: usize = 64;

/// A parsed search query as a boolean tree of keyword terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryExpr {
    /// A single lowercased keyword (already eMule-tokenized, >= 3 bytes).
    Term(String),
    And(Box<QueryExpr>, Box<QueryExpr>),
    Or(Box<QueryExpr>, Box<QueryExpr>),
    /// `left AND NOT right` — eMule's binary NOT.
    Not(Box<QueryExpr>, Box<QueryExpr>),
}

impl QueryExpr {
    /// Serialize to the eD2k binary search-expression format
    /// (`CSearchExpr`): `0x00 <op>` operator nodes (op `0x00`=AND, `0x01`=OR,
    /// `0x02`=NOT) and `0x01 <u16 len> <bytes>` string leaves. A flat AND-tree
    /// produced from a plain keyword list is byte-identical to the output of
    /// [`build_search_expression`](crate::network::kad::messages::build_search_expression).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32);
        self.write_wire(&mut buf);
        buf
    }

    fn write_wire(&self, buf: &mut Vec<u8>) {
        match self {
            QueryExpr::Term(s) => {
                buf.push(0x01);
                // The wire length prefix is a u16, so a term whose UTF-8
                // encoding exceeds 65535 bytes would otherwise have its
                // length silently wrap (`bytes.len() as u16`), writing a
                // length prefix that doesn't match the bytes that follow
                // and desyncing the remote parser for the rest of the
                // expression. No realistic keyword approaches this size, so
                // truncate defensively at a valid UTF-8 boundary rather than
                // rejecting the whole query — this only ever engages for a
                // pathological single token.
                let mut end = s.len().min(u16::MAX as usize);
                while end > 0 && !s.is_char_boundary(end) {
                    end -= 1;
                }
                let bytes = &s.as_bytes()[..end];
                buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
                buf.extend_from_slice(bytes);
            }
            QueryExpr::And(l, r) => Self::write_op(buf, 0x00, l, r),
            QueryExpr::Or(l, r) => Self::write_op(buf, 0x01, l, r),
            QueryExpr::Not(l, r) => Self::write_op(buf, 0x02, l, r),
        }
    }

    fn write_op(buf: &mut Vec<u8>, op: u8, l: &QueryExpr, r: &QueryExpr) {
        buf.push(0x00);
        buf.push(op);
        l.write_wire(buf);
        r.write_wire(buf);
    }

    /// Evaluate the expression against a *lowercased* haystack (typically a
    /// filename). Mirrors the wire/server semantics: AND/OR on substring
    /// presence, NOT as "left present and right absent".
    pub fn matches(&self, haystack_lower: &str) -> bool {
        match self {
            QueryExpr::Term(s) => haystack_lower.contains(s.as_str()),
            QueryExpr::And(l, r) => l.matches(haystack_lower) && r.matches(haystack_lower),
            QueryExpr::Or(l, r) => l.matches(haystack_lower) || r.matches(haystack_lower),
            QueryExpr::Not(l, r) => l.matches(haystack_lower) && !r.matches(haystack_lower),
        }
    }

    /// Positive (non-negated) terms in first-occurrence order, de-duplicated.
    /// Used to pick the Kad lookup keyword and to seed the spam scorer; negated
    /// terms are intentionally excluded so we never look up / score on a term
    /// the user asked to exclude.
    pub fn positive_terms(&self) -> Vec<String> {
        let mut out = Vec::new();
        self.collect_positive(&mut out);
        let mut seen = std::collections::HashSet::new();
        out.retain(|t| seen.insert(t.clone()));
        out
    }

    fn collect_positive(&self, out: &mut Vec<String>) {
        match self {
            QueryExpr::Term(s) => out.push(s.clone()),
            QueryExpr::And(l, r) | QueryExpr::Or(l, r) => {
                l.collect_positive(out);
                r.collect_positive(out);
            }
            QueryExpr::Not(l, _r) => l.collect_positive(out),
        }
    }

    /// True when this is a single bare keyword with no boolean structure. The
    /// Kad result path skips local re-filtering in that case, preserving the
    /// previous "only filter when there is more than one keyword" behavior
    /// (a single-keyword Kad lookup is already exact for that keyword).
    pub fn is_trivial(&self) -> bool {
        matches!(self, QueryExpr::Term(_))
    }

    /// True if the tree contains an OR node (eMule Kad strip is AND-only).
    pub fn contains_or(&self) -> bool {
        match self {
            QueryExpr::Or(_, _) => true,
            QueryExpr::And(l, r) | QueryExpr::Not(l, r) => l.contains_or() || r.contains_or(),
            QueryExpr::Term(_) => false,
        }
    }

    /// True if the tree contains a NOT node.
    pub fn contains_not(&self) -> bool {
        match self {
            QueryExpr::Not(_, _) => true,
            QueryExpr::And(l, r) | QueryExpr::Or(l, r) => l.contains_not() || r.contains_not(),
            QueryExpr::Term(_) => false,
        }
    }

    /// Remove every `Term` equal to `keyword` (case-sensitive; terms are already
    /// lowercased). Used for Kad AND-only restrictive trees: eMule strips the
    /// lookup keyword from the packet because the DHT target already selects
    /// that word. Returns `None` when nothing remains.
    pub fn without_term(&self, keyword: &str) -> Option<QueryExpr> {
        match self {
            QueryExpr::Term(s) => {
                if s == keyword {
                    None
                } else {
                    Some(QueryExpr::Term(s.clone()))
                }
            }
            QueryExpr::And(l, r) => match (l.without_term(keyword), r.without_term(keyword)) {
                (None, None) => None,
                (Some(x), None) | (None, Some(x)) => Some(x),
                (Some(a), Some(b)) => Some(QueryExpr::And(Box::new(a), Box::new(b))),
            },
            QueryExpr::Or(l, r) => {
                // OR trees are not stripped for Kad (eMule keeps the full tree).
                Some(QueryExpr::Or(
                    Box::new(l.as_ref().clone()),
                    Box::new(r.as_ref().clone()),
                ))
            }
            QueryExpr::Not(l, r) => Some(QueryExpr::Not(
                Box::new(l.as_ref().clone()),
                Box::new(r.as_ref().clone()),
            )),
        }
    }
}

/// Positive keyword terms for spam scoring / learning, matching the network
/// search path. Empty when the query does not parse to any positive term.
pub fn positive_terms_from_query(query: &str) -> Vec<String> {
    parse(query.trim())
        .map(|e| e.positive_terms())
        .unwrap_or_default()
}

/// Parse a raw user query into a [`QueryExpr`], or `None` when it yields no
/// usable keyword (e.g. only sub-3-byte words). Operator-free queries are
/// tokenized exactly like [`extract_keywords`] for full backward compatibility.
pub fn parse(query: &str) -> Option<QueryExpr> {
    let query = clamp_query(query);
    // A whole query that is nothing but a server directive is the common case
    // — it is what eMule's "Search Related Files" is a shortcut for, and what
    // a user pastes — and the operator-free path below tokenizes through the
    // Kad publisher's splitter, which knows nothing about directives. Catch it
    // here; `tokenize_term` handles one that appears alongside operators.
    if let Some(term) = server_directive(query.trim()) {
        return Some(QueryExpr::Term(term));
    }
    if !has_operators(query) {
        return fold_and(
            extract_query_keywords(query)
                .into_iter()
                .map(QueryExpr::Term)
                .collect(),
        );
    }

    let toks = lex(query);
    let mut parser = Parser { toks, pos: 0 };
    if let Some(expr) = parser.parse_or(0) {
        return Some(expr);
    }

    // The boolean parse produced nothing usable (e.g. every term was too
    // short). Fall back to the plain tokenizer so the query still searches.
    fold_and(
        extract_query_keywords(query)
            .into_iter()
            .map(QueryExpr::Term)
            .collect(),
    )
}

fn clamp_query(query: &str) -> &str {
    if query.len() <= MAX_QUERY_BYTES {
        return query;
    }
    let mut end = MAX_QUERY_BYTES;
    while end > 0 && !query.is_char_boundary(end) {
        end -= 1;
    }
    &query[..end]
}

/// Whether `query` contains anything that needs the boolean parser. Plain
/// space-separated queries skip it entirely and go through [`extract_keywords`].
fn has_operators(query: &str) -> bool {
    for raw in query.split_whitespace() {
        if raw.contains('(') || raw.contains(')') || raw.contains('"') {
            return true;
        }
        if raw.starts_with('-') && raw.len() > 1 {
            return true;
        }
        let upper = raw.to_ascii_uppercase();
        if upper == "AND" || upper == "OR" || upper == "NOT" {
            return true;
        }
    }
    false
}

/// Fold a list of operands into a left-leaning AND chain
/// (`AND(AND(a, b), c)`), matching the wire layout the flat keyword path emits.
fn fold_and(mut nodes: Vec<QueryExpr>) -> Option<QueryExpr> {
    if nodes.is_empty() {
        return None;
    }
    let mut acc = nodes.remove(0);
    for node in nodes {
        acc = QueryExpr::And(Box::new(acc), Box::new(node));
    }
    Some(acc)
}

/// Split a raw word/phrase into eMule keyword tokens (same separator set and
/// 3-byte minimum as [`extract_keywords`], minus the whole-query de-dup and
/// trailing-extension strip, which only make sense for an entire filename).
fn tokenize_term(raw: &str) -> Vec<String> {
    if let Some(term) = server_directive(raw) {
        return vec![term];
    }
    raw.split(is_keyword_separator)
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_lowercase())
        .collect()
}

/// A term the eD2k server interprets itself rather than matching against
/// filenames: `related::<hash>` (files commonly shared alongside that hash) and
/// `ed2k::<hash>` (that exact file), both optionally naming a size as
/// `related:<size>:<hash>`, and both accepting several hashes.
///
/// These have to survive tokenization whole. `:` is in our separator set, so
/// `related::<hash>` would otherwise come apart into `related` AND the hash and
/// go out as an ordinary filename search that matches nothing — which is how a
/// directive typed into the search box, or a related search built anywhere that
/// routes through this parser, turns silently into a search for nothing.
///
/// eMule keeps them whole by counting `:` as an ordinary keyword character
/// (`Scanner.l`: `keywordchar` is `[^ \"()<>=]`), and its own scanner comment
/// says so outright — "`ed2k::<hash>` is to be handled as any other string
/// term". Its "Search Related Files" menu item is documented as nothing more
/// than a shortcut for typing `related::<hash>` into the search field, and
/// aMule documents the same syntax for users, so this is the form servers
/// actually implement.
///
/// The hash is upper-cased to match the form eMule's own menu item generates
/// (`md4str` uses an upper-case alphabet), since a server free to compare the
/// hex as text rather than parse it would only ever have been tested against
/// that.
fn server_directive(raw: &str) -> Option<String> {
    let (directive, rest) = raw
        .split_once(':')
        .map(|(head, rest)| (head.to_ascii_lowercase(), rest))?;
    if directive != "related" && directive != "ed2k" {
        return None;
    }
    // `related::<hash>` leaves the size field empty; `related:<size>:<hash>`
    // fills it. Anything else is a word that merely began with "ed2k:".
    let mut fields = rest.split(':');
    let size = fields.next()?;
    if !size.is_empty() && !size.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // Each additional hash arrives as `::<hash>`, so the fields between them
    // are empty — that second colon is a separator, not a field.
    let hashes: Vec<String> = fields
        .filter(|f| !f.is_empty())
        .map(|h| h.to_ascii_uppercase())
        .collect();
    if hashes.is_empty() || !hashes.iter().all(|h| is_md4_hex(h)) {
        return None;
    }
    // Rebuilt in the exact shape eMule writes: `related::H1::H2`, or
    // `related:<size>:<hash>` where a size is given.
    let mut term = directive;
    let mut rest = hashes.as_slice();
    if !size.is_empty() {
        term.push(':');
        term.push_str(size);
        term.push(':');
        term.push_str(&hashes[0]);
        rest = &hashes[1..];
    }
    for hash in rest {
        term.push_str("::");
        term.push_str(hash);
    }
    Some(term)
}

fn is_md4_hex(hash: &str) -> bool {
    hash.len() == 32 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_keyword_separator(c: char) -> bool {
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
}

enum Tok {
    LParen,
    RParen,
    And,
    Or,
    Not,
    Word(String),
    Phrase(String),
}

fn lex(query: &str) -> Vec<Tok> {
    let chars: Vec<char> = query.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                toks.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                toks.push(Tok::RParen);
                i += 1;
            }
            '"' => {
                i += 1;
                let start = i;
                while i < chars.len() && chars[i] != '"' {
                    i += 1;
                }
                let phrase: String = chars[start..i].iter().collect();
                if i < chars.len() {
                    i += 1; // consume closing quote
                }
                toks.push(Tok::Phrase(phrase));
            }
            '-' => {
                // A '-' at a token boundary is negation; consume just the dash
                // so the following run becomes the negated primary.
                toks.push(Tok::Not);
                i += 1;
            }
            _ => {
                let start = i;
                while i < chars.len()
                    && !chars[i].is_whitespace()
                    && chars[i] != '('
                    && chars[i] != ')'
                    && chars[i] != '"'
                {
                    i += 1;
                }
                let raw: String = chars[start..i].iter().collect();
                match raw.to_ascii_uppercase().as_str() {
                    "AND" => toks.push(Tok::And),
                    "OR" => toks.push(Tok::Or),
                    "NOT" => toks.push(Tok::Not),
                    _ => toks.push(Tok::Word(raw)),
                }
            }
        }
    }
    toks
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn advance(&mut self) {
        self.pos += 1;
    }

    /// `or_expr := and_expr ( OR and_expr )*`
    fn parse_or(&mut self, depth: usize) -> Option<QueryExpr> {
        let mut left = self.parse_and(depth);
        while matches!(self.peek(), Some(Tok::Or)) {
            self.advance();
            let right = self.parse_and(depth);
            left = match (left, right) {
                (Some(l), Some(r)) => Some(QueryExpr::Or(Box::new(l), Box::new(r))),
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            };
        }
        left
    }

    /// `and_expr := ( NOT? primary )+` with implicit AND between primaries.
    fn parse_and(&mut self, depth: usize) -> Option<QueryExpr> {
        let mut positives: Vec<QueryExpr> = Vec::new();
        let mut negatives: Vec<QueryExpr> = Vec::new();
        loop {
            match self.peek() {
                None | Some(Tok::Or) | Some(Tok::RParen) => break,
                Some(Tok::And) => self.advance(),
                Some(Tok::Not) => {
                    self.advance();
                    if let Some(p) = self.parse_primary(depth) {
                        negatives.push(p);
                    }
                }
                Some(Tok::LParen) | Some(Tok::Word(_)) | Some(Tok::Phrase(_)) => {
                    if let Some(p) = self.parse_primary(depth) {
                        positives.push(p);
                    }
                }
            }
        }

        let mut acc = if !positives.is_empty() {
            fold_and(positives)?
        } else if !negatives.is_empty() {
            // Degenerate all-negative group (e.g. just "-foo"): there is nothing
            // to subtract from, so treat the negated terms as positives rather
            // than emitting a "match everything except" search.
            return fold_and(negatives);
        } else {
            return None;
        };

        for neg in negatives {
            acc = QueryExpr::Not(Box::new(acc), Box::new(neg));
        }
        Some(acc)
    }

    /// `primary := '(' or_expr ')' | quoted | word`
    fn parse_primary(&mut self, depth: usize) -> Option<QueryExpr> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.advance();
                if depth >= MAX_PARSE_DEPTH {
                    self.skip_balanced_group();
                    return None;
                }
                let inner = self.parse_or(depth + 1);
                if matches!(self.peek(), Some(Tok::RParen)) {
                    self.advance();
                }
                inner
            }
            Some(Tok::Word(w)) => {
                let raw = w.clone();
                self.advance();
                fold_and(
                    tokenize_term(&raw)
                        .into_iter()
                        .map(QueryExpr::Term)
                        .collect(),
                )
            }
            Some(Tok::Phrase(p)) => {
                let raw = p.clone();
                self.advance();
                fold_and(
                    tokenize_term(&raw)
                        .into_iter()
                        .map(QueryExpr::Term)
                        .collect(),
                )
            }
            _ => None,
        }
    }

    fn skip_balanced_group(&mut self) {
        let mut nested = 1usize;
        while let Some(tok) = self.peek() {
            match tok {
                Tok::LParen => nested += 1,
                Tok::RParen => {
                    nested = nested.saturating_sub(1);
                    self.advance();
                    if nested == 0 {
                        break;
                    }
                    continue;
                }
                _ => {}
            }
            self.advance();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(s: &str) -> QueryExpr {
        QueryExpr::Term(s.to_string())
    }

    const HASH: &str = "AABBCCDDEEFF00112233445566778899";

    /// eMule's "Search Related Files" is documented as a shortcut for typing
    /// `related::<hash>` into the search box, and aMule documents the syntax
    /// for users, so it has to work typed as well as clicked. `:` being a
    /// keyword separator here meant it came apart into `related` AND the hash
    /// and went out as a filename search matching nothing.
    #[test]
    fn a_server_directive_stays_one_term() {
        assert_eq!(parse(&format!("related::{HASH}")), Some(term(&format!("related::{HASH}"))));
        assert_eq!(parse(&format!("ed2k::{HASH}")), Some(term(&format!("ed2k::{HASH}"))));
        // eMule: "related::<file hash> or related:<file size>:<file hash>".
        assert_eq!(
            parse(&format!("related:1234:{HASH}")),
            Some(term(&format!("related:1234:{HASH}")))
        );
        // Several hashes in one request (eserver 17.14 and later).
        assert_eq!(
            parse(&format!("related::{HASH}::{HASH}")),
            Some(term(&format!("related::{HASH}::{HASH}")))
        );
    }

    /// Upper-cased to match what eMule's own menu item puts on the wire
    /// (`md4str` uses an upper-case alphabet), since a server that compares the
    /// hex as text rather than parsing it would only have been tested on that.
    #[test]
    fn a_directive_hash_is_normalized_to_the_form_emule_sends() {
        assert_eq!(
            parse(&format!("RELATED::{}", HASH.to_lowercase())),
            Some(term(&format!("related::{HASH}")))
        );
    }

    /// A directive is only a directive when it really names hashes. Anything
    /// else keeps the ordinary tokenization, including an ed2k link — which the
    /// paste handler deals with, and which must not become one 100-byte term.
    #[test]
    fn near_misses_are_still_ordinary_keywords() {
        for query in [
            "related::not-a-hash",
            "related::aabbcc",
            "ed2k://|file|movie.mkv|734003200|AABBCCDDEEFF00112233445566778899|/",
            "relatedness::stuff",
            &format!("related:size:{HASH}"),
        ] {
            let parsed = parse(query).expect("still a usable keyword query");
            assert!(
                parsed.positive_terms().len() > 1 || !parsed.positive_terms()[0].contains("::"),
                "{query} should tokenize normally, got {:?}",
                parsed.positive_terms()
            );
        }
    }

    /// aMule documents combining a directive with other constraints, e.g.
    /// `related::<hash> AND Video`, so it has to survive the operator path too
    /// — that one tokenizes through `tokenize_term` rather than the flat
    /// splitter the whole-query check covers.
    #[test]
    fn a_directive_survives_alongside_operators() {
        let parsed = parse(&format!("related::{HASH} AND video")).expect("parses");
        assert_eq!(
            parsed.positive_terms(),
            vec![format!("related::{HASH}"), "video".to_string()]
        );
    }

    /// Mirror of the flat AND-tree the legacy path emits, for byte-compat checks.
    fn flat_wire(keywords: &[&str]) -> Vec<u8> {
        let nodes: Vec<QueryExpr> = keywords.iter().map(|k| term(k)).collect();
        fold_and(nodes).unwrap().to_wire_bytes()
    }

    #[test]
    fn plain_query_is_left_leaning_and_tree() {
        let expr = parse("the matrix reloaded").unwrap();
        assert_eq!(
            expr,
            QueryExpr::And(
                Box::new(QueryExpr::And(
                    Box::new(term("the")),
                    Box::new(term("matrix"))
                )),
                Box::new(term("reloaded"))
            )
        );
    }

    #[test]
    fn plain_query_wire_matches_flat_keyword_tree() {
        // The boolean path must not change the bytes for operator-free queries.
        let expr = parse("alpha bravo charlie").unwrap();
        assert_eq!(
            expr.to_wire_bytes(),
            flat_wire(&["alpha", "bravo", "charlie"])
        );
    }

    #[test]
    fn single_keyword_is_trivial() {
        let expr = parse("ubuntu").unwrap();
        assert_eq!(expr, term("ubuntu"));
        assert!(expr.is_trivial());
    }

    #[test]
    fn or_operator_builds_or_node() {
        let expr = parse("matrix OR reloaded").unwrap();
        assert_eq!(
            expr,
            QueryExpr::Or(Box::new(term("matrix")), Box::new(term("reloaded")))
        );
        assert!(!expr.is_trivial());
        assert!(expr.matches("the matrix 1999"));
        assert!(expr.matches("reloaded edition"));
        assert!(!expr.matches("unrelated movie"));
    }

    #[test]
    fn dash_negation_excludes_term() {
        let expr = parse("movie -cam").unwrap();
        assert_eq!(
            expr,
            QueryExpr::Not(Box::new(term("movie")), Box::new(term("cam")))
        );
        assert!(expr.matches("great movie bluray"));
        assert!(!expr.matches("great movie cam rip"));
        // Negated terms are not used for Kad lookup / spam scoring.
        assert_eq!(expr.positive_terms(), vec!["movie".to_string()]);
    }

    #[test]
    fn without_term_strips_primary_from_and_tree() {
        let expr = parse("matrix reloaded").unwrap();
        let stripped = expr.without_term("matrix").unwrap();
        assert_eq!(stripped, term("reloaded"));
        assert!(expr
            .without_term("matrix")
            .unwrap()
            .without_term("reloaded")
            .is_none());
        assert!(!expr.contains_or());
        assert!(!expr.contains_not());
        let or_expr = parse("matrix OR reloaded").unwrap();
        assert!(or_expr.contains_or());
        // OR trees keep both terms when "stripping"
        assert_eq!(or_expr.without_term("matrix"), Some(or_expr.clone()));
    }

    #[test]
    fn not_keyword_same_as_dash() {
        let dash = parse("movie -cam").unwrap();
        let word = parse("movie NOT cam").unwrap();
        assert_eq!(dash, word);
    }

    #[test]
    fn quoted_phrase_becomes_and_of_words() {
        let expr = parse("\"the matrix\"").unwrap();
        assert_eq!(
            expr,
            QueryExpr::And(Box::new(term("the")), Box::new(term("matrix")))
        );
    }

    #[test]
    fn parentheses_group_or_under_and() {
        // movie AND (1080p OR 720p)
        let expr = parse("movie (1080p OR 720p)").unwrap();
        assert_eq!(
            expr,
            QueryExpr::And(
                Box::new(term("movie")),
                Box::new(QueryExpr::Or(
                    Box::new(term("1080p")),
                    Box::new(term("720p"))
                ))
            )
        );
        assert!(expr.matches("movie 1080p x264"));
        assert!(expr.matches("movie 720p x264"));
        assert!(!expr.matches("movie 480p x264"));
    }

    #[test]
    fn or_has_lower_precedence_than_and() {
        // a b OR c  ==  (a AND b) OR c
        let expr = parse("alpha bravo OR charlie").unwrap();
        assert_eq!(
            expr,
            QueryExpr::Or(
                Box::new(QueryExpr::And(
                    Box::new(term("alpha")),
                    Box::new(term("bravo"))
                )),
                Box::new(term("charlie"))
            )
        );
    }

    /// `extract_keywords` pops a trailing three-character token because on a
    /// *filename* that is the extension. A query is not a filename: the last
    /// word is usually the most specific thing the user typed.
    #[test]
    fn a_three_letter_last_word_survives_a_query() {
        for (query, expected) in [
            ("linux mint iso", vec!["linux", "mint", "iso"]),
            ("star wars dvd", vec!["star", "wars", "dvd"]),
            ("the big cat", vec!["the", "big", "cat"]),
        ] {
            let expr = parse(query).expect("query parses");
            assert_eq!(expr.positive_terms(), expected, "query {query:?}");
        }
    }

    /// The boolean path never stripped, so the two halves of the parser
    /// disagreed: quoting one word changed whether another was searched at all.
    #[test]
    fn both_parser_paths_agree_on_a_three_letter_last_word() {
        let plain = parse("ubuntu server iso").expect("plain parses");
        let boolean = parse("ubuntu AND server AND iso").expect("boolean parses");
        assert_eq!(plain.positive_terms(), boolean.positive_terms());
    }

    #[test]
    fn internal_punctuation_splits_like_extract_keywords() {
        // No leading dash: "anti-virus" is one word that tokenizes to two terms.
        let expr = parse("anti-virus tool").unwrap();
        assert!(expr.matches("best anti virus tool"));
        let pos = expr.positive_terms();
        assert!(pos.contains(&"anti".to_string()));
        assert!(pos.contains(&"virus".to_string()));
        assert!(pos.contains(&"tool".to_string()));
    }

    #[test]
    fn negated_wire_uses_not_opcode() {
        let expr = parse("movie -cam").unwrap();
        let wire = expr.to_wire_bytes();
        // 0x00 0x02 = NOT operator node, then two string leaves.
        assert_eq!(wire[0], 0x00);
        assert_eq!(wire[1], 0x02);
    }

    #[test]
    fn empty_or_too_short_query_is_none() {
        assert!(parse("").is_none());
        assert!(parse("a b").is_none()); // both < 3 bytes
    }

    #[test]
    fn leading_only_negation_falls_back_to_positive() {
        // "-cam" alone has nothing to subtract from; treat it as a positive
        // search rather than "everything except cam".
        let expr = parse("-cam").unwrap();
        assert_eq!(expr, term("cam"));
    }

    #[test]
    fn oversized_term_is_truncated_not_length_wrapped() {
        // A term far longer than u16::MAX bytes must not produce a wire
        // length prefix that undercounts (via `as u16` wraparound) the
        // bytes actually written, which would desync a remote parser
        // reading the rest of the expression.
        let huge = "a".repeat(u16::MAX as usize + 500);
        let expr = term(&huge);
        let wire = expr.to_wire_bytes();
        assert_eq!(wire[0], 0x01);
        let declared_len = u16::from_le_bytes([wire[1], wire[2]]) as usize;
        assert_eq!(declared_len, u16::MAX as usize);
        assert_eq!(wire.len(), 3 + declared_len);
    }

    #[test]
    fn deeply_nested_boolean_query_falls_back_without_recursing_unbounded() {
        let query = format!(
            "{}alpha{}",
            "(".repeat(MAX_PARSE_DEPTH + 16),
            ")".repeat(MAX_PARSE_DEPTH + 16)
        );
        let expr = parse(&query).unwrap();
        assert_eq!(expr, term("alpha"));
    }

    #[test]
    fn very_long_query_is_clamped_before_boolean_parse() {
        let query = format!("{} OR bravo", "alpha ".repeat(MAX_QUERY_BYTES));
        let expr = parse(&query).unwrap();
        assert!(expr.positive_terms().contains(&"alpha".to_string()));
    }

    #[test]
    fn oversized_multibyte_term_truncates_at_char_boundary() {
        // A multi-byte UTF-8 term truncated at exactly u16::MAX bytes could
        // land mid-codepoint; the truncation must back off to a valid
        // boundary so `str::from_utf8` on the receiving end doesn't fail.
        let huge: String = "é".repeat((u16::MAX as usize / 2) + 500);
        let expr = term(&huge);
        let wire = expr.to_wire_bytes();
        let declared_len = u16::from_le_bytes([wire[1], wire[2]]) as usize;
        assert!(declared_len <= u16::MAX as usize);
        let term_bytes = &wire[3..3 + declared_len];
        assert!(std::str::from_utf8(term_bytes).is_ok());
    }
}
