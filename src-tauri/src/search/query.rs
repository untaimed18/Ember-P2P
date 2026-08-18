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
//! To stay byte-for-byte compatible with the previous behavior, an
//! operator-free query is tokenized by
//! [`extract_keywords`](crate::network::kad::publish::extract_keywords) exactly
//! as before and folded into the same left-leaning AND-tree; the boolean parser
//! only engages when the query actually contains operators, quotes,
//! parentheses, or a `-` negation.

use crate::network::kad::publish::extract_keywords;

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
    if !has_operators(query) {
        return fold_and(
            extract_keywords(query)
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
        extract_keywords(query)
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
    raw.split(is_keyword_separator)
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_lowercase())
        .collect()
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
