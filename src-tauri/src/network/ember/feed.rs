//! Feeds: a publisher's signed, updatable list of files, which anyone can
//! follow. See `docs/post-1.7.5.md`, "Follow a publisher (feeds)".
//!
//! A feed is two things. Its **head** is a small record in the Ember DHT
//! (`RECORD_TYPE_FEED`), signed by the publisher's identity and filed under
//! [`feed_key`]; it names the current list by its hashes. The **list** is an
//! ordinary collection file, fetched like any download; the head commits to
//! it, so it needs no signature of its own.
//!
//! The head uses the record header's own fields where they fit (see
//! `SignedRecord::feed_head_record`): the salt is `file_hash`, so a storer's
//! per-publisher dedupe keeps one head per feed; the list's BLAKE3 is
//! `ember_file_hash`, its size `file_size`, the title the name. The record's
//! trailer carries the rest ([`encode_feed_extra`]).
//!
//! A publisher may also list a feed in the public index, for anyone to find
//! without its link: a **listing** (`RECORD_TYPE_FEED_LISTING`) is a copy of
//! the head, flagged ([`encode_feed_listing_extra`]), filed under one of
//! [`FEED_INDEX_SHARDS`] shared keys ([`feed_index_key`]). Taking a feed out
//! of the index is a listing flagged withdrawn, which displaces the last.

use rand::rngs::OsRng;
use rand::RngCore;

/// What tells a feed's key apart from every other key derived from an
/// identity. Changing it would move every feed.
const FEED_KEY_PREFIX: &[u8] = b"ember-feed-v1";
/// The trailer's own version, ahead of its fields.
pub const FEED_HEAD_VERSION: u8 = 1;
/// The longest title, in UTF-8 bytes.
pub const FEED_TITLE_MAX: usize = 64;
/// The longest description, in UTF-8 bytes.
pub const FEED_DESCRIPTION_MAX: usize = 256;
/// Feeds one identity keeps. The client's rule; storers bound a publisher by
/// their own per-publisher budgets.
pub const FEEDS_PER_IDENTITY: usize = 8;
/// The most items one list holds.
pub const FEED_ITEMS_MAX: usize = 2_000;
/// The longest note on one item, in UTF-8 bytes.
pub const FEED_NOTE_MAX: usize = 256;

/// What tells one of an identity's feeds from another.
pub type FeedSalt = [u8; 16];

/// DHT key of the feed `salt` of `publisher`. Storers recompute it from the
/// head and refuse one filed anywhere else.
pub fn feed_key(publisher: &[u8; 32], salt: &FeedSalt) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEED_KEY_PREFIX);
    hasher.update(publisher);
    hasher.update(salt);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    key
}

/// What tells a feed-index key apart from every other key. Changing it would
/// move every listing.
const FEED_INDEX_KEY_PREFIX: &[u8] = b"ember-feed-index-v1";
/// Shards of the public feed index, as rooms' Discover has.
pub const FEED_INDEX_SHARDS: u8 = 16;
/// A listing's flag that takes its feed out of the index. Every newer listing
/// of the feed outranks the one it replaces, so this one, kept as long as a
/// listing, displaces the copies storers still hold.
pub const FEED_LISTING_WITHDRAWN: u8 = 0x01;
/// How long storers keep a listing, or a withdrawal, after it was signed:
/// the governance record lifetime in `dht::store`.
pub const FEED_LISTING_TTL_SECS: i64 = 30 * 24 * 3600;
/// A listing signed this recently says its publisher is running: one
/// signs it anew with every publish and hourly republish, and a republish
/// that does not get through is tried again within minutes.
pub const FEED_LISTING_ACTIVE_SECS: i64 = 3 * 3600;

/// The index shard the feed `salt` of `publisher` is listed in.
pub fn feed_index_shard(publisher: &[u8; 32], salt: &FeedSalt) -> u8 {
    feed_key(publisher, salt)[0] % FEED_INDEX_SHARDS
}

/// DHT key of one shard of the public feed index.
pub fn feed_index_key(shard: u8) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEED_INDEX_KEY_PREFIX);
    hasher.update(&[shard % FEED_INDEX_SHARDS]);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    key
}

/// Every shard's key, in shard order, for a Discover walk.
pub fn all_feed_index_keys() -> [[u8; 16]; FEED_INDEX_SHARDS as usize] {
    std::array::from_fn(|shard| feed_index_key(shard as u8))
}

/// The head a withdrawal carries in place of its feed's: a fixed one that
/// says nothing of the feed, as only its publisher and salt are needed to
/// displace the last listing. Its hashes are not zero, as a storer keeps a
/// record with a digest over a later one without.
pub fn withdrawal_head() -> FeedHead {
    FeedHead {
        sequence: 0,
        list_ed2k_hash: [0xFF; 16],
        list_size: 1,
        list_blake3: [0xFF; 32],
        item_count: 0,
        title: "-".into(),
        description: String::new(),
    }
}

/// A listing's trailer: `flags(1)`, then the head's own trailer
/// ([`encode_feed_extra`]). `None` for a head with a field out of bounds.
pub fn encode_feed_listing_extra(head: &FeedHead, withdrawn: bool) -> Option<Vec<u8>> {
    let head_extra = encode_feed_extra(head)?;
    let mut out = Vec::with_capacity(1 + head_extra.len());
    out.push(if withdrawn { FEED_LISTING_WITHDRAWN } else { 0 });
    out.extend_from_slice(&head_extra);
    Some(out)
}

/// A listing trailer's flags and head fields, as [`decode_feed_extra`] reads
/// them. Flag bits this build does not know are kept, for a later build's
/// listings to pass through it.
#[allow(clippy::type_complexity)]
pub fn decode_feed_listing_extra(extra: &[u8]) -> Option<(u8, (u64, [u8; 16], u32, String))> {
    let (&flags, head) = extra.split_first()?;
    Some((flags, decode_feed_extra(head)?))
}

/// A fresh salt for a new feed.
pub fn generate_feed_salt() -> FeedSalt {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// What a head says about its feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHead {
    /// Higher is newer: the publisher's clock in milliseconds, never less
    /// than one past the last it published, so the latest publish from any
    /// of its devices wins.
    pub sequence: u64,
    pub list_ed2k_hash: [u8; 16],
    pub list_size: u64,
    pub list_blake3: [u8; 32],
    pub item_count: u32,
    pub title: String,
    pub description: String,
}

impl FeedHead {
    /// Whether every field is within what a head may carry.
    pub fn valid(&self) -> bool {
        !self.title.trim().is_empty()
            && self.title.len() <= FEED_TITLE_MAX
            && self.description.len() <= FEED_DESCRIPTION_MAX
            && self.item_count as usize <= FEED_ITEMS_MAX
            && self.list_size > 0
            && self.list_ed2k_hash != [0u8; 16]
            && self.list_blake3 != [0u8; 32]
    }
}

/// The next sequence after `last`, from the clock at `now_ms`.
pub fn next_sequence(last: u64, now_ms: u64) -> u64 {
    now_ms.max(last.saturating_add(1))
}

/// The head's trailer: `version(1) || sequence(8) || list_ed2k_hash(16) ||
/// item_count(4) || description_len(2) || description`, little-endian.
pub fn encode_feed_extra(head: &FeedHead) -> Option<Vec<u8>> {
    if !head.valid() {
        return None;
    }
    let description = head.description.as_bytes();
    let mut out = Vec::with_capacity(1 + 8 + 16 + 4 + 2 + description.len());
    out.push(FEED_HEAD_VERSION);
    out.extend_from_slice(&head.sequence.to_le_bytes());
    out.extend_from_slice(&head.list_ed2k_hash);
    out.extend_from_slice(&head.item_count.to_le_bytes());
    out.extend_from_slice(&(description.len() as u16).to_le_bytes());
    out.extend_from_slice(description);
    Some(out)
}

/// The trailer's fields `(sequence, list_ed2k_hash, item_count,
/// description)`, or nothing if it is not exactly one this build writes.
pub fn decode_feed_extra(extra: &[u8]) -> Option<(u64, [u8; 16], u32, String)> {
    const FIXED: usize = 1 + 8 + 16 + 4 + 2;
    if extra.len() < FIXED || extra[0] != FEED_HEAD_VERSION {
        return None;
    }
    let sequence = u64::from_le_bytes(extra[1..9].try_into().ok()?);
    let list_ed2k_hash: [u8; 16] = extra[9..25].try_into().ok()?;
    let item_count = u32::from_le_bytes(extra[25..29].try_into().ok()?);
    let description_len = u16::from_le_bytes([extra[29], extra[30]]) as usize;
    if extra.len() != FIXED + description_len || description_len > FEED_DESCRIPTION_MAX {
        return None;
    }
    let description = String::from_utf8(extra[FIXED..].to_vec()).ok()?;
    Some((sequence, list_ed2k_hash, item_count, description))
}

/// What a feed link names: whose feed, and which of theirs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeedLink {
    pub publisher: [u8; 32],
    pub salt: FeedSalt,
}

const LINK_SCHEME: &str = "ember-feed:";
const LINK_WEB_PREFIX: &str = "https://emberp2p.org/feed/";
/// The same site under `www.`, which browsers and people add.
const LINK_WEB_PREFIX_WWW: &str = "https://www.emberp2p.org/feed/";
const BASE32: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

impl FeedLink {
    /// `ember-feed:` and the publisher's key and the salt, in base32
    /// (RFC 4648, lowercase, unpadded).
    pub fn format(&self) -> String {
        let mut bytes = [0u8; 48];
        bytes[..32].copy_from_slice(&self.publisher);
        bytes[32..].copy_from_slice(&self.salt);
        format!("{LINK_SCHEME}{}", base32_encode(&bytes))
    }

    /// The same, as the website's address a browser can open. Not handed
    /// out until the website serves it; only parsed.
    #[cfg(test)]
    pub fn web(&self) -> String {
        format!("{LINK_WEB_PREFIX}{}", self.format().trim_start_matches(LINK_SCHEME))
    }

    /// Either form, the website's with or without `www.`, with whitespace
    /// around it and in either case.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        let lower = text.to_ascii_lowercase();
        let body = lower
            .strip_prefix(LINK_SCHEME)
            .or_else(|| lower.strip_prefix(LINK_WEB_PREFIX))
            .or_else(|| lower.strip_prefix(LINK_WEB_PREFIX_WWW))?
            .trim_end_matches('/');
        let bytes = base32_decode(body)?;
        if bytes.len() != 48 {
            return None;
        }
        let mut link = FeedLink { publisher: [0; 32], salt: [0; 16] };
        link.publisher.copy_from_slice(&bytes[..32]);
        link.salt.copy_from_slice(&bytes[32..]);
        crate::network::ember::crypto::verifying_key_from_bytes(&link.publisher)?;
        Some(link)
    }
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Only the one encoding [`base32_encode`] gives for some bytes: no
/// character more than those bytes need, and padding bits zero. Otherwise
/// two texts would name one feed.
fn base32_decode(text: &str) -> Option<Vec<u8>> {
    if text.len() != (text.len() * 5 / 8 * 8).div_ceil(5) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&b| b == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    (buffer == 0).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_reads_back_in_either_form_and_refuses_anything_else() {
        let publisher = crate::network::ember::crypto::signing_key_from_bytes(&[3u8; 32]).verifying_key().to_bytes();
        let link = FeedLink { publisher, salt: [0xAB; 16] };
        let text = link.format();
        assert!(text.starts_with("ember-feed:") && text.len() == "ember-feed:".len() + 77, "{text}");
        assert_eq!(FeedLink::parse(&text), Some(link));
        assert_eq!(FeedLink::parse(&format!("  {}  ", text.to_uppercase())), Some(link));
        assert_eq!(FeedLink::parse(&link.web()), Some(link));
        let www = link.web().replace("https://emberp2p.org/", "https://www.emberp2p.org/");
        assert_eq!(FeedLink::parse(&www), Some(link));
        assert_eq!(FeedLink::parse(&format!("{}/", www.to_uppercase())), Some(link));
        assert!(FeedLink::parse(&link.web().replace("emberp2p.org", "emberp2p.org.evil")).is_none());
        assert!(FeedLink::parse(&text[..text.len() - 1]).is_none(), "short");
        assert!(FeedLink::parse("ember-feed:0000").is_none());
        assert!(FeedLink::parse("ember-channel:abc").is_none());
    }

    #[test]
    fn only_the_one_base32_spelling_of_some_bytes_is_read() {
        let bytes: Vec<u8> = (0u8..48).map(|i| i.wrapping_mul(37)).collect();
        let text = base32_encode(&bytes);
        assert_eq!(base32_decode(&text), Some(bytes.clone()));
        assert!(base32_decode(&format!("{text}a")).is_none(), "a character more than the bytes need");
        assert_eq!(base32_decode(&format!("{text}aa")).map(|b| b.len()), Some(49), "a byte more, spelt as it should be");
        // The last character of 48 bytes carries four bits and one of padding.
        let mut padded = text.clone().into_bytes();
        let last = BASE32.iter().position(|&c| c == *padded.last().unwrap()).unwrap();
        padded.pop();
        padded.push(BASE32[last | 1]);
        assert!(base32_decode(std::str::from_utf8(&padded).unwrap()).is_none(), "padding bits set");
        for n in 0..12usize {
            let bytes = vec![0xA5u8; n];
            assert_eq!(base32_decode(&base32_encode(&bytes)), Some(bytes), "{n} bytes");
        }

        let publisher = crate::network::ember::crypto::signing_key_from_bytes(&[3u8; 32]).verifying_key().to_bytes();
        let link = FeedLink { publisher, salt: [0xAB; 16] }.format();
        assert!(FeedLink::parse(&format!("{link}a")).is_none(), "a trailing character");
    }

    fn head() -> FeedHead {
        FeedHead {
            sequence: 1_900_000_000_000,
            list_ed2k_hash: [0x11; 16],
            list_size: 4_096,
            list_blake3: [0x22; 32],
            item_count: 12,
            title: "Field recordings".into(),
            description: "Birds, mostly.".into(),
        }
    }

    #[test]
    fn the_key_is_per_publisher_and_per_feed() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        let (s, t) = ([3u8; 16], [4u8; 16]);
        assert_eq!(feed_key(&a, &s), feed_key(&a, &s));
        assert_ne!(feed_key(&a, &s), feed_key(&b, &s));
        assert_ne!(feed_key(&a, &s), feed_key(&a, &t));
    }

    #[test]
    fn the_trailer_reads_back_and_refuses_anything_else() {
        let head = head();
        let extra = encode_feed_extra(&head).unwrap();
        assert_eq!(
            decode_feed_extra(&extra),
            Some((head.sequence, head.list_ed2k_hash, head.item_count, head.description.clone()))
        );
        assert!(decode_feed_extra(&extra[..extra.len() - 1]).is_none(), "short");
        let mut longer = extra.clone();
        longer.push(0);
        assert!(decode_feed_extra(&longer).is_none(), "long");
        let mut other = extra;
        other[0] = 2;
        assert!(decode_feed_extra(&other).is_none(), "another version");
    }

    #[test]
    fn a_head_out_of_bounds_is_not_encoded() {
        assert!(encode_feed_extra(&FeedHead { title: "t".repeat(FEED_TITLE_MAX + 1), ..head() }).is_none());
        assert!(encode_feed_extra(&FeedHead { title: "  ".into(), ..head() }).is_none());
        assert!(encode_feed_extra(&FeedHead { description: "d".repeat(FEED_DESCRIPTION_MAX + 1), ..head() }).is_none());
        assert!(encode_feed_extra(&FeedHead { item_count: FEED_ITEMS_MAX as u32 + 1, ..head() }).is_none());
        assert!(encode_feed_extra(&FeedHead { list_size: 0, ..head() }).is_none());
    }

    /// A head round-trips through a signed record, is filed under its key,
    /// and a storer's check refuses it anywhere else or tampered with.
    #[test]
    fn a_signed_head_reads_back_and_is_checked_against_its_key() {
        use crate::network::ember::dht::publish::SignedRecord;
        let identity = crate::network::ember::crypto::signing_key_from_bytes(&[9u8; 32]);
        let salt = [7u8; 16];
        let record = SignedRecord::feed_head_record(&salt, &head(), &identity, 1_900_000_000).unwrap();
        assert_eq!(record.keyword_hash, feed_key(&identity.verifying_key().to_bytes(), &salt));
        assert!(record.feed_store_ok());
        let blob = [record.data.clone(), record.signature.to_vec()].concat();
        assert!(SignedRecord::value_blob_is_authentic(&blob));
        let back = SignedRecord::from_value_blob(&blob).unwrap();
        assert_eq!(back.feed_head(), Some((salt, head())));
        assert!(back.channel.is_none(), "not read as a channel record");

        let mut elsewhere = record.data.clone();
        elsewhere[1] ^= 1;
        let elsewhere = SignedRecord::from_wire(&elsewhere, crate::network::ember::crypto::sign(&identity, &elsewhere)).unwrap();
        assert!(!elsewhere.feed_store_ok(), "filed under a key its salt does not give");

        let mut cut = record.data.clone();
        cut.pop();
        assert!(SignedRecord::parse_unverified(&cut, record.signature).is_none(), "a short trailer is not a record");
        assert!(SignedRecord::feed_head_record(&salt, &FeedHead { title: String::new(), ..head() }, &identity, 1).is_none());
    }

    /// A listing reads back with its head and withdrawal flag, is filed under
    /// the index shard its publisher and salt give, and a storer refuses it
    /// under any other key.
    #[test]
    fn a_signed_listing_reads_back_and_is_checked_against_its_shard() {
        use crate::network::ember::dht::publish::SignedRecord;
        let identity = crate::network::ember::crypto::signing_key_from_bytes(&[11u8; 32]);
        let publisher = identity.verifying_key().to_bytes();
        let salt = [3u8; 16];
        let shard = feed_index_shard(&publisher, &salt);
        assert!(shard < FEED_INDEX_SHARDS);

        for withdrawn in [false, true] {
            let record = SignedRecord::feed_listing_record(&salt, &head(), withdrawn, &identity, 1_900_000_000).unwrap();
            assert_eq!(record.keyword_hash, feed_index_key(shard));
            assert!(record.feed_listing_store_ok());
            assert!(!record.feed_store_ok(), "not a head");
            let blob = [record.data.clone(), record.signature.to_vec()].concat();
            assert!(SignedRecord::value_blob_is_authentic(&blob));
            let back = SignedRecord::from_value_blob(&blob).unwrap();
            assert_eq!(back.feed_listing(), Some((salt, head(), withdrawn)));
            assert_eq!(back.feed_head(), None, "a listing is not read as a head");
        }

        let record = SignedRecord::feed_listing_record(&salt, &head(), false, &identity, 1).unwrap();
        let mut elsewhere = record.data.clone();
        let other = feed_index_key((shard + 1) % FEED_INDEX_SHARDS);
        elsewhere[1..17].copy_from_slice(&other);
        let elsewhere = SignedRecord::from_wire(&elsewhere, crate::network::ember::crypto::sign(&identity, &elsewhere)).unwrap();
        assert!(!elsewhere.feed_listing_store_ok(), "filed under another shard");
        assert!(SignedRecord::feed_listing_record(&salt, &FeedHead { list_size: 0, ..head() }, false, &identity, 1).is_none());
    }

    #[test]
    fn the_index_has_sixteen_distinct_shard_keys() {
        let keys = all_feed_index_keys();
        let unique: std::collections::HashSet<_> = keys.iter().collect();
        assert_eq!(unique.len(), FEED_INDEX_SHARDS as usize);
        assert_eq!(feed_index_key(FEED_INDEX_SHARDS), feed_index_key(0));
        let room_keys = crate::network::ember::channel::all_index_keys();
        assert!(keys.iter().all(|key| !room_keys.contains(key)), "apart from the room index");
    }

    #[test]
    fn a_withdrawal_carries_nothing_of_its_feed() {
        use crate::network::ember::dht::publish::SignedRecord;
        let identity = crate::network::ember::crypto::signing_key_from_bytes(&[11u8; 32]);
        assert!(withdrawal_head().valid());
        let record = SignedRecord::feed_listing_record(&[3u8; 16], &withdrawal_head(), true, &identity, 5).unwrap();
        assert!(record.feed_listing_store_ok());
        assert_ne!(record.ember_file_hash, [0u8; 32], "a storer would keep the listing it is to displace");
        assert_eq!(record.feed_listing(), Some(([3u8; 16], withdrawal_head(), true)));
    }

    #[test]
    fn a_listing_keeps_flags_a_later_build_sets() {
        let mut extra = encode_feed_listing_extra(&head(), true).unwrap();
        extra[0] |= 0x80;
        let (flags, _) = decode_feed_listing_extra(&extra).unwrap();
        assert_eq!(flags & FEED_LISTING_WITHDRAWN, FEED_LISTING_WITHDRAWN);
        assert!(decode_feed_listing_extra(&[]).is_none());
    }

    #[test]
    fn the_sequence_follows_the_clock_and_never_goes_back() {
        assert_eq!(next_sequence(0, 5_000), 5_000);
        assert_eq!(next_sequence(9_000, 5_000), 9_001, "a clock behind the last publish");
        assert_eq!(next_sequence(u64::MAX, 5_000), u64::MAX);
    }
}
