//! Feeds: a publisher's signed, updatable list of files, which anyone can
//! follow. See `docs/post-1.7.5.md`, "Follow a publisher (feeds)".
//!
//! A feed is two things. Its **head** is a small record in the Ember DHT
//! (`RECORD_TYPE_FEED`), signed by the publisher's identity and filed under
//! [`feed_key`]; it names the current list by its hashes. The **list** is a
//! collection file, sealed ([`seal_list`]) and fetched like any download; the
//! head commits to it, so it needs no signature of its own.
//!
//! A feed is public to whoever has its link, and to nobody else unless it is
//! listed: the salt only the link holds is never on the network. The head is
//! filed under the salt's [`feed_locator`], which is its `file_hash`, so a
//! storer's per-publisher dedupe keeps one head per feed; everything in it
//! but its sequence is sealed under a key derived from the salt
//! ([`encode_sealed_head`]), and so is the list. A storer sees who publishes
//! a feed and when, and nothing of what it is.
//!
//! A publisher may also list a feed in the public index, for anyone to find
//! without its link: a **listing** (`RECORD_TYPE_FEED_LISTING`) carries the
//! salt and the head in the clear, flagged ([`encode_feed_listing_extra`]),
//! filed under one of [`FEED_INDEX_SHARDS`] shared keys ([`feed_index_key`]).
//! Taking a feed out of the index is a listing flagged withdrawn, which
//! displaces the last.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;

/// What tells a feed's key apart from every other key derived from an
/// identity. Changing it would move every feed.
const FEED_KEY_PREFIX: &[u8] = b"ember-feed-v2";
/// The head trailer's version, ahead of its fields: its sequence in the
/// clear, the rest sealed. Storers keep any later version, which they read
/// the sequence of and nothing more.
pub const FEED_HEAD_VERSION: u8 = 2;
/// The version of the head a listing carries in the clear.
pub const FEED_LISTED_HEAD_VERSION: u8 = 1;
/// The name a head record carries, its title being sealed.
pub const FEED_HEAD_RECORD_NAME: &str = "-";
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

/// What tells one of an identity's feeds from another. Secret to whoever has
/// the feed's link; never sent.
pub type FeedSalt = [u8; 16];

/// What a head names its feed by in the salt's place: derived from it, and
/// telling nothing of it.
pub type FeedLocator = [u8; 16];

const LOCATOR_CONTEXT: &str = "Ember feed locator v1";
const HEAD_KEY_CONTEXT: &str = "Ember feed head key v1";
const LIST_KEY_CONTEXT: &str = "Ember feed list key v1";
const NONCE_KEY_CONTEXT: &str = "Ember feed nonce key v1";
const HEAD_AAD_PREFIX: &[u8] = b"ember-feed-head";
/// What a sealed list starts with.
pub const SEALED_LIST_MAGIC: &[u8; 8] = b"EMBRFL01";
/// What sealing adds to what it seals: a nonce and a tag.
const SEAL_OVERHEAD: usize = 24 + 16;

/// The locator of the feed `salt`.
pub fn feed_locator(salt: &FeedSalt) -> FeedLocator {
    let key = blake3::derive_key(LOCATOR_CONTEXT, salt);
    let mut locator = [0u8; 16];
    locator.copy_from_slice(&key[..16]);
    locator
}

/// DHT key of the feed `salt` of `publisher`.
pub fn feed_key(publisher: &[u8; 32], salt: &FeedSalt) -> [u8; 16] {
    feed_key_at(publisher, &feed_locator(salt))
}

/// [`feed_key`], from the feed's locator: what storers recompute from a head,
/// refusing one filed anywhere else.
pub fn feed_key_at(publisher: &[u8; 32], locator: &FeedLocator) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(FEED_KEY_PREFIX);
    hasher.update(publisher);
    hasher.update(locator);
    let mut key = [0u8; 16];
    key.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    key
}

/// `plaintext` sealed under the key `context` derives from `salt`, bound to
/// `aad`: `nonce(24) || ciphertext || tag(16)`, XChaCha20-Poly1305. The nonce
/// is a keyed hash of what is sealed, so the same bytes seal the same way: a
/// list written again from its items is the list its head names.
fn seal(context: &str, salt: &FeedSalt, aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let mut nonce_hasher = blake3::Hasher::new_keyed(&blake3::derive_key(NONCE_KEY_CONTEXT, salt));
    nonce_hasher.update(&(aad.len() as u64).to_le_bytes());
    nonce_hasher.update(aad);
    nonce_hasher.update(plaintext);
    let digest = nonce_hasher.finalize();
    let nonce = &digest.as_bytes()[..24];
    let key = blake3::derive_key(context, salt);
    let sealed = XChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .ok()?;
    Some([nonce, &sealed].concat())
}

/// What [`seal`] sealed, if `sealed` is that and untouched.
fn open(context: &str, salt: &FeedSalt, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < SEAL_OVERHEAD {
        return None;
    }
    let (nonce, ciphertext) = sealed.split_at(24);
    let key = blake3::derive_key(context, salt);
    XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .ok()
}

fn head_aad(publisher: &[u8; 32], locator: &FeedLocator, version: u8, sequence: u64) -> Vec<u8> {
    [HEAD_AAD_PREFIX, &[version], publisher, locator, &sequence.to_le_bytes()].concat()
}

/// A head's trailer: `version(1) = 2 || sequence(8) || sealed`, little-endian,
/// where `sealed` is [`seal`] of `list_ed2k_hash(16) || list_blake3(32) ||
/// list_size(8) || item_count(4) || title_len(1) || title ||
/// description_len(2) || description` under the head key, bound to the
/// publisher, the locator, the version and the sequence. `None` for a head
/// with a field out of bounds.
pub fn encode_sealed_head(publisher: &[u8; 32], salt: &FeedSalt, head: &FeedHead) -> Option<Vec<u8>> {
    if !head.valid() {
        return None;
    }
    let (title, description) = (head.title.as_bytes(), head.description.as_bytes());
    let mut body = Vec::with_capacity(16 + 32 + 8 + 4 + 1 + title.len() + 2 + description.len());
    body.extend_from_slice(&head.list_ed2k_hash);
    body.extend_from_slice(&head.list_blake3);
    body.extend_from_slice(&head.list_size.to_le_bytes());
    body.extend_from_slice(&head.item_count.to_le_bytes());
    body.push(u8::try_from(title.len()).ok()?);
    body.extend_from_slice(title);
    body.extend_from_slice(&u16::try_from(description.len()).ok()?.to_le_bytes());
    body.extend_from_slice(description);
    let aad = head_aad(publisher, &feed_locator(salt), FEED_HEAD_VERSION, head.sequence);
    let sealed = seal(HEAD_KEY_CONTEXT, salt, &aad, &body)?;
    let mut out = Vec::with_capacity(1 + 8 + sealed.len());
    out.push(FEED_HEAD_VERSION);
    out.extend_from_slice(&head.sequence.to_le_bytes());
    out.extend_from_slice(&sealed);
    Some(out)
}

/// The head a trailer of [`encode_sealed_head`] seals, for the feed `salt` of
/// `publisher`: `None` for another version, another feed's, or one tampered
/// with, cut short or out of bounds.
pub fn decode_sealed_head(publisher: &[u8; 32], salt: &FeedSalt, extra: &[u8]) -> Option<FeedHead> {
    if extra.len() < 1 + 8 + SEAL_OVERHEAD || extra[0] != FEED_HEAD_VERSION {
        return None;
    }
    let sequence = u64::from_le_bytes(extra[1..9].try_into().ok()?);
    let aad = head_aad(publisher, &feed_locator(salt), FEED_HEAD_VERSION, sequence);
    let body = open(HEAD_KEY_CONTEXT, salt, &aad, &extra[9..])?;
    let at = &mut 0usize;
    let list_ed2k_hash: [u8; 16] = take(&body, at, 16)?.try_into().ok()?;
    let list_blake3: [u8; 32] = take(&body, at, 32)?.try_into().ok()?;
    let list_size = u64::from_le_bytes(take(&body, at, 8)?.try_into().ok()?);
    let item_count = u32::from_le_bytes(take(&body, at, 4)?.try_into().ok()?);
    let title_len = usize::from(take(&body, at, 1)?[0]);
    let title = String::from_utf8(take(&body, at, title_len)?.to_vec()).ok()?;
    let description_len = usize::from(u16::from_le_bytes(take(&body, at, 2)?.try_into().ok()?));
    let description = String::from_utf8(take(&body, at, description_len)?.to_vec()).ok()?;
    if *at != body.len() {
        return None;
    }
    let head = FeedHead { sequence, list_ed2k_hash, list_size, list_blake3, item_count, title, description };
    head.valid().then_some(head)
}

/// The `n` bytes of `body` at `*at`, moving it past them.
fn take<'a>(body: &'a [u8], at: &mut usize, n: usize) -> Option<&'a [u8]> {
    let bytes = body.get(*at..at.checked_add(n)?)?;
    *at += n;
    Some(bytes)
}

/// The sequence a head's trailer carries in the clear, of this version or a
/// later one: what a storer ranks a feed's heads by, reading nothing more.
pub fn head_sequence(extra: &[u8]) -> Option<u64> {
    if extra.first().is_none_or(|version| *version < FEED_HEAD_VERSION) {
        return None;
    }
    Some(u64::from_le_bytes(extra.get(1..9)?.try_into().ok()?))
}

/// `list`, a collection file's bytes, sealed for the feed `salt` of
/// `publisher`: [`SEALED_LIST_MAGIC`], then [`seal`] of the bytes under the
/// list key, bound to the magic, the publisher and the locator. The same
/// bytes seal the same way.
pub fn seal_list(publisher: &[u8; 32], salt: &FeedSalt, list: &[u8]) -> Option<Vec<u8>> {
    let aad = list_aad(publisher, salt);
    let sealed = seal(LIST_KEY_CONTEXT, salt, &aad, list)?;
    Some([SEALED_LIST_MAGIC.as_slice(), &sealed].concat())
}

/// The collection file [`seal_list`] sealed, if `bytes` are that list of the
/// feed `salt` of `publisher`, whole and untouched.
pub fn open_list(publisher: &[u8; 32], salt: &FeedSalt, bytes: &[u8]) -> Option<Vec<u8>> {
    let sealed = bytes.strip_prefix(SEALED_LIST_MAGIC.as_slice())?;
    open(LIST_KEY_CONTEXT, salt, &list_aad(publisher, salt), sealed)
}

fn list_aad(publisher: &[u8; 32], salt: &FeedSalt) -> Vec<u8> {
    [SEALED_LIST_MAGIC.as_slice(), publisher, &feed_locator(salt)].concat()
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
/// How long storers keep a listing, or a withdrawal, after it was signed
/// (`FEED_LISTING_TTL` in `dht::store`). A week: its publisher signs it anew
/// every hour it runs, and junk listings that fill the index lapse within it
/// unless their signers keep at it.
pub const FEED_LISTING_TTL_SECS: i64 = 7 * 24 * 3600;
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

/// Whether a storer keeps a listing of this trailer: flags, and a head of
/// this version or a later one, whatever follows. Only a follower reads the
/// rest, so a later build's listings pass through this one.
pub fn listing_storable(extra: &[u8]) -> bool {
    extra.get(1).is_some_and(|version| *version >= FEED_LISTED_HEAD_VERSION)
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

/// The head a listing carries in the clear, after its flags: `version(1) = 1
/// || sequence(8) || list_ed2k_hash(16) || item_count(4) ||
/// description_len(2) || description`, little-endian, the record's own fields
/// carrying the rest.
pub fn encode_feed_extra(head: &FeedHead) -> Option<Vec<u8>> {
    if !head.valid() {
        return None;
    }
    let description = head.description.as_bytes();
    let mut out = Vec::with_capacity(1 + 8 + 16 + 4 + 2 + description.len());
    out.push(FEED_LISTED_HEAD_VERSION);
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
    if extra.len() < FIXED || extra[0] != FEED_LISTED_HEAD_VERSION {
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

/// The span of a feed file each entry of the feed stream's chunk list names.
pub const FEED_CHUNK_SIZE: usize = 256 * 1024;

const _: () = assert!(
    FEED_CHUNK_SIZE == super::attach::ATTACH_CHUNK_SIZE && FEED_CHUNK_SIZE.is_multiple_of(1024),
    "a feed chunk is a stream chunk, and a whole number of BLAKE3 chunks"
);

/// What the feed stream names chunk `index` of `count` by: the chunk's
/// chaining value in the file's own BLAKE3 tree, so the list is checked
/// against the file's BLAKE3 ([`root_of_chunk_values`]) and each chunk
/// against the list. A file of one chunk is named by its BLAKE3 itself,
/// which has no tree above it.
pub fn chunk_value(index: usize, count: usize, chunk: &[u8]) -> [u8; 32] {
    use blake3::hazmat::HasherExt;
    if count <= 1 {
        return *blake3::hash(chunk).as_bytes();
    }
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset(index as u64 * FEED_CHUNK_SIZE as u64);
    hasher.update(chunk);
    hasher.finalize_non_root()
}

/// The BLAKE3 of the file whose chunks [`chunk_value`] names `values`.
/// `None` for none.
pub fn root_of_chunk_values(values: &[[u8; 32]]) -> Option<[u8; 32]> {
    use blake3::hazmat::{merge_subtrees_root, Mode};
    match values {
        [] => None,
        [only] => Some(*only),
        _ => {
            let (left, right) = values.split_at(left_subtrees(values.len()));
            Some(*merge_subtrees_root(&merge_chunk_values(left), &merge_chunk_values(right), Mode::Hash).as_bytes())
        }
    }
}

/// The chaining value of the subtree `values` name.
fn merge_chunk_values(values: &[[u8; 32]]) -> [u8; 32] {
    use blake3::hazmat::{merge_subtrees_non_root, Mode};
    match values {
        [only] => *only,
        _ => {
            let (left, right) = values.split_at(left_subtrees(values.len()));
            merge_subtrees_non_root(&merge_chunk_values(left), &merge_chunk_values(right), Mode::Hash)
        }
    }
}

/// How many of `count` chunks BLAKE3's tree puts on the left: the largest
/// power of two below `count`, as only the last chunk may be short.
fn left_subtrees(count: usize) -> usize {
    debug_assert!(count > 1);
    1 << (usize::BITS - 1 - (count - 1).leading_zeros())
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

    /// A head's trailer names nothing of its feed but its sequence, opens
    /// only under its own feed's salt and publisher, and refuses tampering.
    #[test]
    fn a_sealed_head_reads_back_only_for_its_feed() {
        let (publisher, salt) = ([5u8; 32], [6u8; 16]);
        let extra = encode_sealed_head(&publisher, &salt, &head()).unwrap();
        assert_eq!(extra[0], FEED_HEAD_VERSION);
        assert_eq!(head_sequence(&extra), Some(head().sequence));
        let text = String::from_utf8_lossy(&extra);
        assert!(!text.contains("Field recordings") && !text.contains("Birds"), "the title and description are sealed");
        assert!(!extra.windows(16).any(|w| w == head().list_ed2k_hash), "the list is not named");
        assert_eq!(encode_sealed_head(&publisher, &salt, &head()), Some(extra.clone()), "the same head seals the same way");
        assert_eq!(decode_sealed_head(&publisher, &salt, &extra), Some(head()));
        assert!(decode_sealed_head(&publisher, &[7u8; 16], &extra).is_none(), "another feed's salt");
        assert!(decode_sealed_head(&[8u8; 32], &salt, &extra).is_none(), "another publisher");
        let mut moved = extra.clone();
        moved[1] ^= 1;
        assert!(decode_sealed_head(&publisher, &salt, &moved).is_none(), "its sequence is bound to what it seals");
        let mut cut = extra.clone();
        cut.pop();
        assert!(decode_sealed_head(&publisher, &salt, &cut).is_none(), "cut short");
        let mut later = extra;
        later[0] = FEED_HEAD_VERSION + 1;
        later.push(0);
        assert_eq!(head_sequence(&later), Some(head().sequence), "a storer reads a later version's sequence");
        assert!(decode_sealed_head(&publisher, &salt, &later).is_none(), "and only a later build reads the rest");
        assert_eq!(head_sequence(&[1, 0, 0, 0, 0, 0, 0, 0, 0]), None, "an older version is not one");
    }

    #[test]
    fn the_locator_is_derived_from_the_salt_and_tells_nothing_of_it() {
        let salt = [9u8; 16];
        assert_eq!(feed_locator(&salt), feed_locator(&salt));
        assert_ne!(feed_locator(&salt), salt);
        assert_ne!(feed_locator(&salt), feed_locator(&[10u8; 16]));
        assert_eq!(feed_key(&[1; 32], &salt), feed_key_at(&[1; 32], &feed_locator(&salt)));
    }

    #[test]
    fn a_sealed_list_opens_only_for_its_feed() {
        let list = b"a collection file's bytes".to_vec();
        let (publisher, salt) = ([5u8; 32], [6u8; 16]);
        let sealed = seal_list(&publisher, &salt, &list).unwrap();
        assert!(sealed.starts_with(SEALED_LIST_MAGIC));
        assert_eq!(seal_list(&publisher, &salt, &list), Some(sealed.clone()), "the same list seals the same way");
        assert_eq!(open_list(&publisher, &salt, &sealed), Some(list.clone()));
        assert!(open_list(&publisher, &[7u8; 16], &sealed).is_none());
        assert!(open_list(&[8u8; 32], &salt, &sealed).is_none());
        assert!(open_list(&publisher, &salt, &list).is_none(), "a list in the clear");
    }

    /// The chunk values of a file come to its BLAKE3 whatever its length:
    /// one chunk, an exact number, a short last one, and counts on either
    /// side of a power of two.
    #[test]
    fn chunk_values_come_to_the_files_blake3() {
        let chunk = FEED_CHUNK_SIZE;
        for size in [1, 1024, chunk, chunk + 1, 2 * chunk, 3 * chunk - 7, 4 * chunk, 5 * chunk + 1, 8 * chunk + 3] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
            let count = size.div_ceil(chunk);
            let values: Vec<[u8; 32]> =
                data.chunks(chunk).enumerate().map(|(index, bytes)| chunk_value(index, count, bytes)).collect();
            assert_eq!(root_of_chunk_values(&values), Some(*blake3::hash(&data).as_bytes()), "{size} bytes");
            if count > 1 {
                let mut swapped = values.clone();
                swapped.swap(0, 1);
                assert_ne!(root_of_chunk_values(&swapped), Some(*blake3::hash(&data).as_bytes()), "{size} bytes, reordered");
            }
        }
        assert_eq!(root_of_chunk_values(&[]), None);
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
        assert_eq!(back.feed_head(&salt), Some(head()));
        assert_eq!(back.feed_head(&[8u8; 16]), None, "another feed's salt");
        assert_eq!(back.file_hash, feed_locator(&salt), "the salt is not in the record");
        assert!(!blob.windows(16).any(|w| w == salt), "nor anywhere in it");
        assert!(!String::from_utf8_lossy(&blob).contains("Field recordings"), "nor the title");
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
            assert_eq!(back.feed_head(&salt), None, "a listing is not read as a head");
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
