//! Room libraries: one member of a private room browsing the files another
//! keeps for that room alone, and asking for one of them.
//!
//! Two frames carry it, [`LIBRARY_REQUEST_PLAIN_VERSION`] and
//! [`LIBRARY_ANSWER_PLAIN_VERSION`], both addressed to one member and sent
//! the way a transfer frame is: never relayed on, and sealed to the pair, so
//! a member a frame passes through on its way learns who is asking whom, as
//! of a transfer, but not what. A frame is
//!
//! `version(1) || sender(32) || target(32) || request_id(16) || nonce(24) || ciphertext`
//!
//! - **The key** comes from the two members' identities and the room
//!   (`derive_pairwise_capability`, purpose `ch-lib-v1 || channel_id`), so it
//!   opens nothing else: not a private message, not a transfer, not this
//!   pair's frames in another room.
//! - **The ciphertext** is XChaCha20-Poly1305 over a plaintext padded to one
//!   length per direction, with the room and the whole header as associated
//!   data, so a frame cannot be moved to another room, pair or request, and a
//!   page of a folder is the same length as a refusal.
//! - **The request id** pairs an answer with what asked for it; the asker
//!   drops an answer it is not waiting for. A fetch's is the transfer id the
//!   file is then offered under, so the offer finds the request it answers.
//!
//! Whether a member's library is open to a room travels room-wide instead, as
//! extension frame [`EXT_KIND_ROOM_LIBRARY`] with body [`encode_status`].
//!
//! [`LIBRARY_REQUEST_PLAIN_VERSION`]: super::channel::LIBRARY_REQUEST_PLAIN_VERSION
//! [`LIBRARY_ANSWER_PLAIN_VERSION`]: super::channel::LIBRARY_ANSWER_PLAIN_VERSION
//! [`EXT_KIND_ROOM_LIBRARY`]: super::channel::EXT_KIND_ROOM_LIBRARY

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key as ChaChaKey, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use super::channel::{LIBRARY_ANSWER_PLAIN_VERSION, LIBRARY_REQUEST_PLAIN_VERSION, XFER_NAME_MAX};
use super::crypto;

const LIBRARY_PURPOSE: &[u8] = b"ch-lib-v1";
const KEY_CONTEXT: &str = "ember room library key v1";
const AAD_DOMAIN: &[u8] = b"ember-room-library-v1\0";
const HEADER_LEN: usize = 1 + 32 + 32 + 16;
const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
/// `type(1) || len(2)` ahead of the fields.
const PLAIN_HEADER_LEN: usize = 3;

/// What every request is padded to: a search, the longest, is under half.
pub const REQUEST_PLAIN_LEN: usize = 160;
/// What every answer is padded to. The frame then comes to the length of a
/// transfer's data block, which is sized to cross a relay hop in one
/// unfragmented datagram; `an_answer_fits_one_unfragmented_datagram` pins it.
pub const ANSWER_PLAIN_LEN: usize = 992;

/// Bytes of an entry id: a folder's or a file's, opaque to the asker.
pub const ENTRY_ID_LEN: usize = 8;
pub type EntryId = [u8; ENTRY_ID_LEN];

/// The longest search, in UTF-8 bytes.
pub const QUERY_MAX_BYTES: usize = 64;
/// The longest name an entry carries: a transfer's, so the file saved under
/// an offer has the name the asker was shown.
pub const NAME_MAX_BYTES: usize = XFER_NAME_MAX;
/// The longest folder a search result names.
pub const FOLDER_MAX_BYTES: usize = 120;

const REQUEST_LIST: u8 = 1;
const REQUEST_FETCH: u8 = 2;

const ANSWER_PAGE: u8 = 1;
const ANSWER_CLOSED: u8 = 2;
const ANSWER_MISSING: u8 = 3;
const ANSWER_PREPARING: u8 = 4;
const ANSWER_REFUSED: u8 = 5;

const ENTRY_FOLDER: u8 = 0;
const ENTRY_FILE: u8 = 1;

/// `kind(1) || id(8) || items or size(8) || modified(8) || name_len(1) || folder_len(1)`.
const ENTRY_FIXED_LEN: usize = 1 + ENTRY_ID_LEN + 8 + 8 + 1 + 1;
/// `total(4) || offset(4) || count(1)` ahead of a page's entries.
const PAGE_HEADER_LEN: usize = 4 + 4 + 1;

/// The version byte the status body starts with.
const STATUS_VERSION: u8 = 1;

/// What one member asks of another's library. Its `Debug` leaves a search
/// out, so a logged command never carries one.
#[derive(Clone, PartialEq, Eq)]
pub enum LibraryRequest {
    /// A page of one folder, or of the library's top when `folder` is `None`.
    /// With a query, a page of the files anywhere in the library whose names
    /// hold every word of it, and `folder` is not read.
    List { folder: Option<EntryId>, offset: u32, query: String },
    /// That file, offered as a transfer under the request's id, if it is still
    /// the `size` it was listed at.
    Fetch { file: EntryId, size: u64 },
}

impl std::fmt::Debug for LibraryRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LibraryRequest::List { folder, offset, query } => write!(
                f,
                "List {{ folder: {}, offset: {offset}, query: {} bytes }}",
                folder.is_some(),
                query.len()
            ),
            LibraryRequest::Fetch { size, .. } => write!(f, "Fetch {{ size: {size} }}"),
        }
    }
}

/// A folder or a file in a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A folder, with how many folders and files are directly in it.
    Folder { items: u32 },
    File { size: u64 },
}

/// One row of a page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryEntry {
    pub id: EntryId,
    pub kind: EntryKind,
    /// Last modified, Unix seconds; 0 when unknown.
    pub modified: i64,
    pub name: String,
    /// For a search result, the folder it is in, from the library's top;
    /// empty otherwise.
    pub folder: String,
}

impl LibraryEntry {
    fn wire_len(&self) -> usize {
        ENTRY_FIXED_LEN + self.name.len() + self.folder.len()
    }

    fn fits_limits(&self) -> bool {
        !self.name.is_empty() && self.name.len() <= NAME_MAX_BYTES && self.folder.len() <= FOLDER_MAX_BYTES
    }
}

/// A page of a folder or of a search: entries `offset..` of `total`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LibraryPage {
    pub total: u32,
    pub offset: u32,
    pub entries: Vec<LibraryEntry>,
}

impl LibraryPage {
    /// As many of `entries`, in order, as one answer holds. An entry over the
    /// wire's limits ends the page rather than being skipped, so the asker's
    /// next offset still points at it and nothing after it is lost.
    pub fn fill(total: u32, offset: u32, entries: impl IntoIterator<Item = LibraryEntry>) -> Self {
        let mut room = ANSWER_PLAIN_LEN - PLAIN_HEADER_LEN - PAGE_HEADER_LEN;
        let mut taken = Vec::new();
        for entry in entries {
            let len = entry.wire_len();
            if !entry.fits_limits() || len > room || taken.len() == u8::MAX as usize {
                break;
            }
            room -= len;
            taken.push(entry);
        }
        Self { total, offset, entries: taken }
    }
}

/// Why a file was not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchRefusal {
    /// No longer in the library, or no longer the file that was listed.
    Gone,
    /// Too much is being readied or sent already: ask again later.
    Busy,
    /// It could not be read.
    Failed,
}

impl FetchRefusal {
    fn byte(self) -> u8 {
        match self {
            FetchRefusal::Gone => 1,
            FetchRefusal::Busy => 2,
            FetchRefusal::Failed => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(FetchRefusal::Gone),
            2 => Some(FetchRefusal::Busy),
            3 => Some(FetchRefusal::Failed),
            _ => None,
        }
    }
}

/// What the library's owner answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LibraryAnswer {
    Page(LibraryPage),
    /// The library is not open to this room, or to the asker.
    Closed,
    /// The folder asked for is not in the library, or no longer.
    Missing,
    /// The file is being readied; its offer follows.
    Preparing,
    Refused(FetchRefusal),
}

/// The key one pair of members seals their library frames in one room with.
pub struct LibraryKey(Zeroizing<[u8; 32]>);

impl LibraryKey {
    /// `None` when `peer` is not a usable key.
    pub fn derive(our_seed: &[u8; 32], peer: &[u8; 32], channel_id: &[u8; 16]) -> Option<Self> {
        let mut purpose = Vec::with_capacity(LIBRARY_PURPOSE.len() + 16);
        purpose.extend_from_slice(LIBRARY_PURPOSE);
        purpose.extend_from_slice(channel_id);
        let base = Zeroizing::new(crypto::derive_pairwise_capability(our_seed, peer, &purpose, 0)?);
        Some(Self(Zeroizing::new(blake3::derive_key(KEY_CONTEXT, base.as_slice()))))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(ChaChaKey::from_slice(self.0.as_slice()))
    }
}

/// The header of a library frame: `(version, sender, target, request_id)`.
///
/// Unauthenticated, like [`super::channel::xfer_frame_peek`]: it says which
/// key to derive, and nothing in it is to be believed until the frame opens.
pub fn frame_peek(bytes: &[u8]) -> Option<(u8, [u8; 32], [u8; 32], [u8; 16])> {
    let version = *bytes.first()?;
    if version != LIBRARY_REQUEST_PLAIN_VERSION && version != LIBRARY_ANSWER_PLAIN_VERSION {
        return None;
    }
    if bytes.len() < HEADER_LEN + NONCE_LEN + AEAD_TAG_LEN {
        return None;
    }
    let sender: [u8; 32] = bytes[1..33].try_into().ok()?;
    let target: [u8; 32] = bytes[33..65].try_into().ok()?;
    let request_id: [u8; 16] = bytes[65..81].try_into().ok()?;
    Some((version, sender, target, request_id))
}

pub fn seal_request(
    key: &LibraryKey,
    channel_id: &[u8; 16],
    sender: &[u8; 32],
    target: &[u8; 32],
    request_id: &[u8; 16],
    request: &LibraryRequest,
) -> Option<Vec<u8>> {
    let plain = encode_request(request)?;
    seal(key, LIBRARY_REQUEST_PLAIN_VERSION, channel_id, sender, target, request_id, &plain)
}

pub fn open_request(key: &LibraryKey, channel_id: &[u8; 16], frame: &[u8]) -> Option<LibraryRequest> {
    let plain = open(key, LIBRARY_REQUEST_PLAIN_VERSION, channel_id, frame)?;
    decode_request(&plain)
}

pub fn seal_answer(
    key: &LibraryKey,
    channel_id: &[u8; 16],
    sender: &[u8; 32],
    target: &[u8; 32],
    request_id: &[u8; 16],
    answer: &LibraryAnswer,
) -> Option<Vec<u8>> {
    let plain = encode_answer(answer)?;
    seal(key, LIBRARY_ANSWER_PLAIN_VERSION, channel_id, sender, target, request_id, &plain)
}

pub fn open_answer(key: &LibraryKey, channel_id: &[u8; 16], frame: &[u8]) -> Option<LibraryAnswer> {
    let plain = open(key, LIBRARY_ANSWER_PLAIN_VERSION, channel_id, frame)?;
    decode_answer(&plain)
}

/// The body of an [`EXT_KIND_ROOM_LIBRARY`](super::channel::EXT_KIND_ROOM_LIBRARY)
/// frame: `version(1) || open(1)`.
pub fn encode_status(open: bool) -> Vec<u8> {
    vec![STATUS_VERSION, u8::from(open)]
}

/// Whether a status body says open. `None` for a shape this build does not
/// write, so a later version is not read as either answer.
pub fn decode_status(body: &[u8]) -> Option<bool> {
    match body {
        [STATUS_VERSION, 0] => Some(false),
        [STATUS_VERSION, 1] => Some(true),
        _ => None,
    }
}

fn associated_data(version: u8, channel_id: &[u8; 16], header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + 1 + 16 + HEADER_LEN);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.push(version);
    aad.extend_from_slice(channel_id);
    aad.extend_from_slice(header);
    aad
}

fn seal(
    key: &LibraryKey,
    version: u8,
    channel_id: &[u8; 16],
    sender: &[u8; 32],
    target: &[u8; 32],
    request_id: &[u8; 16],
    plain: &[u8],
) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + plain.len() + AEAD_TAG_LEN);
    out.push(version);
    out.extend_from_slice(sender);
    out.extend_from_slice(target);
    out.extend_from_slice(request_id);
    let aad = associated_data(version, channel_id, &out);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = key
        .cipher()
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain, aad: &aad })
        .ok()?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Some(out)
}

fn open(key: &LibraryKey, version: u8, channel_id: &[u8; 16], frame: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    if frame.first() != Some(&version) || frame.len() < HEADER_LEN + NONCE_LEN + AEAD_TAG_LEN {
        return None;
    }
    let (header, rest) = frame.split_at(HEADER_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let aad = associated_data(version, channel_id, header);
    let plain = key
        .cipher()
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
        .ok()?;
    Some(Zeroizing::new(plain))
}

/// `type || len || fields`, zero-padded to `size`. `None` when the fields do
/// not fit.
fn pad(kind: u8, fields: &[u8], size: usize) -> Option<Vec<u8>> {
    if PLAIN_HEADER_LEN + fields.len() > size {
        return None;
    }
    let mut out = Vec::with_capacity(size);
    out.push(kind);
    out.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    out.extend_from_slice(fields);
    out.resize(size, 0);
    Some(out)
}

/// The type and fields of a padded plaintext of exactly `size` bytes whose
/// padding is zeros.
fn unpad(plain: &[u8], size: usize) -> Option<(u8, &[u8])> {
    if plain.len() != size {
        return None;
    }
    let len = u16::from_le_bytes([plain[1], plain[2]]) as usize;
    let fields = plain.get(PLAIN_HEADER_LEN..PLAIN_HEADER_LEN + len)?;
    if plain[PLAIN_HEADER_LEN + len..].iter().any(|&b| b != 0) {
        return None;
    }
    Some((plain[0], fields))
}

fn encode_request(request: &LibraryRequest) -> Option<Vec<u8>> {
    match request {
        LibraryRequest::List { folder, offset, query } => {
            if query.len() > QUERY_MAX_BYTES {
                return None;
            }
            let mut fields = Vec::with_capacity(1 + ENTRY_ID_LEN + 4 + 1 + query.len());
            fields.push(u8::from(folder.is_some()));
            fields.extend_from_slice(&folder.unwrap_or_default());
            fields.extend_from_slice(&offset.to_le_bytes());
            fields.push(query.len() as u8);
            fields.extend_from_slice(query.as_bytes());
            pad(REQUEST_LIST, &fields, REQUEST_PLAIN_LEN)
        }
        LibraryRequest::Fetch { file, size } => {
            let mut fields = Vec::with_capacity(ENTRY_ID_LEN + 8);
            fields.extend_from_slice(file);
            fields.extend_from_slice(&size.to_le_bytes());
            pad(REQUEST_FETCH, &fields, REQUEST_PLAIN_LEN)
        }
    }
}

fn decode_request(plain: &[u8]) -> Option<LibraryRequest> {
    let (kind, fields) = unpad(plain, REQUEST_PLAIN_LEN)?;
    match kind {
        REQUEST_LIST => {
            let has_folder = match *fields.first()? {
                0 => false,
                1 => true,
                _ => return None,
            };
            let id: EntryId = fields.get(1..1 + ENTRY_ID_LEN)?.try_into().ok()?;
            let at = 1 + ENTRY_ID_LEN;
            let offset = u32::from_le_bytes(fields.get(at..at + 4)?.try_into().ok()?);
            let query_len = *fields.get(at + 4)? as usize;
            if query_len > QUERY_MAX_BYTES || fields.len() != at + 5 + query_len {
                return None;
            }
            let query = std::str::from_utf8(&fields[at + 5..]).ok()?.to_string();
            Some(LibraryRequest::List {
                folder: has_folder.then_some(id),
                offset,
                query,
            })
        }
        REQUEST_FETCH if fields.len() == ENTRY_ID_LEN + 8 => Some(LibraryRequest::Fetch {
            file: fields[..ENTRY_ID_LEN].try_into().ok()?,
            size: u64::from_le_bytes(fields[ENTRY_ID_LEN..].try_into().ok()?),
        }),
        _ => None,
    }
}

fn encode_answer(answer: &LibraryAnswer) -> Option<Vec<u8>> {
    match answer {
        LibraryAnswer::Page(page) => {
            if page.entries.len() > u8::MAX as usize {
                return None;
            }
            let mut fields = Vec::with_capacity(ANSWER_PLAIN_LEN);
            fields.extend_from_slice(&page.total.to_le_bytes());
            fields.extend_from_slice(&page.offset.to_le_bytes());
            fields.push(page.entries.len() as u8);
            for entry in &page.entries {
                if !entry.fits_limits() {
                    return None;
                }
                let (kind, value) = match entry.kind {
                    EntryKind::Folder { items } => (ENTRY_FOLDER, u64::from(items)),
                    EntryKind::File { size } => (ENTRY_FILE, size),
                };
                fields.push(kind);
                fields.extend_from_slice(&entry.id);
                fields.extend_from_slice(&value.to_le_bytes());
                fields.extend_from_slice(&entry.modified.to_le_bytes());
                fields.push(entry.name.len() as u8);
                fields.push(entry.folder.len() as u8);
                fields.extend_from_slice(entry.name.as_bytes());
                fields.extend_from_slice(entry.folder.as_bytes());
            }
            pad(ANSWER_PAGE, &fields, ANSWER_PLAIN_LEN)
        }
        LibraryAnswer::Closed => pad(ANSWER_CLOSED, &[], ANSWER_PLAIN_LEN),
        LibraryAnswer::Missing => pad(ANSWER_MISSING, &[], ANSWER_PLAIN_LEN),
        LibraryAnswer::Preparing => pad(ANSWER_PREPARING, &[], ANSWER_PLAIN_LEN),
        LibraryAnswer::Refused(reason) => pad(ANSWER_REFUSED, &[reason.byte()], ANSWER_PLAIN_LEN),
    }
}

fn decode_answer(plain: &[u8]) -> Option<LibraryAnswer> {
    let (kind, fields) = unpad(plain, ANSWER_PLAIN_LEN)?;
    match kind {
        ANSWER_PAGE => decode_page(fields).map(LibraryAnswer::Page),
        ANSWER_CLOSED if fields.is_empty() => Some(LibraryAnswer::Closed),
        ANSWER_MISSING if fields.is_empty() => Some(LibraryAnswer::Missing),
        ANSWER_PREPARING if fields.is_empty() => Some(LibraryAnswer::Preparing),
        ANSWER_REFUSED => match fields {
            [reason] => FetchRefusal::from_byte(*reason).map(LibraryAnswer::Refused),
            _ => None,
        },
        _ => None,
    }
}

fn decode_page(fields: &[u8]) -> Option<LibraryPage> {
    let total = u32::from_le_bytes(fields.get(0..4)?.try_into().ok()?);
    let offset = u32::from_le_bytes(fields.get(4..8)?.try_into().ok()?);
    let count = *fields.get(8)? as usize;
    let mut at = PAGE_HEADER_LEN;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let fixed = fields.get(at..at + ENTRY_FIXED_LEN)?;
        let value = u64::from_le_bytes(fixed[1 + ENTRY_ID_LEN..1 + ENTRY_ID_LEN + 8].try_into().ok()?);
        let kind = match fixed[0] {
            ENTRY_FOLDER => EntryKind::Folder { items: u32::try_from(value).ok()? },
            ENTRY_FILE => EntryKind::File { size: value },
            _ => return None,
        };
        let id: EntryId = fixed[1..1 + ENTRY_ID_LEN].try_into().ok()?;
        let modified_at = 1 + ENTRY_ID_LEN + 8;
        let modified = i64::from_le_bytes(fixed[modified_at..modified_at + 8].try_into().ok()?);
        let name_len = fixed[ENTRY_FIXED_LEN - 2] as usize;
        let folder_len = fixed[ENTRY_FIXED_LEN - 1] as usize;
        at += ENTRY_FIXED_LEN;
        let name = std::str::from_utf8(fields.get(at..at + name_len)?).ok()?.to_string();
        at += name_len;
        let folder = std::str::from_utf8(fields.get(at..at + folder_len)?).ok()?.to_string();
        at += folder_len;
        let entry = LibraryEntry { id, kind, modified, name, folder };
        if !entry.fits_limits() {
            return None;
        }
        entries.push(entry);
    }
    if at != fields.len() {
        return None;
    }
    Some(LibraryPage { total, offset, entries })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    const ROOM: [u8; 16] = [7u8; 16];
    const REQUEST: [u8; 16] = [9u8; 16];

    fn pair() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let alice = SigningKey::generate(&mut OsRng);
        let bob = SigningKey::generate(&mut OsRng);
        (
            alice.to_bytes(),
            alice.verifying_key().to_bytes(),
            bob.to_bytes(),
            bob.verifying_key().to_bytes(),
        )
    }

    fn file(n: u8, name: &str) -> LibraryEntry {
        LibraryEntry {
            id: [n; ENTRY_ID_LEN],
            kind: EntryKind::File { size: 1000 + u64::from(n) },
            modified: 1_700_000_000 + i64::from(n),
            name: name.to_string(),
            folder: String::new(),
        }
    }

    #[test]
    fn a_request_opens_for_the_other_member_and_only_in_its_room() {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let alice = LibraryKey::derive(&a_seed, &b_pub, &ROOM).unwrap();
        let bob = LibraryKey::derive(&b_seed, &a_pub, &ROOM).unwrap();
        for request in [
            LibraryRequest::List { folder: None, offset: 0, query: String::new() },
            LibraryRequest::List { folder: Some([3; ENTRY_ID_LEN]), offset: 42, query: "live 1999".into() },
            LibraryRequest::Fetch { file: [5; ENTRY_ID_LEN], size: 123_456 },
        ] {
            let frame = seal_request(&alice, &ROOM, &a_pub, &b_pub, &REQUEST, &request).unwrap();
            assert_eq!(frame.len(), HEADER_LEN + NONCE_LEN + REQUEST_PLAIN_LEN + AEAD_TAG_LEN);
            assert_eq!(
                frame_peek(&frame),
                Some((LIBRARY_REQUEST_PLAIN_VERSION, a_pub, b_pub, REQUEST))
            );
            assert_eq!(open_request(&bob, &ROOM, &frame), Some(request));
            assert!(open_request(&bob, &[8u8; 16], &frame).is_none(), "another room");
            assert!(open_answer(&bob, &ROOM, &frame).is_none(), "a request is not an answer");
        }
    }

    #[test]
    fn a_third_member_cannot_open_a_frame_or_put_a_name_on_one() {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let (c_seed, c_pub, _, _) = pair();
        let alice = LibraryKey::derive(&a_seed, &b_pub, &ROOM).unwrap();
        let frame = seal_answer(&alice, &ROOM, &a_pub, &b_pub, &REQUEST, &LibraryAnswer::Closed).unwrap();
        // Carol holds the room's key but not the pair's.
        let carol = LibraryKey::derive(&c_seed, &a_pub, &ROOM).unwrap();
        assert!(open_answer(&carol, &ROOM, &frame).is_none());
        // Nor can she keep the body and claim it is from her or for her.
        let bob = LibraryKey::derive(&b_seed, &a_pub, &ROOM).unwrap();
        let mut moved = frame.clone();
        moved[1..33].copy_from_slice(&c_pub);
        assert!(open_answer(&bob, &ROOM, &moved).is_none());
        let mut other_request = frame.clone();
        other_request[65] ^= 1;
        assert!(open_answer(&bob, &ROOM, &other_request).is_none());
        assert_eq!(open_answer(&bob, &ROOM, &frame), Some(LibraryAnswer::Closed));
    }

    #[test]
    fn every_answer_is_one_length() {
        let (a_seed, a_pub, _, b_pub) = pair();
        let key = LibraryKey::derive(&a_seed, &b_pub, &ROOM).unwrap();
        let page = LibraryPage::fill(3, 0, vec![file(1, "a.flac"), file(2, "b.flac")]);
        let lengths: Vec<usize> = [
            LibraryAnswer::Page(page),
            LibraryAnswer::Page(LibraryPage::default()),
            LibraryAnswer::Closed,
            LibraryAnswer::Missing,
            LibraryAnswer::Preparing,
            LibraryAnswer::Refused(FetchRefusal::Busy),
        ]
        .iter()
        .map(|answer| seal_answer(&key, &ROOM, &a_pub, &b_pub, &REQUEST, answer).unwrap().len())
        .collect();
        assert!(lengths.iter().all(|len| *len == lengths[0]), "{lengths:?}");
    }

    #[test]
    fn a_page_round_trips_folders_files_and_search_folders() {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let alice = LibraryKey::derive(&a_seed, &b_pub, &ROOM).unwrap();
        let bob = LibraryKey::derive(&b_seed, &a_pub, &ROOM).unwrap();
        let entries = vec![
            LibraryEntry {
                id: [1; ENTRY_ID_LEN],
                kind: EntryKind::Folder { items: 12 },
                modified: 0,
                name: "Live — 1999".into(),
                folder: String::new(),
            },
            LibraryEntry {
                folder: "Music/Albums".into(),
                ..file(2, "track 01.flac")
            },
        ];
        let page = LibraryPage::fill(40, 20, entries.clone());
        assert_eq!(page.entries, entries);
        let frame = seal_answer(&alice, &ROOM, &a_pub, &b_pub, &REQUEST, &LibraryAnswer::Page(page.clone())).unwrap();
        assert_eq!(open_answer(&bob, &ROOM, &frame), Some(LibraryAnswer::Page(page)));
    }

    #[test]
    fn a_page_takes_what_fits_and_stops_at_an_entry_over_the_limits() {
        let long = "x".repeat(NAME_MAX_BYTES);
        let many: Vec<LibraryEntry> = (0..40).map(|n| file(n, &long)).collect();
        let page = LibraryPage::fill(40, 0, many);
        assert!(!page.entries.is_empty() && page.entries.len() < 40);
        assert!(encode_answer(&LibraryAnswer::Page(page)).is_some(), "what it took is encodable");

        let over = "y".repeat(NAME_MAX_BYTES + 1);
        let page = LibraryPage::fill(3, 0, vec![file(1, "a"), file(2, &over), file(3, "c")]);
        assert_eq!(page.entries, vec![file(1, "a")], "stops rather than skipping");
    }

    #[test]
    fn malformed_plaintexts_are_refused() {
        // Padding that is not zeros.
        let mut plain = encode_request(&LibraryRequest::Fetch { file: [1; ENTRY_ID_LEN], size: 9 }).unwrap();
        *plain.last_mut().unwrap() = 1;
        assert!(decode_request(&plain).is_none());
        // A query over the limit is neither written nor read.
        let long = "q".repeat(QUERY_MAX_BYTES + 1);
        assert!(encode_request(&LibraryRequest::List { folder: None, offset: 0, query: long }).is_none());
        // A folder flag that is neither 0 nor 1.
        let mut plain = encode_request(&LibraryRequest::List { folder: None, offset: 0, query: "a".into() }).unwrap();
        plain[PLAIN_HEADER_LEN] = 2;
        assert!(decode_request(&plain).is_none());
        // An unknown refusal reason, an unknown answer type.
        assert!(decode_answer(&pad(ANSWER_REFUSED, &[9], ANSWER_PLAIN_LEN).unwrap()).is_none());
        assert!(decode_answer(&pad(99, &[], ANSWER_PLAIN_LEN).unwrap()).is_none());
        // A page whose count promises more entries than it holds.
        let mut fields = Vec::new();
        fields.extend_from_slice(&5u32.to_le_bytes());
        fields.extend_from_slice(&0u32.to_le_bytes());
        fields.push(2);
        assert!(decode_answer(&pad(ANSWER_PAGE, &fields, ANSWER_PLAIN_LEN).unwrap()).is_none());
    }

    #[test]
    fn status_bodies_are_read_only_in_the_shape_written() {
        assert_eq!(decode_status(&encode_status(true)), Some(true));
        assert_eq!(decode_status(&encode_status(false)), Some(false));
        assert_eq!(decode_status(&[STATUS_VERSION, 2]), None);
        assert_eq!(decode_status(&[STATUS_VERSION + 1, 1]), None);
        assert_eq!(decode_status(&[STATUS_VERSION, 1, 0]), None);
    }

    /// Answers are the largest frames here and cross relays like transfer
    /// blocks do, so they get the same budget the block frame is held to.
    #[test]
    fn an_answer_fits_one_unfragmented_datagram() {
        let budget = crate::network::ember::dht::messages::MAX_UNFRAGMENTED_PAYLOAD;
        let framed = HEADER_LEN
            + NONCE_LEN
            + ANSWER_PLAIN_LEN
            + AEAD_TAG_LEN
            + super::super::channel::GOSSIP_HEADER_LEN
            + super::super::channel::GOSSIP_ENVELOPE_OVERHEAD
            + super::super::channel::CHANNEL_RELAY_ENVELOPE_HEADER;
        assert!(framed <= budget, "an answer frame is {framed} bytes, over {budget}");
    }
}
