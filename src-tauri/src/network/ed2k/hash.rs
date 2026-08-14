// SECURITY NOTE: The ed2k protocol mandates MD4 for file identification hashes.
// MD4 is cryptographically broken (practical collision attacks since 2004). An
// attacker can craft a malicious file with the same ed2k hash as a legitimate one.
// This cannot be changed without breaking eMule/KAD network compatibility.
// AICH (SHA-1 Merkle tree) provides a secondary verification layer.

use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use digest::Digest;
use md4::Md4;

pub const PARTSIZE: u64 = 9_728_000;

const HASH_BUF_SIZE: usize = 1024 * 1024;

/// Non-cancellable version used by download verification (transfer.rs, multi_source.rs).
pub fn ed2k_hash_file(path: &Path) -> anyhow::Result<String> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    ed2k_hash_file_cancellable(path, &NEVER)
}

pub fn ed2k_part_hashes_file(path: &Path) -> anyhow::Result<Vec<[u8; 16]>> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    ed2k_part_hashes_file_cancellable(path, &NEVER)
}

pub fn ed2k_known_met_part_hash_count(file_size: u64) -> usize {
    if file_size < PARTSIZE {
        0
    } else {
        file_size.div_ceil(PARTSIZE) as usize + usize::from(file_size % PARTSIZE == 0)
    }
}

pub fn ed2k_hash_file_cancellable(path: &Path, cancelled: &AtomicBool) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
    ed2k_hash_open_file_cancellable(&mut file, cancelled)
}

/// Hash an already-opened file. Callers that enforce filesystem policy use
/// this to bind verification to the same object identity later finalized.
pub fn ed2k_hash_open_file(file: &mut std::fs::File) -> anyhow::Result<String> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    ed2k_hash_open_file_cancellable(file, &NEVER)
}

/// Cancellable form of [`ed2k_hash_open_file`]. Download verification runs on
/// `spawn_blocking`, which cannot be aborted, so the whole-file read has to
/// poll a flag the async side can set on Stop.
pub fn ed2k_hash_open_file_cancellable(
    file: &mut std::fs::File,
    cancelled: &AtomicBool,
) -> anyhow::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        let hash = Md4::digest([]);
        return Ok(hex::encode(hash));
    }

    // eMule ED2K hash rules (KnownFile.cpp:597-602):
    //   file_size < PARTSIZE:       hash = MD4(data)            (single part, no part hashes)
    //   file_size == PARTSIZE:      hash = MD4(MD4(data) + MD4(""))  (1 data part + 1 empty part)
    //   file_size == n*PARTSIZE:    hash = MD4(part_hashes + MD4("")) (n data parts + trailing empty)
    //   file_size > PARTSIZE (not multiple): hash = MD4(part_hashes)
    if file_size < PARTSIZE {
        let mut hasher = Md4::new();
        let mut buf = vec![0u8; HASH_BUF_SIZE];
        loop {
            if cancelled.load(Ordering::Relaxed) {
                anyhow::bail!("cancelled");
            }
            let n = file.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        return Ok(hex::encode(hasher.finalize()));
    }

    let num_chunks = file_size.div_ceil(PARTSIZE);
    let mut chunk_hashes = Vec::with_capacity((num_chunks as usize + 1) * 16);
    let mut remaining = file_size;
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    for _ in 0..num_chunks {
        let chunk_size = remaining.min(PARTSIZE);
        let mut hasher = Md4::new();
        let mut chunk_remaining = chunk_size;
        while chunk_remaining > 0 {
            if cancelled.load(Ordering::Relaxed) {
                anyhow::bail!("cancelled");
            }
            let to_read = (chunk_remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 {
                anyhow::bail!(
                    "unexpected EOF: {} bytes remaining in chunk",
                    chunk_remaining
                );
            }
            hasher.update(&buf[..n]);
            chunk_remaining -= n as u64;
        }
        chunk_hashes.extend_from_slice(&hasher.finalize());
        remaining -= chunk_size;
    }

    if file_size % PARTSIZE == 0 {
        let empty_hash = Md4::digest([]);
        chunk_hashes.extend_from_slice(&empty_hash);
    }

    let final_hash = Md4::digest(&chunk_hashes);
    Ok(hex::encode(final_hash))
}

pub fn ed2k_part_hashes_file_cancellable(
    path: &Path,
    cancelled: &AtomicBool,
) -> anyhow::Result<Vec<[u8; 16]>> {
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    if file_size < PARTSIZE {
        return Ok(Vec::new());
    }

    let num_chunks = file_size.div_ceil(PARTSIZE);
    let mut part_hashes = Vec::with_capacity((num_chunks as usize) + 1);
    let mut remaining = file_size;
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    for _ in 0..num_chunks {
        let chunk_size = remaining.min(PARTSIZE);
        let mut hasher = Md4::new();
        let mut chunk_remaining = chunk_size;
        while chunk_remaining > 0 {
            if cancelled.load(Ordering::Relaxed) {
                anyhow::bail!("cancelled");
            }
            let to_read = (chunk_remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 {
                anyhow::bail!(
                    "unexpected EOF: {} bytes remaining in chunk",
                    chunk_remaining
                );
            }
            hasher.update(&buf[..n]);
            chunk_remaining -= n as u64;
        }
        part_hashes.push(hasher.finalize().into());
        remaining -= chunk_size;
    }

    if file_size % PARTSIZE == 0 {
        part_hashes.push(Md4::digest([]).into());
    }

    Ok(part_hashes)
}

/// Compute both ED2K and AICH hashes in a single pass over the file,
/// halving disk I/O compared to computing them separately.
/// Returns `(ed2k_hash_hex, aich_hash_hex, ed2k_part_hashes, ember_blake3_hex)`.
///
/// `ember_blake3_hex` is the streaming BLAKE3 of the whole file (slice 18) —
/// the Ember content integrity digest published alongside the eD2K MD4 id.
pub fn hash_file_combined_cancellable(
    path: &Path,
    cancelled: &AtomicBool,
) -> anyhow::Result<(String, String, Vec<[u8; 16]>, String)> {
    use sha1::Sha1;

    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        let ed2k = hex::encode(Md4::digest([]));
        let aich = hex::encode(<[u8; 20]>::from(Sha1::digest([])));
        let ember = hex::encode(blake3::hash(&[]).as_bytes());
        return Ok((ed2k, aich, Vec::new(), ember));
    }

    let is_single_part = file_size < PARTSIZE;
    let aich_block_size = super::aich::AICH_BLOCK_SIZE as u64;

    let mut ed2k_part_hasher = Md4::new();
    let mut ed2k_part_hashes: Vec<u8> = if is_single_part {
        Vec::new()
    } else {
        let num_parts = file_size.div_ceil(PARTSIZE) as usize;
        Vec::with_capacity((num_parts + 1) * 16)
    };
    let mut ed2k_part_hash_list: Vec<[u8; 16]> = if is_single_part {
        Vec::new()
    } else {
        let num_parts = file_size.div_ceil(PARTSIZE) as usize;
        Vec::with_capacity(num_parts + 1)
    };

    let mut aich_block_hasher = Sha1::new();
    let num_aich_blocks = file_size.div_ceil(aich_block_size) as usize;
    let mut aich_leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_aich_blocks);
    let mut ember_hasher = crate::network::ember::crypto::Blake3FileHasher::new();

    let mut ed2k_part_remaining: u64 = file_size.min(PARTSIZE);
    let mut aich_block_remaining: u64 = file_size.min(aich_block_size);

    let mut buf = vec![0u8; HASH_BUF_SIZE];
    let mut file_remaining = file_size;

    while file_remaining > 0 {
        if cancelled.load(Ordering::Relaxed) {
            anyhow::bail!("cancelled");
        }
        let to_read = (file_remaining as usize).min(buf.len());
        let n = file.read(&mut buf[..to_read])?;
        if n == 0 {
            anyhow::bail!("unexpected EOF: {} bytes remaining", file_remaining);
        }

        ember_hasher.update(&buf[..n]);

        let mut offset = 0;
        while offset < n {
            let available = n - offset;
            let can_take = available
                .min(ed2k_part_remaining as usize)
                .min(aich_block_remaining as usize);

            let data = &buf[offset..offset + can_take];
            ed2k_part_hasher.update(data);
            aich_block_hasher.update(data);

            ed2k_part_remaining -= can_take as u64;
            aich_block_remaining -= can_take as u64;
            file_remaining -= can_take as u64;
            offset += can_take;

            if ed2k_part_remaining == 0 && !is_single_part {
                let part_hash: [u8; 16] = ed2k_part_hasher.finalize_reset().into();
                ed2k_part_hashes.extend_from_slice(&part_hash);
                ed2k_part_hash_list.push(part_hash);
                ed2k_part_remaining = file_remaining.min(PARTSIZE);

                // AICH blocks never straddle a part boundary — eMule's
                // CAICHHashTree hashes each part's blocks independently
                // (SHAHashSet.cpp), so force-finalize the current block
                // here even if it's short of a full AICH_BLOCK_SIZE (this
                // is *always* the case, since PARTSIZE isn't a multiple of
                // AICH_BLOCK_SIZE), then start the next part's block count
                // fresh from its own beginning.
                aich_leaf_hashes.push(aich_block_hasher.finalize_reset().into());
                aich_block_remaining = file_remaining.min(aich_block_size);
            } else if aich_block_remaining == 0 {
                aich_leaf_hashes.push(aich_block_hasher.finalize_reset().into());
                aich_block_remaining = file_remaining.min(aich_block_size);
            }
        }
    }

    let ed2k_hash = if is_single_part {
        hex::encode(ed2k_part_hasher.finalize())
    } else {
        if file_size % PARTSIZE == 0 {
            let empty_hash: [u8; 16] = Md4::digest([]).into();
            ed2k_part_hashes.extend_from_slice(&empty_hash);
            ed2k_part_hash_list.push(empty_hash);
        }
        hex::encode(Md4::digest(&ed2k_part_hashes))
    };

    let aich_root = super::aich::hierarchical_root(&aich_leaf_hashes, file_size);
    let aich_hash = hex::encode(aich_root);
    let ember_hash = hex::encode(ember_hasher.finalize());

    Ok((ed2k_hash, aich_hash, ed2k_part_hash_list, ember_hash))
}

/// In-memory equivalent of [`ed2k_hash_file`]. Used by the
/// `compute_ed2k_hash` Tauri command (for UI-side hashing of
/// arbitrary byte buffers — clipboard paste, drag-drop, etc.) and by
/// transfer-verification unit tests.
pub fn ed2k_hash_bytes(data: &[u8]) -> String {
    let file_size = data.len() as u64;

    if file_size == 0 {
        return hex::encode(Md4::digest([]));
    }

    if file_size > 0 && file_size < PARTSIZE {
        return hex::encode(Md4::digest(data));
    }

    let num_chunks = file_size.div_ceil(PARTSIZE);
    let mut chunk_hashes = Vec::with_capacity((num_chunks as usize + 1) * 16);
    for chunk in data.chunks(PARTSIZE as usize) {
        chunk_hashes.extend_from_slice(&Md4::digest(chunk));
    }

    if file_size % PARTSIZE == 0 {
        let empty_hash = Md4::digest([]);
        chunk_hashes.extend_from_slice(&empty_hash);
    }

    hex::encode(Md4::digest(&chunk_hashes))
}

/// MD4 digest of empty input — the ed2k file hash for a **zero-byte** file (`file_size == 0`).
#[inline]
pub fn empty_ed2k_file_md4() -> [u8; 16] {
    Md4::digest([]).into()
}

/// Percent-encode a filename for use in an ed2k link.
/// Encodes characters that are not unreserved per RFC 3986,
/// plus `|` which is the ed2k link field delimiter.
fn percent_encode_ed2k(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for &b in name.as_bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'('
            | b')'
            | b'['
            | b']'
            | b'!'
            | b'\''
            | b','
            | b';'
            | b'@' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0x0F) as usize]));
            }
        }
    }
    out
}

/// Format an ed2k link with optional AICH root hash, Ember BLAKE3 digest, and
/// source endpoints, matching eMule's link variants plus an Ember extension:
///   ed2k://|file|name|size|hash|h=<base32 AICH>|eh=<hex BLAKE3>|sources,ip:port,...|/
///
/// `aich_hex` is the 40-char hex AICH root (as stored on `FileInfo`); it is
/// re-encoded to base32 for the `h=` segment the way eMule expects. `ember_hex`
/// is the 64-char hex BLAKE3 content digest; unknown segments are ignored by
/// eMule, so `eh=` is safe to emit on a mixed network. `sources` are appended
/// only when non-empty.
pub fn format_ed2k_link_ext(
    name: &str,
    size: u64,
    hash: &str,
    aich_hex: Option<&str>,
    ember_hex: Option<&str>,
    sources: &[(String, u16)],
) -> String {
    let mut link = format!(
        "ed2k://|file|{}|{}|{}|",
        percent_encode_ed2k(name),
        size,
        hash.to_uppercase()
    );
    if let Some(hex_str) = aich_hex {
        if let Some(b32) = aich_hex_to_base32(hex_str) {
            link.push_str("h=");
            link.push_str(&b32);
            link.push('|');
        }
    }
    if let Some(digest) =
        ember_hex.filter(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
    {
        link.push_str("eh=");
        link.push_str(&digest.to_lowercase());
        link.push('|');
    }
    if !sources.is_empty() {
        link.push_str("sources");
        for (ip, port) in sources {
            link.push(',');
            link.push_str(ip);
            link.push(':');
            link.push_str(&port.to_string());
        }
        link.push('|');
    }
    link.push('/');
    link
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 encode (uppercase, no padding) — the form eMule uses for
/// the `h=` AICH segment of ed2k links.
fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// Decode RFC 4648 base32 (case-insensitive, padding tolerated). Returns the
/// raw bytes, or `None` if a non-alphabet character is encountered.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.chars() {
        if c == '=' {
            break;
        }
        let val = match c.to_ascii_uppercase() {
            ch @ 'A'..='Z' => ch as u32 - 'A' as u32,
            ch @ '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Convert a 40-char hex AICH root into its base32 representation. Returns
/// `None` when the input is not exactly 20 bytes of valid hex.
fn aich_hex_to_base32(aich_hex: &str) -> Option<String> {
    let trimmed = aich_hex.trim();
    if trimmed.len() != 40 {
        return None;
    }
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    Some(base32_encode(&bytes))
}

/// Convert a base32 AICH segment back into 40-char hex. Returns `None` unless
/// it decodes to exactly 20 bytes.
fn aich_base32_to_hex(b32: &str) -> Option<String> {
    let normalized = b32.trim();
    // A 20-byte AICH root has exactly 32 unpadded RFC 4648 characters.
    // Reject padding/trailing junk rather than allowing the decoder's
    // stop-at-'=' behavior to hide a malformed deep-link segment.
    if normalized.len() != 32
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'2'..=b'7'))
    {
        return None;
    }
    let bytes = base32_decode(normalized)?;
    if bytes.len() != 20 {
        return None;
    }
    Some(hex::encode(bytes))
}

pub fn percent_decode_str(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) =
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""), 16)
            {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(result).unwrap_or_else(|_| s.to_string())
}

pub type ParsedEd2kLink = (String, u64, String, Option<String>, Option<String>);

/// Strictly parse an ed2k link, distinguishing an absent AICH segment from a
/// malformed or conflicting one.
///
/// Trailing optional segments (`h=<base32 AICH>`, `eh=<hex BLAKE3>`,
/// `sources,...`, `s=<url>`, etc.) are tolerated; AICH and the Ember digest
/// are surfaced so imported links can carry recovery / integrity data.
pub fn parse_ed2k_link_strict(link: &str) -> Result<ParsedEd2kLink, &'static str> {
    let trimmed = link.trim();
    if !trimmed.starts_with("ed2k://|file|") {
        return Err("Not an ed2k file link");
    }
    let inner = trimmed
        .strip_prefix("ed2k://|file|")
        .ok_or("Not an ed2k file link")?;
    let mut parts = inner.split('|');
    let raw_name = parts.next().ok_or("Missing ed2k file name")?;
    if raw_name.len() > 4096 {
        return Err("ed2k file name is too long");
    }
    let name = percent_decode_str(raw_name);
    let size = parts
        .next()
        .ok_or("Missing ed2k file size")?
        .parse::<u64>()
        .map_err(|_| "Invalid ed2k file size")?;
    let hash = parts.next().ok_or("Missing ed2k file hash")?.to_lowercase();
    if hash.len() != 32 || hex::decode(&hash).is_err() {
        return Err("Invalid ed2k file hash");
    }
    let mut aich: Option<String> = None;
    let mut ember: Option<String> = None;
    for seg in parts {
        if let Some(b32) = seg.strip_prefix("h=") {
            let decoded = aich_base32_to_hex(b32).ok_or("Invalid AICH h= segment in ed2k link")?;
            match &aich {
                None => aich = Some(decoded),
                Some(existing) if *existing != decoded => {
                    return Err("Conflicting AICH h= segments in ed2k link");
                }
                Some(_) => {}
            }
        } else if let Some(digest) = seg.strip_prefix("eh=") {
            let decoded = digest.trim().to_lowercase();
            if decoded.len() != 64 || hex::decode(&decoded).is_err() {
                return Err("Invalid Ember eh= segment in ed2k link");
            }
            match &ember {
                None => ember = Some(decoded),
                Some(existing) if *existing != decoded => {
                    return Err("Conflicting Ember eh= segments in ed2k link");
                }
                Some(_) => {}
            }
        }
    }
    Ok((name, size, hash, aich, ember))
}

/// Compatibility parser for collection imports. Invalid links (including
/// malformed AICH-bearing links) are skipped rather than partially accepted.
pub fn parse_ed2k_link(link: &str) -> Option<ParsedEd2kLink> {
    parse_ed2k_link_strict(link).ok()
}

#[cfg(test)]
mod link_tests {
    use super::*;

    const HASH: &str = "0123456789abcdef0123456789abcdef";
    // 20-byte AICH root (hex) -> known base32.
    const AICH_HEX: &str = "0000000000000000000000000000000000000000";

    #[test]
    fn base32_round_trips_aich() {
        let aich = "1f2e3d4c5b6a798877665544332211000aabbccd";
        let b32 = aich_hex_to_base32(aich).expect("encode");
        assert_eq!(b32.len(), 32, "20 bytes -> 32 base32 chars");
        let back = aich_base32_to_hex(&b32).expect("decode");
        assert_eq!(back, aich);
    }

    #[test]
    fn base32_all_zero_aich() {
        let b32 = aich_hex_to_base32(AICH_HEX).expect("encode");
        assert_eq!(b32, "A".repeat(32));
    }

    #[test]
    fn plain_link_unchanged() {
        let link = format_ed2k_link_ext("movie.avi", 1234, HASH, None, None, &[]);
        assert_eq!(
            link,
            "ed2k://|file|movie.avi|1234|0123456789ABCDEF0123456789ABCDEF|/"
        );
    }

    #[test]
    fn link_with_aich_has_h_segment() {
        let aich = "1f2e3d4c5b6a798877665544332211000aabbccd";
        let link = format_ed2k_link_ext("movie.avi", 1234, HASH, Some(aich), None, &[]);
        assert!(link.contains("|h="), "expected h= segment: {link}");
        assert!(link.ends_with("|/"));
        // Round-trip the embedded AICH back out.
        let (_, _, _, parsed, ember) = parse_ed2k_link(&link).expect("parse");
        assert_eq!(parsed.as_deref(), Some(aich));
        assert!(ember.is_none());
    }

    #[test]
    fn link_with_ember_hash_has_eh_segment() {
        let digest = "ab".repeat(32);
        let link = format_ed2k_link_ext("movie.avi", 1234, HASH, None, Some(&digest), &[]);
        assert!(link.contains(&format!("|eh={digest}|")), "{link}");
        let (_, _, _, aich, parsed) = parse_ed2k_link(&link).expect("parse");
        assert!(aich.is_none());
        assert_eq!(parsed.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn link_with_sources_appends_endpoint() {
        let sources = vec![("203.0.113.5".to_string(), 4662u16)];
        let link = format_ed2k_link_ext("movie.avi", 1234, HASH, None, None, &sources);
        assert!(link.contains("|sources,203.0.113.5:4662|"), "{link}");
    }

    #[test]
    fn link_with_aich_and_sources_keeps_order() {
        let aich = "1f2e3d4c5b6a798877665544332211000aabbccd";
        let sources = vec![("203.0.113.5".to_string(), 4662u16)];
        let link = format_ed2k_link_ext("a.bin", 9, HASH, Some(aich), None, &sources);
        let h_pos = link.find("h=").unwrap();
        let s_pos = link.find("sources,").unwrap();
        assert!(h_pos < s_pos, "h= must precede sources: {link}");
    }

    #[test]
    fn parse_ignores_unknown_trailing_segments() {
        let link = format!("ed2k://|file|a.bin|9|{HASH}|sources,1.2.3.4:1|s=http://x/y|/");
        let (name, size, hash, aich, ember) = parse_ed2k_link(&link).expect("parse");
        assert_eq!(name, "a.bin");
        assert_eq!(size, 9);
        assert_eq!(hash, HASH);
        assert!(aich.is_none());
        assert!(ember.is_none());
    }

    #[test]
    fn parse_rejects_bad_base32_aich() {
        let link = format!("ed2k://|file|a.bin|9|{HASH}|h=10101010101010101010101010101010|/");
        assert!(parse_ed2k_link_strict(&link).is_err());
        assert!(parse_ed2k_link(&link).is_none());
    }

    #[test]
    fn parse_rejects_empty_and_conflicting_aich_segments() {
        let empty = format!("ed2k://|file|a.bin|9|{HASH}|h=|/");
        assert!(parse_ed2k_link_strict(&empty).is_err());

        let first = base32_encode(&[0x11; 20]);
        let second = base32_encode(&[0x22; 20]);
        let conflicting = format!("ed2k://|file|a.bin|9|{HASH}|h={first}|h={second}|/");
        assert!(parse_ed2k_link_strict(&conflicting).is_err());

        let repeated = format!("ed2k://|file|a.bin|9|{HASH}|h={first}|h={first}|/");
        assert_eq!(
            parse_ed2k_link_strict(&repeated).unwrap().3,
            Some(hex::encode([0x11; 20]))
        );
    }

    #[test]
    fn parse_rejects_bad_and_conflicting_ember_segments() {
        let short = format!("ed2k://|file|a.bin|9|{HASH}|eh=abcd|/");
        assert!(parse_ed2k_link_strict(&short).is_err());

        let first = "ab".repeat(32);
        let second = "cd".repeat(32);
        let conflicting = format!("ed2k://|file|a.bin|9|{HASH}|eh={first}|eh={second}|/");
        assert!(parse_ed2k_link_strict(&conflicting).is_err());

        let repeated = format!("ed2k://|file|a.bin|9|{HASH}|eh={first}|eh={first}|/");
        assert_eq!(parse_ed2k_link_strict(&repeated).unwrap().4, Some(first));
    }
}

#[cfg(test)]
mod combined_hash_tests {
    use super::*;

    /// Cross-validates the two independent AICH-hashing code paths — the
    /// streaming combined ed2k+AICH hasher used when sharing a real file,
    /// and `AICHRecoveryHashSet::build_from_file`'s own read — against each
    /// other on a genuine multi-part (3-part) file. Both must reset AICH
    /// block boundaries at every PARTSIZE boundary (`PARTSIZE %
    /// AICH_BLOCK_SIZE != 0`, so this only exercises correctly if the reset
    /// actually happens); if either regresses to continuous whole-file
    /// block chunking, this test will fail because the two paths would
    /// diverge (or a shared bug would need to affect both identically).
    #[test]
    fn combined_aich_hash_matches_build_from_file_for_multi_part() {
        let aich_block_size = super::super::aich::AICH_BLOCK_SIZE as u64;
        let file_size = PARTSIZE * 2 + aich_block_size;
        let path = std::env::temp_dir().join(format!(
            "ember-hash-test-{}-{}.bin",
            std::process::id(),
            file_size
        ));
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).expect("create temp file");
            let chunk = vec![0x37u8; 1024 * 1024];
            let mut remaining = file_size;
            while remaining > 0 {
                let n = remaining.min(chunk.len() as u64) as usize;
                f.write_all(&chunk[..n]).expect("write temp file");
                remaining -= n as u64;
            }
        }

        static NEVER: AtomicBool = AtomicBool::new(false);
        let (_, combined_aich_hex, combined_part_hashes, _) =
            hash_file_combined_cancellable(&path, &NEVER).expect("combined hash");
        let hs = super::super::aich::AICHRecoveryHashSet::build_from_file(&path)
            .expect("build_from_file");
        let reread_part_hashes =
            ed2k_part_hashes_file_cancellable(&path, &NEVER).expect("part hashes");

        let _ = std::fs::remove_file(&path);

        assert_eq!(combined_aich_hex, hex::encode(hs.root_hash));
        // The part hashes returned as a byproduct of the combined pass must be
        // byte-for-byte identical to independently re-reading the file, since
        // callers (the `SharedFilesChanged` handler) rely on this to skip the
        // second read entirely.
        assert_eq!(combined_part_hashes, reread_part_hashes);
        assert_eq!(
            combined_part_hashes.len(),
            ed2k_known_met_part_hash_count(file_size)
        );
    }
}
