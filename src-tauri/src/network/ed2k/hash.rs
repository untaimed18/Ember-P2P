// SECURITY NOTE: The ed2k protocol mandates MD4 for file identification hashes.
// MD4 is cryptographically broken (practical collision attacks since 2004). An
// attacker can craft a malicious file with the same ed2k hash as a legitimate one.
// This cannot be changed without breaking eMule/KAD network compatibility.
// AICH (SHA-1 Merkle tree) provides a secondary verification layer.

use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use digest::Digest;
use md4::Md4;

pub const PARTSIZE: u64 = 9_728_000;

/// Non-cancellable version used by download verification (transfer.rs, multi_source.rs).
pub fn ed2k_hash_file(path: &Path) -> anyhow::Result<String> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    ed2k_hash_file_cancellable(path, &NEVER)
}

pub fn ed2k_hash_file_cancellable(path: &Path, cancelled: &AtomicBool) -> anyhow::Result<String> {
    let mut file = std::fs::File::open(path)?;
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
    if file_size > 0 && file_size < PARTSIZE {
        let mut hasher = Md4::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            if cancelled.load(Ordering::Relaxed) {
                anyhow::bail!("cancelled");
            }
            let n = file.read(&mut buf)?;
            if n == 0 { break; }
            hasher.update(&buf[..n]);
        }
        return Ok(hex::encode(hasher.finalize()));
    }

    let num_chunks = (file_size + PARTSIZE - 1) / PARTSIZE;
    let mut chunk_hashes = Vec::with_capacity((num_chunks as usize + 1) * 16);
    let mut remaining = file_size;
    let mut buf = vec![0u8; 64 * 1024];

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
            if n == 0 { break; }
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
pub fn ed2k_hash_bytes(data: &[u8]) -> String {
    let file_size = data.len() as u64;

    if file_size == 0 {
        return hex::encode(Md4::digest([]));
    }

    if file_size > 0 && file_size < PARTSIZE {
        return hex::encode(Md4::digest(data));
    }

    let num_chunks = (file_size + PARTSIZE - 1) / PARTSIZE;
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

/// Format an ed2k link: ed2k://|file|name|size|hash|/
pub fn format_ed2k_link(name: &str, size: u64, hash: &str) -> String {
    format!("ed2k://|file|{}|{}|{}|/", name, size, hash.to_uppercase())
}

fn percent_decode_str(s: &str) -> String {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
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

/// Parse an ed2k link, returning (name, size, hash)
pub fn parse_ed2k_link(link: &str) -> Option<(String, u64, String)> {
    let trimmed = link.trim();
    if !trimmed.starts_with("ed2k://|file|") {
        return None;
    }
    let inner = trimmed
        .strip_prefix("ed2k://|file|")?
        .strip_suffix("|/")?;
    let parts: Vec<&str> = inner.split('|').collect();
    if parts.len() < 3 {
        return None;
    }
    let name = percent_decode_str(parts[0]);
    let size = parts[1].parse::<u64>().ok()?;
    let hash = parts[2].to_lowercase();
    if hash.len() != 32 {
        return None;
    }
    Some((name, size, hash))
}

