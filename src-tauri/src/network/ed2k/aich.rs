use std::io::Read;
use std::path::Path;

use digest::Digest;
use sha1::Sha1;

/// AICH block size: 180 KiB (eMule's EMBLOCKSIZE)
const AICH_BLOCK_SIZE: u64 = 184_320;
/// eMule part size: 9.28 MB
#[allow(dead_code)]
const PARTSIZE: u64 = 9_728_000;

/// Compute the AICH root hash for a file.
/// Returns the SHA-1 root of the Merkle hash tree built from 180KB blocks.
pub fn compute_aich_root(path: &Path) -> anyhow::Result<[u8; 20]> {
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok(Sha1::digest([]).into());
    }

    let num_blocks = ((file_size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE) as usize;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);
    let mut buf = vec![0u8; AICH_BLOCK_SIZE as usize];
    let mut remaining = file_size;

    for _ in 0..num_blocks {
        let block_size = remaining.min(AICH_BLOCK_SIZE) as usize;
        let buf_slice = &mut buf[..block_size];
        file.read_exact(buf_slice)?;
        leaf_hashes.push(Sha1::digest(buf_slice).into());
        remaining -= block_size as u64;
    }

    Ok(merkle_root(&leaf_hashes))
}

/// Compute the AICH hash for a single part (for verification).
#[allow(dead_code)]
pub fn compute_aich_part(data: &[u8]) -> [u8; 20] {
    if data.is_empty() {
        return Sha1::digest([]).into();
    }

    let num_blocks = (data.len() + AICH_BLOCK_SIZE as usize - 1) / AICH_BLOCK_SIZE as usize;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);

    for chunk in data.chunks(AICH_BLOCK_SIZE as usize) {
        leaf_hashes.push(Sha1::digest(chunk).into());
    }

    merkle_root(&leaf_hashes)
}

/// Build a Merkle tree root from leaf hashes.
fn merkle_root(leaves: &[[u8; 20]]) -> [u8; 20] {
    if leaves.is_empty() {
        return Sha1::digest([]).into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for pair in current_level.chunks(2) {
            if pair.len() == 2 {
                let mut hasher = Sha1::new();
                hasher.update(pair[0]);
                hasher.update(pair[1]);
                next_level.push(hasher.finalize().into());
            } else {
                next_level.push(pair[0]);
            }
        }
        current_level = next_level;
    }

    current_level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aich_empty() {
        let hash = compute_aich_part(&[]);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_aich_small() {
        let data = vec![0xABu8; 1000];
        let hash = compute_aich_part(&data);
        assert_eq!(hash.len(), 20);
    }

    #[test]
    fn test_merkle_single_leaf() {
        let leaf: [u8; 20] = Sha1::digest(b"hello").into();
        let root = merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_two_leaves() {
        let a: [u8; 20] = Sha1::digest(b"hello").into();
        let b: [u8; 20] = Sha1::digest(b"world").into();
        let root = merkle_root(&[a, b]);
        let mut expected_hasher = Sha1::new();
        expected_hasher.update(a);
        expected_hasher.update(b);
        let expected: [u8; 20] = expected_hasher.finalize().into();
        assert_eq!(root, expected);
    }
}
