use std::io::Read;
use std::path::Path;

use digest::Digest;
use sha1::Sha1;

/// AICH block size: 180 KiB (eMule's EMBLOCKSIZE)
pub const AICH_BLOCK_SIZE: usize = 184_320;

/// Compute the AICH root hash for a file.
/// Returns the SHA-1 root of the Merkle hash tree built from 180KB blocks.
pub fn compute_aich_root(path: &Path) -> anyhow::Result<[u8; 20]> {
    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();

    if file_size == 0 {
        return Ok(Sha1::digest([]).into());
    }

    let block_size_u64 = AICH_BLOCK_SIZE as u64;
    let num_blocks = ((file_size + block_size_u64 - 1) / block_size_u64) as usize;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);
    let mut buf = vec![0u8; AICH_BLOCK_SIZE];
    let mut remaining = file_size;

    for _ in 0..num_blocks {
        let block_size = remaining.min(block_size_u64) as usize;
        let buf_slice = &mut buf[..block_size];
        file.read_exact(buf_slice)?;
        leaf_hashes.push(Sha1::digest(buf_slice).into());
        remaining -= block_size as u64;
    }

    Ok(merkle_root(&leaf_hashes))
}

/// Compute the AICH hash for a single part (for verification).
pub fn compute_aich_part(data: &[u8]) -> [u8; 20] {
    if data.is_empty() {
        return Sha1::digest([]).into();
    }

    let num_blocks = (data.len() + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);

    for chunk in data.chunks(AICH_BLOCK_SIZE) {
        leaf_hashes.push(Sha1::digest(chunk).into());
    }

    merkle_root(&leaf_hashes)
}

/// Build a Merkle tree root using eMule's top-down recursive split algorithm.
/// This matches eMule's CAICHHashTree::ReCalculateHash.
fn merkle_root(leaves: &[[u8; 20]]) -> [u8; 20] {
    if leaves.is_empty() {
        return Sha1::digest([]).into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    build_tree_recursive(leaves, true)
}

fn build_tree_recursive(leaves: &[[u8; 20]], is_left_branch: bool) -> [u8; 20] {
    if leaves.len() <= 1 {
        return leaves.first().copied().unwrap_or_else(|| Sha1::digest([]).into());
    }
    // eMule: nLeft = (nBlocks + bIsLeftBranch) / 2
    let n_left = (leaves.len() + if is_left_branch { 1 } else { 0 }) / 2;
    let left_hash = build_tree_recursive(&leaves[..n_left], true);
    let right_hash = build_tree_recursive(&leaves[n_left..], false);
    let mut hasher = Sha1::new();
    hasher.update(left_hash);
    hasher.update(right_hash);
    hasher.finalize().into()
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
