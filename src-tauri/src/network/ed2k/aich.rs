use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use digest::Digest;
use sha1::Sha1;

/// AICH block size: 180 KiB (eMule's EMBLOCKSIZE)
pub const AICH_BLOCK_SIZE: usize = 184_320;
const PARTSIZE: usize = 9_728_000;
/// Blocks per full part (used to compute global block offsets)
const BLOCKS_PER_FULL_PART: usize = (PARTSIZE + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;

#[allow(dead_code)]
pub fn compute_aich_root(path: &Path) -> anyhow::Result<[u8; 20]> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    compute_aich_root_cancellable(path, &NEVER)
}

pub fn compute_aich_root_cancellable(path: &Path, cancelled: &AtomicBool) -> anyhow::Result<[u8; 20]> {
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
        if cancelled.load(Ordering::Relaxed) {
            anyhow::bail!("cancelled");
        }
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

/// AICH Recovery HashSet: stores the full Merkle tree for a file.
/// Used to identify which 180KB blocks within a part are corrupt.
pub struct AICHRecoveryHashSet {
    pub root_hash: [u8; 20],
    /// All leaf hashes (one per 180KB block)
    pub leaf_hashes: Vec<[u8; 20]>,
    /// Trust count: how many unique IPs reported the same root hash
    pub trust_votes: std::collections::HashMap<[u8; 20], Vec<std::net::Ipv4Addr>>,
}

const AICH_TRUST_THRESHOLD: usize = 10;
const AICH_TRUST_PERCENTAGE: f64 = 0.92;

impl AICHRecoveryHashSet {
    pub fn new(root_hash: [u8; 20]) -> Self {
        Self {
            root_hash,
            leaf_hashes: Vec::new(),
            trust_votes: std::collections::HashMap::new(),
        }
    }

    /// Build from a file, storing all leaf hashes.
    pub fn build_from_file(path: &Path) -> anyhow::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let file_size = file.metadata()?.len();

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

        let root_hash = merkle_root(&leaf_hashes);
        Ok(Self {
            root_hash,
            leaf_hashes,
            trust_votes: std::collections::HashMap::new(),
        })
    }

    /// Build from raw data (e.g., a part or buffer).
    pub fn build_from_data(data: &[u8]) -> Self {
        let num_blocks = (data.len() + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
        let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);

        for chunk in data.chunks(AICH_BLOCK_SIZE) {
            leaf_hashes.push(Sha1::digest(chunk).into());
        }

        let root_hash = merkle_root(&leaf_hashes);
        Self {
            root_hash,
            leaf_hashes,
            trust_votes: std::collections::HashMap::new(),
        }
    }

    /// Add a trust vote for a root hash from a specific IP.
    pub fn add_trust_vote(&mut self, root_hash: [u8; 20], ip: std::net::Ipv4Addr) {
        let voters = self.trust_votes.entry(root_hash).or_default();
        if !voters.contains(&ip) {
            voters.push(ip);
        }
    }

    /// Check if the root hash is trusted (enough unique IP votes with consensus).
    pub fn is_trusted(&self) -> bool {
        if let Some(voters) = self.trust_votes.get(&self.root_hash) {
            if voters.len() < AICH_TRUST_THRESHOLD {
                return false;
            }
            let total_votes: usize = self.trust_votes.values().map(|v| v.len()).sum();
            let our_votes = voters.len();
            (our_votes as f64 / total_votes as f64) >= AICH_TRUST_PERCENTAGE
        } else {
            false
        }
    }

    /// Identify which blocks within a part are corrupt by comparing leaf hashes.
    /// Returns indices of corrupt blocks (relative to the part start).
    pub fn find_corrupt_blocks(
        &self,
        part_index: usize,
        part_data: &[u8],
        _part_size: usize,
    ) -> Vec<usize> {
        let start_block = part_index * BLOCKS_PER_FULL_PART;
        let mut corrupt = Vec::new();

        for (i, chunk) in part_data.chunks(AICH_BLOCK_SIZE).enumerate() {
            let block_idx = start_block + i;
            if block_idx >= self.leaf_hashes.len() {
                break;
            }
            let computed: [u8; 20] = Sha1::digest(chunk).into();
            if computed != self.leaf_hashes[block_idx] {
                corrupt.push(i);
            }
        }

        corrupt
    }

    /// Create recovery data for a part (serialize the leaf hashes needed).
    pub fn create_part_recovery_data(&self, part_index: usize, _part_size: usize) -> Vec<u8> {
        let start_block = part_index * BLOCKS_PER_FULL_PART;
        let end_block = (start_block + BLOCKS_PER_FULL_PART).min(self.leaf_hashes.len());

        let mut data = Vec::new();
        data.extend_from_slice(&(end_block - start_block).to_le_bytes()[..2]);
        for i in start_block..end_block {
            data.extend_from_slice(&self.leaf_hashes[i]);
        }
        data
    }

    /// Read recovery data received from a peer.
    pub fn read_recovery_data(&mut self, data: &[u8], part_index: usize, _part_size: usize) -> bool {
        if data.len() < 2 {
            return false;
        }
        let block_count = u16::from_le_bytes([data[0], data[1]]) as usize;
        let expected_len = 2 + block_count * 20;
        if data.len() < expected_len {
            return false;
        }

        let start_block = part_index * BLOCKS_PER_FULL_PART;

        while self.leaf_hashes.len() < start_block + block_count {
            self.leaf_hashes.push([0u8; 20]);
        }

        for i in 0..block_count {
            let offset = 2 + i * 20;
            let mut hash = [0u8; 20];
            hash.copy_from_slice(&data[offset..offset + 20]);
            self.leaf_hashes[start_block + i] = hash;
        }

        true
    }

    pub fn leaf_count(&self) -> usize {
        self.leaf_hashes.len()
    }
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
