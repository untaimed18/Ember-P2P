use std::io::Read;
use std::path::Path;

use digest::Digest;
use sha1::Sha1;

/// AICH block size: 180 KiB (eMule's EMBLOCKSIZE)
pub const AICH_BLOCK_SIZE: usize = 184_320;
const PARTSIZE: usize = 9_728_000;
/// Blocks per full part (used to compute global block offsets)
const BLOCKS_PER_FULL_PART: usize = (PARTSIZE + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;

/// Upper bound on the trailing recovery-data blob in an `OP_AICHANSWER`.
///
/// An answer covers a single part, whose block-hash synchronisation tree is
/// only ~1 KiB (at most `BLOCKS_PER_FULL_PART` leaves plus the path to the
/// root). This 256 KiB ceiling is hundreds of times that, so it never rejects
/// a legitimate answer, yet stops a peer from padding a valid-looking answer
/// with megabytes of junk that we'd otherwise copy and hold for the full
/// AICH wait window.
pub const MAX_AICH_RECOVERY_BYTES: usize = 256 * 1024;

/// Compute the AICH hash for a single part (for verification).
pub fn compute_aich_part(data: &[u8]) -> [u8; 20] {
    if data.is_empty() {
        return Sha1::digest([]).into();
    }

    let num_blocks = (data.len() + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);

    for chunk in data.chunks(AICH_BLOCK_SIZE) {
        leaf_hashes.push(hash_leaf(chunk));
    }

    merkle_root(&leaf_hashes)
}

/// eMule AICH leaf hash: SHA1(data) with NO prefix byte.
/// eMule's CSHA::Add feeds raw data directly; no domain separation is used.
fn hash_leaf(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// eMule AICH internal node hash: SHA1(left || right) with NO prefix byte.
fn hash_internal(left: &[u8; 20], right: &[u8; 20]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// eMule two-level hierarchical AICH tree.
/// Top level splits by PARTSIZE (parts never mix across subtrees).
/// Bottom level (within each part) splits by EMBLOCKSIZE.
/// Matches eMule's CAICHHashTree where GetBaseSize() transitions from
/// PARTSIZE to EMBLOCKSIZE when data_size <= PARTSIZE.
pub(crate) fn hierarchical_root(all_leaves: &[[u8; 20]], file_size: u64) -> [u8; 20] {
    if all_leaves.is_empty() {
        return hash_leaf(&[]);
    }
    if all_leaves.len() == 1 {
        return all_leaves[0];
    }

    let num_parts = ((file_size as u64 + PARTSIZE as u64 - 1) / PARTSIZE as u64) as usize;
    if num_parts <= 1 {
        return build_tree_recursive(all_leaves, true);
    }

    // Compute per-part subtree hashes
    let mut part_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_parts);
    let mut offset = 0;
    for p in 0..num_parts {
        let part_data_size = if p < num_parts - 1 {
            PARTSIZE
        } else {
            let rem = (file_size % PARTSIZE as u64) as usize;
            if rem == 0 {
                PARTSIZE
            } else {
                rem
            }
        };
        let blocks_in_part = (part_data_size + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
        let end = (offset + blocks_in_part).min(all_leaves.len());
        let part_leaves = &all_leaves[offset..end];
        if part_leaves.len() == 1 {
            part_hashes.push(part_leaves[0]);
        } else {
            part_hashes.push(build_tree_recursive(part_leaves, true));
        }
        offset = end;
    }

    // Top-level tree over part hashes
    build_tree_recursive(&part_hashes, true)
}

/// Single-level Merkle tree used within each part and at the top level.
fn build_tree_recursive(leaves: &[[u8; 20]], is_left_branch: bool) -> [u8; 20] {
    if leaves.len() <= 1 {
        return leaves.first().copied().unwrap_or_else(|| hash_leaf(&[]));
    }
    // eMule: nLeft = (nBlocks + bIsLeftBranch) / 2
    let n_left = (leaves.len() + if is_left_branch { 1 } else { 0 }) / 2;
    let left_hash = build_tree_recursive(&leaves[..n_left], true);
    let right_hash = build_tree_recursive(&leaves[n_left..], false);
    hash_internal(&left_hash, &right_hash)
}

/// Build a full subtree, collecting (position_id, hash) entries for all nodes.
/// Uses the same left/right split convention as eMule's `CAICHHashTree`.
fn build_tree_entries(
    leaves: &[[u8; 20]],
    position: u32,
    is_left_branch: bool,
    entries: &mut Vec<(u32, [u8; 20])>,
) -> [u8; 20] {
    if leaves.len() <= 1 {
        let hash = leaves.first().copied().unwrap_or_else(|| hash_leaf(&[]));
        entries.push((position, hash));
        return hash;
    }
    let n_left = (leaves.len() + if is_left_branch { 1 } else { 0 }) / 2;
    let left_hash = build_tree_entries(&leaves[..n_left], position * 2, true, entries);
    let right_hash = build_tree_entries(&leaves[n_left..], position * 2 + 1, false, entries);
    let hash = hash_internal(&left_hash, &right_hash);
    entries.push((position, hash));
    hash
}

/// Flat Merkle root for a single part's leaves (used by compute_aich_part
/// and recovery code where file_size context is not available).
fn merkle_root(leaves: &[[u8; 20]]) -> [u8; 20] {
    if leaves.is_empty() {
        return hash_leaf(&[]);
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    build_tree_recursive(leaves, true)
}

/// AICH Recovery HashSet: stores the full Merkle tree for a file.
/// Used to identify which 180KB blocks within a part are corrupt.
#[derive(Clone)]
pub struct AICHRecoveryHashSet {
    pub root_hash: [u8; 20],
    /// All leaf hashes (one per 180KB block)
    pub leaf_hashes: Vec<[u8; 20]>,
}

/// Parse eMule tree-format AICH recovery data into ordered leaf hashes.
///
/// eMule's OP_AICHANSWER encodes each hash with a tree-position identifier—a bitmask
/// encoding the path through the binary Merkle tree. The wire format is:
///   <u16: count_16bit_entries> [<u16: id> <20B: hash>]*
///   <u16: count_32bit_entries> [<u32: id> <20B: hash>]*
///
/// The highest set bit of an identifier gives its tree depth. Leaf hashes live at the
/// maximum depth and are returned in left-to-right order (sorted by identifier).
/// Returns `None` if the data doesn't structurally match the eMule wire format.
fn parse_emule_aich_tree(data: &[u8]) -> Option<Vec<[u8; 20]>> {
    if data.len() < 4 {
        return None;
    }

    let count_16 = u16::from_le_bytes([data[0], data[1]]) as usize;
    let section_16_end = 2usize.checked_add(count_16.checked_mul(22)?)?;
    if data.len() < section_16_end + 2 {
        return None;
    }

    let count_32 = u16::from_le_bytes([data[section_16_end], data[section_16_end + 1]]) as usize;
    let expected_len = section_16_end
        .checked_add(2)?
        .checked_add(count_32.checked_mul(24)?)?;
    if data.len() != expected_len {
        return None;
    }

    if count_16 == 0 && count_32 == 0 {
        return None;
    }

    let mut entries: Vec<(u64, [u8; 20])> = Vec::with_capacity(count_16 + count_32);

    let mut offset = 2;
    for _ in 0..count_16 {
        let pos = u16::from_le_bytes([data[offset], data[offset + 1]]) as u64;
        offset += 2;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data[offset..offset + 20]);
        offset += 20;
        if pos > 0 {
            entries.push((pos, hash));
        }
    }

    offset = section_16_end + 2;
    for _ in 0..count_32 {
        let pos = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as u64;
        offset += 4;
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&data[offset..offset + 20]);
        offset += 20;
        if pos > 0 {
            entries.push((pos, hash));
        }
    }

    if entries.is_empty() {
        return None;
    }

    let max_depth = entries
        .iter()
        .map(|&(pos, _)| 63u32 - pos.leading_zeros())
        .max()
        .unwrap_or(0);

    let mut leaves: Vec<(u64, [u8; 20])> = entries
        .into_iter()
        .filter(|&(pos, _)| (63u32 - pos.leading_zeros()) == max_depth)
        .collect();

    if leaves.is_empty() {
        return None;
    }

    leaves.sort_by_key(|&(pos, _)| pos);

    // Derive actual block indices from tree position IDs. The position
    // encodes the path through the binary tree; the leaf index is the
    // position minus the leftmost leaf at that depth. Build a correctly
    // sized vec with gaps filled by zeros for missing leaves.
    let leftmost_at_depth = 1u64 << max_depth;
    let max_idx = leaves
        .iter()
        .map(|&(pos, _)| (pos.saturating_sub(leftmost_at_depth)) as usize)
        .max()
        .unwrap_or(0);
    // A single OP_AICHANSWER covers exactly one part, whose block-hash subtree
    // has at most BLOCKS_PER_FULL_PART (53) leaves. A larger derived leaf index
    // means either a malformed tree or a peer trying to amplify a tiny (<=256
    // KiB) payload into a large sparse zero-filled allocation — reject it before
    // sizing `result`. Mirrors the flat-format `block_count > BLOCKS_PER_FULL_PART`
    // guard in `read_recovery_data`.
    if max_idx >= BLOCKS_PER_FULL_PART {
        return None;
    }
    let mut result = vec![[0u8; 20]; max_idx + 1];
    for (pos, hash) in leaves {
        if pos >= leftmost_at_depth {
            let idx = (pos - leftmost_at_depth) as usize;
            if idx < result.len() {
                result[idx] = hash;
            }
        }
    }
    Some(result)
}

impl AICHRecoveryHashSet {
    pub fn new(root_hash: [u8; 20]) -> Self {
        Self {
            root_hash,
            leaf_hashes: Vec::new(),
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
            leaf_hashes.push(hash_leaf(buf_slice));
            remaining -= block_size as u64;
        }

        let root_hash = hierarchical_root(&leaf_hashes, file_size);
        Ok(Self {
            root_hash,
            leaf_hashes,
        })
    }

    /// Build from raw data (e.g., a part or buffer).
    pub fn build_from_data(data: &[u8]) -> Self {
        let num_blocks = (data.len() + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
        let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks);

        for chunk in data.chunks(AICH_BLOCK_SIZE) {
            leaf_hashes.push(hash_leaf(chunk));
        }

        let root_hash = merkle_root(&leaf_hashes);
        Self {
            root_hash,
            leaf_hashes,
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
            let computed = hash_leaf(chunk);
            if computed != self.leaf_hashes[block_idx] {
                corrupt.push(i);
            }
        }

        corrupt
    }

    /// Create recovery data for a part in eMule's tree-position wire format.
    ///
    /// Wire format: `<u16:count_16>[<u16:id><20B:hash>]*<u16:count_32>[<u32:id><20B:hash>]*`
    /// where each id encodes a path through the binary Merkle tree (root=1,
    /// left=2*parent, right=2*parent+1).  This is the format that stock eMule,
    /// aMule, and all known mods expect in `OP_AICHANSWER`.
    pub fn create_part_recovery_data(&self, part_index: usize, _part_size: usize) -> Vec<u8> {
        let start_block = part_index.saturating_mul(BLOCKS_PER_FULL_PART);
        // `part_index` can originate from an untrusted peer's OP_AICHREQUEST
        // (a raw u16 off the wire), so it may point past the end of the leaf
        // table. Clamp `start_block` to the table length before slicing —
        // otherwise `start_block > end_block` panics the upload task. An
        // out-of-range part simply has no recovery data, so emit the empty
        // (count=0/count=0) envelope.
        let end_block = (start_block + BLOCKS_PER_FULL_PART).min(self.leaf_hashes.len());
        let part_leaves = if start_block >= self.leaf_hashes.len() {
            &[][..]
        } else {
            &self.leaf_hashes[start_block..end_block]
        };

        if part_leaves.is_empty() {
            let mut data = Vec::with_capacity(4);
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            return data;
        }

        let mut entries: Vec<(u32, [u8; 20])> = Vec::new();
        build_tree_entries(part_leaves, 1, true, &mut entries);

        let mut entries_16 = Vec::new();
        let mut entries_32 = Vec::new();
        for &(id, hash) in &entries {
            if id <= u16::MAX as u32 {
                entries_16.push((id, hash));
            } else {
                entries_32.push((id, hash));
            }
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(entries_16.len() as u16).to_le_bytes());
        for &(id, hash) in &entries_16 {
            data.extend_from_slice(&(id as u16).to_le_bytes());
            data.extend_from_slice(&hash);
        }
        data.extend_from_slice(&(entries_32.len() as u16).to_le_bytes());
        for &(id, hash) in &entries_32 {
            data.extend_from_slice(&id.to_le_bytes());
            data.extend_from_slice(&hash);
        }
        data
    }

    /// Read recovery data received from a peer.
    ///
    /// Supports both the eMule tree format (tree-position identifiers + hashes)
    /// and the Ember flat format (block_count + raw hashes). The eMule format is
    /// tried first; if the data doesn't structurally match, we fall back to flat.
    pub fn read_recovery_data(
        &mut self,
        data: &[u8],
        part_index: usize,
        _part_size: usize,
    ) -> bool {
        if let Some(leaves) = parse_emule_aich_tree(data) {
            let start_block = part_index * BLOCKS_PER_FULL_PART;
            while self.leaf_hashes.len() < start_block + leaves.len() {
                self.leaf_hashes.push([0u8; 20]);
            }
            for (i, hash) in leaves.into_iter().enumerate() {
                self.leaf_hashes[start_block + i] = hash;
            }
            return true;
        }

        if data.len() < 2 {
            return false;
        }
        let block_count = u16::from_le_bytes([data[0], data[1]]) as usize;
        // A single part can never legitimately carry more than
        // BLOCKS_PER_FULL_PART block hashes. Reject an inflated count before it
        // drives a large speculative `leaf_hashes` growth.
        if block_count > BLOCKS_PER_FULL_PART {
            return false;
        }
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

/// Apply OP_AICHANSWER recovery payload for one part, then list 180 KiB block indices (within the
/// part) that still disagree with the trusted leaf hashes. Returns `None` if recovery data is invalid.
pub fn corrupt_blocks_from_aich_recovery(
    trusted_master: [u8; 20],
    recovery_data: &[u8],
    part_index: usize,
    part_data: &[u8],
    part_size: usize,
    file_size: u64,
) -> Option<Vec<usize>> {
    let mut hs = AICHRecoveryHashSet::new(trusted_master);
    if !hs.read_recovery_data(recovery_data, part_index, part_size) {
        return None;
    }

    let expected_blocks = (part_data.len() + AICH_BLOCK_SIZE - 1) / AICH_BLOCK_SIZE;
    let start_block = part_index * BLOCKS_PER_FULL_PART;
    let received_blocks = hs.leaf_hashes.len().saturating_sub(start_block);
    if received_blocks < expected_blocks {
        tracing::warn!(
            "AICH recovery: received {received_blocks} leaf hashes but expected {expected_blocks}"
        );
        return None;
    }

    let total_parts = ((file_size as u64) + PARTSIZE as u64 - 1) / PARTSIZE as u64;
    if total_parts <= 1 {
        let part_leaves = &hs.leaf_hashes[start_block..start_block + expected_blocks];
        let computed_root = merkle_root(part_leaves);
        if computed_root != trusted_master {
            tracing::warn!(
                "AICH recovery: Merkle root of received leaves does not match trusted master"
            );
            return None;
        }
    } else {
        let total_blocks =
            ((file_size as u64 + AICH_BLOCK_SIZE as u64 - 1) / AICH_BLOCK_SIZE as u64) as usize;
        if hs.leaf_hashes.len() >= total_blocks {
            let computed_root = hierarchical_root(&hs.leaf_hashes, file_size);
            if computed_root != trusted_master {
                tracing::warn!("AICH recovery: full-tree root mismatch for multi-part file");
                return None;
            }
        } else {
            // Partial tree: verify per-part subtree root against the trusted master.
            // Build the part's local Merkle root from received leaves and verify it
            // matches what hierarchical_root would produce for this part index.
            let part_leaves = &hs.leaf_hashes[start_block..start_block + expected_blocks];
            let part_root = merkle_root(part_leaves);
            // For multi-part files we cannot verify against the master directly with
            // only partial leaves; reject recovery to prevent accepting attacker data.
            tracing::warn!(
                "AICH recovery: partial tree ({}/{} leaves) — cannot verify against master, rejecting",
                hs.leaf_hashes.len(), total_blocks
            );
            let _ = part_root;
            return None;
        }
    }

    Some(hs.find_corrupt_blocks(part_index, part_data, part_size))
}

/// eMule known2_64.met file format version
const KNOWN2_MET_VERSION: u8 = 0x02;
/// Upper bound for app-managed known2_64.met before reading it into memory.
/// 64 MiB is enough for roughly 3.3M AICH leaves (~600 GiB of shared data at
/// 180 KiB per leaf), while preventing a corrupt local file from being slurped
/// wholesale into RAM.
const MAX_KNOWN2_MET_BYTES: u64 = 64 * 1024 * 1024;

/// Save AICH hash sets to known2_64.met (eMule SHAHashSet.cpp format).
/// Format: version(u8) + repeated [master_hash(20) + hash_count(u32) + hashes(20*count)]
pub fn save_known2_met(
    path: &std::path::Path,
    hash_sets: &[AICHRecoveryHashSet],
) -> std::io::Result<()> {
    use std::io::Write;
    let mut buf: Vec<u8> = Vec::new();
    buf.write_all(&[KNOWN2_MET_VERSION])?;
    for hs in hash_sets {
        buf.write_all(&hs.root_hash)?;
        let count = hs.leaf_hashes.len() as u32;
        buf.write_all(&count.to_le_bytes())?;
        for leaf in &hs.leaf_hashes {
            buf.write_all(leaf)?;
        }
    }
    crate::security::atomic_write(path, &buf, false)
}

/// Load AICH hash sets from known2_64.met.
pub fn load_known2_met(path: &std::path::Path) -> std::io::Result<Vec<([u8; 20], Vec<[u8; 20]>)>> {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_KNOWN2_MET_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "known2_64.met too large ({} bytes, max {})",
                    meta.len(),
                    MAX_KNOWN2_MET_BYTES
                ),
            ));
        }
    }
    let data = std::fs::read(path)?;
    if data.is_empty() {
        return Ok(Vec::new());
    }
    let version = data[0];
    if version != KNOWN2_MET_VERSION {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported known2.met version: 0x{version:02X}"),
        ));
    }
    let mut offset = 1;
    let mut result = Vec::new();
    while offset + 24 <= data.len() {
        let mut master = [0u8; 20];
        master.copy_from_slice(&data[offset..offset + 20]);
        offset += 20;
        let count = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;
        // `count` is attacker-controlled only via local file tampering, but
        // compute the record end with checked arithmetic so a corrupt count can
        // never wrap `usize` (32-bit) and slip past the truncation guard into an
        // over-sized read/allocation.
        let record_end = match count.checked_mul(20).and_then(|n| offset.checked_add(n)) {
            Some(end) => end,
            None => {
                tracing::warn!(
                    "known2_64.met record at offset {} claims an overflowing leaf count {}",
                    offset - 24,
                    count
                );
                break;
            }
        };
        if record_end > data.len() {
            tracing::warn!(
                "known2_64.met truncated: record at offset {} claims {} leaves but only {} bytes remain",
                offset - 24, count, data.len() - offset
            );
            break;
        }
        let mut leaves = Vec::with_capacity(count);
        for _ in 0..count {
            let mut h = [0u8; 20];
            h.copy_from_slice(&data[offset..offset + 20]);
            offset += 20;
            leaves.push(h);
        }
        result.push((master, leaves));
    }
    Ok(result)
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
        let leaf = hash_leaf(b"hello");
        let root = merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_two_leaves() {
        let a = hash_leaf(b"hello");
        let b = hash_leaf(b"world");
        let root = merkle_root(&[a, b]);
        let expected = hash_internal(&a, &b);
        assert_eq!(root, expected);
    }

    #[test]
    fn find_corrupt_blocks_detects_mismatch() {
        let data = vec![0x42u8; AICH_BLOCK_SIZE];
        let hs = AICHRecoveryHashSet::build_from_data(&data);
        let mut bad = data.clone();
        bad[0] ^= 0xFF;
        let corrupt = hs.find_corrupt_blocks(0, &bad, bad.len());
        assert_eq!(corrupt, vec![0]);
    }

    /// L5: ensure a final partial AICH block (not a multiple of
    /// AICH_BLOCK_SIZE) is still validated correctly. The last chunk only
    /// spans a few KiB of the 180 KiB AICH block size; `find_corrupt_blocks`
    /// must consume the partial tail without panicking or mis-aligning.
    #[test]
    fn find_corrupt_blocks_final_partial_block() {
        let partial = 12_345;
        let full_blocks = 2;
        let total = full_blocks * AICH_BLOCK_SIZE + partial;
        let data: Vec<u8> = (0..total).map(|i| (i & 0xFF) as u8).collect();
        let hs = AICHRecoveryHashSet::build_from_data(&data);
        // Unmodified buffer: nothing corrupt.
        assert!(hs.find_corrupt_blocks(0, &data, data.len()).is_empty());
        // Flip one byte in the final partial block.
        let mut bad = data.clone();
        let flip_idx = full_blocks * AICH_BLOCK_SIZE + 7;
        bad[flip_idx] ^= 0xFF;
        let corrupt = hs.find_corrupt_blocks(0, &bad, bad.len());
        assert_eq!(corrupt, vec![full_blocks]);
    }

    #[test]
    fn corrupt_blocks_from_aich_recovery_roundtrip() {
        let data = vec![0x42u8; AICH_BLOCK_SIZE * 2];
        let trusted = AICHRecoveryHashSet::build_from_data(&data);
        let recovery = trusted.create_part_recovery_data(0, PARTSIZE as usize);
        let mut bad = data.clone();
        bad[AICH_BLOCK_SIZE + 10] ^= 0xFF;
        let corrupt = corrupt_blocks_from_aich_recovery(
            trusted.root_hash,
            &recovery,
            0,
            &bad,
            bad.len(),
            bad.len() as u64,
        )
        .expect("recovery");
        assert_eq!(corrupt, vec![1]);
    }

    fn build_emule_tree_payload(
        entries_16: &[(u16, [u8; 20])],
        entries_32: &[(u32, [u8; 20])],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(entries_16.len() as u16).to_le_bytes());
        for &(id, ref hash) in entries_16 {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(hash);
        }
        buf.extend_from_slice(&(entries_32.len() as u16).to_le_bytes());
        for &(id, ref hash) in entries_32 {
            buf.extend_from_slice(&id.to_le_bytes());
            buf.extend_from_slice(hash);
        }
        buf
    }

    #[test]
    fn parse_emule_tree_two_leaves() {
        let leaf_a: [u8; 20] = [0xAA; 20];
        let leaf_b: [u8; 20] = [0xBB; 20];
        let root = hash_internal(&leaf_a, &leaf_b);

        // Tree: root(1) -> leaf_a(2), leaf_b(3)
        let data = build_emule_tree_payload(&[(1, root), (2, leaf_a), (3, leaf_b)], &[]);

        let leaves = parse_emule_aich_tree(&data).expect("should parse eMule tree");
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0], leaf_a);
        assert_eq!(leaves[1], leaf_b);
    }

    #[test]
    fn parse_emule_tree_four_leaves() {
        let h: [[u8; 20]; 4] = [[0x11; 20], [0x22; 20], [0x33; 20], [0x44; 20]];
        let n2 = hash_internal(&h[0], &h[1]);
        let n3 = hash_internal(&h[2], &h[3]);
        let root = hash_internal(&n2, &n3);

        // depth-0: root(1), depth-1: n2(2), n3(3), depth-2: leaves 4..7
        let data = build_emule_tree_payload(
            &[
                (1, root),
                (2, n2),
                (3, n3),
                (4, h[0]),
                (5, h[1]),
                (6, h[2]),
                (7, h[3]),
            ],
            &[],
        );

        let leaves = parse_emule_aich_tree(&data).expect("should parse");
        assert_eq!(leaves, &h);
    }

    #[test]
    fn parse_emule_tree_32bit_entries() {
        let leaf_a: [u8; 20] = [0xCC; 20];
        let leaf_b: [u8; 20] = [0xDD; 20];
        let root = hash_internal(&leaf_a, &leaf_b);

        // All entries in the 32-bit section
        let data = build_emule_tree_payload(&[], &[(1, root), (2, leaf_a), (3, leaf_b)]);

        let leaves = parse_emule_aich_tree(&data).expect("should parse 32-bit entries");
        assert_eq!(leaves.len(), 2);
        assert_eq!(leaves[0], leaf_a);
        assert_eq!(leaves[1], leaf_b);
    }

    #[test]
    fn parse_emule_tree_rejects_flat_format() {
        // Flat format: u16 count=2, then 2*20 bytes of hashes
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&[0xAA; 20]);
        data.extend_from_slice(&[0xBB; 20]);

        assert!(parse_emule_aich_tree(&data).is_none());
    }

    #[test]
    fn read_recovery_data_emule_tree_roundtrip() {
        let block_data = vec![0x42u8; AICH_BLOCK_SIZE * 2];
        let trusted = AICHRecoveryHashSet::build_from_data(&block_data);
        let leaf_a = trusted.leaf_hashes[0];
        let leaf_b = trusted.leaf_hashes[1];

        let emule_payload =
            build_emule_tree_payload(&[(1, trusted.root_hash), (2, leaf_a), (3, leaf_b)], &[]);

        // Clean recovery — no blocks should be corrupt
        let result = corrupt_blocks_from_aich_recovery(
            trusted.root_hash,
            &emule_payload,
            0,
            &block_data,
            block_data.len(),
            block_data.len() as u64,
        )
        .expect("recovery from eMule tree");
        assert!(result.is_empty());

        // Corrupt block 1 — should be detected
        let mut bad = block_data.clone();
        bad[AICH_BLOCK_SIZE + 10] ^= 0xFF;
        let corrupt = corrupt_blocks_from_aich_recovery(
            trusted.root_hash,
            &emule_payload,
            0,
            &bad,
            bad.len(),
            bad.len() as u64,
        )
        .expect("recovery from eMule tree");
        assert_eq!(corrupt, vec![1]);
    }
}
