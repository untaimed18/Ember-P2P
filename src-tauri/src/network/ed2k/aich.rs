use std::collections::HashMap;
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

/// Upper bound on the trailing recovery-data blob in an `OP_AICHANSWER`.
///
/// An answer covers a single part, whose block-hash synchronisation tree is
/// only ~1 KiB (at most `BLOCKS_PER_FULL_PART` leaves plus the path to the
/// root). This 256 KiB ceiling is hundreds of times that, so it never rejects
/// a legitimate answer, yet stops a peer from padding a valid-looking answer
/// with megabytes of junk that we'd otherwise copy and hold for the full
/// AICH wait window.
pub const MAX_AICH_RECOVERY_BYTES: usize = 256 * 1024;

pub fn compute_aich_root(path: &Path) -> anyhow::Result<[u8; 20]> {
    static NEVER: AtomicBool = AtomicBool::new(false);
    compute_aich_root_cancellable(path, &NEVER)
}

pub fn compute_aich_root_cancellable(
    path: &Path,
    cancelled: &AtomicBool,
) -> anyhow::Result<[u8; 20]> {
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
        leaf_hashes.push(hash_leaf(buf_slice));
        remaining -= block_size as u64;
    }

    Ok(hierarchical_root(&leaf_hashes, file_size))
}

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

/// Hash `file_size` bytes from `reader` into AICH block leaves, resetting
/// the block boundary at each PARTSIZE part boundary.
///
/// This matters because `PARTSIZE % AICH_BLOCK_SIZE != 0`
/// (9,728,000 / 184,320 is not an integer): eMule's `CAICHHashTree` hashes
/// each part's blocks independently (`SHAHashSet.cpp` — `GetBaseSize()`
/// only switches from `PARTSIZE` to `EMBLOCKSIZE` *within* a subtree whose
/// own data size has already been narrowed to a single part), so every
/// part's last block is short and the next part always starts a fresh
/// full-size block at its own beginning — blocks never straddle a part
/// boundary. Chunking continuously across the whole file instead would
/// silently shift every block after the first part's, producing AICH leaf
/// (and therefore master) hashes that don't match real eMule/aMule peers.
fn hash_leaves_from_reader<R: Read>(
    reader: &mut R,
    file_size: u64,
) -> std::io::Result<Vec<[u8; 20]>> {
    let block_size_u64 = AICH_BLOCK_SIZE as u64;
    let num_blocks_upper_bound = ((file_size + block_size_u64 - 1) / block_size_u64) as usize;
    let mut leaf_hashes: Vec<[u8; 20]> = Vec::with_capacity(num_blocks_upper_bound);
    let mut buf = vec![0u8; AICH_BLOCK_SIZE];

    let num_parts = (((file_size + PARTSIZE as u64 - 1) / PARTSIZE as u64) as usize).max(1);
    let mut remaining = file_size;
    for p in 0..num_parts {
        let part_size = if p < num_parts - 1 {
            PARTSIZE as u64
        } else {
            remaining
        };
        let mut part_remaining = part_size;
        while part_remaining > 0 {
            let block_size = part_remaining.min(block_size_u64) as usize;
            let buf_slice = &mut buf[..block_size];
            reader.read_exact(buf_slice)?;
            leaf_hashes.push(hash_leaf(buf_slice));
            part_remaining -= block_size as u64;
        }
        remaining -= part_size;
    }
    Ok(leaf_hashes)
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

    let part_hashes = compute_all_part_hashes(all_leaves, file_size, num_parts);
    build_tree_recursive(&part_hashes, true)
}

/// Number of top-level blocks a full part's 9.28MB is split into: always 53
/// (`ceil(PARTSIZE / AICH_BLOCK_SIZE)`), an *odd* count. Every full part's
/// own `is_left_branch` therefore genuinely changes its internal split point
/// (`(53 + is_left) / 2` = 27 vs 26), so it must be threaded through from the
/// top-level part tree rather than assumed — see [`compute_part_is_left`].
///
/// Per-part subtree root hashes (bottom level of the two-level tree), one
/// per part, in file order. Shared by [`hierarchical_root`] (master hash)
/// and the AICH-recovery audit-path builder so both always agree on exactly
/// the same per-part hashes.
fn compute_all_part_hashes(all_leaves: &[[u8; 20]], file_size: u64, num_parts: usize) -> Vec<[u8; 20]> {
    let part_is_left = compute_part_is_left(num_parts);
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
            part_hashes.push(build_tree_recursive(part_leaves, part_is_left[p]));
        }
        offset = end;
    }
    part_hashes
}

/// For each of `num_parts` parts, whether it is a "left" or "right" branch
/// in eMule's top-level (part-count) tree — i.e. replays
/// `CAICHHashTree::FindHash`'s `nLeft = (nBlocks + bIsLeftBranch) / 2`
/// recursion down to each individual part and records the branch it landed
/// on. A part's `is_left_branch` is a property of *where it sits in the top
/// tree*, not always `true`: e.g. for a 2-part file, part 0 is left but part
/// 1 is right, which (since 53 — the blocks-per-part count — is odd) changes
/// part 1's own internal block split point and therefore its subtree hash.
fn compute_part_is_left(num_parts: usize) -> Vec<bool> {
    fn walk(start: usize, len: usize, is_left: bool, out: &mut [bool]) {
        if len == 0 {
            return;
        }
        if len == 1 {
            out[start] = is_left;
            return;
        }
        let n_left = (len + if is_left { 1 } else { 0 }) / 2;
        walk(start, n_left, true, out);
        walk(start + n_left, len - n_left, false, out);
    }
    let mut out = vec![false; num_parts];
    walk(0, num_parts, true, &mut out);
    out
}

/// Walks eMule's top-level (part-count) tree from the master root down to
/// `target_part`, returning the part's own global tree-position id and
/// `is_left_branch`, plus the sibling `(id, hash)` pairs needed to climb
/// back up from that part to the master root — ordered shallowest (nearest
/// the root) first. Uses eMule's `HashsIdentifier` bit convention
/// (SHAHashSet.h): left child id = `parent*2 + 1`, right child id =
/// `parent*2` ("a set bit means follow the left branch").
///
/// `part_hashes` must be exactly [`compute_all_part_hashes`]'s output so
/// sibling hashes for parts *other than* `target_part` are correct; only
/// `merkle_root` over small slices of already-computed part hashes is
/// needed here, never the underlying block leaves of other parts.
fn top_level_audit_path(
    part_hashes: &[[u8; 20]],
    target_part: usize,
) -> (u64, bool, Vec<(u64, [u8; 20])>) {
    fn walk(
        leaves: &[[u8; 20]],
        target: usize,
        id: u64,
        is_left: bool,
        out: &mut Vec<(u64, [u8; 20])>,
    ) -> (u64, bool) {
        if leaves.len() <= 1 {
            return (id, is_left);
        }
        let n_left = (leaves.len() + if is_left { 1 } else { 0 }) / 2;
        let left_id = id * 2 + 1;
        let right_id = id * 2;
        if target < n_left {
            out.push((right_id, merkle_root(&leaves[n_left..])));
            walk(&leaves[..n_left], target, left_id, true, out)
        } else {
            out.push((left_id, merkle_root(&leaves[..n_left])));
            walk(&leaves[n_left..], target - n_left, right_id, false, out)
        }
    }
    let mut out = Vec::new();
    let (id, is_left) = walk(part_hashes, target_part, 1, true, &mut out);
    (id, is_left, out)
}

/// Structure-only counterpart of [`top_level_audit_path`] for the receiving
/// side, which doesn't have other parts' hashes to compute sibling values
/// from — it only needs to know *which* sibling ids to look up among the
/// hashes actually received on the wire, and whether its own accumulated
/// hash is the left or right operand when recombining with each one.
fn top_level_path_structure(num_parts: usize, target_part: usize) -> (u64, bool, Vec<(u64, bool)>) {
    fn walk(len: usize, mut target: usize, id: u64, is_left: bool, out: &mut Vec<(u64, bool)>) -> (u64, bool) {
        if len <= 1 {
            return (id, is_left);
        }
        let n_left = (len + if is_left { 1 } else { 0 }) / 2;
        let left_id = id * 2 + 1;
        let right_id = id * 2;
        if target < n_left {
            out.push((right_id, true)); // sibling is the right subtree; we are left
            walk(n_left, target, left_id, true, out)
        } else {
            out.push((left_id, false)); // sibling is the left subtree; we are right
            target -= n_left;
            walk(len - n_left, target, right_id, false, out)
        }
    }
    let mut out = Vec::new();
    let (id, is_left) = walk(num_parts, target_part, 1, true, &mut out);
    (id, is_left, out)
}

/// Left-to-right global tree-position ids for `count` leaves whose subtree
/// root has id `start_id`/`start_is_left`, using eMule's `left = id*2+1`,
/// `right = id*2` convention (mirrors `CAICHHashTree::WriteLowestLevelHashes`
/// / `LoadLowestLevelHashes`'s recursion). Shared by the sender (zips the
/// ids with the actual leaf hashes to write) and the receiver (zips the ids
/// with lookups into the received hash map).
fn leaf_ids(count: usize, start_id: u64, start_is_left: bool) -> Vec<u64> {
    fn walk(count: usize, id: u64, is_left: bool, out: &mut Vec<u64>) {
        if count <= 1 {
            out.push(id);
            return;
        }
        let n_left = (count + if is_left { 1 } else { 0 }) / 2;
        walk(n_left, id * 2 + 1, true, out);
        walk(count - n_left, id * 2, false, out);
    }
    let mut out = Vec::with_capacity(count);
    if count > 0 {
        walk(count, start_id, start_is_left, &mut out);
    }
    out
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
    /// Total file size this hash set covers. Needed (alongside `PARTSIZE`)
    /// to determine `num_parts` and therefore each part's position within
    /// eMule's two-level tree — see `create_part_recovery_data`/
    /// `read_recovery_data`.
    pub file_size: u64,
}

/// Number of AICH blocks in part `part_index` of a `num_parts`-part file of
/// `file_size` bytes — `0` if `part_index` is out of range. All parts except
/// possibly the last are exactly [`BLOCKS_PER_FULL_PART`] (53) blocks.
fn blocks_in_part(file_size: u64, part_index: usize, num_parts: usize) -> usize {
    if part_index >= num_parts {
        return 0;
    }
    let part_data_size = if part_index < num_parts - 1 {
        PARTSIZE as u64
    } else {
        let rem = file_size % PARTSIZE as u64;
        if rem == 0 { PARTSIZE as u64 } else { rem }
    };
    ((part_data_size + AICH_BLOCK_SIZE as u64 - 1) / AICH_BLOCK_SIZE as u64) as usize
}

/// Parse eMule's `OP_AICHANSWER` tree-position wire format into raw
/// `(id, hash)` entries, without interpreting what each id means — that
/// depends on the requested part/file size and is resolved by
/// [`AICHRecoveryHashSet::read_recovery_data`] against the ids it expects
/// (see [`leaf_ids`] / [`top_level_path_structure`]).
///
/// Wire format: `<u16:count_16>[<u16:id><20B:hash>]*<u16:count_32>[<u32:id><20B:hash>]*`
/// Returns `None` if the data doesn't structurally match this format.
fn parse_wire_entries(data: &[u8]) -> Option<Vec<(u64, [u8; 20])>> {
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
    Some(entries)
}

/// Verify a candidate leaf set for one part against a trusted master hash,
/// climbing eMule's two-level tree (leaves -> part subtree root -> top-level
/// audit path -> master), and return the leaves if verification succeeds.
///
/// `sibling_lookup` resolves a top-level audit-path sibling id to its hash;
/// for the eMule tree-position wire format these come from the peer's
/// answer, for the flat (Ember-only) format there is no audit path so it's
/// only ever consulted when `num_parts <= 1`.
fn verify_part_leaves(
    leaves: &[[u8; 20]],
    trusted_master: [u8; 20],
    file_size: u64,
    part_index: usize,
    sibling_lookup: impl Fn(u64) -> Option<[u8; 20]>,
) -> bool {
    if leaves.is_empty() {
        return false;
    }
    let num_parts = (((file_size + PARTSIZE as u64 - 1) / PARTSIZE as u64) as usize).max(1);
    let part_is_left = if num_parts <= 1 {
        true
    } else {
        let (_, is_left, _) = top_level_path_structure(num_parts, part_index);
        is_left
    };
    let mut cur_hash = if leaves.len() == 1 {
        leaves[0]
    } else {
        build_tree_recursive(leaves, part_is_left)
    };

    if num_parts <= 1 {
        return cur_hash == trusted_master;
    }

    let (_, _, path) = top_level_path_structure(num_parts, part_index);
    // `path` is root-to-target order; climb bottom-up by walking it in reverse.
    for &(sibling_id, i_am_left) in path.iter().rev() {
        let Some(sibling_hash) = sibling_lookup(sibling_id) else {
            return false;
        };
        cur_hash = if i_am_left {
            hash_internal(&cur_hash, &sibling_hash)
        } else {
            hash_internal(&sibling_hash, &cur_hash)
        };
    }
    cur_hash == trusted_master
}

impl AICHRecoveryHashSet {
    pub fn new(root_hash: [u8; 20], file_size: u64) -> Self {
        Self {
            root_hash,
            leaf_hashes: Vec::new(),
            file_size,
        }
    }

    /// Build from a file, storing all leaf hashes.
    pub fn build_from_file(path: &Path) -> anyhow::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let file_size = file.metadata()?.len();
        let leaf_hashes = hash_leaves_from_reader(&mut file, file_size)?;
        let root_hash = hierarchical_root(&leaf_hashes, file_size);
        Ok(Self {
            root_hash,
            leaf_hashes,
            file_size,
        })
    }

    /// Build from raw data (e.g., a part or buffer). The buffer is treated
    /// as the whole "file" for tree-position purposes (`file_size =
    /// data.len()`).
    pub fn build_from_data(data: &[u8]) -> Self {
        let file_size = data.len() as u64;
        let mut cursor = std::io::Cursor::new(data);
        let leaf_hashes = hash_leaves_from_reader(&mut cursor, file_size)
            .expect("reading from an in-memory Cursor over `data` cannot fail");
        let root_hash = hierarchical_root(&leaf_hashes, file_size);
        Self {
            root_hash,
            leaf_hashes,
            file_size,
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
    /// left=2*parent+1, right=2*parent — eMule's `HashsIdentifier` convention,
    /// SHAHashSet.h). For multi-part files this includes both the part's own
    /// block leaves *and* the top-level audit-path sibling hashes needed to
    /// climb from the part up to the file's master root (mirrors
    /// `CAICHHashTree::CreatePartRecoveryData` writing sibling hashes at each
    /// level before descending). This is the format stock eMule, aMule, and
    /// all known mods expect in `OP_AICHANSWER`.
    ///
    /// Requires `self.leaf_hashes` to cover the *entire* file (as produced by
    /// `build_from_file`), since the audit path for one part needs the other
    /// parts' subtree hashes too.
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

        let empty_envelope = || {
            let mut data = Vec::with_capacity(4);
            data.extend_from_slice(&0u16.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes());
            data
        };

        if part_leaves.is_empty() {
            return empty_envelope();
        }

        let num_parts = (((self.file_size + PARTSIZE as u64 - 1) / PARTSIZE as u64) as usize).max(1);
        if part_index >= num_parts {
            return empty_envelope();
        }

        let mut entries: Vec<(u64, [u8; 20])> = Vec::new();
        let (part_id, part_is_left) = if num_parts <= 1 {
            (1u64, true)
        } else {
            let part_hashes = compute_all_part_hashes(&self.leaf_hashes, self.file_size, num_parts);
            let (id, is_left, siblings) = top_level_audit_path(&part_hashes, part_index);
            entries.extend(siblings);
            (id, is_left)
        };
        for (id, hash) in leaf_ids(part_leaves.len(), part_id, part_is_left)
            .into_iter()
            .zip(part_leaves.iter().copied())
        {
            entries.push((id, hash));
        }

        let mut entries_16 = Vec::new();
        let mut entries_32 = Vec::new();
        for &(id, hash) in &entries {
            if id <= u16::MAX as u64 {
                entries_16.push((id as u16, hash));
            } else {
                entries_32.push((id as u32, hash));
            }
        }

        let mut data = Vec::new();
        data.extend_from_slice(&(entries_16.len() as u16).to_le_bytes());
        for &(id, hash) in &entries_16 {
            data.extend_from_slice(&id.to_le_bytes());
            data.extend_from_slice(&hash);
        }
        data.extend_from_slice(&(entries_32.len() as u16).to_le_bytes());
        for &(id, hash) in &entries_32 {
            data.extend_from_slice(&id.to_le_bytes());
            data.extend_from_slice(&hash);
        }
        data
    }

    /// Read (and fully verify against `self.root_hash`/`self.file_size`,
    /// which callers must have already set to the *trusted* master hash and
    /// real file size) recovery data received from a peer, populating
    /// `self.leaf_hashes` at the part's global block offset on success.
    ///
    /// Supports both the eMule tree format (tree-position identifiers +
    /// hashes, including any multi-part audit path) and the Ember-only flat
    /// format (block_count + raw leaves, no ids — verifiable only for
    /// single-part files, since it carries no audit path to the master).
    /// Unlike parsing alone, a `true` return means the leaves are
    /// cryptographically tied back to the trusted master hash, not just
    /// well-formed.
    pub fn read_recovery_data(
        &mut self,
        data: &[u8],
        part_index: usize,
        _part_size: usize,
    ) -> bool {
        let trusted_master = self.root_hash;
        let file_size = self.file_size;
        let num_parts = (((file_size + PARTSIZE as u64 - 1) / PARTSIZE as u64) as usize).max(1);
        let block_count = blocks_in_part(file_size, part_index, num_parts);
        if block_count == 0 || block_count > BLOCKS_PER_FULL_PART {
            return false;
        }

        let leaves = if let Some(entries) = parse_wire_entries(data) {
            let map: HashMap<u64, [u8; 20]> = entries.into_iter().collect();
            let (part_id, part_is_left) = if num_parts <= 1 {
                (1u64, true)
            } else {
                let (id, is_left, _) = top_level_path_structure(num_parts, part_index);
                (id, is_left)
            };
            let mut leaves = Vec::with_capacity(block_count);
            for id in leaf_ids(block_count, part_id, part_is_left) {
                match map.get(&id) {
                    Some(hash) => leaves.push(*hash),
                    None => return false,
                }
            }
            if !verify_part_leaves(&leaves, trusted_master, file_size, part_index, |sid| {
                map.get(&sid).copied()
            }) {
                return false;
            }
            leaves
        } else {
            // Flat (Ember-only) fallback: no tree-position ids, so no
            // multi-part audit path either — only verifiable when the
            // part's own subtree root already *is* the master hash.
            if data.len() < 2 {
                return false;
            }
            let flat_count = u16::from_le_bytes([data[0], data[1]]) as usize;
            if flat_count != block_count {
                return false;
            }
            let expected_len = 2 + flat_count * 20;
            if data.len() < expected_len {
                return false;
            }
            let mut leaves = Vec::with_capacity(flat_count);
            for i in 0..flat_count {
                let offset = 2 + i * 20;
                let mut hash = [0u8; 20];
                hash.copy_from_slice(&data[offset..offset + 20]);
                leaves.push(hash);
            }
            if !verify_part_leaves(&leaves, trusted_master, file_size, part_index, |_| None) {
                return false;
            }
            leaves
        };

        let start_block = part_index * BLOCKS_PER_FULL_PART;
        while self.leaf_hashes.len() < start_block + leaves.len() {
            self.leaf_hashes.push([0u8; 20]);
        }
        for (i, hash) in leaves.into_iter().enumerate() {
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
    let mut hs = AICHRecoveryHashSet::new(trusted_master, file_size);
    // `read_recovery_data` verifies the received leaves against
    // `trusted_master` itself — for multi-part files this climbs the
    // top-level audit path shipped alongside the part's block hashes (see
    // `verify_part_leaves`), rather than requiring the whole file's tree to
    // already be known locally. A `false` return means either the data
    // didn't parse, didn't cover every block of this part, or didn't
    // cryptographically tie back to `trusted_master` — reject in all cases.
    if !hs.read_recovery_data(recovery_data, part_index, part_size) {
        tracing::warn!("AICH recovery: failed to verify recovery data for part {part_index} against trusted master");
        return None;
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
    fn parse_wire_entries_extracts_16bit_section() {
        let leaf_a: [u8; 20] = [0xAA; 20];
        let leaf_b: [u8; 20] = [0xBB; 20];
        let data = build_emule_tree_payload(&[(3, leaf_a), (2, leaf_b)], &[]);

        let entries = parse_wire_entries(&data).expect("should parse");
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&(3u64, leaf_a)));
        assert!(entries.contains(&(2u64, leaf_b)));
    }

    #[test]
    fn parse_wire_entries_extracts_32bit_section() {
        let leaf_a: [u8; 20] = [0xCC; 20];
        let leaf_b: [u8; 20] = [0xDD; 20];
        let data = build_emule_tree_payload(&[], &[(3, leaf_a), (2, leaf_b)]);

        let entries = parse_wire_entries(&data).expect("should parse 32-bit entries");
        assert_eq!(entries.len(), 2);
        assert!(entries.contains(&(3u64, leaf_a)));
        assert!(entries.contains(&(2u64, leaf_b)));
    }

    #[test]
    fn parse_wire_entries_rejects_flat_format() {
        // Flat format: u16 count=2, then 2*20 bytes of hashes
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&[0xAA; 20]);
        data.extend_from_slice(&[0xBB; 20]);

        assert!(parse_wire_entries(&data).is_none());
    }

    /// Regression test for eMule's own documented worked example
    /// (SHAHashSet.h `HashsIdentifier`): root=1; left child=3, right
    /// child=2; the left child's own children are 7 (left) and 6 (right).
    /// Left child id = `parent*2+1`, right child id = `parent*2` — the
    /// *opposite* of a textbook binary-heap numbering, and easy to get
    /// backwards (this codebase previously did).
    #[test]
    fn leaf_ids_matches_emule_documented_example() {
        assert_eq!(leaf_ids(2, 1, true), vec![3, 2]);
        assert_eq!(leaf_ids(4, 1, true), vec![7, 6, 5, 4]);
    }

    #[test]
    fn read_recovery_data_emule_tree_roundtrip() {
        let block_data = vec![0x42u8; AICH_BLOCK_SIZE * 2];
        let trusted = AICHRecoveryHashSet::build_from_data(&block_data);
        let leaf_a = trusted.leaf_hashes[0];
        let leaf_b = trusted.leaf_hashes[1];

        // Single-part file: leaf_a (index 0, left) => id 3, leaf_b (index 1,
        // right) => id 2 (see `leaf_ids_matches_emule_documented_example`).
        // Real eMule never sends id 1 (the master) over the wire either.
        let emule_payload = build_emule_tree_payload(&[(3, leaf_a), (2, leaf_b)], &[]);

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

    /// End-to-end regression for the multi-part audit-path fix: a 3-part
    /// file (two full parts + one trailing partial part) exercises a part
    /// that is a top-level "left" branch (part 0), one that is "right"
    /// (part 1 — whose internal block split point the old hardcoded
    /// `is_left_branch=true` bug computed incorrectly, since 53 is odd),
    /// and a single-block trailing part. Every part's recovery answer must
    /// independently verify against the same file-wide master hash, and
    /// still correctly localize an injected corruption.
    #[test]
    fn multi_part_recovery_survives_audit_path_and_detects_corruption() {
        let file_size = PARTSIZE * 2 + AICH_BLOCK_SIZE;
        let data = vec![0xABu8; file_size];
        let trusted = AICHRecoveryHashSet::build_from_data(&data);
        assert_eq!(trusted.leaf_hashes.len(), BLOCKS_PER_FULL_PART * 2 + 1);

        let part_range = |part_index: usize| -> (usize, usize) {
            if part_index < 2 {
                (part_index * PARTSIZE, (part_index + 1) * PARTSIZE)
            } else {
                (2 * PARTSIZE, file_size)
            }
        };

        for part_index in 0..3usize {
            let recovery = trusted.create_part_recovery_data(part_index, PARTSIZE);
            let (start, end) = part_range(part_index);
            let part_data = &data[start..end];
            let corrupt = corrupt_blocks_from_aich_recovery(
                trusted.root_hash,
                &recovery,
                part_index,
                part_data,
                part_data.len(),
                file_size as u64,
            )
            .unwrap_or_else(|| panic!("recovery for part {part_index} should verify against master"));
            assert!(corrupt.is_empty(), "part {part_index} should have no corrupt blocks");
        }

        // Corrupt a block inside part 1 (the top-level "right" branch) and
        // confirm the same per-part recovery answer still verifies and
        // correctly localizes it.
        let recovery = trusted.create_part_recovery_data(1, PARTSIZE);
        let (start, end) = part_range(1);
        let mut bad_part1 = data[start..end].to_vec();
        bad_part1[AICH_BLOCK_SIZE + 5] ^= 0xFF;
        let corrupt = corrupt_blocks_from_aich_recovery(
            trusted.root_hash,
            &recovery,
            1,
            &bad_part1,
            bad_part1.len(),
            file_size as u64,
        )
        .expect("recovery for corrupted part 1 should still verify");
        assert_eq!(corrupt, vec![1]);
    }
}
