/// Ember chunk size: 256 KiB (vs 9.5 MB parts in ed2k).
pub const CHUNK_SIZE: usize = 256 * 1024;

/// BLAKE3 hash tree for chunk verification.
///
/// For a file split into 256 KiB chunks, we compute the BLAKE3 hash of each
/// chunk. The tree root is computed by hashing all chunk hashes together.
/// This root hash is the "Ember file hash" that identifies the file.
#[derive(Debug, Clone)]
pub struct HashTree {
    /// BLAKE3 hash of each chunk (32 bytes each).
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Root hash: BLAKE3 of all chunk hashes concatenated.
    pub root_hash: [u8; 32],
    /// Total file size in bytes.
    pub file_size: u64,
}

impl HashTree {
    /// Build a hash tree from file data.
    #[cfg(test)]
    pub fn from_data(data: &[u8]) -> Self {
        let mut chunk_hashes = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + CHUNK_SIZE).min(data.len());
            let chunk = &data[offset..end];
            let hash = *blake3::hash(chunk).as_bytes();
            chunk_hashes.push(hash);
            offset = end;
        }

        let root_hash = compute_root(&chunk_hashes);

        Self {
            chunk_hashes,
            root_hash,
            file_size: data.len() as u64,
        }
    }

    /// Build a hash tree incrementally from a reader.
    pub fn from_reader<R: std::io::Read>(mut reader: R) -> std::io::Result<Self> {
        let mut chunk_hashes = Vec::new();
        let mut file_size = 0u64;
        let mut buf = vec![0u8; CHUNK_SIZE];

        loop {
            let mut read_total = 0;
            while read_total < CHUNK_SIZE {
                match reader.read(&mut buf[read_total..]) {
                    Ok(0) => break,
                    Ok(n) => read_total += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if read_total == 0 {
                break;
            }
            let hash = *blake3::hash(&buf[..read_total]).as_bytes();
            chunk_hashes.push(hash);
            file_size += read_total as u64;
        }

        let root_hash = compute_root(&chunk_hashes);
        Ok(Self {
            chunk_hashes,
            root_hash,
            file_size,
        })
    }

    /// Number of chunks in the file.
    #[cfg(test)]
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }

    /// Verify a received chunk against the hash tree.
    pub fn verify_chunk(&self, index: usize, data: &[u8]) -> bool {
        if index >= self.chunk_hashes.len() {
            return false;
        }
        let expected = &self.chunk_hashes[index];
        let actual = blake3::hash(data);
        actual.as_bytes() == expected
    }
}

/// Recompute the root a chunk-hash list commits to.
///
/// Public because a receiver is handed the list before any file bytes and has
/// to check it against the root it was offered. That check is what makes the
/// per-chunk hashes trustworthy, and therefore what lets
/// [`HashTree::verify_chunk`] reject a bad chunk as it lands instead of the
/// whole file failing after the last byte.
pub fn root_from_chunk_hashes(chunk_hashes: &[[u8; 32]]) -> [u8; 32] {
    compute_root(chunk_hashes)
}

/// Compute the root hash from chunk hashes.
fn compute_root(chunk_hashes: &[[u8; 32]]) -> [u8; 32] {
    if chunk_hashes.is_empty() {
        return *blake3::hash(b"").as_bytes();
    }
    let mut hasher = blake3::Hasher::new();
    for h in chunk_hashes {
        hasher.update(h);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_tree_from_data() {
        let data = vec![0xABu8; CHUNK_SIZE * 3 + 100]; // 3 full chunks + 100 bytes
        let tree = HashTree::from_data(&data);
        assert_eq!(tree.chunk_count(), 4);
        assert_eq!(tree.file_size, (CHUNK_SIZE * 3 + 100) as u64);
        assert_ne!(tree.root_hash, [0u8; 32]);
    }

    #[test]
    fn hash_tree_verify_chunk() {
        let data = vec![0x42u8; CHUNK_SIZE + 50];
        let tree = HashTree::from_data(&data);

        assert!(tree.verify_chunk(0, &data[..CHUNK_SIZE]));
        assert!(tree.verify_chunk(1, &data[CHUNK_SIZE..]));
        assert!(!tree.verify_chunk(0, &data[CHUNK_SIZE..])); // wrong data for chunk 0
        assert!(!tree.verify_chunk(99, &[])); // out of range
    }

    #[test]
    fn hash_tree_deterministic() {
        let data = b"some file data";
        let t1 = HashTree::from_data(data);
        let t2 = HashTree::from_data(data);
        assert_eq!(t1.root_hash, t2.root_hash);
        assert_eq!(t1.chunk_hashes, t2.chunk_hashes);
    }

    #[test]
    fn hash_tree_from_reader() {
        let data = vec![0xCDu8; CHUNK_SIZE * 2 + 500];
        let tree_direct = HashTree::from_data(&data);
        let tree_reader = HashTree::from_reader(std::io::Cursor::new(&data)).unwrap();

        assert_eq!(tree_direct.root_hash, tree_reader.root_hash);
        assert_eq!(tree_direct.chunk_count(), tree_reader.chunk_count());
        assert_eq!(tree_direct.file_size, tree_reader.file_size);
    }

    #[test]
    fn empty_file_hash_tree() {
        let data = b"";
        let tree = HashTree::from_data(data);
        assert_eq!(tree.chunk_count(), 0);
        assert_eq!(tree.file_size, 0);
    }
}
