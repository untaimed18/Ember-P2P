use std::net::SocketAddr;

use byteorder::{LittleEndian, WriteBytesExt};

/// Ember chunk size: 256 KiB (vs 9.5 MB parts in ed2k).
pub const CHUNK_SIZE: usize = 256 * 1024;

/// Stream protocol message types.
const MSG_REQUEST_CHUNKS: u8 = 0x01;
const MSG_CHUNK_DATA: u8 = 0x02;
const MSG_FILE_INFO: u8 = 0x03;
const MSG_TRANSFER_COMPLETE: u8 = 0x04;

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

/// A chunk request: which chunks to fetch from a peer.
#[derive(Debug, Clone)]
pub struct ChunkRequest {
    pub ember_file_hash: [u8; 32],
    pub chunk_indices: Vec<u32>,
}

impl ChunkRequest {
    /// Encode a chunk request for sending over a QUIC stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 4 + self.chunk_indices.len() * 4);
        buf.push(MSG_REQUEST_CHUNKS);
        buf.extend_from_slice(&self.ember_file_hash);
        buf.write_u32::<LittleEndian>(self.chunk_indices.len() as u32)
            .unwrap();
        for &idx in &self.chunk_indices {
            buf.write_u32::<LittleEndian>(idx).unwrap();
        }
        buf
    }

    /// Decode a chunk request from wire data.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 32 + 4 {
            return None;
        }
        if data[0] != MSG_REQUEST_CHUNKS {
            return None;
        }
        let mut ember_file_hash = [0u8; 32];
        ember_file_hash.copy_from_slice(&data[1..33]);
        let count = u32::from_le_bytes(data[33..37].try_into().ok()?) as usize;
        if data.len() < 37 + count * 4 {
            return None;
        }
        let mut chunk_indices = Vec::with_capacity(count);
        for i in 0..count {
            let offset = 37 + i * 4;
            let idx = u32::from_le_bytes(data[offset..offset + 4].try_into().ok()?);
            chunk_indices.push(idx);
        }
        Some(Self {
            ember_file_hash,
            chunk_indices,
        })
    }
}

/// A chunk data response.
#[derive(Debug, Clone)]
pub struct ChunkData {
    pub ember_file_hash: [u8; 32],
    pub chunk_index: u32,
    pub data: Vec<u8>,
}

impl ChunkData {
    /// Encode chunk data for sending over a QUIC stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + 32 + 4 + 4 + self.data.len());
        buf.push(MSG_CHUNK_DATA);
        buf.extend_from_slice(&self.ember_file_hash);
        buf.write_u32::<LittleEndian>(self.chunk_index).unwrap();
        buf.write_u32::<LittleEndian>(self.data.len() as u32).unwrap();
        buf.extend_from_slice(&self.data);
        buf
    }

    /// Decode chunk data from wire format.
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 1 + 32 + 4 + 4 {
            return None;
        }
        if data[0] != MSG_CHUNK_DATA {
            return None;
        }
        let mut ember_file_hash = [0u8; 32];
        ember_file_hash.copy_from_slice(&data[1..33]);
        let chunk_index = u32::from_le_bytes(data[33..37].try_into().ok()?);
        let data_len = u32::from_le_bytes(data[37..41].try_into().ok()?) as usize;
        if data.len() < 41 + data_len {
            return None;
        }
        Some(Self {
            ember_file_hash,
            chunk_index,
            data: data[41..41 + data_len].to_vec(),
        })
    }
}

/// Source type for the transfer engine's source merging.
#[derive(Debug, Clone, PartialEq)]
pub enum SourceType {
    /// Ember network source (QUIC, BLAKE3 verification).
    Ember {
        node_id: [u8; 16],
        addr: SocketAddr,
        noise_pub: [u8; 32],
    },
    /// Legacy ed2k/KAD source (TCP, MD4/AICH verification).
    Legacy {
        addr: SocketAddr,
        user_hash: Option<[u8; 16]>,
    },
}

/// A unified source entry that can represent both Ember and legacy sources.
#[derive(Debug, Clone)]
pub struct MergedSource {
    pub source_type: SourceType,
    /// Priority: lower is better. Ember sources get lower (better) priority.
    pub priority: u8,
    pub last_seen: i64,
}

impl MergedSource {
    pub fn ember(
        node_id: [u8; 16],
        addr: SocketAddr,
        noise_pub: [u8; 32],
        last_seen: i64,
    ) -> Self {
        Self {
            source_type: SourceType::Ember {
                node_id,
                addr,
                noise_pub,
            },
            priority: 0, // Ember preferred
            last_seen,
        }
    }

    pub fn legacy(addr: SocketAddr, user_hash: Option<[u8; 16]>, last_seen: i64) -> Self {
        Self {
            source_type: SourceType::Legacy { addr, user_hash },
            priority: 10, // Legacy lower priority
            last_seen,
        }
    }

    pub fn is_ember(&self) -> bool {
        matches!(self.source_type, SourceType::Ember { .. })
    }
}

/// Manages merged sources for a single file transfer.
#[derive(Debug)]
pub struct SourceMerger {
    sources: Vec<MergedSource>,
}

impl SourceMerger {
    pub fn new() -> Self {
        Self {
            sources: Vec::new(),
        }
    }

    /// Add or update a source. Deduplicates by address.
    pub fn add_source(&mut self, source: MergedSource) {
        let addr = match &source.source_type {
            SourceType::Ember { addr, .. } => *addr,
            SourceType::Legacy { addr, .. } => *addr,
        };

        if let Some(existing) = self.sources.iter_mut().find(|s| {
            match &s.source_type {
                SourceType::Ember { addr: a, .. } => *a == addr,
                SourceType::Legacy { addr: a, .. } => *a == addr,
            }
        }) {
            // Update: prefer the newer/better source
            if source.priority < existing.priority || source.last_seen > existing.last_seen {
                *existing = source;
            }
        } else {
            self.sources.push(source);
        }
    }

    /// Get all sources sorted by priority (best first).
    pub fn sorted_sources(&self) -> Vec<&MergedSource> {
        let mut sorted: Vec<&MergedSource> = self.sources.iter().collect();
        sorted.sort_by(|a, b| a.priority.cmp(&b.priority).then(b.last_seen.cmp(&a.last_seen)));
        sorted
    }

    /// Number of available sources.
    pub fn source_count(&self) -> usize {
        self.sources.len()
    }

    /// Number of Ember sources.
    pub fn ember_source_count(&self) -> usize {
        self.sources.iter().filter(|s| s.is_ember()).count()
    }

    /// Number of legacy sources.
    pub fn legacy_source_count(&self) -> usize {
        self.sources.iter().filter(|s| !s.is_ember()).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn chunk_request_round_trip() {
        let req = ChunkRequest {
            ember_file_hash: [0xAA; 32],
            chunk_indices: vec![0, 5, 10, 255],
        };
        let encoded = req.encode();
        let decoded = ChunkRequest::decode(&encoded).unwrap();
        assert_eq!(decoded.ember_file_hash, req.ember_file_hash);
        assert_eq!(decoded.chunk_indices, req.chunk_indices);
    }

    #[test]
    fn chunk_data_round_trip() {
        let chunk = ChunkData {
            ember_file_hash: [0xBB; 32],
            chunk_index: 42,
            data: vec![1, 2, 3, 4, 5],
        };
        let encoded = chunk.encode();
        let decoded = ChunkData::decode(&encoded).unwrap();
        assert_eq!(decoded.ember_file_hash, chunk.ember_file_hash);
        assert_eq!(decoded.chunk_index, chunk.chunk_index);
        assert_eq!(decoded.data, chunk.data);
    }

    #[test]
    fn source_merger_deduplicates() {
        let mut merger = SourceMerger::new();
        let addr: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 4662);

        merger.add_source(MergedSource::legacy(addr, None, 100));
        merger.add_source(MergedSource::ember([1; 16], addr, [2; 32], 200));

        // Ember source should replace legacy at same address (better priority)
        assert_eq!(merger.source_count(), 1);
        assert_eq!(merger.ember_source_count(), 1);
    }

    #[test]
    fn source_merger_sorts_by_priority() {
        let mut merger = SourceMerger::new();

        let addr1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 4662);
        let addr2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), 4663);

        merger.add_source(MergedSource::legacy(addr1, None, 100));
        merger.add_source(MergedSource::ember([1; 16], addr2, [2; 32], 100));

        let sorted = merger.sorted_sources();
        assert_eq!(sorted.len(), 2);
        assert!(sorted[0].is_ember()); // Ember first (priority 0)
        assert!(!sorted[1].is_ember()); // Legacy second (priority 10)
    }

    #[test]
    fn empty_file_hash_tree() {
        let data = b"";
        let tree = HashTree::from_data(data);
        assert_eq!(tree.chunk_count(), 0);
        assert_eq!(tree.file_size, 0);
    }
}
