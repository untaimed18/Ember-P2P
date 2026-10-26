//! The data half of a chat attachment: one QUIC stream, one file.
//!
//! [`super::attach`] owns the format and the grant; this owns the two sides of
//! the stream that carries the bytes. Both are deliberately small and
//! self-contained — a transfer is a request, a header, and then chunks in order
//! — because QUIC is doing the work that the room transfer had to hand-roll
//! over datagrams: ordering, retransmission, and congestion control.
//!
//! The recipient dials, not the sender. That is what makes a firewalled sender
//! work without a connect-back dance: whoever wants the file opens the stream,
//! and the offer told them which port to open it to. A sender behind a NAT that
//! blocks inbound QUIC is the case the hole-punch path already exists for; see
//! [`fetch_attachment`] on what a caller should pass as `addr`.

use std::path::PathBuf;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::attach::{
    attach_chunk_count, attach_file_info_len, attach_stream_tag, attach_tags_match,
    chunk_count_up_to, decode_attach_file_info, decode_file_info_up_to, encode_attach_file_info,
    file_info_len_up_to, stream_max_bytes, AttachFileInfo, AttachRequest, AttachStreamStatus,
    ATTACH_CHUNK_SIZE, ATTACH_REQUEST_TAIL_LEN,
};
use super::transfer::HashTree;

/// How long either side waits on a single stream operation before giving up.
///
/// Generous, because a chunk is 256 KiB and a slow link is not a broken one,
/// but bounded: a peer that opens a stream and then says nothing must not hold
/// a task and a file handle for the life of the process.
const ATTACH_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long the receiver waits for the sender's status byte.
///
/// Longer than [`ATTACH_IO_TIMEOUT`] because the sender has to have the file's
/// hash tree before it can answer, and the first stream for a file reads all of
/// it — up to 2 GiB — to get one. The status byte has no "still hashing" value
/// a receiver already in the field would accept (an unknown byte is `Corrupt`,
/// which is not retried), so the wait moves here instead. The sender keeps the
/// tree, so a retry after a timeout on either side answers at once.
pub const ATTACH_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5 * 60);

/// The least a stream waits for the status byte once a fetch has spent its
/// [`ATTACH_STATUS_TIMEOUT`]. Short, so a sender that never answers holds a
/// receive slot for one long wait rather than one per attempt.
pub const ATTACH_RETRY_STATUS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Hash trees kept for chat and room files being served. A tree is
/// `CHUNK_SIZE`-granular, so even a 2 GiB file's is 256 KiB. Feed trees are
/// not counted here; see [`FEED_TREE_CACHE_BYTES`].
const HASH_CACHE_MAX: usize = 16;

/// A cached chat or room tree nobody has asked for in this long is dropped.
/// Past a grant's lifetime nothing will ask again, and a tree that outlives
/// the bytes it describes is only ever a wrong answer.
const HASH_CACHE_IDLE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

/// Bytes of feed trees kept in memory, least recently used dropped first:
/// 64 MiB of chunk values is the lists of some 512 GiB of files. A feed's
/// followers come back for the same files for as long as it is published,
/// and with a count bound a feed of more files than it allowed was hashed
/// over and over, each time out of [`FEED_HASH_BUDGET`], until followers were
/// told busy for files already hashed. They have no idle expiry either: the
/// stamp is checked on every stream all the same, and an idle tree under the
/// bound costs only its bytes, where dropping it costs the next follower a
/// read from [`set_feed_tree_dir`]'s folder or of the whole file.
const FEED_TREE_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// What a feed tree is charged against [`FEED_TREE_CACHE_BYTES`] beyond its
/// values: the key, its path and the slot. Without it a feed of many small
/// files would hold far more than the bound says.
const FEED_TREE_ENTRY_COST: usize = 512;

/// What identifies the bytes a tree was computed over, as far as the file
/// system will say without reading them. Revalidated on every stream, from
/// the handle that stream then serves from.
///
/// Not proof: a same-size rewrite in place that leaves every one of these
/// alone (a coarse-timestamp volume, a memory-mapped write, a tool that
/// restores the time) still matches. [`serve_attachment`] rehashes once on a
/// root mismatch rather than trusting the cache over the grant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FileStamp {
    path: PathBuf,
    size: u64,
    modified: Option<std::time::SystemTime>,
    /// Volume and file id of the open handle, so a replacement renamed into
    /// place under the same name, size and timestamp is still a different file.
    object: (u64, u64),
    /// A second clock where the platform has one: the inode change time on
    /// Unix, which a timestamp-restoring tool cannot set back, and the
    /// creation time on Windows.
    changed: u64,
    /// The tree a feed stream sends: each chunk's BLAKE3 chaining value
    /// (`ember::feed::chunk_value`) rather than its own BLAKE3, so a
    /// follower checks the list against the file's BLAKE3 its feed names.
    subtrees: bool,
}

impl FileStamp {
    fn of(path: &std::path::Path, file: &std::fs::File) -> std::io::Result<Self> {
        let meta = file.metadata()?;
        let object = crate::security::filesystem::opened_file_identity(file)?;
        Ok(Self {
            path: path.to_path_buf(),
            size: meta.len(),
            modified: meta.modified().ok(),
            object: (object.volume_serial, object.file_id),
            changed: change_clock(&meta),
            subtrees: false,
        })
    }
}

#[cfg(unix)]
fn change_clock(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    (meta.ctime() as u64).wrapping_mul(1_000_000_000).wrapping_add(meta.ctime_nsec() as u64)
}

#[cfg(windows)]
fn change_clock(meta: &std::fs::Metadata) -> u64 {
    use std::os::windows::fs::MetadataExt;
    meta.creation_time()
}

#[cfg(not(any(unix, windows)))]
fn change_clock(_meta: &std::fs::Metadata) -> u64 {
    0
}

type HashOutcome = Option<Result<std::sync::Arc<HashTree>, String>>;

enum HashSlot {
    /// One job per file, however many streams are waiting on it — a receiver
    /// retrying while the first hash is still running joins it rather than
    /// starting another read of the whole file.
    Hashing(tokio::sync::watch::Receiver<HashOutcome>),
    Ready {
        tree: std::sync::Arc<HashTree>,
        used: std::time::Instant,
    },
}

type HashCache = std::sync::Mutex<std::collections::HashMap<FileStamp, HashSlot>>;

fn hash_cache() -> &'static HashCache {
    #[cfg(test)]
    if let Some(own) = OWN_HASH_CACHE.with(std::cell::Cell::get) {
        return own;
    }
    static CACHE: std::sync::OnceLock<HashCache> = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
}

#[cfg(test)]
thread_local! {
    static OWN_HASH_CACHE: std::cell::Cell<Option<&'static HashCache>> =
        const { std::cell::Cell::new(None) };
}

/// Give the calling thread a hash cache of its own until the guard drops, so a
/// test that judges a file by what the cache holds cannot have the entry
/// evicted by tests hashing in parallel. Only for tests whose hashing all
/// happens on this thread: a job on the blocking pool still uses the shared one.
#[cfg(test)]
pub(crate) fn isolate_hash_cache() -> impl Drop {
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            OWN_HASH_CACHE.with(|own| own.set(None));
        }
    }
    let cache: &'static HashCache = Box::leak(Box::default());
    OWN_HASH_CACHE.with(|own| own.set(Some(cache)));
    Restore
}

enum HashLookup {
    Ready(std::sync::Arc<HashTree>),
    Wait(tokio::sync::watch::Receiver<HashOutcome>),
    /// Nobody is hashing this file; the caller now owns the job.
    Start(
        tokio::sync::watch::Sender<HashOutcome>,
        tokio::sync::watch::Receiver<HashOutcome>,
    ),
}

fn lookup_hash(stamp: &FileStamp) -> HashLookup {
    let mut cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    let now = std::time::Instant::now();
    match cache.get_mut(stamp) {
        Some(HashSlot::Ready { tree, used }) if fresh(stamp, *used, now) => {
            *used = now;
            return HashLookup::Ready(tree.clone());
        }
        Some(HashSlot::Hashing(rx)) => return HashLookup::Wait(rx.clone()),
        _ => {}
    }
    forget_other_versions(&mut cache, stamp);
    cache.retain(|key, slot| match slot {
        HashSlot::Ready { used, .. } => fresh(key, *used, now),
        HashSlot::Hashing(_) => true,
    });
    // Feed trees are bounded by their bytes when they land, in `keep_tree`.
    if !stamp.subtrees && cache.keys().filter(|key| !key.subtrees).count() >= HASH_CACHE_MAX {
        let oldest = cache
            .iter()
            .filter_map(|(key, slot)| match slot {
                HashSlot::Ready { used, .. } if !key.subtrees => Some((key.clone(), *used)),
                _ => None,
            })
            .min_by_key(|(_, used)| *used)
            .map(|(key, _)| key);
        if let Some(key) = oldest {
            cache.remove(&key);
        }
    }
    let (tx, rx) = tokio::sync::watch::channel(None);
    cache.insert(stamp.clone(), HashSlot::Hashing(rx.clone()));
    HashLookup::Start(tx, rx)
}

/// Whether a tree last used at `used` may still be served at `now`. Only
/// chat and room trees go idle; see [`FEED_TREE_CACHE_BYTES`].
fn fresh(stamp: &FileStamp, used: std::time::Instant, now: std::time::Instant) -> bool {
    stamp.subtrees || now.saturating_duration_since(used) < HASH_CACHE_IDLE
}

/// Drop every entry for `stamp`'s path that is a version of the file no
/// longer on disk. The same version's other kind of tree stays: a file can
/// be both offered in a chat and listed in a feed.
fn forget_other_versions(cache: &mut std::collections::HashMap<FileStamp, HashSlot>, stamp: &FileStamp) {
    cache.retain(|key, _| key.path != stamp.path || FileStamp { subtrees: stamp.subtrees, ..key.clone() } == *stamp);
}

/// Put a finished `tree` in the cache under `stamp`, dropping the least
/// recently used feed trees past [`FEED_TREE_CACHE_BYTES`] when it is one.
fn keep_tree(
    cache: &mut std::collections::HashMap<FileStamp, HashSlot>,
    stamp: FileStamp,
    tree: std::sync::Arc<HashTree>,
) {
    let feed = stamp.subtrees;
    cache.insert(stamp, HashSlot::Ready { tree, used: std::time::Instant::now() });
    if !feed {
        return;
    }
    let cost = |tree: &HashTree| tree.chunk_hashes.len() * 32 + FEED_TREE_ENTRY_COST;
    let mut held: usize = cache
        .iter()
        .filter_map(|(key, slot)| match slot {
            HashSlot::Ready { tree, .. } if key.subtrees => Some(cost(tree)),
            _ => None,
        })
        .sum();
    if held <= FEED_TREE_CACHE_BYTES {
        return;
    }
    let mut feeds: Vec<_> = cache
        .iter()
        .filter_map(|(key, slot)| match slot {
            HashSlot::Ready { tree, used } if key.subtrees => Some((*used, key.clone(), cost(tree))),
            _ => None,
        })
        .collect();
    feeds.sort_by_key(|(used, _, _)| *used);
    // The tree just kept is the newest, and no feed file's is near the bound
    // (an 8 GiB file's is 1 MiB), so it is never the one dropped.
    for (_, key, cost) in feeds {
        if held <= FEED_TREE_CACHE_BYTES {
            break;
        }
        cache.remove(&key);
        held -= cost;
    }
}

/// Whether the tree for `stamp` is cached or being built: a stream for it
/// reads nothing more of the file to answer. Never looks on disk, as it is
/// asked on the runtime; a feed stream has [`recall_feed_tree`] bring a kept
/// tree into the cache first.
fn tree_known(stamp: &FileStamp) -> bool {
    let cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    match cache.get(stamp) {
        Some(HashSlot::Ready { used, .. }) => fresh(stamp, *used, std::time::Instant::now()),
        Some(HashSlot::Hashing(_)) => true,
        None => false,
    }
}

/// Bytes of feed files hashed for followers per [`FEED_HASH_WINDOW`]. The
/// first stream for a file reads all of it, and the job outlives the stream,
/// so without a bound a follower asking for each file of a feed in turn, and
/// hanging up, would keep the publisher's disk reading for as long as they
/// liked. Past it a follower fetches over eD2K, which reads only what it sends.
const FEED_HASH_BUDGET: u64 = 32 * 1024 * 1024 * 1024;
const FEED_HASH_WINDOW: std::time::Duration = std::time::Duration::from_secs(60 * 60);

fn feed_hash_gate() -> &'static std::sync::Arc<tokio::sync::Semaphore> {
    static GATE: std::sync::OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    GATE.get_or_init(|| std::sync::Arc::new(tokio::sync::Semaphore::new(1)))
}

fn feed_hash_spent() -> &'static std::sync::Mutex<(std::time::Instant, u64)> {
    static SPENT: std::sync::OnceLock<std::sync::Mutex<(std::time::Instant, u64)>> = std::sync::OnceLock::new();
    SPENT.get_or_init(|| std::sync::Mutex::new((std::time::Instant::now(), 0)))
}

/// What [`feed_hash_permit`] found once it was a feed stream's turn.
enum FeedHashLeave {
    /// The job ahead of it built the tree, or is building it: nothing to read
    /// and nothing charged.
    Known,
    /// Leave to read the whole file, charged against the hour's budget.
    Granted(tokio::sync::OwnedSemaphorePermit),
    /// The hour's budget would be passed.
    Spent,
}

/// Leave to hash the feed file `stamp` names for a follower: one at a time,
/// and refused once the hour's budget would be passed.
///
/// The tree is looked for again once it is this stream's turn. Streams for
/// the same file queue behind one another while its tree is built, and
/// charging each of them as they joined the queue spent the budget once per
/// stream for one read.
async fn feed_hash_permit(stamp: &FileStamp) -> FeedHashLeave {
    let Ok(permit) = feed_hash_gate().clone().acquire_owned().await else {
        return FeedHashLeave::Spent;
    };
    if tree_known(stamp) {
        return FeedHashLeave::Known;
    }
    let mut spent = feed_hash_spent().lock().unwrap_or_else(|e| e.into_inner());
    if spent.0.elapsed() >= FEED_HASH_WINDOW {
        *spent = (std::time::Instant::now(), 0);
    }
    if spent.1.saturating_add(stamp.size) > FEED_HASH_BUDGET {
        return FeedHashLeave::Spent;
    }
    spent.1 = spent.1.saturating_add(stamp.size);
    #[cfg(test)]
    tests::note_charged(&stamp.path);
    FeedHashLeave::Granted(permit)
}

/// [`feed_hash_permit`] for a feed stream that may have to read its file:
/// the permit, none when the tree is known after all, or the follower told
/// it is busy.
async fn feed_read_leave<W>(send: &mut W, stamp: &FileStamp) -> anyhow::Result<Option<tokio::sync::OwnedSemaphorePermit>>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    match tokio::time::timeout(ATTACH_STATUS_TIMEOUT, feed_hash_permit(stamp)).await {
        Ok(FeedHashLeave::Granted(permit)) => Ok(Some(permit)),
        Ok(FeedHashLeave::Known) => Ok(None),
        _ => {
            refuse(send, AttachStreamStatus::Busy).await?;
            anyhow::bail!("no budget left to hash a feed file for a follower");
        }
    }
}

/// Hash the file `stamp` names and publish the result. Blocking: a read of the
/// whole file.
fn run_hash_job(stamp: FileStamp, tx: tokio::sync::watch::Sender<HashOutcome>) {
    let outcome = hash_stamped_file(&stamp);
    #[cfg(test)]
    tests::note_hashed(&stamp.path);
    let mut cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    let stored = match &outcome {
        Ok(tree) => {
            keep_tree(&mut cache, stamp.clone(), tree.clone());
            stamp.subtrees.then(|| tree.clone())
        }
        // Not cached: the next stream tries again, and the file may be back.
        Err(_) => {
            cache.remove(&stamp);
            None
        }
    };
    drop(cache);
    // Before the waiting streams have their answer, so a follower served from
    // this tree finds it kept: a write of at most 1 MiB, after a read of the
    // whole file.
    if let Some(tree) = stored {
        store_feed_tree(&stamp, &tree);
    }
    let _ = tx.send(Some(outcome));
}

fn hash_stamped_file(stamp: &FileStamp) -> Result<std::sync::Arc<HashTree>, String> {
    let file = std::fs::File::open(&stamp.path).map_err(|e| e.to_string())?;
    let unchanged = |file: &std::fs::File| {
        FileStamp::of(&stamp.path, file).map(|now| FileStamp { subtrees: stamp.subtrees, ..now } == *stamp)
    };
    if !unchanged(&file).map_err(|e| e.to_string())? {
        return Err("attachment changed before it could be hashed".into());
    }
    let reader = std::io::BufReader::new(&file);
    let tree = if stamp.subtrees { subtree_tree(reader, stamp.size) } else { HashTree::from_reader(reader) }
        .map_err(|e| e.to_string())?;
    // A write that landed mid-read leaves a tree of neither version.
    if !unchanged(&file).map_err(|e| e.to_string())? {
        return Err("attachment changed while it was being hashed".into());
    }
    Ok(std::sync::Arc::new(tree))
}

/// The tree a feed stream sends for `size` bytes read from `reader`: each
/// chunk named by its chaining value in the file's BLAKE3 tree, the root
/// the file's BLAKE3 itself.
fn subtree_tree<R: std::io::Read>(mut reader: R, size: u64) -> std::io::Result<HashTree> {
    use crate::network::ember::feed::{chunk_value, root_of_chunk_values};
    let count = usize::try_from(size.div_ceil(ATTACH_CHUNK_SIZE as u64))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "file too large"))?;
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    let mut chunk_hashes = Vec::with_capacity(count);
    let mut read_total = 0u64;
    for index in 0..count {
        let len = (size - read_total).min(ATTACH_CHUNK_SIZE as u64) as usize;
        reader.read_exact(&mut buf[..len])?;
        read_total += len as u64;
        chunk_hashes.push(chunk_value(index, count, &buf[..len]));
    }
    let mut more = [0u8; 1];
    if reader.read(&mut more)? != 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "file grew while it was hashed"));
    }
    let root_hash = root_of_chunk_values(&chunk_hashes).unwrap_or(*blake3::hash(&[]).as_bytes());
    Ok(HashTree { chunk_hashes, root_hash, file_size: size })
}

static FEED_TREE_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Keep the feed trees this side computes in `dir`, so a restart does not read
/// every file followers ask for all over again, out of [`FEED_HASH_BUDGET`].
/// Called once, at startup, with a folder of the app's data folder that no
/// shared or download folder covers: a tree only names what a feed's file
/// holds, which is no secret, but nothing in the folder is the user's to
/// serve, and nothing but [`load_feed_tree`] reads it. Until it is called
/// trees are not kept.
pub fn set_feed_tree_dir(dir: PathBuf) {
    if let Err(error) = std::fs::create_dir_all(&dir) {
        tracing::warn!("Could not create the feed tree folder {}: {error}", dir.display());
        return;
    }
    crate::security::restrict_file_permissions(&dir);
    let _ = FEED_TREE_DIR.set(dir);
}

fn feed_tree_dir() -> Option<&'static std::path::Path> {
    FEED_TREE_DIR.get().map(PathBuf::as_path)
}

/// What [`set_feed_tree_dir`]'s folder may hold before the least recently
/// used trees in it are deleted: 512 MiB of values is the lists of some 4 TiB
/// of files, and the count bounds a feed of a great many small ones.
const FEED_TREE_DISK_BYTES: u64 = 512 * 1024 * 1024;
const FEED_TREE_DISK_FILES: usize = 20_000;

/// The start of a kept tree's file. A file whose first bytes are anything
/// else, an older layout included, is deleted when it is found.
const FEED_TREE_MAGIC: &[u8; 8] = b"EMBRTREE";
const FEED_TREE_VERSION: u32 = 1;

/// The header of the file that keeps `stamp`'s tree: the magic and version,
/// every field of the stamp, and the number of values that follow. A kept
/// tree is taken only for a stamp whose header is this byte for byte, so a
/// file that has changed in any way the stamp can see is read afresh.
fn feed_tree_header(stamp: &FileStamp) -> Option<Vec<u8>> {
    // Nanoseconds from the Unix epoch, negative before it: a `SystemTime`
    // has no layout of its own to write down.
    let modified = stamp.modified.map(|time| match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(after) => after.as_nanos() as i128,
        Err(before) => -(before.duration().as_nanos() as i128),
    });
    let path = stamp.path.as_os_str().as_encoded_bytes();
    let mut header = Vec::with_capacity(80 + path.len());
    header.extend_from_slice(FEED_TREE_MAGIC);
    header.extend_from_slice(&FEED_TREE_VERSION.to_le_bytes());
    header.extend_from_slice(&stamp.size.to_le_bytes());
    header.push(u8::from(modified.is_some()));
    header.extend_from_slice(&modified.unwrap_or(0).to_le_bytes());
    header.extend_from_slice(&stamp.object.0.to_le_bytes());
    header.extend_from_slice(&stamp.object.1.to_le_bytes());
    header.extend_from_slice(&stamp.changed.to_le_bytes());
    header.extend_from_slice(&u32::try_from(path.len()).ok()?.to_le_bytes());
    header.extend_from_slice(path);
    header.extend_from_slice(&stamp.size.div_ceil(ATTACH_CHUNK_SIZE as u64).to_le_bytes());
    Some(header)
}

/// The file `stamp`'s tree is kept in, named by its path and file id: a new
/// version of the same file replaces it, and a file renamed into place under
/// the same name gets one of its own.
fn feed_tree_file(dir: &std::path::Path, stamp: &FileStamp) -> PathBuf {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&stamp.object.0.to_le_bytes());
    hasher.update(&stamp.object.1.to_le_bytes());
    hasher.update(stamp.path.as_os_str().as_encoded_bytes());
    dir.join(format!("{}.tree", hex::encode(&hasher.finalize().as_bytes()[..16])))
}

/// Keep `tree`, just computed for `stamp`, in [`set_feed_tree_dir`]'s folder:
/// the header, the values, and a BLAKE3 of both, so a value the disk changed
/// is caught on reading rather than served to every follower until the file
/// itself changes. Blocking. Best effort: a tree not kept is computed again.
fn store_feed_tree(stamp: &FileStamp, tree: &HashTree) {
    let Some(dir) = feed_tree_dir() else {
        return;
    };
    let Some(mut bytes) = feed_tree_header(stamp) else {
        return;
    };
    if tree.chunk_hashes.len() as u64 != stamp.size.div_ceil(ATTACH_CHUNK_SIZE as u64) {
        return;
    }
    bytes.reserve(tree.chunk_hashes.len() * 32 + 32);
    for value in &tree.chunk_hashes {
        bytes.extend_from_slice(value);
    }
    let check = blake3::hash(&bytes);
    bytes.extend_from_slice(check.as_bytes());
    // Not restricted on its own: the folder's permissions, set when it was
    // made, are what its files get.
    match crate::security::atomic_write(&feed_tree_file(dir, stamp), &bytes, false) {
        Ok(()) => note_feed_tree_written(dir, bytes.len() as u64),
        Err(error) => tracing::debug!("Could not keep a feed file's chunk list: {error}"),
    }
}

/// The tree an earlier run kept for `stamp`, if it is there and whole. A file
/// under the same name whose header differs is of a version no longer on
/// disk, and one cut short or failing its check is no use to anyone; either
/// is deleted. The root is worked out from the values, never read. Blocking:
/// a read of at most 1 MiB, for an 8 GiB file.
fn load_feed_tree(stamp: &FileStamp) -> Option<std::sync::Arc<HashTree>> {
    use std::io::Read;
    let dir = feed_tree_dir()?;
    let header = feed_tree_header(stamp)?;
    let count = usize::try_from(stamp.size.div_ceil(ATTACH_CHUNK_SIZE as u64)).ok()?;
    let len = header.len().checked_add(count.checked_mul(32)?)?.checked_add(32)?;
    let path = feed_tree_file(dir, stamp);
    let file = std::fs::File::open(&path).ok()?;
    let mut bytes = Vec::new();
    // A read that failed says nothing about what the file holds.
    file.take(len as u64 + 1).read_to_end(&mut bytes).ok()?;
    let (body, check) = bytes.split_at(bytes.len().saturating_sub(32));
    if bytes.len() != len || !body.starts_with(&header) || blake3::hash(body).as_bytes() != check {
        let _ = std::fs::remove_file(&path);
        return None;
    }
    let chunk_hashes: Vec<[u8; 32]> = body[header.len()..]
        .chunks_exact(32)
        .map(|value| {
            let mut out = [0u8; 32];
            out.copy_from_slice(value);
            out
        })
        .collect();
    let root_hash = crate::network::ember::feed::root_of_chunk_values(&chunk_hashes)
        .unwrap_or(*blake3::hash(&[]).as_bytes());
    // Its modified time is when it was last used, which is what
    // `prune_feed_trees` goes by.
    let _ = std::fs::File::options()
        .write(true)
        .open(&path)
        .and_then(|file| file.set_modified(std::time::SystemTime::now()));
    Some(std::sync::Arc::new(HashTree { chunk_hashes, root_hash, file_size: stamp.size }))
}

/// Bring the tree an earlier run kept for `stamp` into the cache, unless one
/// is there or being built already. Blocking: see [`load_feed_tree`].
fn recall_feed_tree(stamp: &FileStamp) {
    if tree_known(stamp) {
        return;
    }
    let Some(tree) = load_feed_tree(stamp) else {
        return;
    };
    let mut cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    if cache.contains_key(stamp) {
        return;
    }
    forget_other_versions(&mut cache, stamp);
    keep_tree(&mut cache, stamp.clone(), tree);
}

/// Bytes and files [`set_feed_tree_dir`]'s folder is thought to hold: what
/// the last [`prune_feed_trees`] left plus what was written since, so the
/// folder is listed only when it may be past its bounds rather than on every
/// write. `None` until the first write lists it.
fn feed_tree_disk() -> &'static std::sync::Mutex<Option<(u64, usize)>> {
    static HELD: std::sync::Mutex<Option<(u64, usize)>> = std::sync::Mutex::new(None);
    &HELD
}

fn note_feed_tree_written(dir: &std::path::Path, len: u64) {
    let mut held = feed_tree_disk().lock().unwrap_or_else(|e| e.into_inner());
    // A rewrite of a file already counted is counted again, which only
    // brings the next listing forward.
    let (bytes, files) = held.map_or((u64::MAX, usize::MAX), |(bytes, files)| {
        (bytes.saturating_add(len), files.saturating_add(1))
    });
    *held = Some(if bytes > FEED_TREE_DISK_BYTES || files > FEED_TREE_DISK_FILES {
        prune_feed_trees(dir, FEED_TREE_DISK_BYTES, FEED_TREE_DISK_FILES)
    } else {
        (bytes, files)
    });
}

/// Delete the least recently used files in `dir` while it holds more than
/// `max_bytes` or `max_files`, down to seven eighths of each, so the writes
/// that follow do not each list the folder again. A kept tree's file is
/// touched whenever it is read, so its modified time is its last use; a
/// temporary file a crash left mid-write is counted and goes in its turn.
/// Returns what is left.
fn prune_feed_trees(dir: &std::path::Path, max_bytes: u64, max_files: usize) -> (u64, usize) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (0, 0);
    };
    let mut held: Vec<(std::time::SystemTime, u64, PathBuf)> = entries
        .flatten()
        .filter_map(|entry| {
            let meta = entry.metadata().ok()?;
            meta.is_file()
                .then(|| (meta.modified().unwrap_or(std::time::UNIX_EPOCH), meta.len(), entry.path()))
        })
        .collect();
    let mut bytes: u64 = held.iter().map(|(_, len, _)| len).sum();
    let mut files = held.len();
    if bytes <= max_bytes && files <= max_files {
        return (bytes, files);
    }
    held.sort_by_key(|(modified, _, _)| *modified);
    let (max_bytes, max_files) = (max_bytes - max_bytes / 8, max_files - max_files / 8);
    for (_, len, path) in held {
        if bytes <= max_bytes && files <= max_files {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            bytes -= len;
            files -= 1;
        }
    }
    (bytes, files)
}

/// Drop `tree` from the cache if it is still what `stamp` maps to, so the next
/// lookup hashes the file again.
fn forget_cached_tree(stamp: &FileStamp, tree: &std::sync::Arc<HashTree>) {
    let mut cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    if matches!(
        cache.get(stamp),
        Some(HashSlot::Ready { tree: held, .. }) if std::sync::Arc::ptr_eq(held, tree)
    ) {
        cache.remove(stamp);
    }
}

/// The hash tree for the file `stamp` describes: from the cache, from a job
/// already running, or from a new job this call starts. The flag is true for a
/// tree that came straight from the cache, which is the only kind worth
/// doubting.
///
/// The job is detached from the caller. A stream whose receiver gave up while
/// it waited does not take the work with it, which is what makes the
/// receiver's retry cheap.
///
/// `permit`, a feed stream's leave to hash, is held by the job it starts, so
/// the next waits for the read to end rather than for the stream to.
async fn attachment_tree(
    stamp: FileStamp,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> Result<(std::sync::Arc<HashTree>, bool), String> {
    let mut rx = match lookup_hash(&stamp) {
        HashLookup::Ready(tree) => return Ok((tree, true)),
        HashLookup::Wait(rx) => rx,
        HashLookup::Start(tx, rx) => {
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                run_hash_job(stamp, tx)
            });
            rx
        }
    };
    let outcome = rx
        .wait_for(|outcome| outcome.is_some())
        .await
        .map_err(|_| "attachment hash job went away".to_string())?
        .clone();
    outcome
        .unwrap_or_else(|| Err("attachment hash job went away".into()))
        .map(|tree| (tree, false))
}

/// Start hashing a file we are about to serve, so the stream that asks for it
/// does not have to wait. Blocking: call it from the blocking pool.
pub fn prewarm_attachment_hash(path: &std::path::Path) {
    let Ok(stamp) = std::fs::File::open(path).and_then(|file| FileStamp::of(path, &file)) else {
        return;
    };
    if let HashLookup::Start(tx, _rx) = lookup_hash(&stamp) {
        run_hash_job(stamp, tx);
    }
}

/// Hash a file about to be offered and keep the tree for the stream that will
/// serve it, so the file is read once rather than once to offer and again to
/// serve. Blocking: a read of the whole file.
pub fn hash_for_serving(path: &std::path::Path) -> Result<std::sync::Arc<HashTree>, String> {
    let stamp = std::fs::File::open(path)
        .and_then(|file| FileStamp::of(path, &file))
        .map_err(|e| e.to_string())?;
    match lookup_hash(&stamp) {
        HashLookup::Ready(tree) => Ok(tree),
        HashLookup::Start(tx, rx) => {
            run_hash_job(stamp, tx);
            let outcome = rx.borrow().clone();
            outcome.unwrap_or_else(|| Err("attachment hash job went away".into()))
        }
        // Another caller is already reading it, and a blocking caller cannot
        // wait on that job; one more read is the rare case.
        HashLookup::Wait(_) => hash_stamped_file(&stamp),
    }
}

/// How a file we offered looked when it was last checked. See
/// [`check_held_source`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStamp(FileStamp);

/// What [`check_held_source`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum HeldSource {
    /// Still there and, as far as can be told, still the file offered. Keep
    /// this for the next check.
    Unchanged(SourceStamp),
    /// The bytes as they are now have not been read since the stamp moved, or
    /// since the offer. Keep the earlier stamp, if any, have
    /// [`prewarm_attachment_hash`] read the file, and ask again.
    Checking,
    /// It could not be looked at just now for some reason other than not
    /// being there (a share that is asleep, a lock, a permission). Keep the
    /// earlier stamp and look again later: nothing says it changed.
    Unreadable,
    /// Not there, a different size, or different bytes: a stream for it would
    /// be refused as [`AttachStreamStatus::SourceGone`].
    Gone,
}

/// Whether the file an offer waiting on the friend names is still the one
/// offered under `size` and `root`. Blocking, but never reads the file.
///
/// A stamp that has not moved since `last` settles it. Otherwise — the stamp
/// moved, or this is the first look — it is decided by the tree the hash
/// cache holds for the file as it is now, compared with the offer's root. The
/// first look at a file that has not moved since the offer finds the tree it
/// was hashed into then (see [`hash_for_serving`]) unless that has aged out
/// of the cache. Either way a same-size edit between the offer and the first
/// look is caught, and a file that was only touched is not mistaken for one
/// that changed. Until a tree for the file as it is exists the answer is
/// [`HeldSource::Checking`]: hashing is a read of the whole file. A rewrite
/// the stamp cannot see is still caught by the stream, which checks the root
/// on every serve.
pub fn check_held_source(
    path: &std::path::Path,
    size: u64,
    root: &[u8; 32],
    last: Option<&SourceStamp>,
) -> HeldSource {
    let stamp = match std::fs::File::open(path).and_then(|file| FileStamp::of(path, &file)) {
        Ok(stamp) => stamp,
        Err(e) => return held_source_unopened(path, &e),
    };
    if stamp.size != size {
        return HeldSource::Gone;
    }
    if last.is_some_and(|SourceStamp(seen)| *seen == stamp) {
        return HeldSource::Unchanged(SourceStamp(stamp));
    }
    match cached_tree(&stamp) {
        Some(tree) if tree.file_size == size && tree.root_hash == *root => {
            HeldSource::Unchanged(SourceStamp(stamp))
        }
        Some(_) => HeldSource::Gone,
        None => HeldSource::Checking,
    }
}

/// What a held offer's file at `path` that could not be opened and stamped
/// says: gone only when it is not there and the drive or share it was on is.
/// Windows reports a drive that is unplugged or a mapped share that is
/// unreachable as not found too, and that comes back; a file whose folder was
/// deleted from a drive that is there does not.
fn held_source_unopened(path: &std::path::Path, error: &std::io::Error) -> HeldSource {
    if error.kind() != std::io::ErrorKind::NotFound {
        return HeldSource::Unreadable;
    }
    let folder = path
        .parent()
        .filter(|folder| !folder.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    if std::fs::read_dir(folder).is_ok() || held_source_volume_present(path) {
        HeldSource::Gone
    } else {
        HeldSource::Unreadable
    }
}

/// Whether the drive or share holding `path` can be listed, `D:\` or
/// `\\server\share\`. A path with no root, such as a relative one, is judged
/// by its folder alone.
#[cfg(windows)]
fn held_source_volume_present(path: &std::path::Path) -> bool {
    let root = held_source_volume_root(path);
    !root.as_os_str().is_empty() && std::fs::read_dir(&root).is_ok()
}

#[cfg(windows)]
fn held_source_volume_root(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    path.components()
        .take_while(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
        .collect()
}

/// Where a volume is mounted cannot be told from the path here, so the
/// nearest folder above `path` that is there stands in for it: anything
/// below `/` counts as a volume that is there, `/` alone as one that is not
/// mounted just now.
#[cfg(not(windows))]
fn held_source_volume_present(path: &std::path::Path) -> bool {
    path.ancestors()
        .skip(1)
        .map(|folder| if folder.as_os_str().is_empty() { std::path::Path::new(".") } else { folder })
        .find(|folder| folder.is_dir())
        .is_some_and(|folder| folder != std::path::Path::new("/"))
}

/// The finished tree for `stamp`, if the cache has one. Unlike
/// [`lookup_hash`] this never claims a job.
fn cached_tree(stamp: &FileStamp) -> Option<std::sync::Arc<HashTree>> {
    let cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    match cache.get(stamp) {
        Some(HashSlot::Ready { tree, .. }) => Some(tree.clone()),
        _ => None,
    }
}

/// Bytes the sender writes between checks of the upload cap.
const ATTACH_SEND_SLICE: usize = 16 * 1024;

/// Fill `buf` from the stream, with the timeout measured between reads rather
/// than across the whole buffer.
///
/// A chunk is 256 KiB. Under a low upload cap on the far end that can honestly
/// take longer than [`ATTACH_IO_TIMEOUT`] to arrive, and a timeout over the
/// whole chunk would abandon a transfer that was moving the entire time. Any
/// progress resets it; only a stream that stops delivering anything times out.
///
/// `on_read` is told how much of `buf` is filled after every read, so a
/// progress bar can move while a chunk is still arriving.
async fn read_full<R>(
    recv: &mut R,
    buf: &mut [u8],
    mut on_read: impl FnMut(usize),
) -> Result<(), FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut filled = 0;
    while filled < buf.len() {
        let n = tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read(&mut buf[filled..])).await??;
        if n == 0 {
            return Err(FetchError::Transient(anyhow::anyhow!(
                "attachment stream closed mid-chunk"
            )));
        }
        filled += n;
        on_read(filled);
    }
    Ok(())
}

/// How far a fetch has got, in absolute file positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchProgress {
    /// Bytes that have arrived, the chunk still being read included. For a
    /// progress bar only: nothing has checked the tail of it yet.
    pub received: u64,
    /// Bytes in whole chunks that verified and were written. The only figure
    /// a resume may start from.
    pub verified: u64,
    pub size: u64,
}

/// Why a fetch stopped, sorted by what the caller should do about it.
///
/// The distinction is the whole point: a dropped stream is worth re-dialling
/// and resuming, while bytes that failed their hash will fail again from the
/// same sender, and a refusal means the grant is gone. Collapsing these into
/// one error would have the receiver retrying a lie or giving up on a blip.
#[derive(Debug)]
pub enum FetchError {
    /// The sender answered with a refusal. Not retried: the grant is gone,
    /// the file changed, or the resume cursor was wrong.
    Refused(AttachStreamStatus),
    /// Something failed verification or did not parse. Not retried.
    Corrupt(String),
    /// The stream, the connection, or the disk failed. Worth another dial.
    Transient(anyhow::Error),
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FetchError::Refused(status) => {
                write!(f, "attachment refused by the sender: {status:?}")
            }
            FetchError::Corrupt(detail) => f.write_str(detail),
            FetchError::Transient(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FetchError {}

impl From<std::io::Error> for FetchError {
    fn from(e: std::io::Error) -> Self {
        FetchError::Transient(e.into())
    }
}

impl From<tokio::time::error::Elapsed> for FetchError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        FetchError::Transient(anyhow::anyhow!("attachment stream timed out"))
    }
}

/// What a completed fetch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchOutcome {
    /// Bytes written across this call, which is not the file size when the
    /// transfer resumed.
    pub written: u64,
    /// Total bytes now present in the part file.
    pub total: u64,
    /// True once every chunk has landed and verified.
    pub complete: bool,
}

/// Serve one attachment on a stream the peer opened.
///
/// `resolve` is handed the transfer id and returns the grant — the path, the
/// size, and the root — or `None` when there is no live grant for *this* peer.
/// The caller is responsible for having already established that the peer is
/// who it claims: the QUIC certificate is the identity, and this function only
/// checks that the request also carries the pairwise tag.
///
/// `prefix` is the part of the request the accept loop already read, so this can
/// be called from a dispatcher that consumed the first seven bytes to decide
/// what the connection was.
///
/// `on_progress` is told the transfer id once it is known and authorized, then
/// the absolute byte position after each slice handed to the stream — absolute
/// rather than "sent this call", so a resumed stream reports where the file
/// actually is. It is called every 16 KiB, so it must be cheap. Returning
/// false stops the stream there: the grant was checked when it opened, and
/// this is how a caller withdraws it from a stream already running.
///
/// `limiter` is the user's upload cap. A chat file is still upload, and a user
/// who capped theirs to keep the connection usable should not find a friend's
/// download saturating it; the room transfer honours the same cap. Within it
/// the file is a priority upload, ahead of the eD2K slots.
pub async fn serve_attachment<R, W, F, P>(
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    capability_for: F,
    on_progress: P,
    limiter: Option<&crate::bandwidth::limiter::BandwidthLimiter>,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])>,
    P: FnMut(&[u8; 16], u64, u64) -> bool,
{
    serve_paced(
        super::attach::ATTACH_STREAM_MSG_TYPE,
        recv,
        send,
        prefix,
        with_root(capability_for),
        admit_all,
        on_progress,
        limiter,
        true,
    )
    .await
}

/// The admission of a stream nothing limits but its grant.
fn admit_all(_xfer_id: &[u8; 16]) -> Result<(), AttachStreamStatus> {
    Ok(())
}

/// What [`serve_paced`] is granted for a request: the file, its size, the
/// root it must hash to when one was agreed, the capability the request must
/// be tagged under, and the folders it must be opened within when it may only
/// be served from those.
type Grant = (PathBuf, u64, Option<[u8; 32]>, [u8; 32], Option<Vec<String>>);

/// A grant whose root is known, as a chat or room offer's is, of a file
/// opened wherever the user picked it. No grant is an unknown transfer.
fn with_root<F>(capability_for: F) -> impl FnOnce(&[u8; 16]) -> Result<Grant, AttachStreamStatus>
where
    F: FnOnce(&[u8; 16]) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])>,
{
    move |xfer_id| {
        capability_for(xfer_id)
            .map(|(path, size, root, capability)| (path, size, Some(root), capability, None))
            .ok_or(AttachStreamStatus::Unknown)
    }
}

/// Serve a file of a feed we publish to a follower who asked for it under
/// [`super::attach::FEED_STREAM_MSG_TYPE`].
///
/// What a feed stream may serve for a request: one file of a feed we publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedGrant {
    pub path: PathBuf,
    pub size: u64,
    /// The file's BLAKE3 as its feed's list names it, which its chunk tree
    /// must come to: a tree kept from before that does not is read again.
    pub blake3: [u8; 32],
    /// What the request must be tagged under.
    pub capability: [u8; 32],
    /// The shared and download folders the file is opened within.
    pub roots: Vec<String>,
}

/// Serve a file of a feed we publish to a follower who asked for it under
/// [`super::attach::FEED_STREAM_MSG_TYPE`].
///
/// The chunk list names each chunk by its chaining value in the file's
/// BLAKE3 tree (`ember::feed::chunk_value`), so the follower checks the list
/// against the file's BLAKE3 the signed list names, and every chunk against
/// the list, before a byte is written; the tree is checked against that
/// BLAKE3 here first. Served as a priority upload, as a chat file is.
///
/// `resolve` grants the file, or names the status the follower is refused
/// with. `admit` is asked once the file's chunk list is ready, so a wait for
/// it holds nothing it hands out; what it returns is held while the stream
/// runs, and an `Err` is the status the follower is refused with.
pub async fn serve_feed_stream<R, W, F, A, G, P>(
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    resolve: F,
    admit: A,
    on_progress: P,
    limiter: Option<&crate::bandwidth::limiter::BandwidthLimiter>,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Result<FeedGrant, AttachStreamStatus>,
    A: FnOnce(&[u8; 16]) -> Result<G, AttachStreamStatus>,
    P: FnMut(&[u8; 16], u64, u64) -> bool,
{
    serve_paced(
        super::attach::FEED_STREAM_MSG_TYPE,
        recv,
        send,
        prefix,
        move |xfer_id: &[u8; 16]| {
            resolve(xfer_id).map(|grant| (grant.path, grant.size, Some(grant.blake3), grant.capability, Some(grant.roots)))
        },
        admit,
        on_progress,
        limiter,
        true,
    )
    .await
}

/// [`serve_attachment`] for a request under `stream_type`. A room transfer
/// serves through this with [`super::attach::ROOM_XFER_STREAM_MSG_TYPE`], on
/// equal terms with the eD2K slots.
pub async fn serve_stream<R, W, F, P>(
    stream_type: u8,
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    capability_for: F,
    on_progress: P,
    limiter: Option<&crate::bandwidth::limiter::BandwidthLimiter>,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])>,
    P: FnMut(&[u8; 16], u64, u64) -> bool,
{
    serve_paced(stream_type, recv, send, prefix, with_root(capability_for), admit_all, on_progress, limiter, false).await
}

/// Seconds of a feed stream spent waiting on the follower to take what was
/// sent, over which they must have taken [`FEED_MIN_BYTES_PER_WINDOW`]: a
/// follower reading a trickle would otherwise hold a serve slot for as long
/// as they liked. Time waiting on our own upload cap is not counted.
const FEED_SLOW_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const FEED_MIN_BYTES_PER_WINDOW: u64 = 1024 * 1024;

#[allow(clippy::too_many_arguments)]
async fn serve_paced<R, W, F, A, G, P>(
    stream_type: u8,
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    capability_for: F,
    admit: A,
    mut on_progress: P,
    limiter: Option<&crate::bandwidth::limiter::BandwidthLimiter>,
    priority: bool,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Result<Grant, AttachStreamStatus>,
    A: FnOnce(&[u8; 16]) -> Result<G, AttachStreamStatus>,
    P: FnMut(&[u8; 16], u64, u64) -> bool,
{
    let mut tail = [0u8; ATTACH_REQUEST_TAIL_LEN];
    tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read_exact(&mut tail)).await??;

    let mut full = Vec::with_capacity(7 + tail.len());
    full.extend_from_slice(prefix);
    full.extend_from_slice(&tail);
    let Some(request) = super::attach::decode_stream_request(stream_type, &full) else {
        refuse(send, AttachStreamStatus::Unknown).await?;
        anyhow::bail!("malformed attachment stream request");
    };

    // The grant lookup is what decides whether this peer may read anything, and
    // it is keyed on the peer as well as the transfer — see
    // `Database::chat_attachment_grant`. A miss here is the ordinary case for a
    // transfer that was cancelled, declined, or has lapsed.
    let (path, size, root, capability, roots) = match capability_for(&request.xfer_id) {
        Ok(grant) => grant,
        Err(status) => {
            refuse(send, status).await?;
            return Ok(0);
        }
    };

    // Second, weaker check: the tag proves the dialer holds the offer. Constant
    // time, because a byte-at-a-time timing walk would recover it.
    let expected = attach_stream_tag(&capability, &request.xfer_id);
    if !attach_tags_match(&expected, &request.tag) {
        refuse(send, AttachStreamStatus::Unauthorized).await?;
        anyhow::bail!("attachment stream tag did not verify");
    }

    let Some(chunk_count) = chunk_count_up_to(size, stream_max_bytes(stream_type)) else {
        refuse(send, AttachStreamStatus::SourceGone).await?;
        anyhow::bail!("granted attachment has an impossible size");
    };
    if request.start_chunk >= chunk_count {
        refuse(send, AttachStreamStatus::BadCursor).await?;
        anyhow::bail!("attachment resume cursor past the end of the file");
    }

    // The file lives outside the library and outside our control: the user may
    // have replaced it between the offer and the dial, and serving new bytes
    // under the old root would fail the recipient's per-chunk check anyway.
    // Checking first means we notice here and say so, instead of streaming a
    // file that cannot verify.
    //
    // The check is the tree's root against the grant's, and the tree comes
    // from `attachment_tree`, keyed on what this handle's metadata says the
    // file is. Only a file that has changed since it was last hashed is read
    // in full again; before, every stream — every retry included — re-read up
    // to 2 GiB before answering at all.
    // A feed's file is opened as an upload is, through the approved-root
    // layer: inside a shared or download folder, and not through a link
    // that leads out of them.
    let subtrees = stream_type == super::attach::FEED_STREAM_MSG_TYPE;
    let opened = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<(std::fs::File, FileStamp)> {
            let (path, file) = match &roots {
                Some(roots) => crate::security::filesystem::open_existing_approved(&path, roots, false)?,
                None => {
                    let file = std::fs::File::open(&path)?;
                    (path, file)
                }
            };
            let stamp = FileStamp { subtrees, ..FileStamp::of(&path, &file)? };
            // Here, off the runtime, rather than in `tree_known`: a feed tree
            // an earlier run kept is read into the cache, so the budget below
            // is not charged for a file already read. Not for a file of
            // another size than the grant's, which is refused below anyway.
            if subtrees && stamp.size == size {
                recall_feed_tree(&stamp);
            }
            Ok((file, stamp))
        })
        .await
    };
    let (file, stamp) = match opened {
        Ok(Ok(opened)) => opened,
        Ok(Err(e)) => {
            refuse(send, AttachStreamStatus::SourceGone).await?;
            return Err(e.into());
        }
        Err(e) => {
            refuse(send, AttachStreamStatus::SourceGone).await?;
            anyhow::bail!("attachment open task failed: {e}");
        }
    };
    if stamp.size != size {
        refuse(send, AttachStreamStatus::SourceGone).await?;
        anyhow::bail!("attachment on disk no longer matches the offer");
    }
    let matches = |tree: &HashTree| tree.file_size == size && root.is_none_or(|root| tree.root_hash == root);
    // Anyone with a feed's link may ask, so a feed file read for its list waits
    // its turn and its share of an hour's budget; past that it is refused as
    // busy, and the follower asks again later and the rest of the network
    // meanwhile.
    let permit = if subtrees && !tree_known(&stamp) { feed_read_leave(send, &stamp).await? } else { None };
    let mut hashed = attachment_tree(stamp.clone(), permit).await;
    // A cached tree that disagrees with the grant may be describing bytes the
    // stamp could not tell apart from the current ones. One fresh read settles
    // it before the file is refused. With no root granted, only a size can
    // disagree, which a read of the same stamp would not change. A feed
    // file's second read waits its turn and is charged as a first one is:
    // one whose bytes no longer make its list's BLAKE3 would otherwise be
    // read whole again on every request for it.
    if let Ok((tree, true)) = &hashed {
        if !matches(tree) && root.is_some() {
            forget_cached_tree(&stamp, tree);
            let permit = if subtrees { feed_read_leave(send, &stamp).await? } else { None };
            hashed = attachment_tree(stamp, permit).await;
        }
    }
    let tree = match hashed {
        Ok((tree, _)) if matches(&tree) => tree,
        Ok(_) => {
            refuse(send, AttachStreamStatus::SourceGone).await?;
            anyhow::bail!("attachment on disk no longer matches the offer");
        }
        Err(e) => {
            refuse(send, AttachStreamStatus::SourceGone).await?;
            anyhow::bail!("attachment could not be hashed: {e}");
        }
    };
    let _admitted = match admit(&request.xfer_id) {
        Ok(admitted) => admitted,
        Err(status) => {
            refuse(send, status).await?;
            return Ok(0);
        }
    };

    let info = AttachFileInfo {
        size,
        chunk_hashes: tree.chunk_hashes.clone(),
    };
    tokio::time::timeout(
        ATTACH_IO_TIMEOUT,
        send.write_all(&encode_attach_file_info(&info)),
    )
    .await??;

    // The handle the stamp was read from, so the bytes served are the file the
    // tree was checked against. `tokio::fs` moves each read onto the blocking
    // pool.
    let mut handle = tokio::fs::File::from_std(file);
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    let mut sent = 0u64;
    let mut position = request.start_chunk as u64 * ATTACH_CHUNK_SIZE as u64;
    handle.seek(std::io::SeekFrom::Start(position)).await?;
    if !on_progress(&request.xfer_id, position, size) {
        anyhow::bail!("attachment grant withdrawn before streaming");
    }
    // Registered only once the bytes start, so the hash wait above holds no
    // reserve.
    let priority = limiter.filter(|_| priority).map(|limiter| limiter.priority_upload());
    let slow_floor = stream_type == super::attach::FEED_STREAM_MSG_TYPE;
    let (mut waited, mut taken) = (std::time::Duration::ZERO, 0u64);
    for index in request.start_chunk as usize..info.chunk_count() {
        let len = info
            .chunk_len(index)
            .ok_or_else(|| anyhow::anyhow!("chunk index past the end"))?;
        handle.read_exact(&mut buf[..len]).await?;
        // Sliced so a low cap paces the stream smoothly rather than parking for
        // a whole chunk's worth of tokens and then bursting it, and reported
        // per slice so the sender's bar moves at the same pace.
        for slice in buf[..len].chunks(ATTACH_SEND_SLICE) {
            if let Some(limiter) = limiter {
                let granted = match &priority {
                    Some(priority) => priority.acquire(slice.len() as u64).await,
                    None => limiter.acquire_upload(slice.len() as u64).await,
                };
                if !granted {
                    // The refill task is gone; sending on regardless would
                    // ignore the cap entirely.
                    anyhow::bail!("upload limiter stopped");
                }
            }
            let writing = std::time::Instant::now();
            tokio::time::timeout(ATTACH_IO_TIMEOUT, send.write_all(slice)).await??;
            if slow_floor {
                waited += writing.elapsed();
                taken += slice.len() as u64;
                if waited >= FEED_SLOW_WINDOW {
                    if taken < FEED_MIN_BYTES_PER_WINDOW {
                        anyhow::bail!("the follower took {taken} byte(s) in {}s of waiting", waited.as_secs());
                    }
                    (waited, taken) = (std::time::Duration::ZERO, 0);
                }
            }
            sent += slice.len() as u64;
            position += slice.len() as u64;
            if !on_progress(&request.xfer_id, position, size) {
                anyhow::bail!("attachment grant withdrawn mid-stream");
            }
        }
    }
    tokio::time::timeout(ATTACH_IO_TIMEOUT, send.flush()).await??;
    Ok(sent)
}

async fn refuse<W>(send: &mut W, status: AttachStreamStatus) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(ATTACH_IO_TIMEOUT, send.write_all(&[status.to_byte()])).await??;
    let _ = tokio::time::timeout(ATTACH_IO_TIMEOUT, send.flush()).await;
    Ok(())
}

/// Ask a peer for an attachment and write it into `part`, verifying as it goes.
///
/// `part` is a handle, not a path, and the caller must have opened it through
/// the approved-root layer (`open_or_create_approved`). The part file's name is
/// derived from the transfer id, which the *sending* peer chose, so opening it
/// here by pathname would follow a planted symlink or junction — the exact hole
/// the room transfer's receive path was closed against. Open it read/write and
/// not truncated: whatever whole chunks are already in it are the resume point.
///
/// `on_progress` is called after every read from the stream, with the bytes
/// that have arrived and the bytes that have verified; see [`FetchProgress`].
/// That is many times a chunk, so a caller that emits an event from it should
/// throttle.
///
/// Resumes from whatever is already in `part`, rounded down to a whole verified
/// chunk — a partial chunk is discarded rather than trusted, because nothing has
/// checked it yet.
///
/// Waits at most `status_wait` for the sender's first byte, and adds the time
/// it actually spent waiting to `status_waited` — whatever the outcome, and
/// nothing if the stream failed before the request was sent. A caller spreads
/// one [`ATTACH_STATUS_TIMEOUT`] across a fetch's streams with it: a stream
/// that dropped early leaves the next one nearly the whole wait for the
/// sender's first hash, and one that waited it out leaves the rest only
/// [`ATTACH_RETRY_STATUS_TIMEOUT`], since by then the sender has the tree or
/// is still building it and a retry joins that job.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_attachment_waiting<R, W, P>(
    recv: &mut R,
    send: &mut W,
    xfer_id: &[u8; 16],
    capability: &[u8; 32],
    size: u64,
    root: &[u8; 32],
    part: std::fs::File,
    on_progress: P,
    status_wait: std::time::Duration,
    status_waited: &mut std::time::Duration,
) -> Result<FetchOutcome, FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    P: FnMut(FetchProgress),
{
    fetch_stream_waiting(
        super::attach::ATTACH_STREAM_MSG_TYPE,
        recv,
        send,
        xfer_id,
        capability,
        size,
        root,
        part,
        on_progress,
        status_wait,
        status_waited,
    )
    .await
}

/// [`fetch_attachment_waiting`] with the request sent under `stream_type`.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_stream_waiting<R, W, P>(
    stream_type: u8,
    recv: &mut R,
    send: &mut W,
    xfer_id: &[u8; 16],
    capability: &[u8; 32],
    size: u64,
    root: &[u8; 32],
    part: std::fs::File,
    mut on_progress: P,
    status_wait: std::time::Duration,
    status_waited: &mut std::time::Duration,
) -> Result<FetchOutcome, FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    P: FnMut(FetchProgress),
{
    let chunk_count = attach_chunk_count(size)
        .ok_or_else(|| FetchError::Corrupt("attachment size out of range".into()))?;

    // Whole chunks only. A trailing partial chunk has been through no check at
    // all, so resuming "after" it would import bytes nothing vouches for.
    let have = part.metadata().map(|m| m.len()).unwrap_or(0);
    let start_chunk = u32::try_from(have / ATTACH_CHUNK_SIZE as u64)
        .unwrap_or(0)
        .min(chunk_count.saturating_sub(1));
    let resume_at = start_chunk as u64 * ATTACH_CHUNK_SIZE as u64;

    let request = AttachRequest {
        xfer_id: *xfer_id,
        tag: attach_stream_tag(capability, xfer_id),
        start_chunk,
    };
    tokio::time::timeout(
        ATTACH_IO_TIMEOUT,
        send.write_all(&super::attach::encode_stream_request(stream_type, &request)),
    )
    .await??;
    tokio::time::timeout(ATTACH_IO_TIMEOUT, send.flush()).await??;

    // One byte first, so a refusal is a refusal rather than a short read of a
    // header that was never coming.
    let mut status_byte = [0u8; 1];
    let waiting = std::time::Instant::now();
    let answered = tokio::time::timeout(status_wait, recv.read_exact(&mut status_byte)).await;
    *status_waited += waiting.elapsed();
    answered??;
    let status = AttachStreamStatus::from_byte(status_byte[0]).ok_or_else(|| {
        FetchError::Corrupt("attachment peer sent an unknown status".into())
    })?;
    if status != AttachStreamStatus::Ok {
        return Err(FetchError::Refused(status));
    }

    let info_len = attach_file_info_len(size)
        .ok_or_else(|| FetchError::Corrupt("attachment size out of range".into()))?;
    let mut info_bytes = vec![0u8; info_len];
    info_bytes[0] = AttachStreamStatus::Ok.to_byte();
    read_full(recv, &mut info_bytes[1..], |_| {}).await?;
    let info = decode_attach_file_info(&info_bytes)
        .map_err(|s| FetchError::Corrupt(format!("attachment header refused: {s:?}")))?;

    // The check the whole scheme rests on. Until the chunk list is shown to be
    // the one the offered root commits to, the per-chunk hashes are only what
    // the sender says they are, and verifying against them proves nothing.
    if info.size != size || !info.matches_root(root) {
        return Err(FetchError::Corrupt(
            "attachment chunk list does not match the offered root".into(),
        ));
    }

    let tree = HashTree {
        chunk_hashes: info.chunk_hashes.clone(),
        root_hash: *root,
        file_size: size,
    };

    // `set_len` is what drops a trailing partial chunk; the verified whole
    // chunks before `resume_at` stay where they are.
    let mut part = tokio::fs::File::from_std(part);
    part.set_len(resume_at).await?;
    part.seek(std::io::SeekFrom::Start(resume_at)).await?;

    let mut written = 0u64;
    let mut total = resume_at;
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    for index in start_chunk as usize..info.chunk_count() {
        let len = info
            .chunk_len(index)
            .ok_or_else(|| FetchError::Corrupt("chunk index past the end".into()))?;
        read_full(recv, &mut buf[..len], |filled| {
            on_progress(FetchProgress {
                received: total + filled as u64,
                verified: total,
                size,
            })
        })
        .await?;

        // Per chunk, so a bad one costs this chunk rather than the whole file.
        // The room transfer could only check its root at the end, which meant
        // discarding everything and starting over.
        if !tree.verify_chunk(index, &buf[..len]) {
            return Err(FetchError::Corrupt(format!(
                "attachment chunk {index} did not match its hash"
            )));
        }

        part.write_all(&buf[..len]).await?;
        written += len as u64;
        total += len as u64;
        on_progress(FetchProgress {
            received: total,
            verified: total,
            size,
        });
    }
    part.flush().await?;
    // Durable before the caller is told it may move the file into place: a
    // crash between the two would otherwise leave a short file under a name
    // that says it is finished.
    part.sync_all().await?;

    Ok(FetchOutcome {
        written,
        total,
        complete: total >= size,
    })
}

/// Ask for a file from `start_chunk` on under `stream_type`, and read the
/// sender's answer: its chunk list, once it has one.
///
/// For a fetch that keeps the bytes itself, as a feed's download does in its
/// part file: [`read_verified_chunk`] then reads each chunk in turn. Nothing
/// here checks the list against a root; the caller does, against the root it
/// was offered or the one it saw first.
#[allow(clippy::too_many_arguments)]
pub async fn request_chunks<R, W>(
    stream_type: u8,
    recv: &mut R,
    send: &mut W,
    xfer_id: &[u8; 16],
    capability: &[u8; 32],
    size: u64,
    start_chunk: u32,
    status_wait: std::time::Duration,
) -> Result<AttachFileInfo, FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let max = stream_max_bytes(stream_type);
    let chunk_count = chunk_count_up_to(size, max)
        .ok_or_else(|| FetchError::Corrupt("stream size out of range".into()))?;
    if start_chunk >= chunk_count {
        return Err(FetchError::Corrupt("stream cursor past the end of the file".into()));
    }
    let request = AttachRequest {
        xfer_id: *xfer_id,
        tag: attach_stream_tag(capability, xfer_id),
        start_chunk,
    };
    tokio::time::timeout(
        ATTACH_IO_TIMEOUT,
        send.write_all(&super::attach::encode_stream_request(stream_type, &request)),
    )
    .await??;
    tokio::time::timeout(ATTACH_IO_TIMEOUT, send.flush()).await??;

    let mut status_byte = [0u8; 1];
    tokio::time::timeout(status_wait, recv.read_exact(&mut status_byte)).await??;
    let status = AttachStreamStatus::from_byte(status_byte[0])
        .ok_or_else(|| FetchError::Corrupt("stream peer sent an unknown status".into()))?;
    if status != AttachStreamStatus::Ok {
        return Err(FetchError::Refused(status));
    }
    let info_len = file_info_len_up_to(size, max)
        .ok_or_else(|| FetchError::Corrupt("stream size out of range".into()))?;
    let mut info_bytes = vec![0u8; info_len];
    info_bytes[0] = AttachStreamStatus::Ok.to_byte();
    read_full(recv, &mut info_bytes[1..], |_| {}).await?;
    let info = decode_file_info_up_to(&info_bytes, max)
        .map_err(|s| FetchError::Corrupt(format!("stream header refused: {s:?}")))?;
    if info.size != size {
        return Err(FetchError::Corrupt("stream header names another size".into()));
    }
    Ok(info)
}

/// Read chunk `index` of the file `info` lists into the front of `buf`, and
/// check it against its hash. Returns its length. `on_read` is told the bytes
/// of it read so far, after every read.
#[cfg(test)]
pub async fn read_verified_chunk<R>(
    recv: &mut R,
    info: &AttachFileInfo,
    index: usize,
    buf: &mut [u8],
    on_read: impl FnMut(usize),
) -> Result<usize, FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let len = info
        .chunk_len(index)
        .filter(|len| *len <= buf.len())
        .ok_or_else(|| FetchError::Corrupt("chunk index past the end".into()))?;
    read_full(recv, &mut buf[..len], on_read).await?;
    if blake3::hash(&buf[..len]).as_bytes() != &info.chunk_hashes[index] {
        return Err(FetchError::Corrupt(format!("chunk {index} did not match its hash")));
    }
    Ok(len)
}

/// [`read_verified_chunk`] for a feed stream, whose list names each chunk by
/// its chaining value in the file's BLAKE3 tree (`ember::feed::chunk_value`).
/// The caller has checked the list against the file's BLAKE3.
pub async fn read_verified_feed_chunk<R>(
    recv: &mut R,
    info: &AttachFileInfo,
    index: usize,
    buf: &mut [u8],
) -> Result<usize, FetchError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let len = info
        .chunk_len(index)
        .filter(|len| *len <= buf.len())
        .ok_or_else(|| FetchError::Corrupt("chunk index past the end".into()))?;
    read_full(recv, &mut buf[..len], |_| {}).await?;
    let value = crate::network::ember::feed::chunk_value(index, info.chunk_count(), &buf[..len]);
    if info.chunk_hashes.get(index) != Some(&value) {
        return Err(FetchError::Corrupt(format!("chunk {index} is not the one the feed's file has there")));
    }
    Ok(len)
}

use tokio::io::AsyncSeekExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    async fn fetch_attachment<R, W, P>(
        recv: &mut R,
        send: &mut W,
        xfer_id: &[u8; 16],
        capability: &[u8; 32],
        size: u64,
        root: &[u8; 32],
        part: std::fs::File,
        on_progress: P,
    ) -> Result<FetchOutcome, FetchError>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
        P: FnMut(FetchProgress),
    {
        fetch_attachment_waiting(
            recv,
            send,
            xfer_id,
            capability,
            size,
            root,
            part,
            on_progress,
            ATTACH_STATUS_TIMEOUT,
            &mut std::time::Duration::default(),
        )
        .await
    }
    use super::super::attach::{derive_attach_capability, encode_attach_request};
    use ed25519_dalek::SigningKey;
    use std::path::Path;

    static HASHED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    pub(super) fn note_hashed(path: &Path) {
        HASHED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(path.to_path_buf());
    }

    fn times_hashed(path: &Path) -> usize {
        HASHED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.as_path() == path)
            .count()
    }

    static CHARGED: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

    pub(super) fn note_charged(path: &Path) {
        CHARGED.lock().unwrap_or_else(|e| e.into_inner()).push(path.to_path_buf());
    }

    /// How often a file named `name` was read, or charged to the feed hash
    /// budget, by name: a feed file's stamp carries the path the approved-root
    /// layer opened it under, which need not be spelled as the test's.
    fn times_named(list: &std::sync::Mutex<Vec<PathBuf>>, name: &std::ffi::OsStr) -> usize {
        list.lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|p| p.file_name() == Some(name))
            .count()
    }

    /// Keep feed trees in a folder of this test run's. Once one test has, every
    /// feed file served in the run keeps its tree there, under a name of its
    /// own path.
    fn keep_feed_trees() -> &'static Path {
        set_feed_tree_dir(std::env::temp_dir().join(format!("ember-attach-feed-trees-{}", std::process::id())));
        feed_tree_dir().expect("feed tree folder")
    }

    /// A stamp for a feed file that is never opened.
    fn feed_stamp(tag: &str, size: u64) -> FileStamp {
        FileStamp {
            path: temp_path(tag),
            size,
            modified: Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)),
            object: (4, 5),
            changed: 6,
            subtrees: true,
        }
    }

    /// Serve `source` once to an honest receiver and return what it got.
    async fn serve_once(
        source: &Path,
        size: u64,
        root: [u8; 32],
        xfer_id: [u8; 16],
    ) -> Result<FetchOutcome, FetchError> {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let cap_sender = derive_attach_capability(&a_seed, &b_pub, &xfer_id).expect("cap");
        let cap_recv = derive_attach_capability(&b_seed, &a_pub, &xfer_id).expect("cap");
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);
        let served = source.to_path_buf();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), size, root, cap_sender)),
                |_, _, _| true,
                None,
            )
            .await
        });
        let part = temp_path("part-cache");
        let fetched = fetch_attachment(
            &mut client_r,
            &mut client_w,
            &xfer_id,
            &cap_recv,
            size,
            &root,
            open_part(&part),
            |_| {},
        )
        .await;
        let _ = server.await;
        let _ = std::fs::remove_file(&part);
        fetched
    }

    /// Only the first stream for a file reads all of it. A retry, or a second
    /// stream of the same grant, is answered from the tree the first one built.
    #[tokio::test]
    async fn a_second_stream_for_the_same_file_does_not_rehash_it() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE + 99).map(|i| (i % 211) as u8).collect();
        let source = temp_path("src-cached");
        std::fs::write(&source, &data).expect("write");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;

        for _ in 0..2 {
            let outcome = serve_once(&source, size, root, [12u8; 16]).await.expect("fetch");
            assert!(outcome.complete);
        }
        assert_eq!(times_hashed(&source), 1);
        let _ = std::fs::remove_file(&source);
    }

    /// The cache is keyed on what the file system says the file is, so a file
    /// rewritten after it was hashed is noticed, not served under the old tree.
    #[tokio::test]
    async fn a_file_rewritten_after_it_was_hashed_is_not_served_from_the_cache() {
        let source = temp_path("src-rewritten");
        std::fs::write(&source, b"first version!").expect("write");
        let root = HashTree::from_data(b"first version!").root_hash;
        serve_once(&source, 14, root, [13u8; 16]).await.expect("first serve");

        std::fs::write(&source, b"second version").expect("rewrite");
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(10);
        std::fs::File::options()
            .write(true)
            .open(&source)
            .and_then(|f| f.set_modified(later))
            .expect("move mtime");

        let err = serve_once(&source, 14, root, [13u8; 16])
            .await
            .expect_err("the rewritten file must not verify against the old root");
        assert!(err.to_string().contains("SourceGone"), "unexpected error: {err}");
        assert_eq!(times_hashed(&source), 2, "the new version was hashed afresh");
        let _ = std::fs::remove_file(&source);
    }

    /// Streams that arrive while a file is still being hashed wait on that job
    /// rather than each starting another read of the whole file.
    #[tokio::test]
    async fn concurrent_streams_share_one_hash_job() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 3).map(|i| (i % 7) as u8).collect();
        let source = temp_path("src-shared");
        std::fs::write(&source, &data).expect("write");
        let stamp = FileStamp::of(&source, &std::fs::File::open(&source).expect("open"))
            .expect("stamp");
        let (a, b) = tokio::join!(attachment_tree(stamp.clone(), None), attachment_tree(stamp, None));
        let expected = HashTree::from_data(&data).root_hash;
        assert_eq!(a.expect("first").0.root_hash, expected);
        assert_eq!(b.expect("second").0.root_hash, expected);
        assert_eq!(times_hashed(&source), 1);
        let _ = std::fs::remove_file(&source);
    }

    /// A same-size rewrite that leaves the stamp alone — here, by putting the
    /// modification time back — is exactly what the cache cannot see. A grant
    /// for the new bytes must still be served: the cached tree is doubted once
    /// before the file is refused.
    #[tokio::test]
    async fn a_stale_cached_tree_is_rehashed_before_a_grant_is_refused() {
        let source = temp_path("src-stale");
        std::fs::write(&source, b"version one!").expect("write");
        let original_mtime = std::fs::metadata(&source).expect("meta").modified().expect("mtime");
        let first_root = HashTree::from_data(b"version one!").root_hash;
        serve_once(&source, 12, first_root, [15u8; 16]).await.expect("first serve");

        std::fs::write(&source, b"version two!").expect("rewrite");
        std::fs::File::options()
            .write(true)
            .open(&source)
            .and_then(|f| f.set_modified(original_mtime))
            .expect("restore mtime");
        let second_root = HashTree::from_data(b"version two!").root_hash;
        let outcome = serve_once(&source, 12, second_root, [16u8; 16])
            .await
            .expect("the re-offer of the new bytes is served");
        assert!(outcome.complete);
        assert_eq!(times_hashed(&source), 2);
        let _ = std::fs::remove_file(&source);
    }

    /// The check itself never reads the file, and one that finds it only
    /// touched must not report a file the stream would still serve as gone.
    #[test]
    fn a_held_source_is_judged_by_its_stamp_then_by_a_tree_read_elsewhere() {
        let _own = isolate_hash_cache();
        let source = temp_path("src-held");
        std::fs::write(&source, b"held version").expect("write");
        let root = HashTree::from_data(b"held version").root_hash;
        let set_modified = |secs: u64| {
            std::fs::File::options()
                .write(true)
                .open(&source)
                .and_then(|f| {
                    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(secs))
                })
                .expect("move mtime");
        };

        hash_for_serving(&source).expect("hashed for its offer");
        let HeldSource::Unchanged(first) = check_held_source(&source, 12, &root, None) else {
            panic!("the first look finds the tree the offer was hashed into");
        };
        assert_eq!(
            check_held_source(&source, 12, &root, Some(&first)),
            HeldSource::Unchanged(first.clone())
        );
        assert_eq!(times_hashed(&source), 1, "nothing moved, nothing read again");

        set_modified(10);
        assert_eq!(check_held_source(&source, 12, &root, Some(&first)), HeldSource::Checking);
        assert_eq!(times_hashed(&source), 1, "the check itself never reads it");
        prewarm_attachment_hash(&source);
        let HeldSource::Unchanged(touched) = check_held_source(&source, 12, &root, Some(&first)) else {
            panic!("touched, not changed");
        };
        assert_ne!(touched, first);
        assert_eq!(times_hashed(&source), 2);

        std::fs::write(&source, b"other bytes!").expect("rewrite");
        set_modified(20);
        assert_eq!(check_held_source(&source, 12, &root, Some(&touched)), HeldSource::Checking);
        prewarm_attachment_hash(&source);
        assert_eq!(check_held_source(&source, 12, &root, Some(&touched)), HeldSource::Gone);
        assert_eq!(check_held_source(&source, 13, &root, None), HeldSource::Gone, "another size");
        let _ = std::fs::remove_file(&source);
        assert_eq!(check_held_source(&source, 12, &root, None), HeldSource::Gone);
    }

    /// Edited at the same size between the offer and the first look: no tree
    /// for the file as it is now, so it is read, and then it is not the one
    /// offered. With nothing in the cache at all the first look reads it too,
    /// and a file that is still the offered one stays held.
    #[test]
    fn the_first_look_at_a_held_source_compares_it_with_the_offer() {
        let _own = isolate_hash_cache();
        let source = temp_path("src-held-first");
        std::fs::write(&source, b"as offered").expect("write");
        let root = HashTree::from_data(b"as offered").root_hash;
        hash_for_serving(&source).expect("hashed for its offer");
        std::fs::write(&source, b"as edited!").expect("same-size edit");
        std::fs::File::options()
            .write(true)
            .open(&source)
            .and_then(|f| f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(10)))
            .expect("move mtime");
        assert_eq!(check_held_source(&source, 10, &root, None), HeldSource::Checking);
        prewarm_attachment_hash(&source);
        assert_eq!(check_held_source(&source, 10, &root, None), HeldSource::Gone);

        let edited_root = HashTree::from_data(b"as edited!").root_hash;
        let _fresh = isolate_hash_cache();
        assert_eq!(check_held_source(&source, 10, &edited_root, None), HeldSource::Checking);
        prewarm_attachment_hash(&source);
        assert!(matches!(
            check_held_source(&source, 10, &edited_root, None),
            HeldSource::Unchanged(_)
        ));
        let _ = std::fs::remove_file(&source);
    }

    /// Only a file that is not there is gone; any other failure to open it is
    /// looked at again later.
    #[test]
    fn a_held_source_that_cannot_be_opened_is_gone_only_when_missing() {
        use std::io::{Error, ErrorKind};
        let source = temp_path("src-held-unopened");
        assert_eq!(
            held_source_unopened(&source, &Error::from(ErrorKind::NotFound)),
            HeldSource::Gone
        );
        assert_eq!(
            held_source_unopened(&source.join("offered.bin"), &Error::from(ErrorKind::NotFound)),
            HeldSource::Gone,
            "its folder is missing too, on a drive that is there"
        );
        for kind in [ErrorKind::PermissionDenied, ErrorKind::TimedOut, ErrorKind::Other] {
            assert_eq!(
                held_source_unopened(&source, &Error::from(kind)),
                HeldSource::Unreadable,
                "{kind:?}"
            );
        }
    }

    /// A file on a drive or share that is not there just now is only
    /// unreadable, which is no reason to cancel its offer; one missing from a
    /// drive that is there is gone, with its folder or without.
    #[test]
    fn a_held_source_on_a_missing_drive_is_only_unreadable() {
        let folder = temp_path("src-held-folder");
        let source = folder.join("Nested").join("offered.bin");
        assert_eq!(
            check_held_source(&source, 4, &[0u8; 32], None),
            HeldSource::Gone,
            "folder deleted"
        );

        std::fs::create_dir_all(source.parent().unwrap()).expect("folder");
        assert_eq!(check_held_source(&source, 4, &[0u8; 32], None), HeldSource::Gone);
        let _ = std::fs::remove_dir_all(&folder);

        #[cfg(not(windows))]
        {
            let unmounted = std::path::Path::new("/").join(format!(
                "ember-attach-unmounted-{}",
                rand::random::<u64>()
            ));
            assert_eq!(
                check_held_source(&unmounted.join("offered.bin"), 4, &[0u8; 32], None),
                HeldSource::Unreadable,
                "nothing below / is there"
            );
        }

        #[cfg(windows)]
        {
            assert_eq!(
                held_source_volume_root(std::path::Path::new(r"\\server\share\Folder\offered.bin")),
                std::path::PathBuf::from(r"\\server\share\")
            );
            assert_eq!(
                held_source_volume_root(std::path::Path::new(r"D:\Folder\offered.bin")),
                std::path::PathBuf::from(r"D:\")
            );
            assert_eq!(
                held_source_volume_root(std::path::Path::new(r"Folder\offered.bin")),
                std::path::PathBuf::new()
            );
            assert_eq!(
                held_source_volume_root(std::path::Path::new(r"\\?\C:\Folder\offered.bin")),
                std::path::PathBuf::from(r"\\?\C:\")
            );
            assert_eq!(
                held_source_volume_root(std::path::Path::new(r"\\?\UNC\server\share\Folder\offered.bin")),
                std::path::PathBuf::from(r"\\?\UNC\server\share\")
            );
            let unmapped = ('D'..='Z')
                .rev()
                .map(|letter| std::path::PathBuf::from(format!("{letter}:\\")))
                .find(|root| !root.exists());
            if let Some(root) = unmapped {
                let on_missing_drive = root.join("Shared").join("offered.bin");
                assert_eq!(
                    check_held_source(&on_missing_drive, 4, &[0u8; 32], None),
                    HeldSource::Unreadable,
                    "{}",
                    on_missing_drive.display()
                );
            }
        }
    }

    /// Idle trees go whether or not the cache is full.
    #[test]
    fn an_idle_cached_tree_is_not_served() {
        let stamp = FileStamp {
            path: temp_path("idle-entry"),
            size: 1,
            modified: None,
            object: (1, 2),
            changed: 3,
            subtrees: false,
        };
        let stale_use = std::time::Instant::now()
            .checked_sub(HASH_CACHE_IDLE + std::time::Duration::from_secs(1))
            .expect("clock far enough along");
        hash_cache().lock().unwrap().insert(
            stamp.clone(),
            HashSlot::Ready {
                tree: std::sync::Arc::new(HashTree::from_data(b"x")),
                used: stale_use,
            },
        );
        assert!(matches!(lookup_hash(&stamp), HashLookup::Start(..)));
        hash_cache().lock().unwrap().remove(&stamp);
    }

    /// Feed trees are held to their bytes, least recently used out first, and
    /// neither they nor the chat trees push the other kind out.
    #[test]
    fn feed_trees_are_bounded_by_their_bytes_not_the_chat_count() {
        let _own = isolate_hash_cache();
        let held = |feed: bool| hash_cache().lock().unwrap().keys().filter(|key| key.subtrees == feed).count();
        let chat: Vec<_> = (0..HASH_CACHE_MAX)
            .map(|i| FileStamp { subtrees: false, ..feed_stamp(&format!("bound-chat-{i}"), 1) })
            .collect();
        for stamp in &chat {
            assert!(matches!(lookup_hash(stamp), HashLookup::Start(..)));
            keep_tree(&mut hash_cache().lock().unwrap(), stamp.clone(), std::sync::Arc::new(HashTree::from_data(b"x")));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        // One tree's worth of values, shared: each entry is charged for it all
        // the same.
        let values = FEED_TREE_CACHE_BYTES / 32 / 32;
        let tree = std::sync::Arc::new(HashTree {
            chunk_hashes: vec![[7u8; 32]; values],
            root_hash: [0; 32],
            file_size: (values * ATTACH_CHUNK_SIZE) as u64,
        });
        let fit = FEED_TREE_CACHE_BYTES / (values * 32 + FEED_TREE_ENTRY_COST);
        assert!(fit > HASH_CACHE_MAX, "more feed trees fit than the chat count allows");
        let feeds: Vec<_> = (0..fit + 5).map(|i| feed_stamp(&format!("bound-feed-{i}"), tree.file_size)).collect();
        let keep = |stamp: &FileStamp| {
            keep_tree(&mut hash_cache().lock().unwrap(), stamp.clone(), tree.clone());
            // Apart, so which is least recently used is never a tie.
            std::thread::sleep(std::time::Duration::from_millis(2));
        };
        for stamp in &feeds[..fit] {
            keep(stamp);
        }
        assert_eq!(held(true), fit);
        assert!(matches!(lookup_hash(&feeds[0]), HashLookup::Ready(_)), "asked for again");
        std::thread::sleep(std::time::Duration::from_millis(2));
        for stamp in &feeds[fit..] {
            keep(stamp);
        }
        assert_eq!(held(true), fit);
        assert!(tree_known(&feeds[0]), "the one asked for again stays");
        assert!(!tree_known(&feeds[1]) && !tree_known(&feeds[5]), "the least recently used go");
        assert!(tree_known(&feeds[6]));
        assert!(chat.iter().all(tree_known), "no chat tree went for a feed's");

        let one_more = FileStamp { subtrees: false, ..feed_stamp("bound-chat-more", 1) };
        assert!(matches!(lookup_hash(&one_more), HashLookup::Start(..)));
        assert!(!tree_known(&chat[0]), "the oldest chat tree makes room");
        assert_eq!(held(true), fit, "and no feed tree does");
    }

    /// Streams for one file that queued for the hashing slot while its tree
    /// was being built are not charged for reading it again.
    #[tokio::test]
    async fn streams_queued_behind_a_files_hash_are_not_charged_for_it() {
        let _own = isolate_hash_cache();
        // Far larger than any test file, so a charge for it would show
        // whatever other tests spend meanwhile.
        let stamp = feed_stamp("queued", 6 * 1024 * 1024 * 1024);
        let spent = || feed_hash_spent().lock().unwrap().1;
        let before = spent();
        let ahead = feed_hash_gate().clone().acquire_owned().await.expect("the hashing slot");
        let finish = async {
            tokio::task::yield_now().await;
            keep_tree(&mut hash_cache().lock().unwrap(), stamp.clone(), std::sync::Arc::new(HashTree::from_data(b"x")));
            drop(ahead);
        };
        let (first, second, ()) = tokio::join!(feed_hash_permit(&stamp), feed_hash_permit(&stamp), finish);
        assert!(matches!(first, FeedHashLeave::Known));
        assert!(matches!(second, FeedHashLeave::Known));
        assert!(spent().saturating_sub(before) < stamp.size, "nothing charged for the file");
        assert_eq!(times_named(&CHARGED, stamp.path.file_name().unwrap()), 0);
    }

    /// A kept tree is read back whole, its root worked out from its values;
    /// one kept for a version of the file the stamp no longer describes is
    /// not, and is deleted.
    #[test]
    fn a_kept_feed_tree_is_read_only_for_the_stamp_it_was_kept_for() {
        let dir = keep_feed_trees();
        let size = ATTACH_CHUNK_SIZE as u64 * 2 + 1;
        let data: Vec<u8> = (0..size).map(|i| (i % 23) as u8).collect();
        let tree = subtree_tree(&data[..], size).expect("tree");
        let stamp = feed_stamp("kept-version", size);
        let file = feed_tree_file(dir, &stamp);

        store_feed_tree(&stamp, &tree);
        let kept = load_feed_tree(&stamp).expect("read back");
        assert_eq!(kept.chunk_hashes, tree.chunk_hashes);
        assert_eq!(kept.root_hash, *blake3::hash(&data).as_bytes());
        assert_eq!(kept.file_size, size);

        // A microsecond: Windows keeps times in 100 ns steps.
        let later = stamp.modified.map(|time| time + std::time::Duration::from_micros(1));
        let others = [
            FileStamp { size: size + 1, ..stamp.clone() },
            FileStamp { modified: later, ..stamp.clone() },
            FileStamp { modified: None, ..stamp.clone() },
            FileStamp { changed: 7, ..stamp.clone() },
        ];
        for other in others {
            assert_eq!(feed_tree_file(dir, &other), file, "kept under the same name");
            store_feed_tree(&stamp, &tree);
            assert!(load_feed_tree(&other).is_none(), "{other:?}");
            assert!(!file.exists(), "deleted for {other:?}");
        }
        assert!(load_feed_tree(&stamp).is_none(), "gone");
    }

    /// A kept tree cut short, run on, or with a byte changed is not served,
    /// and is deleted.
    #[test]
    fn a_damaged_kept_feed_tree_is_deleted() {
        let dir = keep_feed_trees();
        let size = ATTACH_CHUNK_SIZE as u64 * 3;
        let data: Vec<u8> = (0..size).map(|i| (i % 31) as u8).collect();
        let tree = subtree_tree(&data[..], size).expect("tree");
        let stamp = feed_stamp("kept-damaged", size);
        let file = feed_tree_file(dir, &stamp);
        let damages: [&dyn Fn(&mut Vec<u8>); 5] = [
            &|bytes| bytes.truncate(bytes.len() - 1),
            &|bytes| bytes.push(0),
            &|bytes| {
                let value = bytes.len() - 40;
                bytes[value] ^= 1;
            },
            &|bytes| bytes[0] ^= 1,
            &|bytes| *bytes = b"not a tree".to_vec(),
        ];
        for (i, damage) in damages.iter().enumerate() {
            store_feed_tree(&stamp, &tree);
            let mut bytes = std::fs::read(&file).expect("kept");
            damage(&mut bytes);
            std::fs::write(&file, &bytes).expect("damage");
            assert!(load_feed_tree(&stamp).is_none(), "damage {i}");
            assert!(!file.exists(), "deleted after damage {i}");
        }
    }

    /// Over either bound the folder loses its least recently used files, down
    /// to seven eighths of it; under both it keeps them all.
    #[test]
    fn the_kept_tree_folder_drops_its_least_recently_used_files() {
        let dir = temp_path("feed-tree-prune");
        std::fs::create_dir_all(&dir).expect("folder");
        let files: Vec<_> = (0..10u64)
            .map(|i| {
                let path = dir.join(format!("{i}.tree"));
                std::fs::write(&path, [0u8; 100]).expect("write");
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .and_then(|f| f.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000 + i)))
                    .expect("date it");
                path
            })
            .collect();
        assert_eq!(prune_feed_trees(&dir, 1000, 10), (1000, 10));
        assert_eq!(prune_feed_trees(&dir, 800, 10), (700, 7));
        assert!(files[..3].iter().all(|path| !path.exists()) && files[3..].iter().all(|path| path.exists()));
        assert_eq!(prune_feed_trees(&dir, 10_000, 5), (500, 5));
        assert!(files[..5].iter().all(|path| !path.exists()) && files[5..].iter().all(|path| path.exists()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The tree built to put a room offer together is the one the stream
    /// serves from; the file is not read a second time.
    #[tokio::test]
    async fn a_file_hashed_for_its_offer_is_served_without_hashing_again() {
        let data = b"offered in a room".to_vec();
        let source = temp_path("src-offer");
        std::fs::write(&source, &data).expect("write");
        let hashed = source.clone();
        let tree = tokio::task::spawn_blocking(move || hash_for_serving(&hashed))
            .await
            .expect("join")
            .expect("hash");
        assert_eq!(tree.root_hash, HashTree::from_data(&data).root_hash);
        let outcome = serve_once(&source, data.len() as u64, tree.root_hash, [23u8; 16])
            .await
            .expect("fetch");
        assert!(outcome.complete);
        assert_eq!(times_hashed(&source), 1);
        let _ = std::fs::remove_file(&source);
    }

    #[tokio::test]
    async fn a_prewarmed_file_is_served_without_hashing_again() {
        let data = b"prewarmed attachment".to_vec();
        let source = temp_path("src-prewarm");
        std::fs::write(&source, &data).expect("write");
        let prewarm = source.clone();
        tokio::task::spawn_blocking(move || prewarm_attachment_hash(&prewarm))
            .await
            .expect("prewarm");
        let root = HashTree::from_data(&data).root_hash;
        let outcome = serve_once(&source, data.len() as u64, root, [14u8; 16])
            .await
            .expect("fetch");
        assert!(outcome.complete);
        assert_eq!(times_hashed(&source), 1);
        let _ = std::fs::remove_file(&source);
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ember-attach-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    /// What production gets from `open_or_create_approved`: read/write, created
    /// if absent, never truncated.
    fn open_part(path: &Path) -> std::fs::File {
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)
            .expect("open part file")
    }

    fn pair() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
        let a = SigningKey::from_bytes(&[11u8; 32]);
        let b = SigningKey::from_bytes(&[22u8; 32]);
        (
            a.to_bytes(),
            a.verifying_key().to_bytes(),
            b.to_bytes(),
            b.verifying_key().to_bytes(),
        )
    }

    /// One in-memory duplex per direction, which is what a QUIC bidirectional
    /// stream is from each end's point of view.
    async fn round_trip(
        data: &[u8],
        xfer_id: [u8; 16],
        part: &Path,
        corrupt_chunk: Option<usize>,
    ) -> anyhow::Result<FetchOutcome> {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let cap_sender = derive_attach_capability(&a_seed, &b_pub, &xfer_id).expect("cap");
        let cap_recv = derive_attach_capability(&b_seed, &a_pub, &xfer_id).expect("cap");

        let source = temp_path("src");
        std::fs::write(&source, data)?;
        let tree = HashTree::from_data(data);
        let root = tree.root_hash;
        let size = data.len() as u64;

        // to_server carries the request; to_client carries the answer.
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);

        let served_source = source.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |id| (*id == xfer_id).then(|| (served_source.clone(), size, root, cap_sender)),
                |_, _, _| true,
                None,
            )
            .await
        });

        let fetched = if let Some(bad) = corrupt_chunk {
            // Serve honestly, then flip a byte of one chunk on the way in, which
            // is what a sender substituting content mid-stream looks like.
            let outcome = fetch_with_corruption(
                &mut client_r,
                &mut client_w,
                &xfer_id,
                &cap_recv,
                size,
                &root,
                part,
                bad,
            )
            .await;
            outcome
        } else {
            fetch_attachment(
                &mut client_r,
                &mut client_w,
                &xfer_id,
                &cap_recv,
                size,
                &root,
                open_part(part),
                |_| {},
            )
            .await
            .map_err(anyhow::Error::from)
        };

        let _ = server.await;
        let _ = std::fs::remove_file(&source);
        fetched
    }

    /// `fetch_attachment` with one chunk's bytes flipped before verification,
    /// by reading the stream through a wrapper.
    #[allow(clippy::too_many_arguments)]
    async fn fetch_with_corruption<R, W>(
        recv: &mut R,
        send: &mut W,
        xfer_id: &[u8; 16],
        capability: &[u8; 32],
        size: u64,
        root: &[u8; 32],
        part: &Path,
        bad_chunk: usize,
    ) -> anyhow::Result<FetchOutcome>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        // Read everything the server sends, corrupt the target chunk, and feed
        // the result back through the real reader over a duplex.
        let info_len = attach_file_info_len(size).expect("len");
        let request = AttachRequest {
            xfer_id: *xfer_id,
            tag: attach_stream_tag(capability, xfer_id),
            start_chunk: 0,
        };
        send.write_all(&encode_attach_request(&request)).await?;
        send.flush().await?;

        let mut header = vec![0u8; info_len];
        recv.read_exact(&mut header).await?;
        let mut body = Vec::new();
        recv.read_to_end(&mut body).await?;
        let at = bad_chunk * ATTACH_CHUNK_SIZE;
        if at < body.len() {
            body[at] ^= 0xFF;
        }

        let (mut feed_w, mut feed_r) = tokio::io::duplex(1 << 20);
        let (mut sink_w, _sink_r) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let _ = feed_w.write_all(&header).await;
            let _ = feed_w.write_all(&body).await;
        });
        fetch_attachment(
            &mut feed_r,
            &mut sink_w,
            xfer_id,
            capability,
            size,
            root,
            open_part(part),
            |_| {},
        )
        .await
        .map_err(anyhow::Error::from)
    }

    /// End to end over a real QUIC connection, authorized the way the accept
    /// loop does it: the receiver dials with the sender's identity pinned, and
    /// the sender reads the receiver's identity and key back off the certificate
    /// the handshake proved, then derives the capability from that key.
    #[tokio::test]
    async fn a_file_crosses_a_real_quic_connection_to_the_pinned_friend() {
        use super::super::crypto::node_id_from_public_key;
        use super::super::quic::{
            build_server_client_endpoint, connect_pinned, connection_ed25519_pubkey,
            connection_node_id, generate_self_signed_cert,
        };

        let sender_sk = SigningKey::from_bytes(&[31u8; 32]);
        let receiver_sk = SigningKey::from_bytes(&[32u8; 32]);
        let sender_seed = sender_sk.to_bytes();
        let receiver_seed = receiver_sk.to_bytes();
        let sender_pub = sender_sk.verifying_key().to_bytes();
        let sender_id = node_id_from_public_key(&sender_sk.verifying_key());
        let receiver_id = node_id_from_public_key(&receiver_sk.verifying_key());

        let (s_cert, s_key) = generate_self_signed_cert(&sender_seed).expect("sender cert");
        let (r_cert, r_key) = generate_self_signed_cert(&receiver_seed).expect("receiver cert");
        let (server, _) = build_server_client_endpoint(&s_cert, &s_key, 0, false)
            .await
            .expect("sender endpoint");
        let (client, _) = build_server_client_endpoint(&r_cert, &r_key, 0, false)
            .await
            .expect("receiver endpoint");
        let addr = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            server.local_addr().expect("addr").port(),
        );

        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2 + 777).map(|i| (i % 241) as u8).collect();
        let source = temp_path("quic-src");
        std::fs::write(&source, &data).expect("write source");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;
        let xfer_id = [40u8; 16];

        let served_source = source.clone();
        let server_task = tokio::spawn(async move {
            let conn = server
                .accept()
                .await
                .expect("incoming")
                .await
                .expect("handshake");
            let peer_id = connection_node_id(&conn).expect("peer id");
            let peer_pub = connection_ed25519_pubkey(&conn).expect("peer key");
            assert_eq!(peer_id, receiver_id, "the identity comes off the certificate");
            let (mut send, mut recv) = conn.accept_bi().await.expect("stream");
            let mut prefix = [0u8; 7];
            recv.read_exact(&mut prefix).await.expect("prefix");
            let cap = derive_attach_capability(&sender_seed, &peer_pub, &xfer_id).expect("cap");
            let sent = serve_attachment(
                &mut recv,
                &mut send,
                &prefix,
                |id| (*id == xfer_id).then(|| (served_source.clone(), size, root, cap)),
                |_, _, _| true,
                None,
            )
            .await
            .expect("serve");
            let _ = send.finish();
            conn.closed().await;
            sent
        });

        let conn = connect_pinned(&client, addr, "ember", Some((&r_cert, &r_key, sender_id)))
            .await
            .expect("pinned dial");
        let (mut send, mut recv) = conn.open_bi().await.expect("open stream");
        let cap = derive_attach_capability(&receiver_seed, &sender_pub, &xfer_id).expect("cap");
        let part = temp_path("quic-part");
        let outcome = fetch_attachment(
            &mut recv,
            &mut send,
            &xfer_id,
            &cap,
            size,
            &root,
            open_part(&part),
            |_| {},
        )
        .await
        .expect("fetch");
        conn.close(0u32.into(), b"done");

        assert!(outcome.complete);
        assert_eq!(std::fs::read(&part).expect("part"), data);
        assert_eq!(server_task.await.expect("server task"), size);
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part);
    }

    /// A room transfer rides the same stream under its own first byte, and a
    /// server reads only its own type: a room request put to the chat server
    /// is refused rather than served.
    #[tokio::test]
    async fn a_room_stream_round_trips_and_is_not_read_as_a_chat_one() {
        use super::super::attach::{encode_stream_request, ROOM_XFER_STREAM_MSG_TYPE};
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE + 5).map(|i| (i % 13) as u8).collect();
        let source = temp_path("room-src");
        std::fs::write(&source, &data).expect("write");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;
        let (xfer_id, cap) = ([21u8; 16], [22u8; 32]);

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);
        let served = source.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_stream(
                ROOM_XFER_STREAM_MSG_TYPE,
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), size, root, cap)),
                |_, _, _| true,
                None,
            )
            .await
        });
        let part = temp_path("room-part");
        let outcome = fetch_stream_waiting(
            ROOM_XFER_STREAM_MSG_TYPE,
            &mut client_r,
            &mut client_w,
            &xfer_id,
            &cap,
            size,
            &root,
            open_part(&part),
            |_| {},
            ATTACH_STATUS_TIMEOUT,
            &mut std::time::Duration::default(),
        )
        .await
        .expect("room fetch");
        assert!(outcome.complete);
        assert_eq!(std::fs::read(&part).expect("part"), data);
        let _ = server.await;

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 16);
        let served = source.clone();
        let chat_server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await.expect("prefix");
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), size, root, cap)),
                |_, _, _| true,
                None,
            )
            .await
        });
        let request = AttachRequest {
            xfer_id,
            tag: attach_stream_tag(&cap, &xfer_id),
            start_chunk: 0,
        };
        client_w
            .write_all(&encode_stream_request(ROOM_XFER_STREAM_MSG_TYPE, &request))
            .await
            .expect("write");
        client_w.flush().await.expect("flush");
        let mut status = [0u8; 1];
        client_r.read_exact(&mut status).await.expect("status");
        assert_eq!(
            AttachStreamStatus::from_byte(status[0]),
            Some(AttachStreamStatus::Unknown)
        );
        assert!(chat_server.await.expect("join").is_err());
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part);
    }

    #[tokio::test]
    async fn a_file_arrives_byte_for_byte() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2 + 1234)
            .map(|i| (i % 251) as u8)
            .collect();
        let part = temp_path("part");
        let outcome = round_trip(&data, [1u8; 16], &part, None)
            .await
            .expect("transfer");

        assert!(outcome.complete);
        assert_eq!(outcome.total, data.len() as u64);
        assert_eq!(std::fs::read(&part).expect("part"), data);
        let _ = std::fs::remove_file(&part);
    }

    /// Both bars move while a chunk is still crossing, and the figure a resume
    /// may start from only ever lands on a chunk that verified.
    #[tokio::test]
    async fn progress_moves_within_a_chunk_but_verified_stays_on_chunk_boundaries() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2 + 999).map(|i| (i % 229) as u8).collect();
        let source = temp_path("src-progress");
        std::fs::write(&source, &data).expect("write");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;
        let (xfer_id, cap) = ([24u8; 16], [25u8; 32]);

        // A narrow pipe toward the receiver, so a chunk arrives in many reads.
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(8 * 1024);
        let served = source.clone();
        let positions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let noted = positions.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), size, root, cap)),
                move |_, position, _| {
                    noted.lock().unwrap().push(position);
                    true
                },
                None,
            )
            .await
        });
        let part = temp_path("part-progress");
        let mut seen = Vec::new();
        let outcome = fetch_attachment(
            &mut client_r,
            &mut client_w,
            &xfer_id,
            &cap,
            size,
            &root,
            open_part(&part),
            |progress| seen.push(progress),
        )
        .await
        .expect("fetch");
        assert!(outcome.complete);
        server.await.expect("join").expect("serve");

        assert!(
            seen.iter().any(|p| p.received > p.verified),
            "nothing was reported from inside a chunk"
        );
        for p in &seen {
            assert!(p.verified <= p.received && p.received <= size, "{p:?}");
            assert!(
                p.verified % ATTACH_CHUNK_SIZE as u64 == 0 || p.verified == size,
                "verified off a chunk boundary: {p:?}"
            );
        }
        assert!(seen
            .windows(2)
            .all(|w| w[0].received <= w[1].received && w[0].verified <= w[1].verified));
        assert_eq!(
            seen.last(),
            Some(&FetchProgress {
                received: size,
                verified: size,
                size
            })
        );

        let positions = positions.lock().unwrap().clone();
        assert!(
            positions.iter().any(|p| p % ATTACH_CHUNK_SIZE as u64 != 0),
            "the sender reported only whole chunks: {positions:?}"
        );
        assert_eq!(positions.last(), Some(&size));

        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part);
    }

    #[tokio::test]
    async fn a_single_chunk_file_works() {
        let data = b"a short attachment".to_vec();
        let part = temp_path("part-small");
        let outcome = round_trip(&data, [2u8; 16], &part, None)
            .await
            .expect("transfer");
        assert!(outcome.complete);
        assert_eq!(std::fs::read(&part).expect("part"), data);
        let _ = std::fs::remove_file(&part);
    }

    /// The point of sending the chunk list: a chunk that does not match is
    /// refused as it lands, not after the last byte.
    #[tokio::test]
    async fn a_corrupted_chunk_is_refused() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2).map(|i| (i % 97) as u8).collect();
        let part = temp_path("part-bad");
        let err = round_trip(&data, [3u8; 16], &part, Some(1))
            .await
            .expect_err("a flipped chunk must fail");
        assert!(
            err.to_string().contains("did not match its hash"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&part);
    }

    /// A stream that drops before the sender answers has not used up the
    /// long status wait: only the time actually spent waiting is counted.
    #[tokio::test]
    async fn a_stream_dropped_before_the_status_counts_only_the_time_waited() {
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (server_w, mut client_r) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(async move {
            let mut request = [0u8; 7];
            let _ = server_r.read_exact(&mut request).await;
            drop(server_w);
        });
        let part = temp_path("part-dropped");
        let mut waited = std::time::Duration::ZERO;
        let fetched = fetch_attachment_waiting(
            &mut client_r,
            &mut client_w,
            &[17u8; 16],
            &[0u8; 32],
            1,
            &[0u8; 32],
            open_part(&part),
            |_| {},
            ATTACH_STATUS_TIMEOUT,
            &mut waited,
        )
        .await;
        server.await.expect("join");
        assert!(matches!(fetched, Err(FetchError::Transient(_))));
        assert!(waited < std::time::Duration::from_secs(5), "waited {waited:?}");
        let _ = std::fs::remove_file(&part);
    }

    /// A grant miss is the ordinary case for a cancelled or lapsed transfer, and
    /// must not look like a protocol error to the peer.
    #[tokio::test]
    async fn an_unknown_transfer_is_refused_without_serving() {
        let (a_seed, _, b_seed, b_pub) = pair();
        let xfer_id = [4u8; 16];
        let cap = derive_attach_capability(&b_seed, &b_pub, &xfer_id).expect("cap");
        let _ = a_seed;

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 16);

        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await.expect("prefix");
            // No grant for anything.
            serve_attachment(&mut server_r, &mut server_w, &prefix, |_| None, |_, _, _| true, None)
                .await
        });

        let request = AttachRequest {
            xfer_id,
            tag: attach_stream_tag(&cap, &xfer_id),
            start_chunk: 0,
        };
        client_w
            .write_all(&encode_attach_request(&request))
            .await
            .expect("write request");
        client_w.flush().await.expect("flush");

        let mut status = [0u8; 1];
        client_r.read_exact(&mut status).await.expect("status");
        assert_eq!(
            AttachStreamStatus::from_byte(status[0]),
            Some(AttachStreamStatus::Unknown)
        );
        assert_eq!(server.await.expect("join").expect("served nothing"), 0);
    }

    /// A cancel while the stream is running has to end it, not just refuse the
    /// next dial: once the caller says the grant is gone, no further chunk is
    /// sent and the receiver sees the stream stop short.
    #[tokio::test]
    async fn a_grant_withdrawn_mid_stream_stops_the_stream() {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let xfer_id = [10u8; 16];
        let cap_sender = derive_attach_capability(&a_seed, &b_pub, &xfer_id).expect("cap");
        let cap_recv = derive_attach_capability(&b_seed, &a_pub, &xfer_id).expect("cap");

        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 4)
            .map(|i| (i % 199) as u8)
            .collect();
        let source = temp_path("src-withdrawn");
        std::fs::write(&source, &data).expect("write");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);
        let served = source.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await.expect("prefix");
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), size, root, cap_sender)),
                |_, position, _| position < ATTACH_CHUNK_SIZE as u64,
                None,
            )
            .await
        });

        let part = temp_path("part-withdrawn");
        let fetched = fetch_attachment(
            &mut client_r,
            &mut client_w,
            &xfer_id,
            &cap_recv,
            size,
            &root,
            open_part(&part),
            |_| {},
        )
        .await;
        assert!(
            matches!(fetched, Err(FetchError::Transient(_))),
            "the receiver sees a stream that stopped short: {fetched:?}"
        );
        let err = server.await.expect("join").expect_err("serving must stop");
        assert!(
            err.to_string().contains("withdrawn"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part);
    }

    /// The tag is the proof the dialer was actually offered this transfer. A
    /// friend with a live grant for a *different* transfer must not be able to
    /// spend it here.
    #[tokio::test]
    async fn a_wrong_tag_is_refused_before_any_bytes() {
        let (a_seed, a_pub, b_seed, b_pub) = pair();
        let xfer_id = [5u8; 16];
        let other_id = [6u8; 16];
        let cap_sender = derive_attach_capability(&a_seed, &b_pub, &xfer_id).expect("cap");
        let wrong = derive_attach_capability(&b_seed, &a_pub, &other_id).expect("cap");

        let source = temp_path("src-tag");
        std::fs::write(&source, b"secret").expect("write");
        let tree = HashTree::from_data(b"secret");
        let root = tree.root_hash;

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 16);
        let served = source.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await.expect("prefix");
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), 6, root, cap_sender)),
                |_, _, _| true,
                None,
            )
            .await
        });

        // Right transfer id, tag computed from the wrong transfer's capability.
        let request = AttachRequest {
            xfer_id,
            tag: attach_stream_tag(&wrong, &other_id),
            start_chunk: 0,
        };
        client_w
            .write_all(&encode_attach_request(&request))
            .await
            .expect("write");
        client_w.flush().await.expect("flush");

        let mut status = [0u8; 1];
        client_r.read_exact(&mut status).await.expect("status");
        assert_eq!(
            AttachStreamStatus::from_byte(status[0]),
            Some(AttachStreamStatus::Unauthorized)
        );
        assert!(server.await.expect("join").is_err());
        let _ = std::fs::remove_file(&source);
    }

    /// A file swapped between the offer and the dial no longer matches the root
    /// it was offered under, and the sender says so rather than streaming bytes
    /// that cannot verify.
    #[tokio::test]
    async fn a_file_changed_since_the_offer_is_not_served() {
        let (a_seed, _a_pub, b_seed, b_pub) = pair();
        let xfer_id = [7u8; 16];
        let cap_sender = derive_attach_capability(&a_seed, &b_pub, &xfer_id).expect("cap");
        let cap_recv = derive_attach_capability(&b_seed, &_a_pub, &xfer_id).expect("cap");

        let source = temp_path("src-swapped");
        std::fs::write(&source, b"the original bytes").expect("write");
        let offered_root = HashTree::from_data(b"the original bytes").root_hash;
        // The user replaced it after the offer went out.
        std::fs::write(&source, b"something else now").expect("rewrite");

        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 16);
        let served = source.clone();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await.expect("prefix");
            serve_attachment(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Some((served.clone(), 18, offered_root, cap_sender)),
                |_, _, _| true,
                None,
            )
            .await
        });

        let part = temp_path("part-swapped");
        let err = fetch_attachment(
            &mut client_r,
            &mut client_w,
            &xfer_id,
            &cap_recv,
            18,
            &offered_root,
            open_part(&part),
            |_| {},
        )
        .await
        .expect_err("a swapped file must not transfer");
        assert!(
            err.to_string().contains("SourceGone"),
            "unexpected error: {err}"
        );
        let _ = server.await;
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part);
    }

    /// An interrupted transfer picks up at a chunk boundary rather than
    /// re-fetching what it already verified.
    #[tokio::test]
    async fn an_interrupted_transfer_resumes_on_a_chunk_boundary() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 3).map(|i| (i % 131) as u8).collect();
        let part = temp_path("part-resume");
        // One whole chunk already verified and on disk.
        std::fs::write(&part, &data[..ATTACH_CHUNK_SIZE]).expect("seed part");

        let outcome = round_trip(&data, [8u8; 16], &part, None)
            .await
            .expect("transfer");

        assert!(outcome.complete);
        assert_eq!(outcome.total, data.len() as u64);
        assert_eq!(
            outcome.written,
            (ATTACH_CHUNK_SIZE * 2) as u64,
            "only the chunks it was still missing"
        );
        assert_eq!(std::fs::read(&part).expect("part"), data);
        let _ = std::fs::remove_file(&part);
    }

    /// A partial chunk on disk has been through no check, so it is dropped
    /// rather than resumed past — otherwise a truncated write would be imported
    /// as verified content.
    #[tokio::test]
    async fn a_half_written_chunk_is_discarded_not_trusted() {
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2).map(|i| (i % 17) as u8).collect();
        let part = temp_path("part-partial");
        // A chunk and a half, the half being garbage.
        let mut seed = data[..ATTACH_CHUNK_SIZE].to_vec();
        seed.extend_from_slice(&[0xFFu8; 4096]);
        std::fs::write(&part, &seed).expect("seed part");

        let outcome = round_trip(&data, [9u8; 16], &part, None)
            .await
            .expect("transfer");

        assert!(outcome.complete);
        assert_eq!(std::fs::read(&part).expect("part"), data);
        let _ = std::fs::remove_file(&part);
    }

    /// Serve `source` as a feed file once, under `capability`, and ask for it
    /// from `start_chunk` under `asked_with`. The chunk list and the chunks
    /// read, or why the request failed.
    async fn feed_round_trip(
        source: Option<&Path>,
        size: u64,
        capability: [u8; 32],
        asked_with: [u8; 32],
        start_chunk: u32,
    ) -> Result<(AttachFileInfo, Vec<u8>), FetchError> {
        feed_round_trip_admitted(source, size, capability, asked_with, start_chunk, Ok(())).await
    }

    /// The folder feed files are served from in these tests, approved as a
    /// root while [`approve_feed_files`]'s guard lives.
    fn feed_files_dir() -> PathBuf {
        std::env::temp_dir().join(format!("ember-attach-feeds-{}", std::process::id())).join("files")
    }

    fn approve_feed_files() -> parking_lot::MutexGuard<'static, ()> {
        let guard = crate::security::filesystem::test_registry_lock();
        let files = feed_files_dir();
        let data = files.with_file_name("data");
        std::fs::create_dir_all(&files).expect("feed files folder");
        std::fs::create_dir_all(&data).expect("data folder");
        crate::security::filesystem::initialize_approved_roots(&data, &[files.to_string_lossy().into_owned()])
            .expect("approve the feed files folder");
        guard
    }

    /// Where a test's feed file is served from.
    fn feed_source(tag: &str) -> PathBuf {
        let files = feed_files_dir();
        std::fs::create_dir_all(&files).expect("feed files folder");
        files.join(format!("{tag}-{}", rand::random::<u64>()))
    }

    /// [`feed_round_trip`], admitted or refused with `admitted`.
    #[allow(clippy::await_holding_lock)]
    async fn feed_round_trip_admitted(
        source: Option<&Path>,
        size: u64,
        capability: [u8; 32],
        asked_with: [u8; 32],
        start_chunk: u32,
        admitted: Result<(), AttachStreamStatus>,
    ) -> Result<(AttachFileInfo, Vec<u8>), FetchError> {
        let _approved = approve_feed_files();
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 20);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 20);
        let served = source.map(Path::to_path_buf);
        let blake3 = source.map_or([0; 32], |path| *blake3::hash(&std::fs::read(path).expect("feed file")).as_bytes());
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_feed_stream(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| {
                    served
                        .map(|path| FeedGrant {
                            path,
                            size,
                            blake3,
                            capability,
                            roots: vec![feed_files_dir().to_string_lossy().into_owned()],
                        })
                        .ok_or(AttachStreamStatus::Unknown)
                },
                |_| admitted,
                |_, _, _| true,
                None,
            )
            .await
        });
        let fetched = async {
            let info = request_chunks(
                super::super::attach::FEED_STREAM_MSG_TYPE,
                &mut client_r,
                &mut client_w,
                &[5u8; 16],
                &asked_with,
                size,
                start_chunk,
                ATTACH_STATUS_TIMEOUT,
            )
            .await?;
            let mut got = Vec::new();
            let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
            for index in start_chunk as usize..info.chunk_count() {
                let len = read_verified_feed_chunk(&mut client_r, &info, index, &mut buf).await?;
                got.extend_from_slice(&buf[..len]);
            }
            Ok((info, got))
        }
        .await;
        drop((client_r, client_w));
        let _ = server.await;
        fetched
    }

    /// Anyone holding the link is served, from the chunk asked for, with a
    /// list that comes to the file's own BLAKE3, so a follower checks it
    /// against the BLAKE3 the feed names, and every chunk against it.
    #[tokio::test]
    async fn a_feed_file_is_served_from_the_chunk_asked_for() {
        use crate::network::ember::feed::root_of_chunk_values;
        for size in [5, ATTACH_CHUNK_SIZE, ATTACH_CHUNK_SIZE + 1, ATTACH_CHUNK_SIZE * 3 + 5, ATTACH_CHUNK_SIZE * 4] {
            let data: Vec<u8> = (0..size).map(|i| (i % 13) as u8).collect();
            let source = feed_source("feed-src");
            std::fs::write(&source, &data).expect("write");
            let from = usize::from(size > ATTACH_CHUNK_SIZE);
            let (info, got) = feed_round_trip(Some(&source), data.len() as u64, [8; 32], [8; 32], from as u32)
                .await
                .expect("served");
            assert_eq!(root_of_chunk_values(&info.chunk_hashes), Some(*blake3::hash(&data).as_bytes()), "{size} bytes");
            assert_eq!(got, data[from * ATTACH_CHUNK_SIZE..], "{size} bytes");
            let _ = std::fs::remove_file(&source);
        }
    }

    /// A feed's file is opened only within the folders the request may read.
    #[tokio::test]
    async fn a_feed_file_outside_its_folders_is_refused() {
        let source = temp_path("feed-outside");
        std::fs::write(&source, b"feed file").expect("write");
        let (mut client_w, mut server_r) = tokio::io::duplex(1 << 16);
        let (mut server_w, mut client_r) = tokio::io::duplex(1 << 16);
        let served = source.clone();
        let elsewhere = std::env::temp_dir().join("ember-attach-no-such-folder").to_string_lossy().into_owned();
        let server = tokio::spawn(async move {
            let mut prefix = [0u8; 7];
            server_r.read_exact(&mut prefix).await?;
            serve_feed_stream(
                &mut server_r,
                &mut server_w,
                &prefix,
                |_| Ok(FeedGrant { path: served, size: 9, blake3: [7; 32], capability: [8; 32], roots: vec![elsewhere] }),
                |_| Ok::<(), AttachStreamStatus>(()),
                |_, _, _| true,
                None,
            )
            .await
        });
        let refused =
            request_chunks(super::super::attach::FEED_STREAM_MSG_TYPE, &mut client_r, &mut client_w, &[5u8; 16], &[8; 32], 9, 0, ATTACH_STATUS_TIMEOUT)
                .await;
        assert!(matches!(refused, Err(FetchError::Refused(AttachStreamStatus::SourceGone))));
        drop((client_r, client_w));
        let _ = server.await;
        let _ = std::fs::remove_file(&source);
    }

    #[tokio::test]
    async fn a_feed_request_without_its_capability_is_refused() {
        let source = feed_source("feed-cap");
        std::fs::write(&source, b"feed file").expect("write");
        let refused = feed_round_trip(Some(&source), 9, [8; 32], [9; 32], 0).await;
        assert!(matches!(refused, Err(FetchError::Refused(AttachStreamStatus::Unauthorized))));
        let _ = std::fs::remove_file(&source);
    }

    #[tokio::test]
    async fn a_file_no_feed_of_ours_lists_is_refused() {
        let refused = feed_round_trip(None, 9, [8; 32], [8; 32], 0).await;
        assert!(matches!(refused, Err(FetchError::Refused(AttachStreamStatus::Unknown))));
    }

    /// A follower turned away for want of a slot is told so, to ask again,
    /// rather than told the file is not ours.
    #[tokio::test]
    async fn a_feed_request_past_the_serve_slots_is_refused_as_busy() {
        let source = feed_source("feed-busy");
        std::fs::write(&source, b"feed file").expect("write");
        let refused = feed_round_trip_admitted(Some(&source), 9, [8; 32], [8; 32], 0, Err(AttachStreamStatus::Busy)).await;
        assert!(matches!(refused, Err(FetchError::Refused(AttachStreamStatus::Busy))));
        let _ = std::fs::remove_file(&source);
    }

    /// A feed file's tree outlives the memory cache, as it does a restart: the
    /// next follower is served from the tree kept on disk, without the file
    /// being read again or charged to the hour's budget.
    #[tokio::test]
    async fn a_kept_feed_tree_is_read_back_rather_than_hashed_and_charged() {
        let dir = keep_feed_trees();
        let data: Vec<u8> = (0..ATTACH_CHUNK_SIZE * 2 + 7).map(|i| (i % 29) as u8).collect();
        let size = data.len() as u64;
        let source = feed_source("feed-kept");
        std::fs::write(&source, &data).expect("write");
        let name = source.file_name().expect("name").to_owned();
        let (first, _) = feed_round_trip(Some(&source), size, [8; 32], [8; 32], 0).await.expect("served");
        assert_eq!((times_named(&HASHED, &name), times_named(&CHARGED, &name)), (1, 1));

        let ours = |key: &FileStamp| key.subtrees && key.path.file_name() == Some(name.as_os_str());
        let stamp = hash_cache().lock().unwrap().keys().find(|key| ours(key)).cloned().expect("cached");
        assert!(feed_tree_file(dir, &stamp).exists(), "kept on disk");
        hash_cache().lock().unwrap().retain(|key, _| !ours(key));

        let (second, got) = feed_round_trip(Some(&source), size, [8; 32], [8; 32], 0).await.expect("served again");
        assert_eq!(second.chunk_hashes, first.chunk_hashes);
        assert_eq!(got, data);
        assert_eq!(
            (times_named(&HASHED, &name), times_named(&CHARGED, &name)),
            (1, 1),
            "read back, not hashed or charged again"
        );
        assert!(tree_known(&stamp), "and cached again");
        let _ = std::fs::remove_file(feed_tree_file(dir, &stamp));
        let _ = std::fs::remove_file(&source);
    }

    /// Past the 2 GiB a chat file may be, which a feed's film can be.
    #[test]
    fn a_feed_stream_carries_files_a_chat_cannot() {
        use super::super::attach::{stream_max_bytes, ATTACH_MAX_BYTES, FEED_STREAM_MAX_BYTES, FEED_STREAM_MSG_TYPE};
        let large = ATTACH_MAX_BYTES + 1;
        assert!(attach_chunk_count(large).is_none());
        assert!(chunk_count_up_to(large, stream_max_bytes(FEED_STREAM_MSG_TYPE)).is_some());
        assert!(chunk_count_up_to(FEED_STREAM_MAX_BYTES + 1, stream_max_bytes(FEED_STREAM_MSG_TYPE)).is_none());
        assert_eq!(stream_max_bytes(super::super::attach::ROOM_XFER_STREAM_MSG_TYPE), ATTACH_MAX_BYTES);
    }

    /// A chunk that is not the one the list hashes is refused before it is
    /// handed on to be written.
    #[tokio::test]
    async fn a_chunk_that_does_not_match_its_hash_is_refused() {
        let data = vec![1u8; 100];
        let info = AttachFileInfo { size: 100, chunk_hashes: HashTree::from_data(&data).chunk_hashes };
        let (mut tx, mut rx) = tokio::io::duplex(1024);
        tx.write_all(&[2u8; 100]).await.expect("write");
        let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
        let read = read_verified_chunk(&mut rx, &info, 0, &mut buf, |_| {}).await;
        assert!(matches!(read, Err(FetchError::Corrupt(_))));
    }
}
