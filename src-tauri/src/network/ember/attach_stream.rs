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
    decode_attach_file_info, encode_attach_file_info, AttachFileInfo, AttachRequest,
    AttachStreamStatus, ATTACH_CHUNK_SIZE, ATTACH_REQUEST_TAIL_LEN,
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

/// Hash trees kept for files being served. A tree is `CHUNK_SIZE`-granular, so
/// even a 2 GiB file's is 256 KiB.
const HASH_CACHE_MAX: usize = 16;

/// A cached tree nobody has asked for in this long is dropped. Past a grant's
/// lifetime nothing will ask again, and a tree that outlives the bytes it
/// describes is only ever a wrong answer.
const HASH_CACHE_IDLE: std::time::Duration = std::time::Duration::from_secs(60 * 60);

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

fn hash_cache() -> &'static std::sync::Mutex<std::collections::HashMap<FileStamp, HashSlot>> {
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<FileStamp, HashSlot>>,
    > = std::sync::OnceLock::new();
    CACHE.get_or_init(Default::default)
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
        Some(HashSlot::Ready { tree, used })
            if now.saturating_duration_since(*used) < HASH_CACHE_IDLE =>
        {
            *used = now;
            return HashLookup::Ready(tree.clone());
        }
        Some(HashSlot::Hashing(rx)) => return HashLookup::Wait(rx.clone()),
        _ => {}
    }
    // Every other entry for the same path is a version of the file that is no
    // longer on disk.
    cache.retain(|key, _| key.path != stamp.path);
    let now = std::time::Instant::now();
    cache.retain(|_, slot| match slot {
        HashSlot::Ready { used, .. } => now.saturating_duration_since(*used) < HASH_CACHE_IDLE,
        HashSlot::Hashing(_) => true,
    });
    if cache.len() >= HASH_CACHE_MAX {
        let oldest = cache
            .iter()
            .filter_map(|(key, slot)| match slot {
                HashSlot::Ready { used, .. } => Some((key.clone(), *used)),
                HashSlot::Hashing(_) => None,
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

/// Hash the file `stamp` names and publish the result. Blocking: a read of the
/// whole file.
fn run_hash_job(stamp: FileStamp, tx: tokio::sync::watch::Sender<HashOutcome>) {
    let outcome = hash_stamped_file(&stamp);
    #[cfg(test)]
    tests::note_hashed(&stamp.path);
    let mut cache = hash_cache().lock().unwrap_or_else(|e| e.into_inner());
    match &outcome {
        Ok(tree) => {
            cache.insert(
                stamp,
                HashSlot::Ready {
                    tree: tree.clone(),
                    used: std::time::Instant::now(),
                },
            );
        }
        // Not cached: the next stream tries again, and the file may be back.
        Err(_) => {
            cache.remove(&stamp);
        }
    }
    drop(cache);
    let _ = tx.send(Some(outcome));
}

fn hash_stamped_file(stamp: &FileStamp) -> Result<std::sync::Arc<HashTree>, String> {
    let file = std::fs::File::open(&stamp.path).map_err(|e| e.to_string())?;
    if FileStamp::of(&stamp.path, &file).map_err(|e| e.to_string())? != *stamp {
        return Err("attachment changed before it could be hashed".into());
    }
    let tree = HashTree::from_reader(std::io::BufReader::new(&file)).map_err(|e| e.to_string())?;
    // A write that landed mid-read leaves a tree of neither version.
    if FileStamp::of(&stamp.path, &file).map_err(|e| e.to_string())? != *stamp {
        return Err("attachment changed while it was being hashed".into());
    }
    Ok(std::sync::Arc::new(tree))
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
async fn attachment_tree(stamp: FileStamp) -> Result<(std::sync::Arc<HashTree>, bool), String> {
    let mut rx = match lookup_hash(&stamp) {
        HashLookup::Ready(tree) => return Ok((tree, true)),
        HashLookup::Wait(rx) => rx,
        HashLookup::Start(tx, rx) => {
            tokio::task::spawn_blocking(move || run_hash_job(stamp, tx));
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
        capability_for,
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
    serve_paced(stream_type, recv, send, prefix, capability_for, on_progress, limiter, false).await
}

#[allow(clippy::too_many_arguments)]
async fn serve_paced<R, W, F, P>(
    stream_type: u8,
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    capability_for: F,
    mut on_progress: P,
    limiter: Option<&crate::bandwidth::limiter::BandwidthLimiter>,
    priority: bool,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])>,
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
    let Some((path, size, root, capability)) = capability_for(&request.xfer_id) else {
        refuse(send, AttachStreamStatus::Unknown).await?;
        return Ok(0);
    };

    // Second, weaker check: the tag proves the dialer holds the offer. Constant
    // time, because a byte-at-a-time timing walk would recover it.
    let expected = attach_stream_tag(&capability, &request.xfer_id);
    if !attach_tags_match(&expected, &request.tag) {
        refuse(send, AttachStreamStatus::Unauthorized).await?;
        anyhow::bail!("attachment stream tag did not verify");
    }

    let Some(chunk_count) = attach_chunk_count(size) else {
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
    let opened = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<(std::fs::File, FileStamp)> {
            let file = std::fs::File::open(&path)?;
            let stamp = FileStamp::of(&path, &file)?;
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
    let matches = |tree: &HashTree| tree.file_size == size && tree.root_hash == root;
    let mut hashed = attachment_tree(stamp.clone()).await;
    // A cached tree that disagrees with the grant may be describing bytes the
    // stamp could not tell apart from the current ones. One fresh read settles
    // it before the file is refused.
    if let Ok((tree, true)) = &hashed {
        if !matches(tree) {
            forget_cached_tree(&stamp, tree);
            hashed = attachment_tree(stamp).await;
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
            tokio::time::timeout(ATTACH_IO_TIMEOUT, send.write_all(slice)).await??;
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
        let (a, b) = tokio::join!(attachment_tree(stamp.clone()), attachment_tree(stamp));
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

    /// Idle trees go whether or not the cache is full.
    #[test]
    fn an_idle_cached_tree_is_not_served() {
        let stamp = FileStamp {
            path: temp_path("idle-entry"),
            size: 1,
            modified: None,
            object: (1, 2),
            changed: 3,
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
}
