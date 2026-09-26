//! Ember Transfer: one member hands a file to one other member.
//!
//! This is the first working piece of the Ember transfer system. It carries
//! files between two people who met in a channel, over the authenticated
//! Noise/UDP session the room already gives them, and it is deliberately
//! nothing like the broadcast attachment path it replaced:
//!
//! - **Addressed, not flooded.** Every frame names one recipient. Asking for
//!   a file costs the room nothing.
//! - **Accepted before it starts.** No bytes move until the recipient says
//!   yes, so nobody has files pushed onto their disk.
//! - **Receiver-driven.** The receiver asks for the blocks it is missing and
//!   the sender only answers. That is the flow control, and it is also why a
//!   dropped block is simply asked for again instead of ending the transfer.
//! - **Authenticated to the pair.** Every frame carries a tag under a key only
//!   the two ends can derive, so a third member of the room cannot put either
//!   name on a transfer frame even though they hold the same content key. See
//!   `channel::derive_xfer_key`.
//!
//! The state machine here is deliberately transport-agnostic: it decides
//! *which* blocks to ask for and *which* to answer with, and knows nothing
//! about sockets. [`super::channel`] owns the wire format, and the network
//! task owns the sending. A later QUIC implementation should be able to keep
//! this file as-is.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::channel::{
    xfer_block_count, XFER_BLOCK_SIZE, XFER_BLOCK_TIMEOUT_MS, XFER_OFFER_TTL_SECS, XFER_STALL_SECS,
    XFER_WINDOW_BLOCKS,
};

/// Where finished room transfers land, beside `Downloads` and `Chat Files`
/// under the download folder. Not `Downloads`: that folder is shared by
/// default, and a file a member handed you in a room is not one you chose to
/// publish to the network.
pub const CHANNEL_FILES_DIR: &str = "Channel Files";

/// Progress is reported to the UI in steps this many percent apart.
///
/// A 2 GiB file is two million blocks; emitting an IPC message per
/// block would cost more than the transfer.
const PROGRESS_STEP_PCT: u8 = 1;

/// ...and at least this often while bytes are moving, however little. The UI
/// works out the transfer speed from successive reports, and a percent of a
/// large file on a slow link can be minutes apart.
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_secs(1);

/// When a transfer's progress is next worth telling the UI.
#[derive(Default)]
struct ProgressReporter {
    pct: u8,
    bytes: u64,
    at: Option<Instant>,
}

impl ProgressReporter {
    /// `Some(pct)` when a whole step has passed, when a second has passed with
    /// bytes moved, or on `always`.
    fn due(&mut self, pct: u8, bytes: u64, always: bool) -> Option<u8> {
        let stepped = pct / PROGRESS_STEP_PCT > self.pct / PROGRESS_STEP_PCT;
        let timely = bytes > self.bytes
            && self.at.is_none_or(|at| at.elapsed() >= PROGRESS_MIN_INTERVAL);
        if !(stepped || timely || always) {
            return None;
        }
        self.pct = self.pct.max(pct);
        self.bytes = bytes;
        self.at = Some(Instant::now());
        Some(pct)
    }
}

/// How much longer than the recipient's prompt the sender holds an unanswered
/// offer open. See [`SendState::is_stalled`].
const OFFER_GRACE_SECS: u64 = 30;

/// A transfer the QUIC accept loop may serve as a stream.
///
/// Kept apart from [`SendState`] because the accept loop runs on its own task
/// and cannot reach `NetworkState`. The event loop keeps the map in step with
/// `xfer_send`, so a transfer that ends stops being servable within a tick.
pub struct StreamGrant {
    /// The member the file was offered to. The accept loop compares this with
    /// the key the dialer's certificate proved, never with anything it says.
    pub peer: [u8; 32],
    pub path: PathBuf,
    pub size: u64,
    pub root: [u8; 32],
    /// See `channel::derive_xfer_stream_capability`.
    pub capability: [u8; 32],
    pub progress: Arc<StreamProgress>,
}

/// How far a served stream has got, written by the accept loop and read back
/// by the event loop for the progress bar and the stall timer.
#[derive(Default)]
pub struct StreamProgress {
    /// Absolute bytes handed to the stream.
    pub position: AtomicU64,
    /// A stream has opened for the transfer, which only its recipient can do
    /// after accepting — so it stands in for an accept that was lost.
    pub opened: AtomicBool,
}

pub type StreamGrants = Arc<parking_lot::Mutex<HashMap<[u8; 16], StreamGrant>>>;

/// What to serve for `xfer_id` to the member whose key the QUIC handshake
/// proved: `(path, size, root, capability)`, or nothing when the transfer was
/// offered to someone else or has ended.
pub fn stream_grant_for(
    grants: &StreamGrants,
    xfer_id: &[u8; 16],
    peer: &[u8; 32],
) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])> {
    let map = grants.lock();
    let grant = map.get(xfer_id).filter(|g| g.peer == *peer)?;
    Some((grant.path.clone(), grant.size, grant.root, grant.capability))
}

/// Record how far a served stream has got. False once the grant is gone,
/// which ends a stream already running; a contended lock is not an ending,
/// and the next chunk looks again.
pub fn note_stream_served(
    grants: &StreamGrants,
    xfer_id: &[u8; 16],
    peer: &[u8; 32],
    position: u64,
) -> bool {
    use std::sync::atomic::Ordering;
    let Some(map) = grants.try_lock() else {
        return true;
    };
    match map.get(xfer_id).filter(|g| g.peer == *peer) {
        Some(grant) => {
            grant.progress.opened.store(true, Ordering::Relaxed);
            grant.progress.position.fetch_max(position, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// A file we have offered, or are sending.
pub struct SendState {
    pub channel_id: [u8; 16],
    pub peer: [u8; 32],
    /// Authenticator key for this transfer, derived once at setup rather than
    /// per frame — a static DH per block would be the most expensive thing in
    /// the send path. See `channel::derive_xfer_key`.
    pub key: [u8; 32],
    pub name: String,
    pub size: u64,
    pub path: PathBuf,
    /// The recipient has accepted. Until then nothing is read from disk.
    pub accepted: bool,
    /// Blocks asked for and not yet answered, oldest first.
    queue: VecDeque<u64>,
    /// Mirrors `queue` so a repeated request cannot enqueue the same block
    /// twice. A receiver re-asking after a timeout is normal, not abuse.
    queued: HashSet<u64>,
    pub sent_blocks: u64,
    pub updated_at: Instant,
    /// Held open once the transfer starts, rather than reopened per block.
    /// At the full block rate that would be nearly two hundred `open` calls a
    /// second for one file.
    ///
    /// Buffered for the same reason [`RecvState::file`] is: the receiver asks
    /// for a window of consecutive blocks, so one read syscall answers all of
    /// them instead of one per 1008-byte block on the network task.
    handle: Option<std::io::BufReader<std::fs::File>>,
    /// Where `handle`'s cursor is, when known. See [`RecvState::write_pos`] —
    /// seeking a `BufReader` discards its buffer, so skipping the redundant
    /// seek is what makes the buffering worth having.
    read_pos: Option<u64>,
    /// Bytes served over a QUIC stream, when the transfer went that way.
    streamed: u64,
    reporter: ProgressReporter,
}

impl SendState {
    pub fn new(
        channel_id: [u8; 16],
        peer: [u8; 32],
        key: [u8; 32],
        name: String,
        size: u64,
        path: PathBuf,
    ) -> Self {
        Self {
            channel_id,
            peer,
            key,
            name,
            size,
            path,
            accepted: false,
            queue: VecDeque::new(),
            queued: HashSet::new(),
            sent_blocks: 0,
            updated_at: Instant::now(),
            handle: None,
            read_pos: None,
            streamed: 0,
            reporter: ProgressReporter::default(),
        }
    }

    /// Record where a served stream has got to. A stream only opens after the
    /// recipient accepted, so it also counts as the accept. Only movement
    /// feeds the stall timer: this is called every tick while a stream is
    /// open, and one whose recipient vanished must still time out.
    pub fn note_streamed(&mut self, position: u64) {
        if !self.accepted {
            self.accepted = true;
            self.updated_at = Instant::now();
        }
        if position > self.streamed {
            self.streamed = position.min(self.size);
            self.updated_at = Instant::now();
        }
    }

    /// Read one block, opening the file on first use and keeping the handle.
    pub fn read_block(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        if self.handle.is_none() {
            self.handle = Some(std::io::BufReader::with_capacity(
                XFER_WINDOW_BLOCKS * XFER_BLOCK_SIZE,
                std::fs::File::open(&self.path)?,
            ));
            self.read_pos = Some(0);
        }
        let resuming_at = self.read_pos.take();
        let file = self
            .handle
            .as_mut()
            .expect("handle was just opened or already present");
        let mut buf = vec![0u8; len];
        if resuming_at != Some(offset) {
            file.seek(SeekFrom::Start(offset))?;
        }
        file.read_exact(&mut buf)?;
        self.read_pos = Some(offset + len as u64);
        Ok(buf)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.sent_blocks
            .saturating_mul(XFER_BLOCK_SIZE as u64)
            .max(self.streamed)
            .min(self.size)
    }

    /// Percentage to report, if it is due. See [`ProgressReporter::due`].
    pub fn progress_step(&mut self) -> Option<u8> {
        let bytes = self.bytes_sent();
        let pct = bytes
            .saturating_mul(100)
            .checked_div(self.size)
            .unwrap_or(100)
            .min(100) as u8;
        self.reporter.due(pct, bytes, false)
    }

    pub fn total_blocks(&self) -> u64 {
        xfer_block_count(self.size)
    }

    /// Take a request for `count` blocks starting at `start`.
    ///
    /// Out-of-range blocks are dropped rather than rejecting the whole run: a
    /// receiver that asks past the end of the file gets nothing back for those
    /// blocks, which is all the answer that request deserves. The queue is
    /// capped at one window so a peer cannot make us buffer without bound.
    pub fn enqueue(&mut self, start: u64, count: u16) {
        let total = self.total_blocks();
        for block in start..start.saturating_add(count as u64) {
            if block >= total || self.queued.contains(&block) {
                continue;
            }
            if self.queue.len() >= XFER_WINDOW_BLOCKS {
                break;
            }
            self.queue.push_back(block);
            self.queued.insert(block);
        }
        self.updated_at = Instant::now();
    }

    pub fn next_block(&mut self) -> Option<u64> {
        let block = self.queue.pop_front()?;
        self.queued.remove(&block);
        Some(block)
    }

    pub fn has_work(&self) -> bool {
        self.accepted && !self.queue.is_empty()
    }

    pub fn note_sent(&mut self) {
        self.sent_blocks = self.sent_blocks.saturating_add(1);
        self.updated_at = Instant::now();
    }

    /// Whether the peer has gone quiet for long enough to give up on.
    ///
    /// Measured from the last request *or* the last block we answered, so a
    /// slow but live receiver is never mistaken for a dead one.
    ///
    /// An offer nobody has answered yet gets the longer offer window instead.
    /// The stall timeout is about a transfer that has gone silent mid-flight;
    /// applying it to an unanswered offer would have this side give up while
    /// the prompt was still on the other person's screen, and their accept
    /// would then arrive to find nothing waiting for it.
    ///
    /// The grace margin keeps that ordering strict. Both ends run the same
    /// [`XFER_OFFER_TTL_SECS`], but the recipient's clock starts when the
    /// offer lands rather than when it was sent, so without it an accept at
    /// the very edge of the window could still race the sender's cleanup.
    pub fn is_stalled(&self, now: Instant) -> bool {
        let window = if self.accepted {
            Duration::from_secs(XFER_STALL_SECS)
        } else {
            Duration::from_secs(XFER_OFFER_TTL_SECS.max(0) as u64 + OFFER_GRACE_SECS)
        };
        now.saturating_duration_since(self.updated_at) > window
    }
}

/// A file we have accepted and are pulling in.
pub struct RecvState {
    pub channel_id: [u8; 16],
    pub peer: [u8; 32],
    /// Authenticator key for this transfer. See `channel::derive_xfer_key`.
    pub key: [u8; 32],
    pub name: String,
    pub size: u64,
    pub root: [u8; 32],
    /// Where bytes land while the transfer runs.
    pub part_path: PathBuf,
    /// Where the finished file is moved to.
    pub final_path: PathBuf,
    /// The approved download root both of the above must stay inside.
    ///
    /// Carried so completion can re-verify rather than renaming by pathname:
    /// the `.part` name is derived from a wire-supplied `xfer_id`, so the paths
    /// here are partly peer-chosen, and the download root's approval can be
    /// revoked between the offer and the last block.
    pub download_root: PathBuf,
    /// What the `.part` was when it was opened, so a swap underneath the
    /// transfer is refused at completion instead of moved into place.
    pub part_identity: crate::security::filesystem::ObjectIdentity,
    /// Buffered so a window's worth of blocks costs one write syscall instead
    /// of one each. Blocks are 1008 bytes and arrive at up to
    /// `XFER_BLOCKS_OUT_PER_SEC` across `XFER_MAX_ACTIVE` transfers, and this
    /// runs on the network task — against a download folder on a share, a
    /// cold disk, or one a virus scanner is watching, a syscall per block was
    /// enough to starve UDP receive.
    file: std::io::BufWriter<std::fs::File>,
    /// Where `file`'s cursor is, when known. Blocks normally arrive in order,
    /// so tracking this lets the common case skip the `seek` that would
    /// otherwise flush the buffer on every block and undo the buffering.
    /// `None` means "unknown, seek before writing".
    write_pos: Option<u64>,
    /// One bit per block.
    have: Vec<u64>,
    have_blocks: u64,
    total_blocks: u64,
    /// Blocks asked for, and when. Used to re-ask rather than to give up.
    inflight: HashMap<u64, Instant>,
    pub updated_at: Instant,
    /// A QUIC stream is writing the part file. No blocks are asked for until
    /// it ends: it writes through its own handle onto the same file cursor, so
    /// the two must never write at once.
    streaming: bool,
    /// Verified bytes the stream has written.
    streamed: u64,
    /// Every chunk a stream wrote was checked against the offered root, so
    /// completion need not read the whole file back to hash it.
    pub stream_verified: bool,
    /// No block below this is missing, so [`Self::next_requests`] starts
    /// here rather than walking every block already received each tick.
    first_missing: u64,
    reporter: ProgressReporter,
}

impl RecvState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_id: [u8; 16],
        peer: [u8; 32],
        key: [u8; 32],
        name: String,
        size: u64,
        root: [u8; 32],
        part_path: PathBuf,
        final_path: PathBuf,
        download_root: PathBuf,
        part_identity: crate::security::filesystem::ObjectIdentity,
        file: std::fs::File,
    ) -> Self {
        let total_blocks = xfer_block_count(size);
        let words = (total_blocks as usize).div_ceil(64).max(1);
        Self {
            channel_id,
            peer,
            key,
            name,
            size,
            root,
            part_path,
            final_path,
            download_root,
            part_identity,
            file: std::io::BufWriter::with_capacity(
                XFER_WINDOW_BLOCKS * XFER_BLOCK_SIZE,
                file,
            ),
            write_pos: None,
            have: vec![0u64; words],
            have_blocks: 0,
            total_blocks,
            inflight: HashMap::new(),
            updated_at: Instant::now(),
            streaming: false,
            streamed: 0,
            stream_verified: false,
            first_missing: 0,
            reporter: ProgressReporter::default(),
        }
    }

    fn advance_first_missing(&mut self) {
        while self.first_missing < self.total_blocks && self.has(self.first_missing) {
            self.first_missing += 1;
        }
    }

    pub fn bytes_received(&self) -> u64 {
        self.have_blocks
            .saturating_mul(XFER_BLOCK_SIZE as u64)
            .max(self.streamed)
            .min(self.size)
    }

    /// A clone of the part file's handle for a stream to write through.
    ///
    /// Flushed first so nothing buffered here lands on top of it later. The
    /// clone shares this handle's cursor, which is why block requests stop
    /// while streaming.
    pub fn stream_handle(&mut self) -> std::io::Result<std::fs::File> {
        self.file.flush()?;
        self.write_pos = None;
        self.file.get_ref().try_clone()
    }

    pub fn set_streaming(&mut self, streaming: bool) {
        self.streaming = streaming;
        self.updated_at = Instant::now();
    }

    /// Verified bytes a running stream has written, for the progress bar and
    /// the stall timer.
    pub fn note_streamed(&mut self, verified: u64) {
        if verified > self.streamed {
            self.streamed = verified.min(self.size);
            self.updated_at = Instant::now();
        }
    }

    /// Take over what a stream verified before it stopped, so the block
    /// protocol asks only for the rest. `verified` is a prefix of the file;
    /// a block counts only if it lies wholly inside it.
    pub fn adopt_verified_prefix(&mut self, verified: u64) {
        let verified = verified.min(self.size);
        let whole = verified / XFER_BLOCK_SIZE as u64;
        let tail_done = verified == self.size && self.total_blocks > 0;
        let upto = if tail_done { self.total_blocks } else { whole.min(self.total_blocks) };
        for block in 0..upto {
            if !self.has(block) {
                self.set(block);
                self.have_blocks = self.have_blocks.saturating_add(1);
            }
        }
        self.advance_first_missing();
        self.inflight.clear();
        self.write_pos = None;
        self.updated_at = Instant::now();
    }

    fn has(&self, block: u64) -> bool {
        let (word, bit) = ((block / 64) as usize, block % 64);
        self.have.get(word).is_some_and(|w| w & (1u64 << bit) != 0)
    }

    fn set(&mut self, block: u64) {
        let (word, bit) = ((block / 64) as usize, block % 64);
        if let Some(w) = self.have.get_mut(word) {
            *w |= 1u64 << bit;
        }
    }

    /// Store one block's payload. Returns whether it was new.
    ///
    /// A duplicate is written off as normal rather than treated as an error:
    /// re-requesting after a timeout races with the original arriving late,
    /// and both copies are identical.
    pub fn write_block(&mut self, offset: u64, data: &[u8]) -> std::io::Result<bool> {
        // A late answer to a request made before the stream took over. The
        // stream writes the same bytes, and writing these on the shared cursor
        // while it runs could land either one at the wrong offset.
        if self.streaming {
            return Ok(false);
        }
        if data.is_empty() || offset >= self.size {
            return Ok(false);
        }
        if !offset.is_multiple_of(XFER_BLOCK_SIZE as u64) {
            return Ok(false);
        }
        let end = offset.saturating_add(data.len() as u64);
        if end > self.size {
            return Ok(false);
        }
        let block = offset / XFER_BLOCK_SIZE as u64;
        // The last block is short; every other one has to be full, or the
        // bitmap would count a partial write as a complete block.
        let expected = if block + 1 == self.total_blocks {
            (self.size - offset) as usize
        } else {
            XFER_BLOCK_SIZE
        };
        if data.len() != expected {
            return Ok(false);
        }
        self.inflight.remove(&block);
        self.updated_at = Instant::now();
        if self.has(block) {
            return Ok(false);
        }
        // Cleared first so any failure below leaves the cursor unknown rather
        // than claimed: a half-applied seek or write must force a real seek
        // next time, never let the next block land at a guessed offset.
        let resuming_at = self.write_pos.take();
        if resuming_at != Some(offset) {
            self.file.seek(SeekFrom::Start(offset))?;
        }
        self.file.write_all(data)?;
        self.write_pos = Some(offset + data.len() as u64);
        self.set(block);
        self.have_blocks = self.have_blocks.saturating_add(1);
        self.advance_first_missing();
        Ok(true)
    }

    pub fn is_complete(&self) -> bool {
        self.have_blocks >= self.total_blocks
    }

    pub fn finish(&mut self) -> std::io::Result<()> {
        // `flush` empties the buffer into the file; `sync_all` on the inner
        // handle then commits it. The verify pass that follows reopens the
        // part file by path, so the flush has to happen before it, not just
        // whenever the writer is dropped.
        self.file.flush()?;
        self.write_pos = None;
        self.file.get_ref().sync_all()
    }

    /// Percentage to report, if it is due. See [`ProgressReporter::due`].
    pub fn progress_step(&mut self) -> Option<u8> {
        let bytes = self.bytes_received();
        let pct = bytes
            .saturating_mul(100)
            .checked_div(self.size)
            .unwrap_or(100)
            .min(100) as u8;
        self.reporter.due(pct, bytes, pct >= 100)
    }

    /// Blocks to ask for now, grouped into contiguous runs.
    ///
    /// Keeps [`XFER_WINDOW_BLOCKS`] outstanding. A block whose request has
    /// gone unanswered past [`XFER_BLOCK_TIMEOUT_MS`] is eligible again, which
    /// is the whole of the loss recovery: nothing is lost, it is just late.
    pub fn next_requests(&mut self, now: Instant) -> Vec<(u64, u16)> {
        if self.streaming {
            return Vec::new();
        }
        let timeout = Duration::from_millis(XFER_BLOCK_TIMEOUT_MS);
        self.inflight
            .retain(|_, at| now.saturating_duration_since(*at) <= timeout);
        let mut budget = XFER_WINDOW_BLOCKS.saturating_sub(self.inflight.len());
        if budget == 0 {
            return Vec::new();
        }
        let mut runs: Vec<(u64, u16)> = Vec::new();
        let mut run: Option<(u64, u16)> = None;
        for block in self.first_missing..self.total_blocks {
            if budget == 0 {
                break;
            }
            if self.has(block) || self.inflight.contains_key(&block) {
                if let Some(pending) = run.take() {
                    runs.push(pending);
                }
                continue;
            }
            self.inflight.insert(block, now);
            budget -= 1;
            run = match run {
                Some((start, count)) if count < XFER_WINDOW_BLOCKS as u16 => {
                    Some((start, count + 1))
                }
                Some(pending) => {
                    runs.push(pending);
                    Some((block, 1))
                }
                None => Some((block, 1)),
            };
        }
        if let Some(pending) = run {
            runs.push(pending);
        }
        runs
    }

    pub fn is_stalled(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.updated_at) > Duration::from_secs(XFER_STALL_SECS)
    }
}

/// An offer waiting on the user to accept or decline.
pub struct PendingOffer {
    pub channel_id: [u8; 16],
    pub peer: [u8; 32],
    /// Authenticator key for this transfer. See `channel::derive_xfer_key`.
    pub key: [u8; 32],
    pub name: String,
    pub size: u64,
    pub root: [u8; 32],
    pub received_at: Instant,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Removes its directory when the test drops it, so a failing assert
    /// cannot leave stray part files behind in the temp dir.
    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_recv(size: u64) -> (RecvState, TempDir) {
        let dir = std::env::temp_dir().join(format!(
            "ember-xfer-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let part = dir.join("x.part");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&part)
            .unwrap();
        let part_identity =
            crate::security::filesystem::object_identity_from_file(&file).unwrap();
        let state = RecvState::new(
            [1u8; 16],
            [2u8; 32],
            [3u8; 32],
            "x.bin".into(),
            size,
            [0u8; 32],
            part.clone(),
            dir.join("x.bin"),
            dir.clone(),
            part_identity,
            file,
        );
        (state, TempDir(dir))
    }

    /// While a stream writes the part file, nothing is asked for and a late
    /// block is dropped rather than written over it.
    #[test]
    fn a_streaming_receive_asks_for_nothing_and_writes_no_blocks() {
        let size = XFER_BLOCK_SIZE as u64 * 3;
        let (mut recv, _dir) = temp_recv(size);
        recv.set_streaming(true);
        assert!(recv.next_requests(Instant::now()).is_empty());
        assert!(!recv
            .write_block(0, &block_bytes(0, XFER_BLOCK_SIZE))
            .unwrap());
        assert_eq!(recv.bytes_received(), 0);
        recv.note_streamed(XFER_BLOCK_SIZE as u64 + 10);
        assert_eq!(recv.bytes_received(), XFER_BLOCK_SIZE as u64 + 10);
        recv.set_streaming(false);
        assert!(!recv.next_requests(Instant::now()).is_empty());
    }

    /// A stream that stopped partway hands its verified prefix over: whole
    /// blocks inside it count as received, the one it cut through does not.
    #[test]
    fn a_verified_prefix_becomes_received_blocks() {
        let size = XFER_BLOCK_SIZE as u64 * 4 + 7;
        let (mut recv, _dir) = temp_recv(size);
        recv.adopt_verified_prefix(XFER_BLOCK_SIZE as u64 * 2 + 100);
        assert_eq!(recv.have_blocks, 2);
        let runs = recv.next_requests(Instant::now());
        assert_eq!(runs.first().map(|r| r.0), Some(2), "asks from the block it cut through");

        let (mut whole, _dir2) = temp_recv(size);
        whole.adopt_verified_prefix(size);
        assert!(whole.is_complete(), "the short tail counts once the prefix is the file");
    }

    fn grant_table(peer: [u8; 32]) -> StreamGrants {
        let grants = StreamGrants::default();
        grants.lock().insert(
            [9u8; 16],
            StreamGrant {
                peer,
                path: PathBuf::from("offered.bin"),
                size: 10,
                root: [4u8; 32],
                capability: [5u8; 32],
                progress: Default::default(),
            },
        );
        grants
    }

    /// Only the member the file was offered to is served, and only while the
    /// transfer holds a grant.
    #[test]
    fn a_stream_grant_is_served_only_to_its_member() {
        let grants = grant_table([1u8; 32]);
        assert_eq!(
            stream_grant_for(&grants, &[9u8; 16], &[1u8; 32]),
            Some((PathBuf::from("offered.bin"), 10, [4u8; 32], [5u8; 32]))
        );
        assert!(stream_grant_for(&grants, &[9u8; 16], &[2u8; 32]).is_none());
        assert!(stream_grant_for(&grants, &[8u8; 16], &[1u8; 32]).is_none());
    }

    #[test]
    fn serving_records_progress_and_stops_once_the_grant_is_gone() {
        use std::sync::atomic::Ordering;
        let grants = grant_table([1u8; 32]);
        assert!(!note_stream_served(&grants, &[9u8; 16], &[2u8; 32], 4));
        assert!(note_stream_served(&grants, &[9u8; 16], &[1u8; 32], 6));
        assert!(note_stream_served(&grants, &[9u8; 16], &[1u8; 32], 3), "never walks back");
        {
            let map = grants.lock();
            let progress = &map[&[9u8; 16]].progress;
            assert!(progress.opened.load(Ordering::Relaxed));
            assert_eq!(progress.position.load(Ordering::Relaxed), 6);
        }
        grants.lock().clear();
        assert!(!note_stream_served(&grants, &[9u8; 16], &[1u8; 32], 8));
    }

    /// Requests start at the first block still missing, and a block that
    /// arrived out of order does not move that point past the gap before it.
    #[test]
    fn requests_start_at_the_first_missing_block() {
        let size = XFER_BLOCK_SIZE as u64 * 6;
        let (mut recv, _dir) = temp_recv(size);
        for block in [0u64, 1, 3] {
            let offset = block * XFER_BLOCK_SIZE as u64;
            assert!(recv.write_block(offset, &block_bytes(block, XFER_BLOCK_SIZE)).unwrap());
        }
        assert_eq!(recv.first_missing, 2);
        let runs = recv.next_requests(Instant::now());
        assert_eq!(runs, vec![(2, 1), (4, 2)]);
        let offset = 2 * XFER_BLOCK_SIZE as u64;
        assert!(recv.write_block(offset, &block_bytes(2, XFER_BLOCK_SIZE)).unwrap());
        assert_eq!(recv.first_missing, 4, "skips the block that was already there");
    }

    #[test]
    fn a_served_stream_counts_as_accepted_progress() {
        let (mut send, _dir, _) = temp_send(4);
        assert!(!send.accepted);
        send.note_streamed(XFER_BLOCK_SIZE as u64 * 2);
        assert!(send.accepted);
        assert_eq!(send.bytes_sent(), XFER_BLOCK_SIZE as u64 * 2);
        assert_eq!(send.progress_step(), Some(50));
    }

    /// Within a percent, progress still reaches the UI once a second while
    /// bytes are moving — the speed shown is worked out from these reports —
    /// and never when nothing moved.
    #[test]
    fn progress_is_reported_each_second_while_bytes_move() {
        let mut reporter = ProgressReporter::default();
        assert_eq!(reporter.due(0, 10, false), Some(0));
        assert_eq!(reporter.due(0, 20, false), None, "not twice inside a second");
        reporter.at = Instant::now().checked_sub(Duration::from_millis(1_100));
        assert_eq!(reporter.due(0, 30, false), Some(0));
        reporter.at = Instant::now().checked_sub(Duration::from_millis(1_100));
        assert_eq!(reporter.due(0, 30, false), None, "nothing moved");
        assert_eq!(reporter.due(1, 31, false), Some(1), "a whole step is reported at once");
    }

    /// A stream that stopped moving is not kept alive by being looked at.
    #[test]
    fn a_stuck_stream_still_stalls() {
        let (mut send, _dir, _) = temp_send(4);
        send.note_streamed(100);
        send.updated_at = Instant::now()
            .checked_sub(Duration::from_secs(XFER_STALL_SECS + 1))
            .expect("clock far enough along");
        send.note_streamed(100);
        assert!(send.is_stalled(Instant::now()));
        send.note_streamed(200);
        assert!(!send.is_stalled(Instant::now()));
    }

    /// Position-dependent bytes, so a block written or read at the wrong
    /// offset cannot coincidentally match the expected content.
    fn block_bytes(block: u64, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| (block as u8).wrapping_mul(31).wrapping_add(i as u8))
            .collect()
    }

    fn temp_send(blocks: u64) -> (SendState, TempDir, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!(
            "ember-xfer-send-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("src.bin");
        let mut contents = Vec::new();
        for block in 0..blocks {
            contents.extend_from_slice(&block_bytes(block, XFER_BLOCK_SIZE));
        }
        std::fs::write(&path, &contents).unwrap();
        let state = SendState::new(
            [1u8; 16],
            [2u8; 32],
            [3u8; 32],
            "src.bin".into(),
            contents.len() as u64,
            path,
        );
        (state, TempDir(dir), contents)
    }

    /// The sequential case, which is the one that skips the `seek` so the
    /// buffering actually batches.
    #[test]
    fn sequential_buffered_writes_reproduce_the_file() {
        let size = XFER_BLOCK_SIZE as u64 * 5;
        let (mut recv, _dir) = temp_recv(size);
        let mut expected = Vec::new();
        for block in 0..5u64 {
            let data = block_bytes(block, XFER_BLOCK_SIZE);
            assert!(recv
                .write_block(block * XFER_BLOCK_SIZE as u64, &data)
                .unwrap());
            expected.extend_from_slice(&data);
        }
        assert!(recv.is_complete());
        recv.finish().unwrap();
        assert_eq!(std::fs::read(&recv.part_path).unwrap(), expected);
    }

    /// Out-of-order arrival, including a short final block. Skipping a
    /// redundant seek must never let a jump write at the previous cursor.
    #[test]
    fn out_of_order_buffered_writes_land_at_their_offsets() {
        let size = XFER_BLOCK_SIZE as u64 * 2 + 100;
        let (mut recv, _dir) = temp_recv(size);
        let b0 = block_bytes(0, XFER_BLOCK_SIZE);
        let b1 = block_bytes(1, XFER_BLOCK_SIZE);
        let b2 = block_bytes(2, 100);

        assert!(recv.write_block(XFER_BLOCK_SIZE as u64, &b1).unwrap());
        assert!(recv.write_block(0, &b0).unwrap());
        assert!(recv.write_block(XFER_BLOCK_SIZE as u64 * 2, &b2).unwrap());
        // A block already held is refused, and must leave the cursor alone.
        assert!(!recv.write_block(0, &b0).unwrap());
        assert!(recv.is_complete());
        recv.finish().unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(&b0);
        expected.extend_from_slice(&b1);
        expected.extend_from_slice(&b2);
        assert_eq!(std::fs::read(&recv.part_path).unwrap(), expected);
    }

    #[test]
    fn buffered_reads_return_the_right_block_in_any_order() {
        let (mut send, _dir, contents) = temp_send(6);
        let at = |block: u64| {
            let start = (block * XFER_BLOCK_SIZE as u64) as usize;
            contents[start..start + XFER_BLOCK_SIZE].to_vec()
        };
        // Sequential first: the reads that reuse the buffer without seeking.
        for block in 0..3u64 {
            let got = send
                .read_block(block * XFER_BLOCK_SIZE as u64, XFER_BLOCK_SIZE)
                .unwrap();
            assert_eq!(got, at(block), "sequential block {block}");
        }
        // Then jump around, which has to invalidate the buffer and seek.
        for block in [5u64, 0, 4, 1] {
            let got = send
                .read_block(block * XFER_BLOCK_SIZE as u64, XFER_BLOCK_SIZE)
                .unwrap();
            assert_eq!(got, at(block), "seeking block {block}");
        }
    }

    #[test]
    fn requests_cover_every_block_and_respect_the_window() {
        let (mut recv, _dir) = temp_recv(XFER_BLOCK_SIZE as u64 * 200);
        let now = Instant::now();
        let runs = recv.next_requests(now);
        let asked: u64 = runs.iter().map(|(_, count)| *count as u64).sum();
        assert_eq!(asked, XFER_WINDOW_BLOCKS as u64);
        // Contiguous from zero, so one run is enough to describe them.
        assert_eq!(runs, vec![(0, XFER_WINDOW_BLOCKS as u16)]);

        // Nothing more until something is answered or times out.
        assert!(recv.next_requests(now).is_empty());
    }

    #[test]
    fn an_unanswered_block_is_asked_for_again() {
        let (mut recv, _dir) = temp_recv(XFER_BLOCK_SIZE as u64 * 4);
        let now = Instant::now();
        assert_eq!(recv.next_requests(now), vec![(0, 4)]);
        assert!(recv.next_requests(now).is_empty());

        let later = now + Duration::from_millis(XFER_BLOCK_TIMEOUT_MS + 1);
        assert_eq!(recv.next_requests(later), vec![(0, 4)]);
    }

    #[test]
    fn received_blocks_are_not_asked_for_again() {
        let (mut recv, _dir) = temp_recv(XFER_BLOCK_SIZE as u64 * 4);
        let now = Instant::now();
        let _ = recv.next_requests(now);
        let block = vec![7u8; XFER_BLOCK_SIZE];
        assert!(recv.write_block(XFER_BLOCK_SIZE as u64, &block).unwrap());

        let later = now + Duration::from_millis(XFER_BLOCK_TIMEOUT_MS + 1);
        let runs = recv.next_requests(later);
        // Block 1 is held, so the run splits around it.
        assert_eq!(runs, vec![(0, 1), (2, 2)]);
    }

    #[test]
    fn a_duplicate_block_is_accepted_but_counted_once() {
        let (mut recv, _dir) = temp_recv(XFER_BLOCK_SIZE as u64 * 2);
        let block = vec![3u8; XFER_BLOCK_SIZE];
        assert!(recv.write_block(0, &block).unwrap());
        assert!(!recv.write_block(0, &block).unwrap());
        assert_eq!(recv.have_blocks, 1);
    }

    #[test]
    fn misaligned_or_wrong_length_blocks_are_refused() {
        let (mut recv, _dir) = temp_recv(XFER_BLOCK_SIZE as u64 * 2);
        let full = vec![1u8; XFER_BLOCK_SIZE];
        // Not on a block boundary.
        assert!(!recv.write_block(1, &full).unwrap());
        // Short, but not the final block.
        assert!(!recv.write_block(0, &full[..10]).unwrap());
        // Past the end.
        assert!(!recv.write_block(XFER_BLOCK_SIZE as u64 * 2, &full).unwrap());
        assert_eq!(recv.have_blocks, 0);
    }

    #[test]
    fn the_short_final_block_is_accepted_at_its_real_length() {
        let size = XFER_BLOCK_SIZE as u64 + 10;
        let (mut recv, _dir) = temp_recv(size);
        assert!(recv.write_block(0, &vec![1u8; XFER_BLOCK_SIZE]).unwrap());
        // A full-length write for the tail would run past the file.
        assert!(!recv
            .write_block(XFER_BLOCK_SIZE as u64, &vec![2u8; XFER_BLOCK_SIZE])
            .unwrap());
        assert!(recv
            .write_block(XFER_BLOCK_SIZE as u64, &[2u8; 10])
            .unwrap());
        assert!(recv.is_complete());
    }

    #[test]
    fn completion_writes_every_byte_in_order() {
        let size = XFER_BLOCK_SIZE as u64 * 3 + 7;
        let (mut recv, _dir) = temp_recv(size);
        let mut expected = Vec::new();
        // Out of order on purpose: offsets, not arrival order, decide layout.
        for block in [2u64, 0, 3, 1] {
            let offset = block * XFER_BLOCK_SIZE as u64;
            let len = ((size - offset) as usize).min(XFER_BLOCK_SIZE);
            let data = vec![block as u8; len];
            assert!(recv.write_block(offset, &data).unwrap());
        }
        for block in 0..4u64 {
            let offset = block * XFER_BLOCK_SIZE as u64;
            let len = ((size - offset) as usize).min(XFER_BLOCK_SIZE);
            expected.extend(std::iter::repeat_n(block as u8, len));
        }
        recv.finish().unwrap();
        let on_disk = std::fs::read(&recv.part_path).unwrap();
        assert_eq!(on_disk, expected);
        assert!(recv.is_complete());
    }

    #[test]
    fn the_send_queue_ignores_repeats_and_out_of_range_blocks() {
        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "f".into(),
            XFER_BLOCK_SIZE as u64 * 3,
            PathBuf::from("f"),
        );
        send.accepted = true;
        send.enqueue(0, 3);
        send.enqueue(0, 3);
        // Past the end of the file, so nothing is queued for it.
        send.enqueue(99, 4);
        assert_eq!(send.next_block(), Some(0));
        assert_eq!(send.next_block(), Some(1));
        assert_eq!(send.next_block(), Some(2));
        assert_eq!(send.next_block(), None);
        assert!(!send.has_work());
    }

    #[test]
    fn the_send_queue_is_capped_at_one_window() {
        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "f".into(),
            XFER_BLOCK_SIZE as u64 * 10_000,
            PathBuf::from("f"),
        );
        for start in 0..100u64 {
            send.enqueue(start * 64, 64);
        }
        let mut drained = 0;
        while send.next_block().is_some() {
            drained += 1;
        }
        assert_eq!(drained, XFER_WINDOW_BLOCKS);
    }

    /// The bug this pins: an unanswered offer used to age out on the 90s
    /// stall timer while the recipient's prompt lived for 300s, so a slow
    /// "yes" arrived to find the sender had already given up.
    #[test]
    fn an_unanswered_offer_outlives_the_stall_timeout() {
        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "f".into(),
            XFER_BLOCK_SIZE as u64,
            PathBuf::from("f"),
        );
        let now = send.updated_at;
        let past_stall = now + Duration::from_secs(XFER_STALL_SECS + 1);
        assert!(
            !send.is_stalled(past_stall),
            "an offer still waiting for an answer must not be dropped early"
        );
        // Still held at the recipient's own expiry, so a last-moment accept
        // cannot land on a sender that has already cleaned up.
        assert!(!send.is_stalled(now + Duration::from_secs(XFER_OFFER_TTL_SECS as u64)));
        let past_offer =
            now + Duration::from_secs(XFER_OFFER_TTL_SECS as u64 + OFFER_GRACE_SECS + 1);
        assert!(send.is_stalled(past_offer));

        // Once accepted, the tighter stall window applies again.
        send.accepted = true;
        assert!(send.is_stalled(past_stall));
    }

    #[test]
    fn the_source_file_is_opened_once_and_read_by_offset() {
        let dir = std::env::temp_dir().join(format!(
            "ember-xfer-read-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let guard = TempDir(dir.clone());
        let path = dir.join("src.bin");
        let mut body = vec![1u8; XFER_BLOCK_SIZE];
        body.extend(std::iter::repeat_n(2u8, 10));
        std::fs::write(&path, &body).unwrap();

        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "src.bin".into(),
            body.len() as u64,
            path,
        );
        assert_eq!(send.read_block(0, XFER_BLOCK_SIZE).unwrap(), vec![1u8; XFER_BLOCK_SIZE]);
        // Second read reuses the handle and still seeks correctly.
        assert_eq!(
            send.read_block(XFER_BLOCK_SIZE as u64, 10).unwrap(),
            vec![2u8; 10]
        );
        // And re-reading an earlier block seeks backwards rather than
        // continuing from wherever the last read left off.
        assert_eq!(send.read_block(0, 4).unwrap(), vec![1u8; 4]);
        drop(guard);
    }

    #[test]
    fn send_progress_only_reports_when_it_moves() {
        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "f".into(),
            XFER_BLOCK_SIZE as u64 * 100,
            PathBuf::from("f"),
        );
        assert_eq!(send.progress_step(), None);
        send.note_sent();
        assert_eq!(send.progress_step(), Some(1));
        assert_eq!(send.progress_step(), None);
        for _ in 0..99 {
            send.note_sent();
        }
        assert_eq!(send.progress_step(), Some(100));
    }

    #[test]
    fn nothing_is_sent_before_the_offer_is_accepted() {
        let mut send = SendState::new(
            [0u8; 16],
            [0u8; 32],
            [3u8; 32],
            "f".into(),
            XFER_BLOCK_SIZE as u64,
            PathBuf::from("f"),
        );
        send.enqueue(0, 1);
        assert!(!send.has_work());
        send.accepted = true;
        assert!(send.has_work());
    }
}
