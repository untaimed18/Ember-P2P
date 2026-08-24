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
use std::time::{Duration, Instant};

use super::channel::{
    xfer_block_count, XFER_BLOCK_SIZE, XFER_BLOCK_TIMEOUT_MS, XFER_OFFER_TTL_SECS, XFER_STALL_SECS,
    XFER_WINDOW_BLOCKS,
};

/// Progress is reported to the UI in steps this many percent apart.
///
/// A 100 MB file is a hundred thousand blocks; emitting an IPC message per
/// block would cost more than the transfer.
const PROGRESS_STEP_PCT: u8 = 1;

/// How much longer than the recipient's prompt the sender holds an unanswered
/// offer open. See [`SendState::is_stalled`].
const OFFER_GRACE_SECS: u64 = 30;

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
    handle: Option<std::fs::File>,
    reported_pct: u8,
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
            reported_pct: 0,
        }
    }

    /// Read one block, opening the file on first use and keeping the handle.
    pub fn read_block(&mut self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        if self.handle.is_none() {
            self.handle = Some(std::fs::File::open(&self.path)?);
        }
        let file = self
            .handle
            .as_mut()
            .expect("handle was just opened or already present");
        let mut buf = vec![0u8; len];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn bytes_sent(&self) -> u64 {
        self.sent_blocks
            .saturating_mul(XFER_BLOCK_SIZE as u64)
            .min(self.size)
    }

    /// Percentage to report, if it has moved a whole step since last time.
    pub fn progress_step(&mut self) -> Option<u8> {
        let total = self.total_blocks();
        let pct = self
            .sent_blocks
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(100)
            .min(100) as u8;
        if pct / PROGRESS_STEP_PCT > self.reported_pct / PROGRESS_STEP_PCT {
            self.reported_pct = pct;
            return Some(pct);
        }
        None
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
    file: std::fs::File,
    /// One bit per block.
    have: Vec<u64>,
    have_blocks: u64,
    total_blocks: u64,
    /// Blocks asked for, and when. Used to re-ask rather than to give up.
    inflight: HashMap<u64, Instant>,
    pub updated_at: Instant,
    reported_pct: u8,
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
            file,
            have: vec![0u64; words],
            have_blocks: 0,
            total_blocks,
            inflight: HashMap::new(),
            updated_at: Instant::now(),
            reported_pct: 0,
        }
    }

    pub fn bytes_received(&self) -> u64 {
        (self.have_blocks.saturating_mul(XFER_BLOCK_SIZE as u64)).min(self.size)
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
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(data)?;
        self.set(block);
        self.have_blocks = self.have_blocks.saturating_add(1);
        Ok(true)
    }

    pub fn is_complete(&self) -> bool {
        self.have_blocks >= self.total_blocks
    }

    pub fn finish(&mut self) -> std::io::Result<()> {
        self.file.flush()?;
        self.file.sync_all()
    }

    /// Percentage to report, if it has moved a whole step since last time.
    pub fn progress_step(&mut self) -> Option<u8> {
        let pct = self
            .have_blocks
            .saturating_mul(100)
            .checked_div(self.total_blocks)
            .unwrap_or(100) as u8;
        if pct / PROGRESS_STEP_PCT > self.reported_pct / PROGRESS_STEP_PCT || pct >= 100 {
            self.reported_pct = pct;
            return Some(pct);
        }
        None
    }

    /// Blocks to ask for now, grouped into contiguous runs.
    ///
    /// Keeps [`XFER_WINDOW_BLOCKS`] outstanding. A block whose request has
    /// gone unanswered past [`XFER_BLOCK_TIMEOUT_MS`] is eligible again, which
    /// is the whole of the loss recovery: nothing is lost, it is just late.
    pub fn next_requests(&mut self, now: Instant) -> Vec<(u64, u16)> {
        let timeout = Duration::from_millis(XFER_BLOCK_TIMEOUT_MS);
        self.inflight
            .retain(|_, at| now.saturating_duration_since(*at) <= timeout);
        let mut budget = XFER_WINDOW_BLOCKS.saturating_sub(self.inflight.len());
        if budget == 0 {
            return Vec::new();
        }
        let mut runs: Vec<(u64, u16)> = Vec::new();
        let mut run: Option<(u64, u16)> = None;
        for block in 0..self.total_blocks {
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
        let state = RecvState::new(
            [1u8; 16],
            [2u8; 32],
            [3u8; 32],
            "x.bin".into(),
            size,
            [0u8; 32],
            part,
            dir.join("x.bin"),
            file,
        );
        (state, TempDir(dir))
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
