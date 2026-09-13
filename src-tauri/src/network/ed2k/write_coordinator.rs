//! Per-file write coordinator for ED2K downloads.
//!
//! Background
//! ----------
//! The previous design wrapped a single `std::fs::File` in
//! `Arc<std::sync::Mutex<_>>` and, for every received block, spawned a fresh
//! `tokio::task::spawn_blocking` that locked the mutex, seeked, and wrote.
//! With multiple concurrent sources this serialized all disk I/O on one
//! mutex, churned the blocking thread pool, and held the file lock during
//! `sync_data()` and verification reads — directly stalling other sources.
//!
//! `PartFileWriter` replaces that with one **dedicated worker thread** per
//! file that owns the `File`, processes a bounded `mpsc` channel of
//! operations, and replies via `oneshot`. Callers `await` the response.
//! The `File` is never shared, so there is no per-block lock contention,
//! and CPU-bound work that pairs naturally with the I/O (MD4 of a part
//! immediately after the verification read) executes on the same worker
//! thread, so the async runtime is never blocked on hashing.
//!
//! eMule wire-protocol compatibility is unaffected — this only changes how
//! we move bytes into the on-disk `.part` file.

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Weak};

use tokio::sync::{mpsc, oneshot, Semaphore};

/// Bounded operation queue per writer. Generous so byte-arrival bursts from
/// multiple sources don't backpressure the network loop, but bounded so a
/// stuck disk eventually exerts backpressure rather than letting the queue
/// grow unbounded.
const WRITER_QUEUE_CAPACITY: usize = 4096;
const MAX_WRITER_IO_BYTES: usize = 16 * 1024 * 1024;
/// How often the discard watchdog re-reads the flag. Only has to beat the
/// `.part` delete retry budget in `cleanup_partial_files` (6 x 500 ms), so it
/// is deliberately coarse: this is one tokio timer per active download, not a
/// thread, and an idle writer must not wake up on a fast tick.
const DISCARD_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(250);

/// One live writer per `.part` path, across download generations.
///
/// Every start path aborts the previous worker before spawning a new one, but
/// `abort()` only unwinds the *task*: the worker thread it owns keeps the file
/// handle until it has drained its queue and run its trailing fsync, and most
/// of those start paths do not wait for that at all (the KAD-disconnect path
/// drains `download_handles` entirely, so the next start does not even see a
/// handle to wait on). Two writer threads on one `.part` interleave seeks and
/// writes, so a block the old generation still had queued can land on top of
/// one the new generation just wrote — a torn part that only surfaces later as
/// an MD4/AICH mismatch and a re-download.
///
/// The permit is taken before the file is opened and released by the worker
/// thread itself, after it has closed its handle. That makes the hand-off
/// ordered no matter which start path spawned the new generation, so callers
/// do not each have to re-implement the wait.
static PART_WRITER_GATES: LazyLock<parking_lot::Mutex<HashMap<PathBuf, Weak<Semaphore>>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// How long a new writer waits for the previous one to release the path.
/// Generous enough for a multi-GB trailing fsync on a slow disk, bounded so a
/// genuinely stuck writer fails the new download instead of hanging it
/// forever. Failing is the safe direction: the transfer is re-queued and
/// retried, whereas opening anyway is the corruption this gate exists to stop.
const WRITER_HANDOFF_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Budget for one write / read / MD4 round-trip, covering both the enqueue and
/// the acknowledgement.
///
/// Both halves need bounding. The queue is bounded too, so a worker parked
/// inside a `WriteFile` the volume will never answer blocks `Sender::send` as
/// soon as `WRITER_QUEUE_CAPACITY` operations have piled up behind it — and an
/// unbounded wait on either half parks the download worker permanently, with no
/// way out: the I/O runs on a `std::thread`, so `abort()`ing the task that owns
/// the writer cannot interrupt it.
///
/// Sized off the worst *legitimate* wait, which is queue drain and not the
/// operation itself. A caller's acknowledgement also waits out everything the
/// serial worker still has in front of it: up to `WRITER_QUEUE_CAPACITY` (4096)
/// queued eD2K blocks of `EMBLOCKSIZE` (180 KiB), about 720 MB, plus this
/// operation's own ≤ `MAX_WRITER_IO_BYTES` (16 MiB). Even a 5 MB/s SMB share
/// over a saturated WAN link drains that in roughly 150 s, and the enqueue and
/// the acknowledgement are each at most one such drain, so 300 s covers the
/// pathological-but-working case end to end. What is left over the line is a
/// volume that has stopped answering rather than answering slowly: an unmounted
/// network share, a spun-down or hung external disk, a cloud-sync placeholder
/// whose provider is offline.
const WRITER_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Budget for `sync_data`, double [`WRITER_IO_TIMEOUT`].
///
/// `fsync` is legitimately the slowest thing the worker does and the one
/// operation that cannot be split into `MAX_WRITER_IO_BYTES` pieces: it has to
/// push every dirty page of a `.part` that may be tens of GB, and on a
/// multi-source download it is called with the whole file's write history
/// behind it. Healthy storage still answers in seconds — ten minutes means the
/// volume is neither completing the request nor failing it.
const WRITER_SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The gate for `path`, creating it if this is the first writer.
///
/// Entries are held by `Weak`, and an `OwnedSemaphorePermit` keeps its
/// `Arc<Semaphore>` alive, so a path with no writer and no waiter drops out on
/// the next sweep rather than accumulating one entry per completed download.
fn writer_gate(path: &Path) -> Arc<Semaphore> {
    let mut gates = PART_WRITER_GATES.lock();
    if let Some(existing) = gates.get(path).and_then(Weak::upgrade) {
        return existing;
    }
    gates.retain(|_, weak| weak.strong_count() > 0);
    let gate = Arc::new(Semaphore::new(1));
    gates.insert(path.to_path_buf(), Arc::downgrade(&gate));
    gate
}

fn validate_range(offset: u64, len: usize) -> io::Result<()> {
    if len > MAX_WRITER_IO_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("writer operation too large: {len} bytes"),
        ));
    }
    offset
        .checked_add(len as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "writer range overflows"))?;
    Ok(())
}

/// Operation submitted to the writer thread. Keep payloads owned (no
/// borrows) so the worker thread can run independently.
enum WriteOp {
    Write {
        offset: u64,
        data: Vec<u8>,
        ack: oneshot::Sender<io::Result<()>>,
    },
    #[allow(dead_code)]
    Read {
        offset: u64,
        len: usize,
        ack: oneshot::Sender<io::Result<Vec<u8>>>,
    },
    /// Combined read + MD4 hash. Used for ed2k part verification — keeping
    /// the hash on the same thread as the read avoids a runtime hop and
    /// avoids blocking an async worker on `Md4::digest`.
    HashPartMd4 {
        offset: u64,
        len: usize,
        ack: oneshot::Sender<io::Result<(Vec<u8>, [u8; 16])>>,
    },
    SyncData {
        ack: oneshot::Sender<io::Result<()>>,
    },
    /// Causes the worker to drop the file handle and exit cleanly.
    /// Sent by `Inner::Drop` when the last clone goes away.
    Close,
    /// The `.part` is about to be deleted: skip remaining queued writes and
    /// skip the trailing fsync so the handle is released immediately.
    Abandon,
}

struct Inner {
    tx: mpsc::Sender<WriteOp>,
    /// The transfer's discard flag, set only when its `.part` is about to be
    /// deleted. A plain cancel (Pause / Stop) deliberately leaves this unset,
    /// so those paths still get a drained queue and a trailing fsync.
    discard: Option<Arc<AtomicBool>>,
    /// Set the first time an operation exceeds its budget — i.e. once the
    /// volume has stopped answering. Shared with the worker thread so it can
    /// drop the rest of its queue instead of replaying operations whose callers
    /// have already been told they failed.
    wedged: Arc<AtomicBool>,
    /// The `.part` this writer owns, so the one warning below names the volume
    /// that wedged rather than leaving the user to guess which download stalled.
    path: PathBuf,
}

impl Inner {
    fn should_abandon(&self) -> bool {
        self.discard
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    /// Declare the writer dead because an operation blew its budget, and return
    /// the error to hand the caller.
    ///
    /// There is nothing to cancel: the operation is sitting in a syscall on the
    /// worker's own `std::thread` and will return when (or if) the volume
    /// answers. All this can do is stop further work queueing behind it and get
    /// the file handle released, so the transfer fails and retries instead of
    /// holding a download slot and a `.part` handle forever.
    fn poison(&self, stage: &str) -> io::Error {
        if !self.wedged.swap(true, Ordering::AcqRel) {
            tracing::warn!(
                "part file writer for {} stopped answering while trying to {stage} an operation \
                 — failing this and every later operation instead of parking the download worker",
                self.path.display()
            );
            // The worker only re-reads the flag between operations, so this is
            // what wakes it when its queue is empty. Best-effort on purpose: a
            // queue already full of stalled writes has no room, and the flag
            // alone still makes the worker exit when it next dequeues.
            let _ = self.tx.try_send(WriteOp::Abandon);
        }
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "part file writer stopped answering for {}",
                self.path.display()
            ),
        )
    }

    /// Fail fast once poisoned. Without this every subsequent block from every
    /// remaining source would wait out a fresh full budget, so a download with
    /// a deep pipeline would take hours to give up on a dead volume instead of
    /// one timeout.
    fn wedged_error(&self) -> Option<io::Error> {
        self.wedged.load(Ordering::Acquire).then(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "part file writer already stopped answering for {}",
                    self.path.display()
                ),
            )
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // A wedged writer gets the same treatment as a discard: draining and
        // fsyncing is exactly what it can no longer do, and the queued writes
        // behind the stall have already been failed to their callers.
        if self.should_abandon() || self.wedged.load(Ordering::Acquire) {
            let _ = self.tx.try_send(WriteOp::Abandon);
            return;
        }
        // Do not queue SyncData here: a discard that loses the race with Drop
        // would fsync a multi-GB `.part` before the handle is released, which
        // is exactly what leaves Temp/{id}.part visible on Windows. Graceful
        // close still fsyncs once in `writer_loop` after draining writes.
        let _ = self.tx.try_send(WriteOp::Close);
    }
}

/// Cheap-to-clone handle to a per-file writer thread. All operations are
/// async and serialize through the worker.
#[derive(Clone)]
pub struct PartFileWriter {
    inner: Arc<Inner>,
}

/// Open mode for `PartFileWriter::open`. Mirrors the two call sites from
/// the previous mutex-based code:
///   * single-source (`transfer.rs`) creates+sets length when starting a
///     fresh download, or reuses an existing `.part` file when resuming;
///   * multi-source (`multi_source.rs`) only ever attaches to a `.part`
///     file that the single-source bootstrap already created.
pub enum OpenMode {
    /// Open existing or create new; if `set_len_to` is `Some(len)` and the
    /// file is empty (or shorter than `len`), set length to `len`.
    /// `truncate_existing` controls whether to wipe an existing file (only
    /// safe when there's no resume metadata pointing into it).
    CreateOrOpen {
        set_len_to: Option<u64>,
        truncate_existing: bool,
    },
    /// Open an existing read+write file. Errors if the file does not exist.
    OpenExisting,
}

impl PartFileWriter {
    /// Open the part file and spawn its dedicated worker thread.
    ///
    /// The worker is a `std::thread::spawn` (not `tokio::task::spawn_blocking`)
    /// so it doesn't compete for slots in the bounded blocking pool with
    /// short-lived tasks like hash verification or `.part.met` saves.
    ///
    /// `discard` is the transfer's discard flag, from
    /// `TransferControl::discarding_flag`. Once set, the worker drops the file
    /// handle without draining remaining writes or fsyncing, so Cancel can
    /// delete Temp/{id}.part on Windows. Pause and Stop keep the `.part` for
    /// resume and must never set it.
    pub async fn open(
        path: PathBuf,
        mode: OpenMode,
        allowed_roots: Vec<String>,
        discard: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        // Claim the path before touching the file: `CreateOrOpen` can set (or
        // truncate) the length, which must not happen while a previous
        // generation's worker still holds the handle. See `PART_WRITER_GATES`.
        let gate = writer_gate(&path);
        let permit = match tokio::time::timeout(WRITER_HANDOFF_TIMEOUT, gate.acquire_owned()).await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) => {
                return Err(io::Error::other("part writer gate closed"));
            }
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "timed out waiting for the previous writer on {} to close",
                        path.display()
                    ),
                ));
            }
        };

        // Open on a blocking thread because creating + sizing the file can
        // be slow on cold disks. After this returns the worker thread takes
        // ownership of the handle.
        let path_for_open = path.clone();
        let file =
            tokio::task::spawn_blocking(move || open_file(&path_for_open, mode, &allowed_roots))
                .await
                .map_err(|e| {
                    io::Error::other(format!("spawn_blocking: {e}"))
                })??;

        let (tx, mut rx) = mpsc::channel::<WriteOp>(WRITER_QUEUE_CAPACITY);
        let discard_for_loop = discard.clone();
        let wedged = Arc::new(AtomicBool::new(false));
        let wedged_for_loop = wedged.clone();

        std::thread::Builder::new()
            .name(format!(
                "ember-part-writer-{}",
                path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            ))
            .spawn(move || {
                // Declared first so it drops last: the path stays claimed
                // until `writer_loop` has returned, which is after it has
                // fsynced and dropped the file handle.
                let _permit = permit;
                writer_loop(file, &mut rx, discard_for_loop, wedged_for_loop)
            })
            .map_err(|e| {
                io::Error::other(format!("spawn writer thread: {e}"))
            })?;

        // The worker parks in `blocking_recv`, so it cannot notice the discard
        // flag on its own. `Inner::drop` usually delivers `Abandon`, but a
        // download task still parked in `spawn_blocking` (final verify, MD4)
        // has not dropped its writer yet, and `abort()` cannot pre-empt it —
        // exactly the state a Cancel interrupts. This watcher closes that gap
        // so the `.part` handle is released while the delete is still retrying,
        // without the worker having to poll on a timer. A `WeakSender` keeps it
        // from holding the channel open past the worker's own exit.
        if let Some(flag) = discard.clone() {
            let weak_tx = tx.downgrade();
            tokio::spawn(async move {
                while !flag.load(Ordering::Acquire) {
                    let Some(tx) = weak_tx.upgrade() else { return };
                    if tx.is_closed() {
                        return;
                    }
                    drop(tx);
                    tokio::time::sleep(DISCARD_POLL_INTERVAL).await;
                }
                if let Some(tx) = weak_tx.upgrade() {
                    let _ = tx.try_send(WriteOp::Abandon);
                }
            });
        }

        Ok(Self {
            inner: Arc::new(Inner {
                tx,
                discard,
                wedged,
                path,
            }),
        })
    }

    /// Hand `op` to the worker and wait for its acknowledgement, both under one
    /// `budget`.
    ///
    /// A single deadline rather than one per half: each half is at most one
    /// queue drain (see [`WRITER_IO_TIMEOUT`]), and giving them separate
    /// budgets would double how long a caller can park on a dead volume for no
    /// gain in tolerance.
    ///
    /// A timed-out operation is *not* cancelled — see [`Inner::poison`]. When
    /// the abandoned write eventually lands, the bytes it carries are bytes the
    /// caller has already released back to the gap list, so nothing on disk is
    /// claimed as present that is not, and the worker exits before touching
    /// anything queued behind it (see `writer_loop`), so a stale write can
    /// never overwrite a newer one for the same range.
    async fn submit<T>(
        &self,
        budget: std::time::Duration,
        op: WriteOp,
        ack_rx: oneshot::Receiver<io::Result<T>>,
    ) -> io::Result<T> {
        if let Some(err) = self.inner.wedged_error() {
            return Err(err);
        }
        let deadline = tokio::time::Instant::now() + budget;
        match tokio::time::timeout_at(deadline, self.inner.tx.send(op)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "writer task closed",
                ))
            }
            Err(_) => return Err(self.inner.poison("queue")),
        }
        match tokio::time::timeout_at(deadline, ack_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer dropped ack",
            )),
            Err(_) => Err(self.inner.poison("complete")),
        }
    }

    /// Write `data` at `offset`. Awaits the worker's confirmation that the
    /// bytes hit the kernel (write returned). Does NOT fsync.
    pub async fn write(&self, offset: u64, data: Vec<u8>) -> io::Result<()> {
        validate_range(offset, data.len())?;
        let (ack, ack_rx) = oneshot::channel();
        self.submit(
            WRITER_IO_TIMEOUT,
            WriteOp::Write { offset, data, ack },
            ack_rx,
        )
        .await
    }

    /// Read `len` bytes starting at `offset`.
    #[allow(dead_code)]
    pub async fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        validate_range(offset, len)?;
        let (ack, ack_rx) = oneshot::channel();
        self.submit(
            WRITER_IO_TIMEOUT,
            WriteOp::Read { offset, len, ack },
            ack_rx,
        )
        .await
    }

    /// Read `len` bytes at `offset` AND compute their MD4 hash on the
    /// worker thread. Returns `(buffer, md4_hash)`. The buffer is returned
    /// alongside the hash so callers can run AICH recovery on a hash
    /// mismatch without re-reading the part.
    pub async fn hash_part_md4(&self, offset: u64, len: usize) -> io::Result<(Vec<u8>, [u8; 16])> {
        validate_range(offset, len)?;
        let (ack, ack_rx) = oneshot::channel();
        self.submit(
            WRITER_IO_TIMEOUT,
            WriteOp::HashPartMd4 { offset, len, ack },
            ack_rx,
        )
        .await
    }

    /// Flush kernel buffers to storage (`fsync`-equivalent). Used once
    /// before final hash verification on multi-source downloads where the
    /// file has been written by many writers and we want to be sure the
    /// disk image is canonical before the read-back.
    pub async fn sync_data(&self) -> io::Result<()> {
        let (ack, ack_rx) = oneshot::channel();
        self.submit(WRITER_SYNC_TIMEOUT, WriteOp::SyncData { ack }, ack_rx)
            .await
    }
}

fn open_file(path: &Path, mode: OpenMode, allowed_roots: &[String]) -> io::Result<std::fs::File> {
    match mode {
        OpenMode::CreateOrOpen {
            set_len_to,
            truncate_existing,
        } => {
            // `<download_folder>/Temp` is otherwise only ever created during
            // startup, which is best-effort because an unreachable download
            // folder must not stop the app from launching (see `lib.rs`). Retry
            // it here so a drive reconnected mid-session starts working without
            // a restart. Best-effort on purpose: if this fails, the open below
            // produces the real error. `open_or_create_approved` still performs
            // every approved-root and reparse-point check on the final path, so
            // creating the parent grants no additional reach.
            if let Some(parent) = path.parent() {
                if !parent.is_dir() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            let (_verified, f) = crate::security::filesystem::open_or_create_approved(
                path,
                allowed_roots,
                truncate_existing,
            )?;
            if let Some(len) = set_len_to {
                if len > 0 {
                    let cur = f.metadata()?.len();
                    if cur != len {
                        f.set_len(len)?;
                    }
                }
            }
            Ok(f)
        }
        OpenMode::OpenExisting => {
            let (_, file) =
                crate::security::filesystem::open_existing_approved(path, allowed_roots, true)?;
            Ok(file)
        }
    }
}

fn writer_loop(
    mut file: std::fs::File,
    rx: &mut mpsc::Receiver<WriteOp>,
    discard: Option<Arc<AtomicBool>>,
    wedged: Arc<AtomicBool>,
) {
    fn discarding(discard: &Option<Arc<AtomicBool>>) -> bool {
        discard
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    let mut abandon = discarding(&discard);
    while !abandon {
        // `blocking_recv` is documented to work outside an async context,
        // which is exactly the situation here (we're on a `std::thread`). The
        // discard watchdog spawned in `open` pokes `Abandon` into the queue, so
        // parking here costs nothing while idle and still releases the handle
        // promptly on a Cancel.
        let Some(op) = rx.blocking_recv() else {
            break;
        };
        // Checked between operations, which is the first moment after a wedged
        // syscall finally returns. Every caller still in this queue has already
        // been handed a `TimedOut` (or a `BrokenPipe` when its ack sender drops
        // with `rx` below) and has released its write reservation, so those
        // bytes are back to being gaps. Executing them anyway would put data on
        // disk that no gap list accounts for, and — because the retry is free to
        // re-reserve the same ranges the moment the transfer restarts — an
        // ancient queued block could land on top of a newer one for the same
        // offsets: precisely the torn part `PART_WRITER_GATES` exists to stop,
        // reintroduced inside a single writer. Drop the handle instead.
        //
        // The discard flag is read in the same place and for a related reason.
        // It used to be read only at loop entry and inside the `SyncData` arm,
        // leaving `WriteOp::Abandon` as the only thing that could cut a discard
        // short mid-queue — and both senders of it use `try_send`, which drops
        // silently when the 4096-slot queue is full. `Inner::poison` reasons
        // that a dropped `Abandon` is safe because "the flag alone still makes
        // the worker exit when it next dequeues", which was true of `wedged`
        // and not of this one. Cancelling a download with a deep queue on a
        // slow volume therefore executed up to ~720 MB of writes nobody wanted
        // before releasing the handle, missing the ~8s cleanup budget and
        // orphaning the `.part` on Windows.
        if wedged.load(Ordering::Acquire) || discarding(&discard) {
            abandon = true;
            break;
        }
        match op {
            WriteOp::Write { offset, data, ack } => {
                let res = (|| -> io::Result<()> {
                    file.seek(SeekFrom::Start(offset))?;
                    file.write_all(&data)?;
                    Ok(())
                })();
                let _ = ack.send(res);
            }
            WriteOp::Read { offset, len, ack } => {
                let res = (|| -> io::Result<Vec<u8>> {
                    file.seek(SeekFrom::Start(offset))?;
                    let mut buf = vec![0u8; len];
                    file.read_exact(&mut buf)?;
                    Ok(buf)
                })();
                let _ = ack.send(res);
            }
            WriteOp::HashPartMd4 { offset, len, ack } => {
                let res = (|| -> io::Result<(Vec<u8>, [u8; 16])> {
                    file.seek(SeekFrom::Start(offset))?;
                    let mut buf = vec![0u8; len];
                    file.read_exact(&mut buf)?;
                    use digest::Digest;
                    use md4::Md4;
                    let hash: [u8; 16] = Md4::digest(&buf).into();
                    Ok((buf, hash))
                })();
                let _ = ack.send(res);
            }
            WriteOp::SyncData { ack } => {
                // An explicit fsync on a file that is about to be deleted is
                // pure latency, and it is what holds the handle open.
                if discarding(&discard) {
                    abandon = true;
                    let _ = ack.send(Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "part writer abandoned",
                    )));
                    break;
                }
                let _ = ack.send(file.sync_data());
            }
            WriteOp::Close => break,
            WriteOp::Abandon => {
                abandon = true;
                break;
            }
        }
    }
    // Final best-effort flush so a sudden process exit after the last queued
    // write doesn't lose data the OS hadn't written yet. Skipped only when the
    // `.part` is being deleted: fsync is what keeps the handle open on Windows.
    // Pause and Stop keep the file, and their `.part.met` gap list is written
    // durably, so skipping here would leave resume metadata describing bytes
    // that a crash could still lose.
    if !abandon {
        let _ = file.sync_data();
    }
    drop(file);
}

#[cfg(test)]
// `await_holding_lock` fires on `test_registry_lock`, which is held across the
// awaits on purpose: it serialises tests that swap the process-global approved
// -root registry, and the window it has to cover is exactly the asynchronous
// file open. Dropping it sooner would reintroduce the race it exists to
// prevent. These are `#[tokio::test]`s on the current-thread runtime, so there
// is no executor thread for the guard to strand.
#[allow(clippy::await_holding_lock)]
mod tests {
    use super::*;

    fn approved_temp_file(name: &str) -> (PathBuf, Vec<String>, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "ember-pfw-root-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_s = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_s),
        )
        .unwrap();
        (root.join(format!("{name}.bin")), vec![root_s], base)
    }

    #[tokio::test]
    async fn write_then_read_round_trip() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("rt");
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(1024),
                truncate_existing: true,
            },
            allowed,
            None,
        )
        .await
        .unwrap();

        writer.write(100, vec![0xABu8; 64]).await.unwrap();
        let buf = writer.read(100, 64).await.unwrap();
        assert!(buf.iter().all(|&b| b == 0xAB));

        drop(writer);
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn hash_part_md4_matches_direct_md4() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("md4");
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(4096),
                truncate_existing: true,
            },
            allowed,
            None,
        )
        .await
        .unwrap();

        let payload: Vec<u8> = (0..4096u32).map(|i| (i & 0xFF) as u8).collect();
        writer.write(0, payload.clone()).await.unwrap();

        let (buf, hash) = writer.hash_part_md4(0, 4096).await.unwrap();
        assert_eq!(buf, payload);

        use digest::Digest;
        let expected: [u8; 16] = md4::Md4::digest(&payload).into();
        assert_eq!(hash, expected);

        drop(writer);
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn concurrent_writes_serialize_correctly() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("concurrent");
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(1_000_000),
                truncate_existing: true,
            },
            allowed,
            None,
        )
        .await
        .unwrap();

        let mut handles = Vec::new();
        for i in 0..50u64 {
            let w = writer.clone();
            handles.push(tokio::spawn(async move {
                let buf = vec![(i & 0xFF) as u8; 1024];
                w.write(i * 2048, buf).await.unwrap();
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        for i in 0..50u64 {
            let buf = writer.read(i * 2048, 1024).await.unwrap();
            assert!(buf.iter().all(|&b| b == (i & 0xFF) as u8));
        }

        drop(writer);
        let _ = std::fs::remove_dir_all(base);
    }

    #[tokio::test]
    async fn discard_flag_releases_the_file_without_waiting_on_fsync() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("abandon");
        let discard = Arc::new(AtomicBool::new(false));
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(4096),
                truncate_existing: true,
            },
            allowed,
            Some(discard.clone()),
        )
        .await
        .unwrap();
        writer.write(0, vec![0xCDu8; 64]).await.unwrap();
        discard.store(true, Ordering::Release);
        drop(writer);
        for _ in 0..50 {
            if std::fs::remove_file(&path).is_ok() {
                let _ = std::fs::remove_dir_all(base);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("discarded writer did not release {}", path.display());
    }

    /// Aborting a download task does not stop the writer thread it owns: the
    /// thread still drains its queue and fsyncs while holding the handle, and
    /// most start paths spawn the replacement worker immediately (the
    /// KAD-disconnect path drains `download_handles`, so the next start has no
    /// handle to wait on at all). Opening a second writer in that window is
    /// what lets a stale queued block overwrite a fresh one.
    #[tokio::test]
    async fn a_second_writer_waits_for_the_previous_one_to_close() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("handoff");
        let first = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(4096),
                truncate_existing: true,
            },
            allowed.clone(),
            None,
        )
        .await
        .unwrap();

        let second_path = path.clone();
        let second_allowed = allowed.clone();
        let mut second = tokio::spawn(async move {
            PartFileWriter::open(
                second_path,
                OpenMode::OpenExisting,
                second_allowed,
                None,
            )
            .await
        });

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(300), &mut second)
                .await
                .is_err(),
            "a second writer opened {} while the first still held it",
            path.display()
        );

        drop(first);

        let second = tokio::time::timeout(std::time::Duration::from_secs(10), second)
            .await
            .expect("the second writer must open once the first has closed")
            .expect("second writer task panicked")
            .expect("second writer failed to open");
        drop(second);
        let _ = std::fs::remove_dir_all(base);
    }

    /// Pause and Stop cancel the transfer control but keep the `.part` and its
    /// durably-written `.part.met` for resume, so they must NOT set the discard
    /// flag: queued writes still have to land and be acked, and the trailing
    /// fsync still has to run. Otherwise the sidecar's gap list names bytes a
    /// crash could still lose.
    #[tokio::test]
    async fn a_writer_whose_transfer_is_only_cancelled_still_drains_and_syncs() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("pause-drain");
        let control = crate::sharing::manager::TransferControl::new();
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(4096),
                truncate_existing: true,
            },
            allowed,
            Some(control.discarding_flag()),
        )
        .await
        .unwrap();

        // Exactly what Pause and Stop do to the control.
        control.pause();
        control.cancel();

        writer
            .write(0, vec![0xABu8; 64])
            .await
            .expect("a paused transfer's writer must still accept queued writes");
        writer
            .sync_data()
            .await
            .expect("a paused transfer's writer must still fsync");
        drop(writer);

        for _ in 0..50 {
            if let Ok(bytes) = std::fs::read(&path) {
                if bytes[..64] == [0xABu8; 64] {
                    let _ = std::fs::remove_dir_all(base);
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("paused writer lost its queued bytes for {}", path.display());
    }

    /// A volume that stops answering — an unmounted network share, a hung
    /// external disk, an offline cloud-sync placeholder — leaves the worker
    /// inside a syscall nothing can cancel, and because the I/O is on a
    /// `std::thread` rather than the runtime, aborting the download task cannot
    /// free it either. Once one acknowledgement has blown its budget, every
    /// later operation has to fail immediately instead of parking its caller
    /// for a fresh full budget, and the worker has to release the `.part`
    /// handle rather than replay a queue whose callers were already told their
    /// writes failed.
    #[tokio::test]
    async fn a_wedged_writer_fails_fast_and_releases_the_file() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (path, allowed, base) = approved_temp_file("wedged");
        let writer = PartFileWriter::open(
            path.clone(),
            OpenMode::CreateOrOpen {
                set_len_to: Some(4096),
                truncate_existing: true,
            },
            allowed,
            None,
        )
        .await
        .unwrap();

        // Exactly the state an expired acknowledgement leaves behind, without
        // having to wedge a real volume for five minutes.
        assert_eq!(
            writer.inner.poison("complete").kind(),
            io::ErrorKind::TimedOut
        );

        let started = std::time::Instant::now();
        let err = writer
            .write(0, vec![0xCDu8; 64])
            .await
            .expect_err("a wedged writer must refuse further writes");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            writer.sync_data().await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "operations after the first timeout must fail fast, not wait out fresh budgets"
        );

        drop(writer);
        for _ in 0..50 {
            if std::fs::remove_file(&path).is_ok() {
                let _ = std::fs::remove_dir_all(base);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("wedged writer did not release {}", path.display());
    }
}
