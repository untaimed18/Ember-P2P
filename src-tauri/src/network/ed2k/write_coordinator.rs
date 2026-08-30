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

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

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
}

impl Inner {
    fn should_abandon(&self) -> bool {
        self.discard
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if self.should_abandon() {
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

        std::thread::Builder::new()
            .name(format!(
                "ember-part-writer-{}",
                path.file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
            ))
            .spawn(move || writer_loop(file, &mut rx, discard_for_loop))
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
            inner: Arc::new(Inner { tx, discard }),
        })
    }

    /// Write `data` at `offset`. Awaits the worker's confirmation that the
    /// bytes hit the kernel (write returned). Does NOT fsync.
    pub async fn write(&self, offset: u64, data: Vec<u8>) -> io::Result<()> {
        validate_range(offset, data.len())?;
        let (ack, ack_rx) = oneshot::channel();
        self.inner
            .tx
            .send(WriteOp::Write { offset, data, ack })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer task closed"))?;
        ack_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer dropped ack"))?
    }

    /// Read `len` bytes starting at `offset`.
    #[allow(dead_code)]
    pub async fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        validate_range(offset, len)?;
        let (ack, ack_rx) = oneshot::channel();
        self.inner
            .tx
            .send(WriteOp::Read { offset, len, ack })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer task closed"))?;
        ack_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer dropped ack"))?
    }

    /// Read `len` bytes at `offset` AND compute their MD4 hash on the
    /// worker thread. Returns `(buffer, md4_hash)`. The buffer is returned
    /// alongside the hash so callers can run AICH recovery on a hash
    /// mismatch without re-reading the part.
    pub async fn hash_part_md4(&self, offset: u64, len: usize) -> io::Result<(Vec<u8>, [u8; 16])> {
        validate_range(offset, len)?;
        let (ack, ack_rx) = oneshot::channel();
        self.inner
            .tx
            .send(WriteOp::HashPartMd4 { offset, len, ack })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer task closed"))?;
        ack_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer dropped ack"))?
    }

    /// Flush kernel buffers to storage (`fsync`-equivalent). Used once
    /// before final hash verification on multi-source downloads where the
    /// file has been written by many writers and we want to be sure the
    /// disk image is canonical before the read-back.
    pub async fn sync_data(&self) -> io::Result<()> {
        let (ack, ack_rx) = oneshot::channel();
        self.inner
            .tx
            .send(WriteOp::SyncData { ack })
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer task closed"))?;
        ack_rx
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer dropped ack"))?
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
}
