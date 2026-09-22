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

// `serve_attachment` runs from the QUIC accept loop; `fetch_attachment` is the
// receiving side and is tested but not yet called, because the friend-session
// signalling that decides to fetch is the next step. See the note in
// `super::attach`.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::attach::{
    attach_chunk_count, attach_file_info_len, attach_stream_tag, attach_tags_match,
    decode_attach_file_info, encode_attach_file_info, encode_attach_request, AttachFileInfo,
    AttachRequest, AttachStreamStatus, ATTACH_CHUNK_SIZE, ATTACH_REQUEST_TAIL_LEN,
};
use super::transfer::HashTree;

/// How long either side waits on a single stream operation before giving up.
///
/// Generous, because a chunk is 256 KiB and a slow link is not a broken one,
/// but bounded: a peer that opens a stream and then says nothing must not hold
/// a task and a file handle for the life of the process.
const ATTACH_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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
/// `tail` is the part of the request the accept loop has not already read, so
/// this can be called from a dispatcher that consumed the first seven bytes to
/// decide what the connection was.
pub async fn serve_attachment<R, W, F>(
    recv: &mut R,
    send: &mut W,
    prefix: &[u8; 7],
    capability_for: F,
) -> anyhow::Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: FnOnce(&[u8; 16]) -> Option<(PathBuf, u64, [u8; 32], [u8; 32])>,
{
    let mut tail = [0u8; ATTACH_REQUEST_TAIL_LEN];
    tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read_exact(&mut tail)).await??;

    let mut full = Vec::with_capacity(7 + tail.len());
    full.extend_from_slice(prefix);
    full.extend_from_slice(&tail);
    let Some(request) = super::attach::decode_attach_request(&full) else {
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

    // Re-hashed per stream rather than cached. The file lives outside the
    // library and outside our control: the user may have replaced it between
    // the offer and the dial, and serving new bytes under the old root would
    // fail the recipient's per-chunk check anyway. Hashing first means we
    // notice here and say so, instead of streaming a file that cannot verify.
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            refuse(send, AttachStreamStatus::SourceGone).await?;
            return Err(e.into());
        }
    };
    let tree = HashTree::from_reader(std::io::BufReader::new(file))?;
    if tree.file_size != size || tree.root_hash != root {
        refuse(send, AttachStreamStatus::SourceGone).await?;
        anyhow::bail!("attachment on disk no longer matches the offer");
    }

    let info = AttachFileInfo {
        size,
        chunk_hashes: tree.chunk_hashes,
    };
    tokio::time::timeout(
        ATTACH_IO_TIMEOUT,
        send.write_all(&encode_attach_file_info(&info)),
    )
    .await??;

    let mut handle = std::fs::File::open(&path)?;
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    let mut sent = 0u64;
    for index in request.start_chunk as usize..info.chunk_count() {
        let len = info
            .chunk_len(index)
            .ok_or_else(|| anyhow::anyhow!("chunk index past the end"))?;
        read_chunk_at(&mut handle, index, &mut buf[..len])?;
        tokio::time::timeout(ATTACH_IO_TIMEOUT, send.write_all(&buf[..len])).await??;
        sent += len as u64;
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

fn read_chunk_at(file: &mut std::fs::File, index: usize, out: &mut [u8]) -> std::io::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(index as u64 * ATTACH_CHUNK_SIZE as u64))?;
    file.read_exact(out)
}

/// Ask a peer for an attachment and write it into `part_path`, verifying as it
/// goes.
///
/// `on_progress` is called with the running total so a caller can drive a
/// progress bar; it is called per chunk, so a caller that emits an event from it
/// should throttle.
///
/// Resumes from whatever is already in `part_path`, rounded down to a whole
/// verified chunk — a partial chunk is discarded rather than trusted, because
/// nothing has checked it yet.
pub async fn fetch_attachment<R, W, P>(
    recv: &mut R,
    send: &mut W,
    xfer_id: &[u8; 16],
    capability: &[u8; 32],
    size: u64,
    root: &[u8; 32],
    part_path: &Path,
    mut on_progress: P,
) -> anyhow::Result<FetchOutcome>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    P: FnMut(u64, u64),
{
    let chunk_count =
        attach_chunk_count(size).ok_or_else(|| anyhow::anyhow!("attachment size out of range"))?;

    // Whole chunks only. A trailing partial chunk has been through no check at
    // all, so resuming "after" it would import bytes nothing vouches for.
    let have = std::fs::metadata(part_path).map(|m| m.len()).unwrap_or(0);
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
        send.write_all(&encode_attach_request(&request)),
    )
    .await??;
    tokio::time::timeout(ATTACH_IO_TIMEOUT, send.flush()).await??;

    // One byte first, so a refusal is a refusal rather than a short read of a
    // header that was never coming.
    let mut status_byte = [0u8; 1];
    tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read_exact(&mut status_byte)).await??;
    let status = AttachStreamStatus::from_byte(status_byte[0])
        .ok_or_else(|| anyhow::anyhow!("attachment peer sent an unknown status"))?;
    if status != AttachStreamStatus::Ok {
        anyhow::bail!("attachment refused by the sender: {status:?}");
    }

    let info_len = attach_file_info_len(size)
        .ok_or_else(|| anyhow::anyhow!("attachment size out of range"))?;
    let mut info_bytes = vec![0u8; info_len];
    info_bytes[0] = AttachStreamStatus::Ok.to_byte();
    tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read_exact(&mut info_bytes[1..])).await??;
    let info = decode_attach_file_info(&info_bytes)
        .map_err(|s| anyhow::anyhow!("attachment header refused: {s:?}"))?;

    // The check the whole scheme rests on. Until the chunk list is shown to be
    // the one the offered root commits to, the per-chunk hashes are only what
    // the sender says they are, and verifying against them proves nothing.
    if info.size != size || !info.matches_root(root) {
        anyhow::bail!("attachment chunk list does not match the offered root");
    }

    let tree = HashTree {
        chunk_hashes: info.chunk_hashes.clone(),
        root_hash: *root,
        file_size: size,
    };

    // Explicitly not truncating: whatever whole chunks are already here have
    // been verified, and `resume_at` is where writing continues from. The
    // `set_len` below is what drops a trailing partial chunk.
    let mut part = tokio::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .read(true)
        .open(part_path)
        .await?;
    part.set_len(resume_at).await?;
    part.seek(std::io::SeekFrom::Start(resume_at)).await?;

    let mut written = 0u64;
    let mut total = resume_at;
    let mut buf = vec![0u8; ATTACH_CHUNK_SIZE];
    for index in start_chunk as usize..info.chunk_count() {
        let len = info
            .chunk_len(index)
            .ok_or_else(|| anyhow::anyhow!("chunk index past the end"))?;
        tokio::time::timeout(ATTACH_IO_TIMEOUT, recv.read_exact(&mut buf[..len])).await??;

        // Per chunk, so a bad one costs this chunk rather than the whole file.
        // The room transfer could only check its root at the end, which meant
        // discarding everything and starting over.
        if !tree.verify_chunk(index, &buf[..len]) {
            anyhow::bail!("attachment chunk {index} did not match its hash");
        }

        part.write_all(&buf[..len]).await?;
        written += len as u64;
        total += len as u64;
        on_progress(total, size);
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
    use super::super::attach::derive_attach_capability;
    use ed25519_dalek::SigningKey;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ember-attach-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
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
            serve_attachment(&mut server_r, &mut server_w, &prefix, |id| {
                (*id == xfer_id).then(|| (served_source.clone(), size, root, cap_sender))
            })
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
                part,
                |_, _| {},
            )
            .await
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
            part,
            |_, _| {},
        )
        .await
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
            serve_attachment(&mut server_r, &mut server_w, &prefix, |_| None).await
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
            serve_attachment(&mut server_r, &mut server_w, &prefix, |_| {
                Some((served.clone(), 6, root, cap_sender))
            })
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
            serve_attachment(&mut server_r, &mut server_w, &prefix, |_| {
                Some((served.clone(), 18, offered_root, cap_sender))
            })
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
            &part,
            |_, _| {},
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
