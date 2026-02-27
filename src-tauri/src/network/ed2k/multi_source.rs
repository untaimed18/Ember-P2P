use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::sharing::manager::TransferControl;

use super::part_tracker::PartTracker;
use super::transfer::{DownloadEvent, Ed2kDownload};

/// Maximum decompressed part size (PARTSIZE + margin = 10 MiB)
const MAX_DECOMPRESSED_PART: usize = 10 * 1024 * 1024;

/// Maximum allowed file size for downloads (4 TiB)
const MAX_DOWNLOAD_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024 * 1024;

/// A source that can provide parts of a file.
#[derive(Debug, Clone)]
pub struct DownloadSource {
    pub peer_ip: String,
    pub peer_port: u16,
    pub available_parts: Vec<bool>,
}

/// Coordinates downloading a single file from multiple sources.
/// Each source downloads different parts to maximize throughput.
pub struct MultiSourceDownload {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub sources: Vec<DownloadSource>,
    pub download_dir: PathBuf,
    pub user_hash: [u8; 16],
    pub nickname: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
}

impl MultiSourceDownload {
    /// Run the multi-source download. If only one source, falls back to single-source.
    pub async fn run(self, event_tx: mpsc::Sender<DownloadEvent>) -> anyhow::Result<()> {
        if self.sources.is_empty() {
            anyhow::bail!("no sources available");
        }

        if self.file_size > MAX_DOWNLOAD_FILE_SIZE {
            anyhow::bail!(
                "file size {} exceeds maximum allowed ({})",
                self.file_size,
                MAX_DOWNLOAD_FILE_SIZE
            );
        }

        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }

        if self.sources.len() == 1 {
            let source = &self.sources[0];
            let download = Ed2kDownload {
                transfer_id: self.transfer_id.clone(),
                file_hash: self.file_hash,
                file_name: self.file_name.clone(),
                file_size: self.file_size,
                source_addr: format!("{}:{}", source.peer_ip, source.peer_port)
                    .parse()
                    .map_err(|e| anyhow::anyhow!("invalid addr: {e}"))?,
                download_dir: self.download_dir.clone(),
                user_hash: self.user_hash,
                nickname: self.nickname.clone(),
                tcp_port: self.tcp_port,
                udp_port: self.udp_port,
                bandwidth_limiter: self.bandwidth_limiter.clone(),
                control: TransferControl::new(),
            };
            return download.run(event_tx).await;
        }

        info!(
            "Starting multi-source download of {} from {} sources",
            hex::encode(self.file_hash),
            self.sources.len()
        );

        let part_path = self.download_dir.join(format!("{}.part", self.transfer_id));
        let tracker = Arc::new(RwLock::new(PartTracker::new(self.file_size, &part_path)));

        // Pre-create the output file
        {
            let t = tracker.read().await;
            if t.completed_count() == 0 {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&part_path)?;
                if self.file_size > 0 {
                    f.set_len(self.file_size)?;
                }
            }
        }

        // Assign parts to sources using round-robin across available parts
        let part_count = {
            let t = tracker.read().await;
            t.part_count
        };

        // Build per-source part assignments
        let mut source_parts: Vec<Vec<usize>> = vec![Vec::new(); self.sources.len()];
        let mut part_idx = 0;

        for p in 0..part_count {
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled by user");
            }

            let t = tracker.read().await;
            if t.is_part_complete(p) {
                continue;
            }

            // Find a source that has this part (round-robin)
            let mut assigned = false;
            for attempt in 0..self.sources.len() {
                let src_idx = (part_idx + attempt) % self.sources.len();
                let src = &self.sources[src_idx];
                if src.available_parts.is_empty()
                    || src.available_parts.get(p).copied().unwrap_or(false)
                {
                    source_parts[src_idx].push(p);
                    assigned = true;
                    break;
                }
            }
            if !assigned {
                // No source has this part; assign to first source anyway (it may fail)
                source_parts[0].push(p);
            }
            part_idx += 1;
        }

        // Shared part hashes for per-part verification (populated by first source)
        let part_hashes: Arc<RwLock<Vec<[u8; 16]>>> = Arc::new(RwLock::new(Vec::new()));

        // Progress aggregator channel
        let (progress_tx, mut progress_rx) = mpsc::channel::<(usize, u64)>(256);
        let transfer_id = self.transfer_id.clone();
        let file_size = self.file_size;
        let event_tx_clone = event_tx.clone();

        // Aggregator task that merges progress from all sources
        let aggregator = tokio::spawn(async move {
            let mut total_downloaded: u64 = 0;
            while let Some((_source_idx, bytes)) = progress_rx.recv().await {
                total_downloaded += bytes;
                let _ = event_tx_clone
                    .send(DownloadEvent::Progress {
                        transfer_id: transfer_id.clone(),
                        downloaded: total_downloaded,
                        total: file_size,
                    })
                    .await;
            }
        });

        // Spawn per-source download tasks
        let mut handles = Vec::new();
        for (src_idx, parts) in source_parts.into_iter().enumerate() {
            if parts.is_empty() {
                continue;
            }
            let source = self.sources[src_idx].clone();
            let tracker = tracker.clone();
            let part_path = part_path.clone();
            let file_hash = self.file_hash;
            let file_size = self.file_size;
            let user_hash = self.user_hash;
            let nickname = self.nickname.clone();
            let tcp_port = self.tcp_port;
            let udp_port = self.udp_port;
            let bw = self.bandwidth_limiter.clone();
            let progress_tx = progress_tx.clone();
            let ph = part_hashes.clone();

            let handle = tokio::spawn(async move {
                let result = download_parts_from_source(
                    src_idx,
                    &source,
                    &parts,
                    tracker,
                    &part_path,
                    &file_hash,
                    file_size,
                    &user_hash,
                    &nickname,
                    tcp_port,
                    udp_port,
                    bw,
                    progress_tx,
                    ph,
                )
                .await;

                if let Err(e) = &result {
                    warn!("Source {} ({}) failed: {e}", src_idx, source.peer_ip);
                }
                (src_idx, parts, result)
            });
            handles.push(handle);
        }

        // Drop our copy of progress_tx so the aggregator can finish
        drop(progress_tx);

        // Wait for all sources to complete
        for handle in handles {
            if let Ok((_src_idx, _parts, result)) = handle.await {
                if result.is_err() {
                    // Parts from failed sources remain incomplete in tracker
                }
            }
        }

        aggregator.await?;

        // Retry incomplete parts (from failed sources or hash mismatches)
        const MAX_RETRY_ROUNDS: usize = 3;
        for retry_round in 1..=MAX_RETRY_ROUNDS {
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled by user");
            }

            let incomplete: Vec<usize> = {
                let t = tracker.read().await;
                (0..t.part_count)
                    .filter(|&i| !t.is_part_complete(i))
                    .collect()
            };
            if incomplete.is_empty() {
                break;
            }

            warn!(
                "Retry round {}/{}: {} incomplete parts",
                retry_round,
                MAX_RETRY_ROUNDS,
                incomplete.len()
            );

            // Distribute incomplete parts across all sources round-robin
            let mut retry_assignments: Vec<Vec<usize>> =
                vec![Vec::new(); self.sources.len()];
            for (i, &part_idx) in incomplete.iter().enumerate() {
                retry_assignments[i % self.sources.len()].push(part_idx);
            }

            let (retry_tx, mut retry_rx) = mpsc::channel::<(usize, u64)>(256);
            let tid = self.transfer_id.clone();
            let fs = self.file_size;
            let etx = event_tx.clone();
            let retry_agg = tokio::spawn(async move {
                let mut total: u64 = 0;
                while let Some((_, bytes)) = retry_rx.recv().await {
                    total += bytes;
                    let _ = etx
                        .send(DownloadEvent::Progress {
                            transfer_id: tid.clone(),
                            downloaded: total,
                            total: fs,
                        })
                        .await;
                }
            });

            let mut retry_handles = Vec::new();
            for (src_idx, parts) in retry_assignments.into_iter().enumerate() {
                if parts.is_empty() {
                    continue;
                }
                let source = self.sources[src_idx].clone();
                let tracker = tracker.clone();
                let part_path = part_path.clone();
                let file_hash = self.file_hash;
                let file_size = self.file_size;
                let user_hash = self.user_hash;
                let nickname = self.nickname.clone();
                let tcp_port = self.tcp_port;
                let udp_port = self.udp_port;
                let bw = self.bandwidth_limiter.clone();
                let retry_tx = retry_tx.clone();
                let ph = part_hashes.clone();

                retry_handles.push(tokio::spawn(async move {
                    let _ = download_parts_from_source(
                        src_idx, &source, &parts, tracker, &part_path,
                        &file_hash, file_size, &user_hash, &nickname,
                        tcp_port, udp_port, bw, retry_tx, ph,
                    )
                    .await;
                }));
            }

            drop(retry_tx);
            for h in retry_handles {
                let _ = h.await;
            }
            retry_agg.await?;
        }

        // Check if all parts are complete
        let all_done = {
            let t = tracker.read().await;
            t.all_complete()
        };

        if all_done {
            let safe_name = crate::security::sanitize_filename(&self.file_name);
            let final_path = self.download_dir.join(&safe_name);
            {
                let t = tracker.read().await;
                t.delete_met();
            }
            std::fs::rename(&part_path, &final_path)?;

            // Verify final file hash
            let verify_path = final_path.clone();
            let expected = hex::encode(self.file_hash);
            match tokio::task::spawn_blocking(move || {
                super::hash::ed2k_hash_file(&verify_path)
            }).await {
                Ok(Ok(actual)) if actual == expected => {
                    info!("Multi-source download complete and verified: {}", self.file_name);
                }
                Ok(Ok(actual)) => {
                    warn!(
                        "Multi-source download hash mismatch for {}: expected={}, got={}",
                        self.file_name, expected, actual
                    );
                }
                _ => {
                    info!("Multi-source download complete (hash check failed): {}", self.file_name);
                }
            }

            let _ = event_tx
                .send(DownloadEvent::Completed {
                    transfer_id: self.transfer_id.clone(),
                })
                .await;
        } else {
            let remaining = {
                let t = tracker.read().await;
                t.part_count - t.completed_count()
            };
            let _ = event_tx
                .send(DownloadEvent::Failed {
                    transfer_id: self.transfer_id.clone(),
                    error: format!("{remaining} parts still incomplete after retries"),
                })
                .await;
        }

        Ok(())
    }
}

async fn download_parts_from_source(
    _src_idx: usize,
    source: &DownloadSource,
    parts: &[usize],
    tracker: Arc<RwLock<PartTracker>>,
    part_path: &std::path::Path,
    file_hash: &[u8; 16],
    _file_size: u64,
    user_hash: &[u8; 16],
    nickname: &str,
    tcp_port: u16,
    udp_port: u16,
    bw: Arc<BandwidthLimiter>,
    progress_tx: mpsc::Sender<(usize, u64)>,
    shared_part_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
) -> anyhow::Result<()> {
    use super::messages::*;
    use flate2::read::ZlibDecoder;
    use std::io::{Read, Seek, Write};
    use tokio::net::TcpStream;

    let addr: SocketAddr = format!("{}:{}", source.peer_ip, source.peer_port).parse()?;

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        TcpStream::connect(addr),
    )
    .await??;

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    // Hello handshake
    let hello_payload = build_hello(user_hash, 0, tcp_port, nickname);
    write_packet_async_ms(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

    let (h_proto, h_opcode, _payload) = read_packet_timeout_ms(&mut reader).await?;
    if h_proto != OP_EDONKEYHEADER || h_opcode != OP_HELLOANSWER {
        anyhow::bail!("source {}: expected HelloAnswer, got proto=0x{h_proto:02X} op=0x{h_opcode:02X}", _src_idx);
    }

    let emule_payload = build_emule_info(udp_port);
    write_packet_async_ms(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

    let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
    match read_packet_timeout_ms(&mut reader).await {
        Ok((proto, opcode, payload)) => {
            if proto == OP_EMULEPROT && opcode == OP_EMULEINFOANSWER {
                debug!("Got EmuleInfoAnswer from source {}", _src_idx);
            } else {
                deferred_packet = Some((proto, opcode, payload));
            }
        }
        Err(e) => {
            debug!("EmuleInfo exchange failed for source {}: {e}", _src_idx);
        }
    }

    // File request
    let file_req = build_file_request(file_hash);
    write_packet_async_ms(&mut writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req).await?;
    write_packet_async_ms(&mut writer, OP_EDONKEYHEADER, OP_REQUESTFILENAME, &file_req).await?;

    // Read responses (consume deferred packet first)
    for _ in 0..5 {
        let (proto, opcode, _payload) = if let Some(pkt) = deferred_packet.take() {
            pkt
        } else {
            read_packet_timeout_ms(&mut reader).await?
        };
        if proto == OP_EDONKEYHEADER && opcode == OP_FILEREQANSNOFIL {
            anyhow::bail!("peer does not have the file");
        }
        if proto == OP_EDONKEYHEADER && opcode == OP_FILESTATUS {
            break;
        }
    }

    // Request part hashset if not already populated (first source to connect does this)
    {
        let existing = shared_part_hashes.read().await;
        if existing.is_empty() {
            drop(existing);
            let hashset_req = build_hashset_request(file_hash);
            write_packet_async_ms(
                &mut writer,
                OP_EDONKEYHEADER,
                OP_HASHSETREQ,
                &hashset_req,
            )
            .await?;
            match read_packet_timeout_ms(&mut reader).await {
                Ok((proto, opcode, payload))
                    if proto == OP_EDONKEYHEADER && opcode == OP_HASHSETANSWER =>
                {
                    if let Ok((_h, hashes)) = parse_hashset_answer(&payload) {
                        debug!("Got hashset with {} part hashes from source {}", hashes.len(), _src_idx);
                        let mut ph = shared_part_hashes.write().await;
                        if ph.is_empty() {
                            *ph = hashes;
                        }
                    }
                }
                _ => {
                    debug!("No hashset answer from source {} (peer may not support it)", _src_idx);
                }
            }
        }
    }

    // Request upload slot
    let upload_req = build_file_request(file_hash);
    write_packet_async_ms(&mut writer, OP_EDONKEYHEADER, OP_STARTUPLOADREQ, &upload_req).await?;

    // Wait for the uploader to grant a slot. Don't re-request; eMule
    // uploaders push OP_ACCEPTUPLOADREQ when a slot opens.
    let queue_start = std::time::Instant::now();
    loop {
        if queue_start.elapsed().as_secs() > 600 {
            anyhow::bail!("timed out waiting for upload slot");
        }
        let remaining = 600u64.saturating_sub(queue_start.elapsed().as_secs()).max(60);
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(remaining),
            read_packet_async_ms(&mut reader),
        )
        .await;
        let (proto, opcode, _payload) = match result {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => anyhow::bail!("connection lost while queued: {e}"),
            Err(_) => anyhow::bail!("timed out waiting for upload slot"),
        };
        if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
            break;
        }
        if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
            anyhow::bail!("peer has no free upload slots (OutOfPartReqs)");
        }
        // OP_QUEUERANKING or OP_QUEUERANK — just keep waiting
    }

    // Open the shared .part file
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(part_path)?;

    // eMule-style adaptive pipelining: keeps 1-3 request packets outstanding
    const MAX_BLOCKS_PER_REQUEST: usize = 3;
    let mut peer_out_of_parts = false;
    let mut measured_speed: u64 = 0;
    let mut speed_start = std::time::Instant::now();
    let mut speed_bytes: u64 = 0;

    for &part_idx in parts {
        if peer_out_of_parts {
            break;
        }
        {
            let t = tracker.read().await;
            if t.is_part_complete(part_idx) {
                continue;
            }
        }

        let (part_start, part_end) = {
            let t = tracker.read().await;
            t.part_range(part_idx)
        };

        // Pre-compute all block offsets for this part
        let mut all_blocks: Vec<(u64, u64)> = Vec::new();
        {
            let mut cursor = part_start;
            while cursor < part_end {
                let chunk_end = (cursor + EMBLOCKSIZE).min(part_end);
                all_blocks.push((cursor, chunk_end));
                cursor = chunk_end;
            }
        }

        let batches: Vec<Vec<(u64, u64)>> = all_blocks
            .chunks(MAX_BLOCKS_PER_REQUEST)
            .map(|c| c.to_vec())
            .collect();

        let max_outstanding = outstanding_requests_for_speed_ms(measured_speed);
        let mut sent_idx: usize = 0;
        let mut total_sent_bytes: u64 = 0;
        let mut total_received: u64 = 0;

        // Send initial batch of requests
        while sent_idx < batches.len() && sent_idx < max_outstanding {
            let batch = &batches[sent_idx];
            let req_payload = build_request_parts_i64(file_hash, batch);
            write_packet_async_ms(&mut writer, OP_EMULEPROT, OP_REQUESTPARTS_I64, &req_payload)
                .await?;
            total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
            sent_idx += 1;
        }

        let mut blocks_received_in_current_req: usize = 0;
        let mut completed_reqs: usize = 0;

        while total_received < total_sent_bytes {
            if peer_out_of_parts {
                break;
            }

            let (proto, opcode, payload) = read_packet_timeout_ms(&mut reader).await?;

            match (proto, opcode) {
                (OP_EMULEPROT, OP_SENDINGPART_I64) | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                    let (_hash, start, end, data) = if opcode == OP_SENDINGPART_I64 {
                        parse_sending_part_i64(&payload)?
                    } else {
                        parse_sending_part_32(&payload)?
                    };

                    let piece_len = end - start;
                    bw.acquire_download(piece_len).await;

                    output.seek(std::io::SeekFrom::Start(start))?;
                    output.write_all(data)?;

                    total_received += piece_len;
                    blocks_received_in_current_req += 1;
                    speed_bytes += piece_len;
                    let _ = progress_tx.send((_src_idx, piece_len)).await;
                }
                (OP_EMULEPROT, OP_COMPRESSEDPART_I64) | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
                    let (_hash, start, _packed_len, compressed) =
                        parse_compressed_part_i64(&payload)?;

                    let mut decoder = ZlibDecoder::new(compressed);
                    let mut decompressed = Vec::new();
                    let mut buf = [0u8; 8192];
                    loop {
                        let n = decoder.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        decompressed.extend_from_slice(&buf[..n]);
                        if decompressed.len() > MAX_DECOMPRESSED_PART {
                            anyhow::bail!("decompressed part exceeds size limit");
                        }
                    }

                    let piece_len = decompressed.len() as u64;
                    bw.acquire_download(piece_len).await;

                    output.seek(std::io::SeekFrom::Start(start))?;
                    output.write_all(&decompressed)?;

                    total_received += piece_len;
                    blocks_received_in_current_req += 1;
                    speed_bytes += piece_len;
                    let _ = progress_tx.send((_src_idx, piece_len)).await;
                }
                (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                    peer_out_of_parts = true;
                    break;
                }
                _ => {}
            }

            // Pipeline refill when a request's worth of blocks completes
            let blocks_in_batch = if completed_reqs < batches.len() {
                batches[completed_reqs].len()
            } else {
                MAX_BLOCKS_PER_REQUEST
            };
            if blocks_received_in_current_req >= blocks_in_batch {
                blocks_received_in_current_req = 0;
                completed_reqs += 1;
                if sent_idx < batches.len() {
                    let batch = &batches[sent_idx];
                    let req_payload = build_request_parts_i64(file_hash, batch);
                    write_packet_async_ms(
                        &mut writer,
                        OP_EMULEPROT,
                        OP_REQUESTPARTS_I64,
                        &req_payload,
                    )
                    .await?;
                    total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                    sent_idx += 1;
                }
            }

            let elapsed = speed_start.elapsed();
            if elapsed.as_millis() >= 2000 {
                measured_speed =
                    (speed_bytes as u128 * 1000 / elapsed.as_millis().max(1)) as u64;
                speed_bytes = 0;
                speed_start = std::time::Instant::now();
            }
        }

        // Verify part hash before marking complete
        let hash_ok = {
            let ph = shared_part_hashes.read().await;
            if part_idx < ph.len() {
                let expected_hash = ph[part_idx];
                let t = tracker.read().await;
                let (ps, pe) = t.part_range(part_idx);
                let part_len = (pe - ps) as usize;
                drop(t);

                output.seek(std::io::SeekFrom::Start(ps))?;
                let mut part_data = vec![0u8; part_len];
                output.read_exact(&mut part_data)?;

                use digest::Digest;
                use md4::Md4;
                let actual_hash: [u8; 16] = Md4::digest(&part_data).into();

                if actual_hash != expected_hash {
                    warn!(
                        "Multi-source part {} hash mismatch from source {}! expected={} got={}",
                        part_idx, _src_idx,
                        hex::encode(expected_hash),
                        hex::encode(actual_hash)
                    );
                    false
                } else {
                    debug!("Multi-source part {} hash verified OK (source {})", part_idx, _src_idx);
                    true
                }
            } else {
                true // no hashset available, assume OK
            }
        };

        {
            let mut t = tracker.write().await;
            if hash_ok {
                t.mark_complete(part_idx);
            } else {
                t.mark_incomplete(part_idx);
            }
            t.save();
        }
    }

    // Signal the uploader that we're done
    write_packet_async_ms(
        &mut writer,
        OP_EDONKEYHEADER,
        OP_END_OF_DOWNLOAD,
        &[],
    )
    .await
    .ok();

    Ok(())
}

fn outstanding_requests_for_speed_ms(speed: u64) -> usize {
    if speed < 4 * 1024 {
        1
    } else if speed < 36 * 1024 {
        2
    } else {
        3
    }
}

fn parse_sending_part_32(payload: &[u8]) -> std::io::Result<([u8; 16], u64, u64, &[u8])> {
    if payload.len() < 24 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sending part 32 too short",
        ));
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[..16]);
    let start = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]) as u64;
    let end = u32::from_le_bytes([payload[20], payload[21], payload[22], payload[23]]) as u64;
    Ok((hash, start, end, &payload[24..]))
}

async fn read_packet_timeout_ms<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(60),
        read_packet_async_ms(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async_ms<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }
    Ok((protocol, opcode, payload))
}

async fn write_packet_async_ms<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    writer.write_u32_le((1 + payload.len()) as u32).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}
