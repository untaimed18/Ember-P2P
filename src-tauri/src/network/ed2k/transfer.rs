use std::io::{Read, Seek, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::sharing::manager::TransferControl;

use super::messages::*;
use super::part_tracker::PartTracker;

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_SECS: u64 = 10;
const MAX_QUEUE_WAIT_SECS: u64 = 600;
const READ_TIMEOUT_SECS: u64 = 60;

/// Maximum decompressed part size (PARTSIZE + margin = 10 MiB)
const MAX_DECOMPRESSED_PART: usize = 10 * 1024 * 1024;

/// Maximum allowed file size for downloads (4 TiB)
const MAX_DOWNLOAD_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024 * 1024;

pub struct Ed2kDownload {
    pub transfer_id: String,
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub source_addr: SocketAddr,
    pub download_dir: PathBuf,
    pub user_hash: [u8; 16],
    pub nickname: String,
    pub tcp_port: u16,
    pub udp_port: u16,
    pub bandwidth_limiter: Arc<BandwidthLimiter>,
    pub control: Arc<TransferControl>,
}

#[derive(Debug, Clone)]
pub enum DownloadEvent {
    Progress {
        transfer_id: String,
        downloaded: u64,
        total: u64,
    },
    SourcesUpdate {
        transfer_id: String,
        total: u32,
        active: u32,
        queued: u32,
    },
    Completed {
        transfer_id: String,
    },
    Failed {
        transfer_id: String,
        error: String,
    },
}

impl Ed2kDownload {
    async fn check_control(&self) -> anyhow::Result<()> {
        if self.control.is_cancelled() {
            anyhow::bail!("cancelled by user");
        }
        while self.control.is_paused() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            if self.control.is_cancelled() {
                anyhow::bail!("cancelled while paused");
            }
        }
        Ok(())
    }

    pub async fn run(self, event_tx: mpsc::Sender<DownloadEvent>) -> anyhow::Result<()> {
        info!(
            "Starting download {} from {}",
            hex::encode(self.file_hash),
            self.source_addr
        );

        let mut last_err = String::new();

        for attempt in 1..=MAX_RETRIES {
            self.check_control().await?;

            if attempt > 1 {
                warn!(
                    "Retry {}/{} for {} after: {}",
                    attempt, MAX_RETRIES, self.transfer_id, last_err
                );
                tokio::time::sleep(std::time::Duration::from_secs(
                    RETRY_DELAY_SECS * attempt as u64,
                ))
                .await;
            }

            match self.download_inner(&event_tx).await {
                Ok(_) => {
                    let _ = event_tx
                        .send(DownloadEvent::Completed {
                            transfer_id: self.transfer_id.clone(),
                        })
                        .await;
                    return Ok(());
                }
                Err(e) => {
                    if self.control.is_cancelled() {
                        let _ = event_tx
                            .send(DownloadEvent::Failed {
                                transfer_id: self.transfer_id.clone(),
                                error: "Cancelled by user".to_string(),
                            })
                            .await;
                        return Ok(());
                    }
                    last_err = e.to_string();
                    warn!("Download attempt {attempt} failed: {last_err}");
                }
            }
        }

        let _ = event_tx
            .send(DownloadEvent::Failed {
                transfer_id: self.transfer_id.clone(),
                error: format!("Failed after {MAX_RETRIES} attempts: {last_err}"),
            })
            .await;

        anyhow::bail!("Failed after {MAX_RETRIES} attempts: {last_err}")
    }

    async fn download_inner(&self, event_tx: &mpsc::Sender<DownloadEvent>) -> anyhow::Result<()> {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            TcpStream::connect(self.source_addr),
        )
        .await??;

        let (reader, writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        // Send Hello
        let hello_payload = build_hello(&self.user_hash, 0, self.tcp_port, &self.nickname);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

        // Read HelloAnswer
        let (proto, opcode, _payload) = read_packet_with_timeout(&mut reader).await?;
        if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
            anyhow::bail!("expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
        }
        debug!("Got HelloAnswer from {}", self.source_addr);

        // Send EmuleInfo
        let emule_payload = build_emule_info(self.udp_port);
        write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

        // Read EmuleInfoAnswer (optional, some clients skip it)
        let (proto2, opcode2, payload2) = read_packet_with_timeout(&mut reader).await?;
        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFOANSWER {
            debug!("Got EmuleInfoAnswer");
        } else {
            debug!("Peer skipped EmuleInfoAnswer (got proto=0x{proto2:02X} op=0x{opcode2:02X}), deferring");
            deferred_packet = Some((proto2, opcode2, payload2));
        }

        // Send file request
        let file_req = build_file_request(&self.file_hash);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_SETREQFILEID, &file_req).await?;
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_REQUESTFILENAME, &file_req).await?;

        // Read FileStatus and FileName responses
        let mut got_status = false;
        let mut available_parts: Vec<bool> = Vec::new();

        for _ in 0..5 {
            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                read_packet_with_timeout(&mut reader).await?
            };

            match (proto, opcode) {
                (OP_EDONKEYHEADER, OP_FILESTATUS) => {
                    let (_hash, parts) = parse_file_status(&payload)?;
                    available_parts = parts;
                    got_status = true;
                    debug!("FileStatus: {} parts", available_parts.len());
                }
                (OP_EDONKEYHEADER, OP_REQFILENAMEANSWER) => {
                    debug!("Got filename answer");
                }
                (OP_EDONKEYHEADER, OP_FILEREQANSNOFIL) => {
                    anyhow::bail!("peer does not have the file");
                }
                _ => {
                    debug!("Ignoring packet proto=0x{proto:02X} op=0x{opcode:02X}");
                }
            }

            if got_status {
                break;
            }
        }

        if !got_status {
            anyhow::bail!("never received FileStatus");
        }

        // Request part hashset for verification
        let hashset_req = build_hashset_request(&self.file_hash);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HASHSETREQ, &hashset_req).await?;

        let mut part_hashes: Vec<[u8; 16]> = Vec::new();
        // Try to read hashset answer (some peers may not support it)
        match read_packet_with_timeout(&mut reader).await {
            Ok((proto, opcode, payload)) => {
                if proto == OP_EDONKEYHEADER && opcode == OP_HASHSETANSWER {
                    match parse_hashset_answer(&payload) {
                        Ok((_hash, hashes)) => {
                            debug!("Got hashset with {} part hashes", hashes.len());
                            part_hashes = hashes;
                        }
                        Err(e) => debug!("Failed to parse hashset answer: {e}"),
                    }
                } else {
                    debug!("Expected hashset answer, got proto=0x{proto:02X} op=0x{opcode:02X}");
                }
            }
            Err(e) => debug!("No hashset answer (peer may not support it): {e}"),
        }

        // Request upload slot
        let upload_req = build_file_request(&self.file_hash);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_STARTUPLOADREQ, &upload_req).await?;

        let _ = event_tx
            .send(DownloadEvent::SourcesUpdate {
                transfer_id: self.transfer_id.clone(),
                total: 1,
                active: 0,
                queued: 1,
            })
            .await;

        // Wait for AcceptUploadReq. The uploader decides when to grant a slot;
        // we simply keep the connection open and listen. Re-requesting too
        // aggressively gets clients penalised by eMule servers.
        let queue_start = std::time::Instant::now();

        loop {
            self.check_control().await?;

            if queue_start.elapsed().as_secs() > MAX_QUEUE_WAIT_SECS {
                anyhow::bail!("timed out waiting for upload slot after {MAX_QUEUE_WAIT_SECS}s");
            }

            // Use a longer timeout while queued — the uploader will push
            // OP_ACCEPTUPLOADREQ when a slot opens. We use the full queue
            // wait budget as the read timeout so we don't time out early.
            let remaining = MAX_QUEUE_WAIT_SECS - queue_start.elapsed().as_secs().min(MAX_QUEUE_WAIT_SECS);
            let read_timeout = remaining.max(READ_TIMEOUT_SECS);

            let result = tokio::time::timeout(
                std::time::Duration::from_secs(read_timeout),
                read_packet_async(&mut reader),
            )
            .await;

            let (proto, opcode, payload) = match result {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => anyhow::bail!("connection lost while queued: {e}"),
                Err(_) => {
                    anyhow::bail!("timed out waiting for upload slot after {MAX_QUEUE_WAIT_SECS}s");
                }
            };

            if proto == OP_EDONKEYHEADER && opcode == OP_ACCEPTUPLOADREQ {
                debug!("Upload accepted");
                let _ = event_tx
                    .send(DownloadEvent::SourcesUpdate {
                        transfer_id: self.transfer_id.clone(),
                        total: 1,
                        active: 1,
                        queued: 0,
                    })
                    .await;
                break;
            }

            if proto == OP_EMULEPROT && opcode == OP_QUEUERANKING && payload.len() >= 2 {
                let rank = u16::from_le_bytes([payload[0], payload[1]]);
                info!(
                    "Queued at position {} on peer {}",
                    rank, self.source_addr
                );
                continue;
            }

            if proto == OP_EDONKEYHEADER && opcode == OP_QUEUERANK && payload.len() >= 4 {
                let rank = u32::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]);
                info!(
                    "Queued at position {} on peer {} (legacy)",
                    rank, self.source_addr
                );
                continue;
            }

            if proto == OP_EDONKEYHEADER && opcode == OP_OUTOFPARTREQS {
                info!("Peer rejected with OutOfPartReqs, will retry later");
                anyhow::bail!("peer has no free upload slots (OutOfPartReqs)");
            }

            debug!("Waiting for accept, got proto=0x{proto:02X} op=0x{opcode:02X}");
        }

        if self.file_size > MAX_DOWNLOAD_FILE_SIZE {
            anyhow::bail!(
                "file size {} exceeds maximum allowed ({})",
                self.file_size,
                MAX_DOWNLOAD_FILE_SIZE
            );
        }

        // Ensure download directory exists
        if !self.download_dir.exists() {
            std::fs::create_dir_all(&self.download_dir)?;
        }

        // Create or resume output file (sanitize filename to prevent path traversal)
        let safe_name = crate::security::sanitize_filename(&self.file_name);
        let part_path = self.download_dir.join(format!("{}.part", self.transfer_id));
        let final_path = self.download_dir.join(&safe_name);

        let mut tracker = PartTracker::new(self.file_size, &part_path);

        let mut output = if part_path.exists() && tracker.completed_count() > 0 {
            info!(
                "Resuming download: {}/{} parts complete",
                tracker.completed_count(),
                tracker.part_count
            );
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .read(true)
                .open(&part_path)?
        } else {
            let f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&part_path)?;
            if self.file_size > 0 {
                f.set_len(self.file_size)?;
            }
            f
        };

        // Calculate current downloaded bytes from completed parts
        let mut downloaded: u64 = (0..tracker.part_count)
            .filter(|&i| tracker.is_part_complete(i))
            .map(|i| {
                let (start, end) = tracker.part_range(i);
                end - start
            })
            .sum();

        // Download needed parts with retry for hash-failed parts.
        // eMule-style adaptive pipelining: sends 1-3 OP_REQUESTPARTS_I64 packets
        // simultaneously based on connection speed, keeping the peer's upload pipe full.
        const MAX_PART_RETRIES: usize = 3;
        const MAX_BLOCKS_PER_REQUEST: usize = 3;
        let mut peer_out_of_parts = false;
        let mut measured_speed: u64 = 0;
        let mut speed_measure_start = std::time::Instant::now();
        let mut speed_measure_bytes: u64 = 0;

        for retry_round in 0..=MAX_PART_RETRIES {
            let needed = tracker.needed_parts(&available_parts);
            if needed.is_empty() {
                break;
            }
            if retry_round > 0 {
                warn!(
                    "Retry round {}/{} for {} hash-failed parts",
                    retry_round, MAX_PART_RETRIES, needed.len()
                );
            }

            for part_idx in needed {
                if peer_out_of_parts {
                    break;
                }
                self.check_control().await?;

                let (part_start, part_end) = tracker.part_range(part_idx);

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

                // Group blocks into request batches of 3 (OP_REQUESTPARTS_I64 limit)
                let batches: Vec<Vec<(u64, u64)>> = all_blocks
                    .chunks(MAX_BLOCKS_PER_REQUEST)
                    .map(|c| c.to_vec())
                    .collect();

                // Adaptive outstanding requests based on observed speed (like eMule)
                let max_outstanding = outstanding_requests_for_speed(measured_speed);
                let mut sent_idx: usize = 0;
                let mut total_sent_bytes: u64 = 0;
                let mut total_received: u64 = 0;

                // Send initial batch of requests to fill the pipeline
                while sent_idx < batches.len() && sent_idx < max_outstanding {
                    let batch = &batches[sent_idx];
                    let req_payload = build_request_parts_i64(&self.file_hash, batch);
                    write_packet_async(
                        &mut writer,
                        OP_EMULEPROT,
                        OP_REQUESTPARTS_I64,
                        &req_payload,
                    )
                    .await?;
                    total_sent_bytes += batch.iter().map(|(s, e)| e - s).sum::<u64>();
                    sent_idx += 1;
                }

                // Track how many blocks received per request for pipeline refill
                let mut blocks_received_in_current_req: usize = 0;
                let mut completed_reqs: usize = 0;

                // Receive loop: process blocks and refill pipeline as requests complete
                while total_received < total_sent_bytes {
                    if peer_out_of_parts {
                        break;
                    }
                    self.check_control().await?;

                    let (proto, opcode, payload) =
                        read_packet_with_timeout(&mut reader).await?;

                    match (proto, opcode) {
                        (OP_EMULEPROT, OP_SENDINGPART_I64)
                        | (OP_EDONKEYHEADER, OP_SENDINGPART) => {
                            let (_hash, start, end, data) =
                                if opcode == OP_SENDINGPART_I64 {
                                    parse_sending_part_i64(&payload)?
                                } else {
                                    parse_sending_part_32(&payload)?
                                };

                            let piece_len = end - start;
                            self.acquire_download_bandwidth(piece_len).await;

                            output.seek(std::io::SeekFrom::Start(start))?;
                            output.write_all(data)?;

                            total_received += piece_len;
                            downloaded += piece_len;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += piece_len;

                            let _ = event_tx
                                .send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded,
                                    total: self.file_size,
                                })
                                .await;
                        }
                        (OP_EMULEPROT, OP_COMPRESSEDPART_I64)
                        | (OP_EMULEPROT, OP_COMPRESSEDPART) => {
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
                            self.acquire_download_bandwidth(piece_len).await;

                            output.seek(std::io::SeekFrom::Start(start))?;
                            output.write_all(&decompressed)?;

                            total_received += piece_len;
                            downloaded += piece_len;
                            blocks_received_in_current_req += 1;
                            speed_measure_bytes += piece_len;

                            let _ = event_tx
                                .send(DownloadEvent::Progress {
                                    transfer_id: self.transfer_id.clone(),
                                    downloaded,
                                    total: self.file_size,
                                })
                                .await;
                        }
                        (OP_EDONKEYHEADER, OP_OUTOFPARTREQS) => {
                            info!("Peer session limit reached (OutOfPartReqs), will re-queue");
                            peer_out_of_parts = true;
                            break;
                        }
                        _ => {
                            debug!(
                                "During download, ignoring proto=0x{proto:02X} op=0x{opcode:02X}"
                            );
                        }
                    }

                    // When a request's worth of blocks is complete, send the next one
                    let blocks_in_current_batch = if completed_reqs < batches.len() {
                        batches[completed_reqs].len()
                    } else {
                        MAX_BLOCKS_PER_REQUEST
                    };
                    if blocks_received_in_current_req >= blocks_in_current_batch {
                        blocks_received_in_current_req = 0;
                        completed_reqs += 1;
                        // Pipeline refill: send next request if available
                        if sent_idx < batches.len() {
                            let batch = &batches[sent_idx];
                            let req_payload = build_request_parts_i64(&self.file_hash, batch);
                            write_packet_async(
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

                    // Update speed measurement every 2 seconds
                    let elapsed = speed_measure_start.elapsed();
                    if elapsed.as_millis() >= 2000 {
                        measured_speed = (speed_measure_bytes as u128 * 1000
                            / elapsed.as_millis().max(1)) as u64;
                        speed_measure_bytes = 0;
                        speed_measure_start = std::time::Instant::now();
                    }
                }

                // Verify part hash if we have the hashset
                if part_idx < part_hashes.len() {
                    let expected_hash = part_hashes[part_idx];
                    let (ps, pe) = tracker.part_range(part_idx);
                    let part_len = (pe - ps) as usize;

                    output.seek(std::io::SeekFrom::Start(ps))?;
                    let mut part_data = vec![0u8; part_len];
                    output.read_exact(&mut part_data)?;

                    use digest::Digest;
                    use md4::Md4;
                    let actual_hash: [u8; 16] = Md4::digest(&part_data).into();

                    if actual_hash != expected_hash {
                        let aich_hash = super::aich::compute_aich_part(&part_data);
                        let total_blocks = (part_data.len() + super::aich::AICH_BLOCK_SIZE - 1)
                            / super::aich::AICH_BLOCK_SIZE;
                        warn!(
                            "Part {} hash mismatch! expected={} got={}, AICH={} ({} blocks in part)",
                            part_idx,
                            hex::encode(expected_hash),
                            hex::encode(actual_hash),
                            hex::encode(aich_hash),
                            total_blocks,
                        );
                        tracker.mark_incomplete(part_idx);
                        tracker.save();
                        continue;
                    }
                    debug!("Part {} hash verified OK", part_idx);
                }

                tracker.mark_complete(part_idx);
                tracker.save();
            }

            // If peer ended the session, reset flag for next retry round
            peer_out_of_parts = false;
        }

        // Signal the uploader that we're done downloading from them
        write_packet_async(
            &mut writer,
            OP_EDONKEYHEADER,
            OP_END_OF_DOWNLOAD,
            &[],
        )
        .await
        .ok();

        if !tracker.all_complete() {
            let remaining = tracker.part_count - tracker.completed_count();
            anyhow::bail!(
                "{remaining} parts still failing hash verification after {MAX_PART_RETRIES} retries"
            );
        }

        output.flush()?;
        drop(output);

        // Clean up part.met and rename to final filename
        tracker.delete_met();
        std::fs::rename(&part_path, &final_path)?;
        // Verify the final file hash
        let output_path = final_path.clone();
        let expected_hash = hex::encode(self.file_hash);
        match tokio::task::spawn_blocking(move || {
            super::hash::ed2k_hash_file(&output_path)
        }).await {
            Ok(Ok(actual_hash)) if actual_hash == expected_hash => {
                info!("Download complete and verified: {}", self.file_name);
            }
            Ok(Ok(actual_hash)) => {
                warn!(
                    "Download complete but hash mismatch for {}: expected={}, got={}",
                    self.file_name, expected_hash, actual_hash
                );
            }
            _ => {
                info!("Download complete (could not verify hash): {}", self.file_name);
            }
        }

        Ok(())
    }

    async fn acquire_download_bandwidth(&self, bytes: u64) {
        self.bandwidth_limiter.acquire_download(bytes).await;
    }
}

/// eMule-style adaptive pipelining: number of OP_REQUESTPARTS packets to
/// keep in flight simultaneously based on observed connection speed.
/// Ref: eMule DownloadClient.cpp — slow connections get 1 request (3 blocks),
/// medium get 2 (6 blocks), fast get 3 (9 blocks).
fn outstanding_requests_for_speed(speed: u64) -> usize {
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

async fn read_packet_with_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(READ_TIMEOUT_SECS),
        read_packet_async(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async<R: AsyncReadExt + Unpin>(
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

async fn write_packet_async<W: AsyncWriteExt + Unpin>(
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
