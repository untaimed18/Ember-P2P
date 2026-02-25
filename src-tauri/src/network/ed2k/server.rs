use std::collections::VecDeque;
use std::io::{Read as _, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;

use super::messages::*;

const MAX_CONCURRENT_UPLOADS: usize = 5;
const CLIENT_TIMEOUT_SECS: u64 = 120;

pub struct UploadEvent {
    pub transfer_id: String,
    pub kind: UploadEventKind,
}

pub enum UploadEventKind {
    Started {
        file_name: String,
        file_hash: String,
        total_size: u64,
        peer_addr: String,
    },
    Progress {
        uploaded: u64,
        total: u64,
    },
    Completed,
    Failed {
        error: String,
    },
}

struct UploadServer {
    local_index: Arc<RwLock<LocalIndex>>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    shared_folders: Vec<String>,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    upload_queue: Arc<tokio::sync::Mutex<VecDeque<SocketAddr>>>,
}

pub async fn start_upload_server(
    tcp_port: u16,
    user_hash: [u8; 16],
    nickname: String,
    udp_port: u16,
    shared_folders: Vec<String>,
    local_index: Arc<RwLock<LocalIndex>>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{tcp_port}").parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("ED2K TCP upload server listening on port {tcp_port}");

    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upload_queue = Arc::new(tokio::sync::Mutex::new(VecDeque::new()));

    let server = Arc::new(UploadServer {
        local_index,
        transfer_manager,
        bandwidth_limiter,
        shared_folders,
        user_hash,
        nickname,
        tcp_port,
        udp_port,
        active_count,
        upload_event_tx,
        upload_queue,
    });

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                debug!("Incoming ED2K connection from {peer_addr}");
                let server = server.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.handle_connection(stream, peer_addr).await {
                        warn!("Connection from {peer_addr} ended: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("TCP accept error: {e}");
            }
        }
    }
}

impl UploadServer {
    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let (reader, writer) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let mut writer = tokio::io::BufWriter::new(writer);

        // Read Hello from peer
        let (proto, opcode, _payload) = read_packet_timeout(&mut reader).await?;
        if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
            anyhow::bail!("expected Hello, got proto=0x{proto:02X} op=0x{opcode:02X}");
        }
        debug!("Got Hello from {peer_addr}");

        // Send HelloAnswer
        let hello_payload = build_hello(&self.user_hash, 0, self.tcp_port, &self.nickname);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HELLOANSWER, &hello_payload).await?;

        // Handle EmuleInfo exchange
        let (proto, opcode, _payload) = read_packet_timeout(&mut reader).await?;
        if proto == OP_EMULEPROT && opcode == OP_EMULEINFO {
            let emule_payload = build_emule_info(self.udp_port);
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_payload).await?;
        }

        // Now handle file requests in a loop
        let mut current_file_hash: Option<[u8; 16]> = None;
        let mut uploaded: u64 = 0;
        let mut transfer_id: Option<String> = None;
        let mut total_size: u64 = 0;

        loop {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
                read_packet_async_inner(&mut reader),
            )
            .await;

            let (proto, opcode, payload) = match result {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    debug!("Client disconnected: {e}");
                    break;
                }
                Err(_) => {
                    debug!("Client timed out");
                    break;
                }
            };

            match (proto, opcode) {
                (OP_EDONKEYHEADER, OP_SETREQFILEID) => {
                    if payload.len() >= 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[..16]);
                        current_file_hash = Some(hash);

                        let hash_hex = hex::encode(hash);
                        let index = self.local_index.read().await;
                        if let Some(file) = index.get_by_hash(&hash_hex) {
                            let part_count = ((file.size + PARTSIZE - 1) / PARTSIZE) as u16;
                            let bitmap_bytes = ((part_count as usize) + 7) / 8;
                            let mut status_payload = Vec::with_capacity(18 + bitmap_bytes);
                            status_payload.extend_from_slice(&hash);
                            status_payload.extend_from_slice(&part_count.to_le_bytes());
                            // All parts available (all bits set)
                            let full_bytes = bitmap_bytes;
                            for i in 0..full_bytes {
                                let remaining_bits = part_count as usize - i * 8;
                                if remaining_bits >= 8 {
                                    status_payload.push(0xFF);
                                } else {
                                    status_payload.push((1u8 << remaining_bits) - 1);
                                }
                            }
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILESTATUS,
                                &status_payload,
                            )
                            .await?;

                            total_size = file.size;
                        } else {
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILEREQANSNOFIL,
                                &hash,
                            )
                            .await?;
                            current_file_hash = None;
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_REQUESTFILENAME) => {
                    if let Some(hash) = current_file_hash {
                        let hash_hex = hex::encode(hash);
                        let index = self.local_index.read().await;
                        if let Some(file) = index.get_by_hash(&hash_hex) {
                            let name_bytes = file.name.as_bytes();
                            let mut resp = Vec::with_capacity(16 + 2 + name_bytes.len());
                            resp.extend_from_slice(&hash);
                            resp.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
                            resp.extend_from_slice(name_bytes);
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_REQFILENAMEANSWER,
                                &resp,
                            )
                            .await?;
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_STARTUPLOADREQ) => {
                    if current_file_hash.is_none() && payload.len() >= 16 {
                        let mut hash = [0u8; 16];
                        hash.copy_from_slice(&payload[..16]);
                        current_file_hash = Some(hash);
                    }

                    let current_active = self
                        .active_count
                        .load(std::sync::atomic::Ordering::Relaxed);

                    let should_accept = if current_active >= MAX_CONCURRENT_UPLOADS {
                        false
                    } else {
                        let mut queue = self.upload_queue.lock().await;
                        if queue.is_empty() {
                            true
                        } else if queue.front() == Some(&peer_addr) {
                            queue.pop_front();
                            true
                        } else {
                            false
                        }
                    };

                    if !should_accept {
                        let mut queue = self.upload_queue.lock().await;
                        let rank = if let Some(pos) = queue.iter().position(|a| *a == peer_addr) {
                            (pos + 1) as u16
                        } else {
                            queue.push_back(peer_addr);
                            queue.len() as u16
                        };
                        drop(queue);
                        let mut qr_payload = Vec::with_capacity(12);
                        qr_payload.extend_from_slice(&rank.to_le_bytes());
                        qr_payload.resize(12, 0);
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_QUEUERANKING,
                            &qr_payload,
                        )
                        .await?;
                        continue;
                    }

                    // Accept the upload
                    write_packet_async(
                        &mut writer,
                        OP_EDONKEYHEADER,
                        OP_ACCEPTUPLOADREQ,
                        &[],
                    )
                    .await?;

                    self.active_count
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                    if let Some(hash) = current_file_hash {
                        let tid = uuid::Uuid::new_v4().to_string();
                        transfer_id = Some(tid.clone());

                        let hash_hex = hex::encode(hash);
                        let file_name = {
                            let index = self.local_index.read().await;
                            index.get_by_hash(&hash_hex).map(|f| f.name.clone())
                        };

                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: tid,
                            kind: UploadEventKind::Started {
                                file_name: file_name.unwrap_or_default(),
                                file_hash: hash_hex,
                                total_size,
                                peer_addr: peer_addr.to_string(),
                            },
                        }).await;
                    }
                }

                (OP_EMULEPROT, OP_REQUESTPARTS_I64) | (OP_EDONKEYHEADER, OP_REQUESTPARTS) => {
                    let hash = if let Some(h) = current_file_hash {
                        h
                    } else {
                        continue;
                    };

                    let offsets = if opcode == OP_REQUESTPARTS_I64 {
                        parse_request_parts_i64(&payload)?
                    } else {
                        parse_request_parts_32(&payload)?
                    };

                    let hash_hex = hex::encode(hash);
                    let file_path = {
                        let index = self.local_index.read().await;
                        index.get_by_hash(&hash_hex).map(|f| PathBuf::from(&f.path))
                    };

                    let file_path = match file_path {
                        Some(p) => {
                            let in_shared = self.shared_folders.iter().any(|folder| {
                                p.starts_with(folder)
                            });
                            if !in_shared && !self.shared_folders.is_empty() {
                                warn!("Rejected upload for file not in shared folders: {}", p.display());
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_FILEREQANSNOFIL,
                                    &hash,
                                )
                                .await?;
                                continue;
                            }
                            p
                        }
                        None => {
                            write_packet_async(
                                &mut writer,
                                OP_EDONKEYHEADER,
                                OP_FILEREQANSNOFIL,
                                &hash,
                            )
                            .await?;
                            continue;
                        }
                    };

                    for (start, end) in offsets {
                        if start >= end {
                            continue;
                        }

                        // Check if the upload was cancelled by the user
                        // (TransferManager::cancel removes the transfer from active)
                        if let Some(tid) = &transfer_id {
                            let mgr = self.transfer_manager.read().await;
                            let cancelled = !mgr.active.contains_key(tid);
                            drop(mgr);
                            if cancelled {
                                info!("Upload {tid} cancelled by user, aborting");
                                self.active_count
                                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                                return Ok(());
                            }
                        }

                        let len = (end - start) as usize;
                        let mut data = vec![0u8; len];

                        let read_result = {
                            let fp = file_path.clone();
                            tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
                                let mut f = std::fs::File::open(&fp)?;
                                f.seek(SeekFrom::Start(start))?;
                                let mut buf = vec![0u8; len];
                                f.read_exact(&mut buf)?;
                                Ok(buf)
                            })
                            .await?
                        };

                        data = match read_result {
                            Ok(d) => d,
                            Err(e) => {
                                warn!("Failed to read file chunk: {e}");
                                break;
                            }
                        };

                        // Apply bandwidth limiting
                        self.acquire_upload_bandwidth(data.len() as u64).await;

                        // Build SendingPart_I64 packet
                        let mut part_payload = Vec::with_capacity(32 + data.len());
                        part_payload.extend_from_slice(&hash);
                        part_payload.extend_from_slice(&start.to_le_bytes());
                        part_payload.extend_from_slice(&end.to_le_bytes());
                        part_payload.extend_from_slice(&data);

                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_SENDINGPART_I64,
                            &part_payload,
                        )
                        .await?;

                        uploaded += data.len() as u64;

                        if let Some(tid) = &transfer_id {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind: UploadEventKind::Progress {
                                    uploaded,
                                    total: total_size,
                                },
                            }).await;
                        }
                    }
                }

                (OP_EDONKEYHEADER, OP_CANCELTRANSFER) | (OP_EDONKEYHEADER, OP_END_OF_DOWNLOAD) => {
                    debug!("Peer {peer_addr} cancelled/ended transfer");
                    if let Some(tid) = &transfer_id {
                        let _ = self.upload_event_tx.send(UploadEvent {
                            transfer_id: tid.clone(),
                            kind: UploadEventKind::Completed,
                        }).await;
                    }
                    self.active_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    break;
                }

                (OP_EDONKEYHEADER, OP_HASHSETREQ) if payload.len() >= 16 => {
                    let mut req_hash = [0u8; 16];
                    req_hash.copy_from_slice(&payload[..16]);
                    let hash_hex = hex::encode(req_hash);
                    let file_info = {
                        let index = self.local_index.read().await;
                        index.get_by_hash(&hash_hex).cloned()
                    };

                    if let Some(file) = file_info {
                        let path = PathBuf::from(&file.path);
                        let hashset_result = tokio::task::spawn_blocking(move || {
                            compute_part_hashes(&path)
                        })
                        .await?;

                        match hashset_result {
                            Ok(hashes) => {
                                let mut resp = Vec::with_capacity(16 + 2 + hashes.len() * 16);
                                resp.extend_from_slice(&req_hash);
                                resp.extend_from_slice(&(hashes.len() as u16).to_le_bytes());
                                for h in &hashes {
                                    resp.extend_from_slice(h);
                                }
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_HASHSETANSWER,
                                    &resp,
                                )
                                .await?;
                            }
                            Err(e) => {
                                warn!("Failed to compute hashset: {e}");
                            }
                        }
                    }
                }

                (OP_EMULEPROT, OP_REQUESTSOURCES) => {
                    if let Some(hash) = current_file_hash {
                        let mut resp = Vec::with_capacity(18);
                        resp.extend_from_slice(&hash);
                        resp.extend_from_slice(&0u16.to_le_bytes()); // 0 sources
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_ANSWERSOURCES2,
                            &resp,
                        )
                        .await?;
                    }
                }

                _ => {
                    debug!(
                        "Upload server ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {peer_addr}"
                    );
                }
            }
        }

        // Remove from upload queue on disconnect
        {
            let mut queue = self.upload_queue.lock().await;
            queue.retain(|a| *a != peer_addr);
        }

        // Cleanup: emit completion/failure for any tracked upload
        if let Some(tid) = &transfer_id {
            // If we got here without an explicit cancel/end, treat it as completed
            // (the peer may have disconnected after getting what it needed)
            let _ = self.upload_event_tx.send(UploadEvent {
                transfer_id: tid.clone(),
                kind: if uploaded > 0 {
                    UploadEventKind::Completed
                } else {
                    UploadEventKind::Failed {
                        error: "Peer disconnected before any data transferred".to_string(),
                    }
                },
            }).await;

            let prev = self
                .active_count
                .load(std::sync::atomic::Ordering::Relaxed);
            if prev > 0 {
                self.active_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        Ok(())
    }

    async fn acquire_upload_bandwidth(&self, bytes: u64) {
        loop {
            if self.bandwidth_limiter.acquire_upload(bytes).await {
                return;
            }
        }
    }
}

fn parse_request_parts_i64(payload: &[u8]) -> anyhow::Result<Vec<(u64, u64)>> {
    if payload.len() < 16 + 48 {
        anyhow::bail!("RequestParts_I64 too short");
    }
    // Skip 16-byte file hash
    let mut offsets = Vec::new();
    let starts_offset = 16;
    let ends_offset = 16 + 24; // 3 * 8 bytes

    for i in 0..3 {
        let start = u64::from_le_bytes(
            payload[starts_offset + i * 8..starts_offset + i * 8 + 8]
                .try_into()?,
        );
        let end = u64::from_le_bytes(
            payload[ends_offset + i * 8..ends_offset + i * 8 + 8]
                .try_into()?,
        );
        if start > 0 || end > 0 {
            offsets.push((start, end));
        }
    }
    Ok(offsets)
}

fn parse_request_parts_32(payload: &[u8]) -> anyhow::Result<Vec<(u64, u64)>> {
    if payload.len() < 16 + 24 {
        anyhow::bail!("RequestParts too short");
    }
    let mut offsets = Vec::new();
    let starts_offset = 16;
    let ends_offset = 16 + 12; // 3 * 4 bytes

    for i in 0..3 {
        let start = u32::from_le_bytes(
            payload[starts_offset + i * 4..starts_offset + i * 4 + 4]
                .try_into()?,
        ) as u64;
        let end = u32::from_le_bytes(
            payload[ends_offset + i * 4..ends_offset + i * 4 + 4]
                .try_into()?,
        ) as u64;
        if start > 0 || end > 0 {
            offsets.push((start, end));
        }
    }
    Ok(offsets)
}

const OP_HASHSETREQ: u8 = 0x51;
const OP_HASHSETANSWER: u8 = 0x52;

fn compute_part_hashes(path: &std::path::Path) -> anyhow::Result<Vec<[u8; 16]>> {
    use digest::Digest;
    use md4::Md4;

    let mut file = std::fs::File::open(path)?;
    let file_size = file.metadata()?.len();
    let num_parts = ((file_size + PARTSIZE - 1) / PARTSIZE) as usize;

    let mut hashes = Vec::with_capacity(num_parts);
    let mut buf = vec![0u8; 64 * 1024];
    let mut remaining = file_size;

    for _ in 0..num_parts {
        let part_size = remaining.min(PARTSIZE);
        let mut hasher = Md4::new();
        let mut part_remaining = part_size;

        while part_remaining > 0 {
            let to_read = (part_remaining as usize).min(buf.len());
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            part_remaining -= n as u64;
        }

        let hash = hasher.finalize();
        let mut h = [0u8; 16];
        h.copy_from_slice(&hash);
        hashes.push(h);
        remaining -= part_size;
    }

    Ok(hashes)
}

async fn read_packet_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
        read_packet_async_inner(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

async fn read_packet_async_inner<R: AsyncReadExt + Unpin>(
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
