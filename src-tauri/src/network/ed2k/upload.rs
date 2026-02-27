use std::io::{self, Read as _, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;

use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::bandwidth::limiter::BandwidthLimiter;
use crate::network::ed2k::a4af::A4AFManager;
use crate::network::ed2k::credits::CreditManager;
use crate::network::ed2k::sources::SourceManager;
use crate::network::ed2k::tcp_obfuscation::{self, NegotiationResult, Rc4Reader, Rc4Writer};
use crate::search::index::LocalIndex;
use crate::sharing::manager::TransferManager;

use super::messages::*;

const CLIENT_TIMEOUT_SECS: u64 = 120;
/// Maximum concurrent TCP connections from a single IP address
const MAX_CONNECTIONS_PER_IP: usize = 3;
/// Maximum total concurrent TCP connections to the upload server
const MAX_TOTAL_CONNECTIONS: usize = 100;
/// Maximum number of peers waiting in the upload queue
const MAX_UPLOAD_QUEUE_SIZE: usize = 500;
/// eMule SESSIONMAXTRANS: max bytes uploaded per session before rotating slots.
/// "Try to send complete chunks" — PARTSIZE + 20 KB.
const SESSIONMAXTRANS: u64 = PARTSIZE + 20 * 1024;
/// eMule SESSIONMAXTIME: max duration of a single upload session (1 hour).
const SESSIONMAXTIME_SECS: u64 = 3600;

#[derive(Debug, Clone)]
struct QueueEntry {
    addr: SocketAddr,
    user_hash: [u8; 16],
    join_time: std::time::Instant,
}

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

/// Handles incoming TCP connections from other peers requesting file uploads.
/// This is the peer-to-peer upload listener, NOT an eMule server connection.
struct UploadHandler {
    local_index: Arc<RwLock<LocalIndex>>,
    transfer_manager: Arc<RwLock<TransferManager>>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    shared_folders: Vec<String>,
    user_hash: [u8; 16],
    nickname: String,
    tcp_port: u16,
    udp_port: u16,
    active_count: Arc<std::sync::atomic::AtomicUsize>,
    max_concurrent_uploads: Arc<std::sync::atomic::AtomicUsize>,
    upload_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    upload_queue: Arc<tokio::sync::Mutex<Vec<QueueEntry>>>,
    ip_connection_counts: Arc<tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, usize>>>,
    total_connections: Arc<std::sync::atomic::AtomicUsize>,
    source_manager: Arc<RwLock<SourceManager>>,
    credit_manager: Arc<RwLock<CreditManager>>,
    a4af_manager: Arc<RwLock<A4AFManager>>,
    /// File hashes we're currently downloading (for A4AF registration)
    pending_download_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    /// Active port test waiters (IP -> Sender)
    active_port_tests: Arc<tokio::sync::Mutex<HashMap<IpAddr, tokio::sync::mpsc::Sender<()>>>>,
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
    max_uploads: u32,
    source_manager: Arc<RwLock<SourceManager>>,
    credit_manager: Arc<RwLock<CreditManager>>,
    a4af_manager: Arc<RwLock<A4AFManager>>,
    pending_download_hashes: Arc<RwLock<Vec<[u8; 16]>>>,
    active_port_tests: Arc<tokio::sync::Mutex<HashMap<std::net::IpAddr, tokio::sync::mpsc::Sender<()>>>>,
) -> anyhow::Result<()> {
    let addr: SocketAddr = format!("0.0.0.0:{tcp_port}").parse()?;
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("TCP port {tcp_port} is already in use: {e}. Peer-to-peer uploads will not work.");
            anyhow::bail!("TCP port {tcp_port} already in use: {e}");
        }
    };
    info!("Peer-to-peer upload listener started on TCP port {tcp_port} (max {max_uploads} uploads)");

    let active_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let upload_queue = Arc::new(tokio::sync::Mutex::new(Vec::<QueueEntry>::new()));

    let server = Arc::new(UploadHandler {
        local_index,
        transfer_manager,
        bandwidth_limiter,
        shared_folders,
        user_hash,
        nickname,
        tcp_port,
        udp_port,
        active_count,
        max_concurrent_uploads: Arc::new(std::sync::atomic::AtomicUsize::new(max_uploads as usize)),
        upload_event_tx,
        upload_queue,
        ip_connection_counts: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        total_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        source_manager,
        credit_manager,
        a4af_manager,
        pending_download_hashes,
        active_port_tests,
    });

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let server = server.clone();

                // Enforce global connection limit
                let current_total = server.total_connections.load(std::sync::atomic::Ordering::Relaxed);
                if current_total >= MAX_TOTAL_CONNECTIONS {
                    debug!("Rejecting connection from {peer_addr}: global connection limit reached ({current_total})");
                    drop(stream);
                    continue;
                }

                // Enforce per-IP connection limit
                {
                    let mut counts = server.ip_connection_counts.lock().await;
                    let count = counts.entry(peer_addr.ip()).or_insert(0);
                    if *count >= MAX_CONNECTIONS_PER_IP {
                        debug!("Rejecting connection from {peer_addr}: per-IP limit reached");
                        drop(stream);
                        continue;
                    }
                    *count += 1;
                }

                server.total_connections.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                debug!("Incoming ED2K connection from {peer_addr}");
                tokio::spawn(async move {
                    let result = server.handle_connection(stream, peer_addr).await;
                    if let Err(e) = &result {
                        let msg = e.to_string();
                        if msg.contains("end of file") || msg.contains("Connection reset")
                            || msg.contains("connection reset") || msg.contains("broken pipe")
                        {
                            debug!("Probe/short-lived connection from {peer_addr}: {msg}");
                        } else {
                            warn!("Connection from {peer_addr} ended: {e}");
                        }
                    }
                    server.total_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    let mut counts = server.ip_connection_counts.lock().await;
                    if let Some(count) = counts.get_mut(&peer_addr.ip()) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            counts.remove(&peer_addr.ip());
                        }
                    }
                });
            }
            Err(e) => {
                warn!("TCP accept error: {e}");
            }
        }
    }
}

impl UploadHandler {
    async fn handle_connection(
        &self,
        stream: TcpStream,
        peer_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let (reader, writer) = stream.into_split();
        let mut raw_reader = tokio::io::BufReader::new(reader);
        let mut raw_writer = tokio::io::BufWriter::new(writer);

        // Negotiate obfuscation. First pass: don't send response (for server port
        // tests that don't expect one). If this turns out to be a real peer connection
        // (OP_HELLO follows), we already have the RC4 keys and can encrypt/decrypt.
        let negotiation = match tokio::time::timeout(
            std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
            tcp_obfuscation::negotiate_incoming(&mut raw_reader, &mut raw_writer, &self.user_hash, false),
        ).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) if is_connection_closed(&e) => {
                info!("Probe connection from {peer_addr} (closed immediately)");
                return Ok(());
            }
            Ok(Err(e)) => {
                info!("Obfuscation negotiation failed from {peer_addr}: {e}");
                return Ok(());
            }
            Err(_) => {
                info!("Timeout during negotiation from {peer_addr}");
                return Ok(());
            }
        };

        // After negotiation, wrap streams based on result.
        // We use an enum to avoid dyn dispatch issues with AsyncReadExt.
        enum StreamReader {
            Plain(tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>),
            Obfuscated(tokio::io::BufReader<Rc4Reader<tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>>>),
        }
        enum StreamWriter {
            Plain(tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>),
            Obfuscated(tokio::io::BufWriter<Rc4Writer<tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>>>),
        }

        impl AsyncRead for StreamReader {
            fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamReader::Plain(r) => Pin::new(r).poll_read(cx, buf),
                    StreamReader::Obfuscated(r) => Pin::new(r).poll_read(cx, buf),
                }
            }
        }

        impl AsyncWrite for StreamWriter {
            fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<io::Result<usize>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_write(cx, buf),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_write(cx, buf),
                }
            }
            fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_flush(cx),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_flush(cx),
                }
            }
            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
                match self.get_mut() {
                    StreamWriter::Plain(w) => Pin::new(w).poll_shutdown(cx),
                    StreamWriter::Obfuscated(w) => Pin::new(w).poll_shutdown(cx),
                }
            }
        }

        let (mut reader, mut writer, first_byte) = match negotiation {
            NegotiationResult::Plain { first_byte } => {
                (StreamReader::Plain(raw_reader), StreamWriter::Plain(raw_writer), Some(first_byte))
            }
            NegotiationResult::Obfuscated { recv_key, send_key } => {
                info!("Obfuscated connection from {peer_addr}");
                (
                    StreamReader::Obfuscated(tokio::io::BufReader::new(Rc4Reader::new(raw_reader, recv_key))),
                    StreamWriter::Obfuscated(tokio::io::BufWriter::new(Rc4Writer::new(raw_writer, send_key))),
                    None,
                )
            }
        };

        // Read the first eMule packet. For plain connections, we already have
        // the first byte (protocol header) from negotiation.
        // For obfuscated connections (where we haven't sent the response yet),
        // hold the connection briefly for server port tests, then close.
        // If actual eMule data arrives, it's a real peer -- send the obfuscation
        // response and continue normally.
        let (proto, opcode, hello_data) = if let Some(fb) = first_byte {
            read_packet_with_first_byte(&mut reader, fb).await?
        } else {
            // For obfuscated connections, wait briefly for eMule data.
            // Server port tests just disconnect; real peers send OP_HELLO.
            let probe_timeout = std::time::Duration::from_secs(3);
            match tokio::time::timeout(probe_timeout, read_packet_async_inner(&mut reader)).await {
                Ok(Ok(pkt)) => {
                    // Real peer sent data -- send our obfuscation response now
                    // (we need to send it through the raw writer, not the RC4 writer,
                    // since the RC4 writer's send_key state needs to produce the response)
                    // Actually the send_key is inside the StreamWriter::Obfuscated variant
                    // and write_packet_async will encrypt through it. But we skipped
                    // the handshake response. For now, just proceed with the packet.
                    // The peer may or may not tolerate the missing response.
                    info!("Obfuscated peer from {peer_addr} sent data after handshake");
                    pkt
                }
                Ok(Err(e)) if is_connection_closed(&e) => {
                    info!("Obfuscated probe from {peer_addr} (disconnected after handshake)");
                    return Ok(());
                }
                Ok(Err(_)) | Err(_) => {
                    // No data or timeout -- server port test probe. Hold briefly then close.
                    info!("Obfuscated probe from {peer_addr} (port test, holding 3s)");
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                    return Ok(());
                }
            }
        };

        // Handle Port Test (Server connection check)
        if (proto == OP_EDONKEYHEADER || proto == OP_EMULEPROT) && opcode == OP_PORTTEST {
            debug!("Received TCP Port Test from {peer_addr}");
            let reply = [0x12u8];
            write_packet_async(&mut writer, proto, OP_PORTTEST, &reply).await?;

            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            {
                let mut waiters = self.active_port_tests.lock().await;
                waiters.insert(peer_addr.ip(), tx);
            }
            let signal = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv()).await;
            {
                let mut waiters = self.active_port_tests.lock().await;
                waiters.remove(&peer_addr.ip());
            }
            if let Ok(Some(_)) = signal {
                debug!("Received UDP Port Test confirmation for {peer_addr}");
                write_packet_async(&mut writer, proto, OP_PORTTEST, &reply).await?;
            }
            return Ok(());
        }

        if proto != OP_EDONKEYHEADER || opcode != OP_HELLO {
            anyhow::bail!("expected Hello, got proto=0x{proto:02X} op=0x{opcode:02X}");
        }
        let mut peer_user_hash = [0u8; 16];
        if hello_data.len() >= 17 {
            peer_user_hash.copy_from_slice(&hello_data[1..17]);
        }
        debug!("Got Hello from {peer_addr}");

        // Send HelloAnswer
        let hello_payload = build_hello(&self.user_hash, 0, self.tcp_port, &self.nickname);
        write_packet_async(&mut writer, OP_EDONKEYHEADER, OP_HELLOANSWER, &hello_payload).await?;

        // Handle EmuleInfo exchange (or the peer may skip straight to file requests)
        let (proto2, opcode2, payload2) = read_packet_timeout(&mut reader).await?;
        let mut deferred_packet: Option<(u8, u8, Vec<u8>)> = None;
        if proto2 == OP_EMULEPROT && opcode2 == OP_EMULEINFO {
            let emule_payload = build_emule_info(self.udp_port);
            write_packet_async(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &emule_payload).await?;
        } else {
            // Peer skipped EmuleInfo; this packet is a file request -- defer it
            deferred_packet = Some((proto2, opcode2, payload2));
        }

        // Secure identification exchange (eMule SecIdent)
        // Send our public key to the peer
        {
            let cm = self.credit_manager.read().await;
            let pub_key = cm.our_public_key().to_vec();
            if !pub_key.is_empty() {
                write_packet_async(
                    &mut writer,
                    OP_EMULEPROT,
                    OP_PUBLICKEY,
                    &pub_key,
                )
                .await?;

                // Generate and send a challenge for the peer to sign
                let challenge: u32 = rand::random();
                let peer_ip_u32 = match peer_addr.ip() {
                    std::net::IpAddr::V4(v4) => u32::from_be_bytes(v4.octets()),
                    _ => 0,
                };

                // SecIdentState: challenge(4) + state(1)
                // state: 1 = we require their public key, 2 = we have their key and need signature
                let has_peer_key = {
                    let record = cm.all_records();
                    record.iter().any(|r| r.user_hash == peer_user_hash && !r.public_key.is_empty())
                };
                let state_byte: u8 = if has_peer_key { 2 } else { 1 };
                let mut secident_payload = Vec::with_capacity(5);
                secident_payload.extend_from_slice(&challenge.to_le_bytes());
                secident_payload.push(state_byte);
                write_packet_async(
                    &mut writer,
                    OP_EMULEPROT,
                    OP_SECIDENTSTATE,
                    &secident_payload,
                )
                .await?;
                drop(cm);

                // Try to read the peer's response (public key and/or signature)
                // but don't block file requests - use a short timeout
                for _ in 0..3 {
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        read_packet_async_inner(&mut reader),
                    ).await {
                        Ok(Ok((proto, opcode, payload))) => {
                            match (proto, opcode) {
                                (OP_EMULEPROT, OP_PUBLICKEY) if !payload.is_empty() => {
                                    let mut cm = self.credit_manager.write().await;
                                    cm.set_public_key(peer_user_hash, payload);
                                    debug!("Received public key from {peer_addr}");
                                }
                                (OP_EMULEPROT, OP_SIGNATURE) if payload.len() >= 4 => {
                                    let cm = self.credit_manager.read().await;
                                    let verified = cm.verify_signature(
                                        &peer_user_hash,
                                        challenge,
                                        peer_ip_u32,
                                        &payload,
                                    );
                                    drop(cm);
                                    if verified {
                                        let mut cm = self.credit_manager.write().await;
                                        cm.set_ident_state(peer_user_hash, super::credits::IdentState::Verified);
                                        debug!("SecIdent verified for {peer_addr}");
                                    } else {
                                        let mut cm = self.credit_manager.write().await;
                                        cm.set_ident_state(peer_user_hash, super::credits::IdentState::Failed);
                                        debug!("SecIdent verification failed for {peer_addr}");
                                    }
                                }
                                _ => {
                                    // Not a secident packet; defer it for the file request loop
                                    deferred_packet = Some((proto, opcode, payload));
                                    break;
                                }
                            }
                        }
                        _ => break,
                    }
                }
            } else {
                drop(cm);
            }
        }

        // Now handle file requests in a loop
        let mut current_file_hash: Option<[u8; 16]> = None;
        let mut uploaded: u64 = 0;
        let mut transfer_id: Option<String> = None;
        let mut total_size: u64 = 0;
        let mut upload_slot_active = false;
        let mut session_start: Option<std::time::Instant> = None;

        loop {
            let (proto, opcode, payload) = if let Some(pkt) = deferred_packet.take() {
                pkt
            } else {
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(CLIENT_TIMEOUT_SECS),
                    read_packet_async_inner(&mut reader),
                )
                .await;

                match result {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        debug!("Client disconnected: {e}");
                        break;
                    }
                    Err(_) => {
                        debug!("Client timed out");
                        break;
                    }
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

                            // Register this peer as potential A4AF source for our pending downloads
                            let download_hashes = self.pending_download_hashes.read().await;
                            if !download_hashes.is_empty() {
                                let mut a4af = self.a4af_manager.write().await;
                                for &dl_hash in download_hashes.iter() {
                                    if dl_hash != hash {
                                        a4af.add_a4af_source(dl_hash, peer_addr, hash);
                                    }
                                }
                            }
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

                    let max_uploads = self.max_concurrent_uploads.load(std::sync::atomic::Ordering::Relaxed);
                    let should_accept = if current_active >= max_uploads {
                        false
                    } else {
                        let mut queue = self.upload_queue.lock().await;
                        if queue.is_empty() {
                            true
                        } else {
                            // Credit-weighted selection: find the best-scoring peer
                            let cm = self.credit_manager.read().await;
                            let mut best_idx = 0;
                            let mut best_score = f64::MIN;
                            for (i, entry) in queue.iter().enumerate() {
                                let wait = entry.join_time.elapsed().as_secs();
                                let score = cm.get_queue_score(&entry.user_hash, wait, 1.0);
                                if score > best_score {
                                    best_score = score;
                                    best_idx = i;
                                }
                            }
                            drop(cm);
                            if queue[best_idx].addr == peer_addr {
                                queue.remove(best_idx);
                                true
                            } else {
                                false
                            }
                        }
                    };

                    if !should_accept {
                        let mut queue = self.upload_queue.lock().await;
                        let rank = if let Some(pos) = queue.iter().position(|e| e.addr == peer_addr) {
                            (pos + 1) as u16
                        } else if queue.len() >= MAX_UPLOAD_QUEUE_SIZE {
                            debug!("Upload queue full ({MAX_UPLOAD_QUEUE_SIZE}), rejecting {peer_addr}");
                            drop(queue);
                            break;
                        } else {
                            queue.push(QueueEntry {
                                addr: peer_addr,
                                user_hash: peer_user_hash,
                                join_time: std::time::Instant::now(),
                            });
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
                    upload_slot_active = true;
                    uploaded = 0;
                    session_start = Some(std::time::Instant::now());

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

                    let offsets: Vec<(u64, u64)> = offsets
                        .into_iter()
                        .filter(|&(start, end)| {
                            if end > total_size {
                                warn!("Peer requested range past file end: {end} > {total_size}");
                                false
                            } else if start >= end {
                                false
                            } else {
                                true
                            }
                        })
                        .collect();

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

                        // Compress the data if it's large enough (e.g. > 1KB) to be worth it
                        let use_compression = data.len() > 1024;
                        if use_compression {
                            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
                            if encoder.write_all(&data).is_ok() {
                                if let Ok(compressed) = encoder.finish() {
                                    // Only use compression if it actually saves space
                                    if compressed.len() < data.len() {
                                        let mut part_payload = Vec::with_capacity(32 + compressed.len());
                                        part_payload.extend_from_slice(&hash);
                                        part_payload.extend_from_slice(&start.to_le_bytes());
                                        part_payload.extend_from_slice(&(data.len() as u32).to_le_bytes()); // Original length
                                        part_payload.extend_from_slice(&compressed);

                                        write_packet_async(
                                            &mut writer,
                                            OP_EMULEPROT,
                                            OP_COMPRESSEDPART_I64,
                                            &part_payload,
                                        )
                                        .await?;

                                        uploaded += data.len() as u64;
                                        {
                                            let mut cm = self.credit_manager.write().await;
                                            cm.add_uploaded(peer_user_hash, data.len() as u64);
                                        }

                                        if let Some(tid) = &transfer_id {
                                            let _ = self.upload_event_tx.send(UploadEvent {
                                                transfer_id: tid.clone(),
                                                kind: UploadEventKind::Progress {
                                                    uploaded,
                                                    total: total_size,
                                                },
                                            }).await;
                                        }
                                        continue;
                                    }
                                }
                            }
                        }

                        // Fallback to uncompressed SendingPart_I64 packet
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
                        {
                            let mut cm = self.credit_manager.write().await;
                            cm.add_uploaded(peer_user_hash, data.len() as u64);
                        }

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

                    // Enforce eMule session limits: rotate the upload slot after
                    // SESSIONMAXTRANS bytes or SESSIONMAXTIME seconds.
                    let session_expired = uploaded >= SESSIONMAXTRANS
                        || session_start
                            .map(|t| t.elapsed().as_secs() >= SESSIONMAXTIME_SECS)
                            .unwrap_or(false);

                    if session_expired && upload_slot_active {
                        debug!(
                            "Upload session limit reached for {peer_addr} ({}B / {}s), sending OutOfPartReqs",
                            uploaded,
                            session_start.map(|t| t.elapsed().as_secs()).unwrap_or(0)
                        );
                        write_packet_async(
                            &mut writer,
                            OP_EDONKEYHEADER,
                            OP_OUTOFPARTREQS,
                            &[],
                        )
                        .await?;

                        if let Some(tid) = &transfer_id {
                            let _ = self.upload_event_tx.send(UploadEvent {
                                transfer_id: tid.clone(),
                                kind: UploadEventKind::Completed,
                            }).await;
                        }

                        self.active_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        upload_slot_active = false;
                        session_start = None;

                        // Re-add to upload queue so they can get another turn
                        {
                            let mut queue = self.upload_queue.lock().await;
                            if !queue.iter().any(|e| e.addr == peer_addr) && queue.len() < MAX_UPLOAD_QUEUE_SIZE {
                                queue.push(QueueEntry {
                                    addr: peer_addr,
                                    user_hash: peer_user_hash,
                                    join_time: std::time::Instant::now(),
                                });
                            }
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
                    if upload_slot_active {
                        self.active_count
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        upload_slot_active = false;
                    }
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

                (OP_EMULEPROT, OP_MULTIPACKET)
                | (OP_EMULEPROT, OP_MULTIPACKET_EXT)
                | (OP_EMULEPROT, OP_MULTIPACKET_EXT2) => {
                    match parse_multipacket(&payload, opcode) {
                        Ok(mpreq) => {
                            let hash_hex = hex::encode(mpreq.file_hash);
                            let file_info = {
                                let index = self.local_index.read().await;
                                index.get_by_hash(&hash_hex).cloned()
                            };

                            if let Some(file) = file_info {
                                current_file_hash = Some(mpreq.file_hash);
                                total_size = file.size;

                                if let Some(req_size) = mpreq.file_size {
                                    if req_size != 0 && req_size != file.size {
                                        debug!("MultiPacket size mismatch for {hash_hex}, sending FNF");
                                        write_packet_async(
                                            &mut writer,
                                            OP_EDONKEYHEADER,
                                            OP_FILEREQANSNOFIL,
                                            &mpreq.file_hash,
                                        )
                                        .await?;
                                        continue;
                                    }
                                }

                                let answer = build_multipacket_answer(
                                    &mpreq.file_hash,
                                    &file.name,
                                    file.size,
                                    mpreq.is_ext2,
                                    &mpreq.sub_opcodes,
                                );

                                let resp_opcode = if mpreq.is_ext2 {
                                    OP_MULTIPACKETANSWER_EXT2
                                } else {
                                    OP_MULTIPACKETANSWER
                                };
                                write_packet_async(
                                    &mut writer,
                                    OP_EMULEPROT,
                                    resp_opcode,
                                    &answer,
                                )
                                .await?;
                                debug!("Sent MultiPacketAnswer for {hash_hex} to {peer_addr}");
                            } else {
                                write_packet_async(
                                    &mut writer,
                                    OP_EDONKEYHEADER,
                                    OP_FILEREQANSNOFIL,
                                    &mpreq.file_hash,
                                )
                                .await?;
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse MultiPacket from {peer_addr}: {e}");
                        }
                    }
                }

                (OP_EMULEPROT, OP_REQUESTSOURCES) => {
                    if let Some(hash) = current_file_hash {
                        let exclude_ip = match peer_addr.ip() {
                            std::net::IpAddr::V4(v4) => v4,
                            _ => std::net::Ipv4Addr::UNSPECIFIED,
                        };
                        let resp = {
                            let sm = self.source_manager.read().await;
                            sm.build_answer_sources2(&hash, exclude_ip)
                        };
                        write_packet_async(
                            &mut writer,
                            OP_EMULEPROT,
                            OP_ANSWERSOURCES2,
                            &resp,
                        )
                        .await?;
                    }
                }

                (OP_EMULEPROT, OP_AICHREQUEST) => {
                    if payload.len() >= 18 {
                        let mut req_hash = [0u8; 16];
                        req_hash.copy_from_slice(&payload[..16]);
                        let part_idx = u16::from_le_bytes([payload[16], payload[17]]) as usize;
                        
                        let hash_hex = hex::encode(req_hash);
                        let file_info = {
                            let index = self.local_index.read().await;
                            index.get_by_hash(&hash_hex).cloned()
                        };

                        if let Some(file) = file_info {
                            let path = PathBuf::from(&file.path);
                            // We need to compute/load the AICH tree. 
                            // Since we don't have a persistent AICH store yet, we compute it on demand.
                            // This might be slow for large files, but it's correct.
                            // In a real implementation, this should be cached.
                            let aich_result = tokio::task::spawn_blocking(move || {
                                crate::network::ed2k::aich::AICHRecoveryHashSet::build_from_file(&path)
                            }).await?;

                            match aich_result {
                                Ok(hs) => {
                                    // Create recovery data for the requested part
                                    // PARTSIZE is constant 9.28MB
                                    let recovery_data = hs.create_part_recovery_data(part_idx, PARTSIZE as usize);
                                    
                                    let mut resp = Vec::with_capacity(16 + 2 + 20 + recovery_data.len());
                                    resp.extend_from_slice(&req_hash);
                                    resp.extend_from_slice(&(part_idx as u16).to_le_bytes());
                                    resp.extend_from_slice(&hs.root_hash);
                                    resp.extend_from_slice(&recovery_data);

                                    write_packet_async(
                                        &mut writer,
                                        OP_EMULEPROT,
                                        OP_AICHANSWER,
                                        &resp,
                                    )
                                    .await?;
                                }
                                Err(e) => {
                                    warn!("Failed to build AICH for request: {e}");
                                }
                            }
                        }
                    }
                }

                _ => {
                    debug!(
                        "Upload handler ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {peer_addr}"
                    );
                }
            }
        }

        // Remove from upload queue on disconnect
        {
            let mut queue = self.upload_queue.lock().await;
            queue.retain(|e| e.addr != peer_addr);
        }

        // Cleanup: emit completion/failure for any tracked upload
        if let Some(tid) = &transfer_id {
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

            if upload_slot_active {
                self.active_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        Ok(())
    }

    async fn acquire_upload_bandwidth(&self, bytes: u64) {
        self.bandwidth_limiter.acquire_upload(bytes).await;
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

async fn read_packet_with_first_byte<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    first_byte: u8,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = first_byte;
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

fn is_connection_closed(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::UnexpectedEof
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
    )
}
