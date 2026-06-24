use std::io::{self, Cursor, Read};
use std::net::SocketAddr;

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::messages::*;

const SERVER_POLL_READABLE_TIMEOUT_MS: u64 = 5;
const SERVER_POLL_PACKET_TIMEOUT_SECS: u64 = 1;

// Server protocol opcodes (OP_EDONKEYHEADER)
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_SERVERLIST: u8 = 0x32;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_IDCHANGE: u8 = 0x40;
pub const OP_SERVERIDENT: u8 = 0x41;
#[allow(dead_code)]
pub const OP_SEARCHREQUEST: u8 = 0x16;
pub const OP_SEARCHRESULT: u8 = 0x33;
pub const OP_GETSOURCES: u8 = 0x19;
pub const OP_FOUNDSOURCES: u8 = 0x42;
#[allow(dead_code)]
pub const OP_GETSERVERLIST: u8 = 0x14;
pub const OP_REJECT: u8 = 0x05;
pub const OP_OFFERFILES: u8 = 0x15;
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
pub const OP_CALLBACK_FAIL: u8 = 0x36;
pub const OP_GETSOURCES_OBFU: u8 = 0x23;
pub const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
pub const OP_QUERY_MORE_RESULT: u8 = 0x21;

/// SRV_TCPFLG constants: server capability flags from OP_IDCHANGE (eMule Server.h)
pub const SRV_TCPFLG_COMPRESSION: u32 = 0x0001;
pub const SRV_TCPFLG_NEWTAGS: u32 = 0x0008;
pub const SRV_TCPFLG_UNICODE: u32 = 0x0010;
pub const SRV_TCPFLG_RELATEDSEARCH: u32 = 0x0040;
pub const SRV_TCPFLG_TYPETAGINTEGER: u32 = 0x0080;
pub const SRV_TCPFLG_LARGEFILES: u32 = 0x0100;
pub const SRV_TCPFLG_TCPOBFUSCATION: u32 = 0x0400;

/// LowID threshold: client_id < this means LowID
pub const LOWID_THRESHOLD: u32 = 0x0100_0000;

/// A file to offer to the ed2k server via OP_OFFERFILES.
pub struct OfferFile {
    pub hash: [u8; 16],
    pub name: String,
    pub size: u64,
    pub is_complete: bool,
    pub file_type: String,
}

#[derive(Debug, Clone)]
pub struct ServerSearchResult {
    pub file_hash: [u8; 16],
    pub client_id: u32,
    pub client_port: u16,
    pub file_name: String,
    pub file_size: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub rating: Option<u8>,
    pub comment: Option<String>,
    pub media: crate::types::MediaMetadata,
}

#[derive(Debug, Clone)]
pub struct ServerSource {
    pub ip: String,
    pub port: u16,
    /// LowID client_id from the server (0 = HighID, use ip:port directly)
    pub client_id: u32,
    pub crypt_options: Option<u8>,
    pub user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct ServerSession {
    pub client_id: u32,
    pub server_flags: u32,
    pub server_name: String,
    pub user_count: u32,
    pub file_count: u32,
    /// Raw OP_SERVERLIST payload received during login (if any)
    pub server_list_data: Option<Vec<u8>>,
    /// MOTD messages received during login (for frontend display)
    pub motd_messages: Vec<String>,
    /// Server-reported public IP from OP_IDCHANGE (offset 12, if present).
    pub server_reported_ip: u32,
}

enum ServerTransport {
    Plain {
        reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    },
    Encrypted(super::server_crypt::ObfuscatedServerStream),
}

pub struct Ed2kServerConnection {
    transport: ServerTransport,
    pub session: Option<ServerSession>,
    /// Connected server's soft per-client file limit (`GetSoftFiles()` in
    /// eMule). 0 = unknown. Used to cap `OP_OFFERFILES` like eMule does.
    soft_files: u32,
}

#[derive(Debug)]
enum PollReadPacketResult {
    Packet((u8, Vec<u8>)),
    Idle,
    Disconnected(io::Error),
}

fn classify_packet_read_result(
    result: io::Result<(u8, Vec<u8>)>,
    encrypted: bool,
) -> PollReadPacketResult {
    match result {
        Ok(pkt) => PollReadPacketResult::Packet(pkt),
        Err(e) => {
            if encrypted {
                warn!("Server packet read error (encrypted): {e}");
            } else {
                warn!("Server packet read error: {e}");
            }
            PollReadPacketResult::Disconnected(e)
        }
    }
}

fn packet_poll_timeout_result(encrypted: bool) -> PollReadPacketResult {
    let mode = if encrypted { "encrypted" } else { "plain" };
    warn!("Server poll read timed out mid-packet ({mode}), stream is corrupt — forcing disconnect");
    PollReadPacketResult::Disconnected(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("mid-packet read timeout ({mode}), BufReader state corrupted"),
    ))
}

impl Ed2kServerConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
                .await??;
        let _ = stream.set_nodelay(true);

        let (reader, writer) = stream.into_split();
        Ok(Self {
            transport: ServerTransport::Plain {
                reader: tokio::io::BufReader::new(reader),
                writer: tokio::io::BufWriter::new(writer),
            },
            session: None,
            soft_files: 0,
        })
    }

    pub async fn connect_encrypted(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = super::server_crypt::connect_obfuscated(addr).await?;
        Ok(Self {
            transport: ServerTransport::Encrypted(stream),
            session: None,
            soft_files: 0,
        })
    }

    /// Record the connected server's soft per-client file limit so
    /// `offer_files` can cap each OP_OFFERFILES the way eMule does.
    pub fn set_soft_files(&mut self, soft_files: u32) {
        self.soft_files = soft_files;
    }

    pub async fn login(
        &mut self,
        user_hash: &[u8; 16],
        nickname: &str,
        tcp_port: u16,
    ) -> anyhow::Result<ServerSession> {
        let is_encrypted = matches!(self.transport, ServerTransport::Encrypted(_));
        let mut flags: u32 = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES;
        // Only advertise crypto preference when we're actually on an encrypted connection.
        // Lugdunum servers close plain connections from clients that claim SRVCAP_REQUESTCRYPT,
        // expecting them to reconnect on the obfuscation port.
        if is_encrypted {
            flags |= SRVCAP_SUPPORTCRYPT | SRVCAP_REQUESTCRYPT | SRVCAP_REQUIRECRYPT;
        }
        let payload = build_login_request(user_hash, tcp_port, nickname, flags);
        info!(
            "Sending OP_LOGINREQUEST ({} bytes, encrypted={}): port={}, flags=0x{:04X}",
            payload.len(),
            is_encrypted,
            tcp_port,
            flags
        );

        // Build the full wire packet: [protocol(1)][length(4)][opcode(1)][payload]
        let mut wire_packet = Vec::with_capacity(6 + payload.len());
        wire_packet.push(OP_EDONKEYHEADER);
        let wire_len = u32::try_from(1 + payload.len())
            .map_err(|_| anyhow::anyhow!("login packet too large"))?;
        wire_packet.extend_from_slice(&wire_len.to_le_bytes());
        wire_packet.push(OP_LOGINREQUEST);
        wire_packet.extend_from_slice(&payload);

        match &mut self.transport {
            ServerTransport::Plain { writer, .. } => {
                writer.write_all(&wire_packet).await?;
                writer.flush().await?;
            }
            ServerTransport::Encrypted(stream) => {
                stream.write_login(&wire_packet).await?;
            }
        }

        let mut session = ServerSession {
            client_id: 0,
            server_flags: 0,
            server_name: String::new(),
            user_count: 0,
            file_count: 0,
            server_list_data: None,
            motd_messages: Vec::new(),
            server_reported_ip: 0,
        };

        let mut packets_read = 0u32;
        let mut last_error: Option<String> = None;

        for i in 0..50 {
            let (opcode, payload) = match self.read_packet().await {
                Ok(p) => p,
                Err(e) => {
                    info!(
                        "Server read error on packet {i}: kind={:?} msg={e}",
                        e.kind()
                    );
                    last_error = Some(format!("{} ({})", e, e.kind()));
                    break;
                }
            };
            packets_read += 1;

            match opcode {
                OP_SERVERMESSAGE => {
                    if payload.len() >= 2 {
                        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                        if payload.len() >= 2 + len {
                            let msg = String::from_utf8_lossy(&payload[2..2 + len]).to_string();
                            info!("Server MOTD: {msg}");
                            session.motd_messages.push(msg);
                        }
                    }
                }
                OP_IDCHANGE => {
                    if payload.len() >= 4 {
                        session.client_id =
                            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if session.client_id == 0 {
                            return Err(anyhow::anyhow!("server rejected login (client_id=0)"));
                        }
                        if payload.len() >= 8 {
                            session.server_flags = u32::from_le_bytes([
                                payload[4], payload[5], payload[6], payload[7],
                            ]);
                            let f = session.server_flags;
                            info!(
                                "Server TCP flags: 0x{f:04X} [{}{}{}{}{}{}{}]",
                                if f & SRV_TCPFLG_COMPRESSION != 0 {
                                    "zlib "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_NEWTAGS != 0 {
                                    "newtags "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_UNICODE != 0 {
                                    "unicode "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_RELATEDSEARCH != 0 {
                                    "relsearch "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_TYPETAGINTEGER != 0 {
                                    "typeint "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_LARGEFILES != 0 {
                                    "large "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_TCPOBFUSCATION != 0 {
                                    "obfu "
                                } else {
                                    ""
                                },
                            );
                        }
                        if payload.len() >= 16 {
                            let reported_ip = u32::from_le_bytes([
                                payload[12],
                                payload[13],
                                payload[14],
                                payload[15],
                            ]);
                            if reported_ip >= LOWID_THRESHOLD {
                                session.server_reported_ip = reported_ip;
                            }
                        }
                        info!("Server assigned client ID: {}", session.client_id);
                    }
                    let ret = session.clone();
                    self.session = Some(session);
                    return Ok(ret);
                }
                OP_SERVERSTATUS => {
                    if payload.len() >= 8 {
                        session.user_count =
                            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        session.file_count =
                            u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        debug!(
                            "Server status: {} users, {} files",
                            session.user_count, session.file_count
                        );
                    }
                }
                OP_SERVERIDENT => {
                    if let Some(name) = parse_server_ident_name(&payload) {
                        session.server_name = name;
                        debug!("Server name: {}", session.server_name);
                    }
                }
                OP_SERVERLIST => {
                    debug!("Got server list from server ({} bytes)", payload.len());
                    session.server_list_data = Some(payload);
                }
                OP_REJECT => {
                    anyhow::bail!("Server rejected login");
                }
                _ => {
                    debug!("Login phase: ignoring opcode 0x{opcode:02X}");
                }
            }
        }

        match last_error {
            Some(err) => anyhow::bail!(
                "Server closed connection after {packets_read} packet(s): {err}"
            ),
            None => anyhow::bail!(
                "Login sequence did not complete after {packets_read} packets (no IDCHANGE received)"
            ),
        }
    }

    async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        match &mut self.transport {
            ServerTransport::Plain { reader, .. } => read_server_packet_timeout(reader).await,
            ServerTransport::Encrypted(stream) => {
                tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_packet())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "encrypted server read timed out")
                    })?
            }
        }
    }

    /// Write a zlib-compressed packet (eMule header 0xD4 instead of 0xE3).
    async fn write_packet_compressed(
        &mut self,
        opcode: u8,
        compressed_payload: &[u8],
    ) -> io::Result<()> {
        const OP_PACKEDPROT: u8 = 0xD4;
        let wire_len = u32::try_from(1 + compressed_payload.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "compressed packet too large for u32 length field",
            )
        })?;
        match &mut self.transport {
            ServerTransport::Plain { writer, .. } => {
                use tokio::io::AsyncWriteExt;
                writer.write_u8(OP_PACKEDPROT).await?;
                writer.write_all(&wire_len.to_le_bytes()).await?;
                writer.write_u8(opcode).await?;
                writer.write_all(compressed_payload).await?;
                writer.flush().await?;
                Ok(())
            }
            ServerTransport::Encrypted(stream) => {
                let mut wire = Vec::with_capacity(6 + compressed_payload.len());
                wire.push(OP_PACKEDPROT);
                wire.extend_from_slice(&wire_len.to_le_bytes());
                wire.push(opcode);
                wire.extend_from_slice(compressed_payload);
                let mut encrypted = vec![0u8; wire.len()];
                stream.send_key.process(&wire, &mut encrypted);
                stream.writer.write_all(&encrypted).await?;
                stream.writer.flush().await?;
                Ok(())
            }
        }
    }

    async fn write_packet(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        match &mut self.transport {
            ServerTransport::Plain { writer, .. } => {
                write_server_packet(writer, opcode, payload).await
            }
            ServerTransport::Encrypted(stream) => {
                let wire_len = u32::try_from(1 + payload.len()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "packet payload too large for u32 length field",
                    )
                })?;
                let mut wire = Vec::with_capacity(6 + payload.len());
                wire.push(OP_EDONKEYHEADER);
                wire.extend_from_slice(&wire_len.to_le_bytes());
                wire.push(opcode);
                wire.extend_from_slice(payload);
                debug!(
                    "Server write_packet: opcode=0x{opcode:02X}, wire={} bytes",
                    wire.len(),
                );
                let mut encrypted = vec![0u8; wire.len()];
                stream.send_key.process(&wire, &mut encrypted);
                stream.writer.write_all(&encrypted).await?;
                stream.writer.flush().await?;
                Ok(())
            }
        }
    }

    /// Poll for a server packet without blocking. Cancel-safe: only starts
    /// reading after confirming data is available, avoiding mid-read cancellation
    /// that would corrupt the stream (read_exact is NOT cancel-safe).
    async fn poll_read_packet(&mut self) -> PollReadPacketResult {
        match &mut self.transport {
            ServerTransport::Plain { reader, .. } => {
                let has_buffered = !reader.buffer().is_empty();
                if !has_buffered {
                    let tcp = reader.get_ref();
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(SERVER_POLL_READABLE_TIMEOUT_MS),
                        tcp.readable(),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        _ => return PollReadPacketResult::Idle,
                    }
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(SERVER_POLL_PACKET_TIMEOUT_SECS),
                    read_server_packet(reader),
                )
                .await
                {
                    Ok(result) => match classify_packet_read_result(result, false) {
                        PollReadPacketResult::Packet(pkt) => {
                            info!(
                                "Server packet: opcode=0x{:02X}, {} bytes",
                                pkt.0,
                                pkt.1.len()
                            );
                            PollReadPacketResult::Packet(pkt)
                        }
                        other => other,
                    },
                    Err(_) => {
                        if has_buffered {
                            // BufReader had data and we started reading a packet;
                            // timing out mid-read means the stream is corrupted.
                            packet_poll_timeout_result(false)
                        } else {
                            // Entered because tcp.readable() indicated readiness, but
                            // no data arrived within the timeout. This is a spurious
                            // wakeup (common on Windows), not corruption.
                            PollReadPacketResult::Idle
                        }
                    }
                }
            }
            ServerTransport::Encrypted(stream) => {
                let has_buffered = !stream.reader.buffer().is_empty();
                if !has_buffered {
                    let tcp = stream.reader.get_ref();
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(SERVER_POLL_READABLE_TIMEOUT_MS),
                        tcp.readable(),
                    )
                    .await
                    {
                        Ok(Ok(_)) => {}
                        _ => return PollReadPacketResult::Idle,
                    }
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(SERVER_POLL_PACKET_TIMEOUT_SECS),
                    stream.read_packet(),
                )
                .await
                {
                    Ok(result) => match classify_packet_read_result(result, true) {
                        PollReadPacketResult::Packet(pkt) => {
                            info!(
                                "Server packet (encrypted): opcode=0x{:02X}, {} bytes",
                                pkt.0,
                                pkt.1.len()
                            );
                            PollReadPacketResult::Packet(pkt)
                        }
                        other => other,
                    },
                    Err(_) => {
                        if has_buffered {
                            packet_poll_timeout_result(true)
                        } else {
                            PollReadPacketResult::Idle
                        }
                    }
                }
            }
        }
    }

    /// Send a pre-built search expression (AND tree or single keyword) as
    /// `OP_SEARCHREQUEST`. Multi-word queries MUST use the AND-tree wire
    /// format for reliable results across all eD2K servers.
    pub async fn send_search_expr_bytes(&mut self, expr: &[u8]) -> anyhow::Result<()> {
        info!(
            "Sending OP_SEARCHREQUEST expression ({} bytes payload)",
            expr.len(),
        );
        self.write_packet(OP_SEARCHREQUEST, expr).await?;
        Ok(())
    }

    /// Send a source request to the server (eMule DownloadQueue.cpp format).
    /// Uses OP_GETSOURCES_OBFU only when our connection is encrypted (so our
    /// login advertised crypt) AND the server supports it; otherwise plain
    /// OP_GETSOURCES — see the opcode selection below for why.
    /// Returns the number of bytes sent on the wire (header + opcode +
    /// payload) so callers can attribute the cost to source-exchange
    /// overhead in the Statistics panel. Returns 0 when the request was
    /// silently skipped (e.g. the server lacks LARGEFILES support).
    pub async fn send_get_sources(
        &mut self,
        file_hash: &[u8; 16],
        file_size: u64,
    ) -> anyhow::Result<u64> {
        let mut payload = Vec::with_capacity(28);
        payload.extend_from_slice(file_hash);
        let srv_flags = self.session.as_ref().map(|s| s.server_flags).unwrap_or(0);
        let supports_large = (srv_flags & SRV_TCPFLG_LARGEFILES) != 0;
        // Match eMule's `CPartFile::IsLargeFile()` boundary (OLD_MAX_EMULE_FILE_SIZE),
        // NOT u32::MAX. Files in the (OLD_MAX_EMULE_FILE_SIZE, u32::MAX] window are
        // large on the wire (uploaders offer them with the 64-bit encoding), so a
        // 32-bit source request won't match the server's large-file index.
        let is_large = file_size > OLD_MAX_EMULE_FILE_SIZE;
        if is_large && !supports_large {
            debug!("Skipping source query for large file — server does not support LARGEFILES");
            return Ok(0);
        }
        if is_large {
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&file_size.to_le_bytes());
        } else {
            payload.extend_from_slice(&(file_size as u32).to_le_bytes());
        }
        // Only request the *obfuscated* source variant when our login actually
        // advertised crypt support to this server. `login()` only sets
        // SRVCAP_SUPPORTCRYPT/REQUESTCRYPT on an encrypted connection (plain
        // Lugdunum connections that claim crypt get dropped), so on a plain
        // connection we announced "no crypt". Sending OP_GETSOURCES_OBFU there
        // is inconsistent with that login — the server sees a non-crypt client
        // asking for obfuscated sources and silently ignores the request,
        // returning no OP_FOUNDSOURCES at all. eMule keeps these in lockstep
        // (it only emits OP_GETSOURCES_OBFU when its crypt layer is enabled,
        // which is also when its login advertises crypt). Mirror that: use the
        // OBFU opcode only when this connection is encrypted AND the server
        // supports it; otherwise send the plain OP_GETSOURCES.
        let is_encrypted = matches!(self.transport, ServerTransport::Encrypted(_));
        let opcode = if is_encrypted && (srv_flags & SRV_TCPFLG_TCPOBFUSCATION) != 0 {
            OP_GETSOURCES_OBFU
        } else {
            OP_GETSOURCES
        };
        debug!(
            "OP_GETSOURCES: opcode={} (0x{:02X}), file_size={}, conn_encrypted={}, srv_obfu={}",
            if opcode == OP_GETSOURCES_OBFU {
                "OBFU"
            } else {
                "PLAIN"
            },
            opcode,
            file_size,
            is_encrypted,
            (srv_flags & SRV_TCPFLG_TCPOBFUSCATION) != 0,
        );
        self.write_packet(opcode, &payload).await?;
        // Wire framing: 1 protocol + 4 length + 1 opcode + payload.
        Ok(6 + payload.len() as u64)
    }

    /// eMule keep-alive: send empty OP_OFFERFILES (file count = 0).
    pub async fn keep_alive(&mut self) -> anyhow::Result<()> {
        self.write_packet(OP_OFFERFILES, &0u32.to_le_bytes())
            .await?;
        Ok(())
    }

    /// Send eMule's `OP_GETSERVERLIST` to ask the server for its known
    /// peer servers. The response arrives later as `OP_SERVERLIST` and
    /// is parsed by `ServerList::add_from_server_list_packet`. Called
    /// after login when `add_servers_from_server` is enabled.
    pub async fn request_server_list(&mut self) -> anyhow::Result<()> {
        self.write_packet(OP_GETSERVERLIST, &[]).await?;
        debug!("Sent OP_GETSERVERLIST request to server");
        Ok(())
    }

    /// Request additional search results from the server (up to 5 batches).
    pub async fn request_more_results(&mut self) -> anyhow::Result<()> {
        self.write_packet(OP_QUERY_MORE_RESULT, &[]).await?;
        debug!("Sent OP_QUERY_MORE_RESULT to server");
        Ok(())
    }

    pub async fn request_callback(&mut self, client_id: u32) -> anyhow::Result<()> {
        let payload = client_id.to_le_bytes().to_vec();
        self.write_packet(OP_CALLBACKREQUEST, &payload).await?;
        info!("Sent callback request for LowID client {client_id}");
        Ok(())
    }

    /// Send OP_OFFERFILES to the server, capping each packet at the server's
    /// soft per-client file limit exactly like eMule's
    /// `CSharedFileList::SendListToServer`:
    ///
    /// ```text
    /// limit = GetSoftFiles(); if (limit == 0 || limit > 200) limit = 200;
    /// ```
    ///
    /// A strict server can ignore/penalize a client that offers more files
    /// than its limit in one packet (which then withholds source replies), so
    /// we chunk the offer into ≤`limit`-file `OP_OFFERFILES` packets rather
    /// than blasting all shares at once.
    pub async fn offer_files(&mut self, files: &[OfferFile], tcp_port: u16) -> anyhow::Result<()> {
        let limit = if self.soft_files == 0 || self.soft_files > 200 {
            200
        } else {
            self.soft_files as usize
        };
        if files.is_empty() {
            // Preserve the empty (count=0) offer some callers may rely on.
            return self.offer_files_chunk(files, tcp_port).await;
        }
        let total = files.len();
        if total > limit {
            info!(
                "OP_OFFERFILES: {total} files exceeds server soft limit {limit}; sending in {} chunks",
                (total + limit - 1) / limit
            );
        }
        for chunk in files.chunks(limit) {
            self.offer_files_chunk(chunk, tcp_port).await?;
        }
        Ok(())
    }

    /// Send a single OP_OFFERFILES packet (one chunk). Matches eMule
    /// SharedFileList.cpp's per-file encoding; uses magic client ID/port
    /// values when the server supports SRV_TCPFLG_COMPRESSION.
    async fn offer_files_chunk(
        &mut self,
        files: &[OfferFile],
        tcp_port: u16,
    ) -> anyhow::Result<()> {
        let real_client_id = self.our_client_id().unwrap_or(0);
        let srv_flags = self.session.as_ref().map(|s| s.server_flags).unwrap_or(0);
        let use_magic_ids = (srv_flags & SRV_TCPFLG_COMPRESSION) != 0;

        let mut payload = Vec::with_capacity(4 + files.len() * 64);
        payload.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for file in files {
            payload.extend_from_slice(&file.hash);

            if use_magic_ids {
                if file.is_complete {
                    payload.extend_from_slice(&0xFBFBFBFBu32.to_le_bytes());
                    payload.extend_from_slice(&0xFBFBu16.to_le_bytes());
                } else {
                    payload.extend_from_slice(&0xFCFCFCFCu32.to_le_bytes());
                    payload.extend_from_slice(&0xFCFCu16.to_le_bytes());
                }
            } else {
                payload.extend_from_slice(&real_client_id.to_le_bytes());
                payload.extend_from_slice(&tcp_port.to_le_bytes());
            }

            let mut tag_count: u32 = 0;
            let mut tags = Vec::new();
            write_string_tag(&mut tags, 0x01, &file.name); // FT_FILENAME
            tag_count += 1;
            // eMule offers files above OLD_MAX_EMULE_FILE_SIZE (not u32::MAX) as
            // large: FT_FILESIZE (low 32) + FT_FILESIZE_HI (high 32, may be 0).
            // Using the same boundary keeps the server's large-file index aligned
            // with our later OP_GETSOURCES so source lookups for ~4 GiB files match.
            if file.size > OLD_MAX_EMULE_FILE_SIZE {
                write_uint32_tag(&mut tags, 0x02, file.size as u32);
                tag_count += 1;
                write_uint32_tag(&mut tags, 0x3A, (file.size >> 32) as u32);
                tag_count += 1;
            } else {
                write_uint32_tag(&mut tags, 0x02, file.size as u32);
                tag_count += 1;
            }
            // FT_FILETYPE (0x03) -- file type string
            if !file.file_type.is_empty() {
                write_string_tag(&mut tags, 0x03, &file.file_type);
                tag_count += 1;
            }
            payload.extend_from_slice(&tag_count.to_le_bytes());
            payload.extend_from_slice(&tags);
        }
        // Compress payload if server supports compression (eMule SharedFileList.cpp)
        if (srv_flags & SRV_TCPFLG_COMPRESSION) != 0 && payload.len() > 100 {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write as _;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            match encoder.write_all(&payload).and_then(|_| encoder.finish()) {
                Ok(compressed) if compressed.len() < payload.len() => {
                    debug!(
                        "Compressed OP_OFFERFILES: {} -> {} bytes",
                        payload.len(),
                        compressed.len()
                    );
                    self.write_packet_compressed(OP_OFFERFILES, &compressed)
                        .await?;
                    info!(
                        "Sent compressed OP_OFFERFILES with {} shared files to server",
                        files.len()
                    );
                    return Ok(());
                }
                Ok(_) => debug!("OP_OFFERFILES compression not smaller, sending uncompressed"),
                Err(e) => debug!("OP_OFFERFILES compression failed: {e}, sending uncompressed"),
            }
        }
        self.write_packet(OP_OFFERFILES, &payload).await?;
        info!(
            "Sent OP_OFFERFILES with {} shared files to server",
            files.len()
        );
        Ok(())
    }

    pub async fn poll_messages(&mut self) -> io::Result<Vec<ServerEvent>> {
        let mut events = Vec::new();
        loop {
            match self.poll_read_packet().await {
                PollReadPacketResult::Packet((opcode, payload)) => {
                    info!(
                        "Server poll received opcode=0x{opcode:02X}, {} bytes",
                        payload.len()
                    );
                    events.extend(parse_server_event(opcode, &payload));
                }
                PollReadPacketResult::Idle => break,
                PollReadPacketResult::Disconnected(err) => return Err(err),
            }
        }
        Ok(events)
    }

    pub fn is_low_id(&self) -> bool {
        self.session
            .as_ref()
            .map(|s| s.client_id > 0 && s.client_id < LOWID_THRESHOLD)
            .unwrap_or(false)
    }

    pub fn our_client_id(&self) -> Option<u32> {
        self.session.as_ref().map(|s| s.client_id)
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.transport, ServerTransport::Encrypted(_))
    }

    pub async fn disconnect(self) {
        match self.transport {
            ServerTransport::Plain { mut writer, .. } => {
                let _ = tokio::time::timeout(std::time::Duration::from_secs(2), writer.shutdown())
                    .await;
            }
            ServerTransport::Encrypted(mut stream) => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stream.writer.shutdown(),
                )
                .await;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    CallbackRequested {
        ip: String,
        port: u16,
        crypt_options: Option<u8>,
        user_hash: Option<[u8; 16]>,
    },
    CallbackFailed,
    Message(String),
    StatusUpdate {
        users: u32,
        files: u32,
    },
    ServerIdent {
        name: String,
    },
    ServerList {
        data: Vec<u8>,
    },
    SearchResult {
        results: Vec<ServerSearchResult>,
    },
    FoundSources {
        file_hash: [u8; 16],
        sources: Vec<ServerSource>,
    },
}

fn parse_server_event(opcode: u8, payload: &[u8]) -> Vec<ServerEvent> {
    let mut events = Vec::new();
    match opcode {
        OP_CALLBACKREQUESTED => {
            if payload.len() >= 6 {
                let ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let port = u16::from_le_bytes([payload[4], payload[5]]);
                let crypt_options = payload.get(6).copied();
                let user_hash = if payload.len() >= 23 {
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(&payload[7..23]);
                    Some(hash)
                } else {
                    None
                };
                info!("Callback requested: connect to {ip}:{port}");
                events.push(ServerEvent::CallbackRequested {
                    ip: ip.to_string(),
                    port,
                    crypt_options,
                    user_hash,
                });
            }
        }
        OP_CALLBACK_FAIL => {
            debug!("Server reported callback failure");
            events.push(ServerEvent::CallbackFailed);
        }
        OP_SERVERMESSAGE => {
            if payload.len() >= 2 {
                let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                if payload.len() >= 2 + len {
                    let msg = String::from_utf8_lossy(&payload[2..2 + len]).to_string();
                    events.push(ServerEvent::Message(msg));
                }
            }
        }
        OP_SERVERSTATUS => {
            if payload.len() >= 8 {
                let users = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let files = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                events.push(ServerEvent::StatusUpdate { users, files });
            }
        }
        OP_SERVERIDENT => {
            if let Some(name) = parse_server_ident_name(payload) {
                events.push(ServerEvent::ServerIdent { name });
            }
        }
        OP_SERVERLIST => {
            debug!("Got server list from server ({} bytes)", payload.len());
            events.push(ServerEvent::ServerList {
                data: payload.to_vec(),
            });
        }
        OP_SEARCHRESULT => match parse_search_result(payload) {
            Ok(results) => {
                debug!("Server search result: {} files", results.len());
                events.push(ServerEvent::SearchResult { results });
            }
            Err(e) => {
                debug!("Failed to parse search result: {e}");
            }
        },
        OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU => {
            match parse_found_sources(payload, opcode == OP_FOUNDSOURCES_OBFU) {
                Ok((file_hash, sources)) => {
                    debug!(
                        "Server found {} sources for file {}",
                        sources.len(),
                        hex::encode(file_hash)
                    );
                    events.push(ServerEvent::FoundSources { file_hash, sources });
                }
                Err(e) => {
                    debug!("Failed to parse found sources: {e}");
                }
            }
        }
        _ => {
            debug!("Ignoring server opcode 0x{opcode:02X}");
        }
    }
    events
}

fn parse_server_ident_name(payload: &[u8]) -> Option<String> {
    // eMule: server_hash(16) + server_ip(4) + server_port(2) + tag_count(4) + tags
    if payload.len() < 26 {
        return None;
    }
    let tag_count =
        u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]) as usize;
    let mut offset = 26;
    for _ in 0..tag_count.min(32) {
        if offset >= payload.len() {
            break;
        }
        let tag_type = payload[offset];
        offset += 1;
        if offset + 3 > payload.len() {
            break;
        }
        let name_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
        offset += 2;
        if offset + name_len > payload.len() {
            break;
        }
        let name_id = if name_len == 1 {
            Some(payload[offset])
        } else {
            None
        };
        offset += name_len;

        match tag_type {
            0x02 => {
                if offset + 2 > payload.len() {
                    break;
                }
                let slen = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                if offset + slen > payload.len() {
                    break;
                }
                if name_id == Some(0x01) {
                    if let Ok(s) = std::str::from_utf8(&payload[offset..offset + slen]) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            return Some(trimmed.to_string());
                        }
                    }
                }
                offset += slen;
            }
            0x03 => offset += 4,
            0x08 => offset += 2,
            0x09 => offset += 1,
            _ => break,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[test]
    fn classify_packet_read_timeout_as_disconnect() {
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "server read timed out");
        match classify_packet_read_result(Err(timeout), false) {
            PollReadPacketResult::Disconnected(err) => {
                assert_eq!(err.kind(), io::ErrorKind::TimedOut);
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[test]
    fn poll_timeout_is_treated_as_disconnect() {
        match packet_poll_timeout_result(false) {
            PollReadPacketResult::Disconnected(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected Disconnected, got {other:?}"),
        }
        match packet_poll_timeout_result(true) {
            PollReadPacketResult::Disconnected(e) => assert_eq!(e.kind(), io::ErrorKind::TimedOut),
            other => panic!("expected Disconnected, got {other:?}"),
        }
    }

    #[test]
    fn classify_packet_read_eof_as_disconnect() {
        let eof = io::Error::new(io::ErrorKind::UnexpectedEof, "closed");
        match classify_packet_read_result(Err(eof), true) {
            PollReadPacketResult::Disconnected(err) => {
                assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected disconnect, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_packet_reads_loopback_server_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let payload = {
                let mut p = Vec::new();
                p.extend_from_slice(&2u16.to_le_bytes());
                p.extend_from_slice(b"hi");
                p
            };
            let mut packet = Vec::new();
            packet.push(OP_EDONKEYHEADER);
            packet.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
            packet.push(OP_SERVERMESSAGE);
            packet.extend_from_slice(&payload);
            socket.write_all(&packet).await.unwrap();
            socket.flush().await.unwrap();
            let _ = shutdown_rx.await;
        });

        let mut conn = Ed2kServerConnection::connect(addr).await.unwrap();
        let (opcode, payload) = conn.read_packet().await.unwrap();
        let _ = shutdown_tx.send(());
        let events = parse_server_event(opcode, &payload);

        assert!(matches!(
            events.as_slice(),
            [ServerEvent::Message(msg)] if msg == "hi"
        ));
    }

    #[test]
    fn search_result_extracts_media_rating_and_comment() {
        fn put_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        fn old_name(buf: &mut Vec<u8>, tag_type: u8, name: &str) {
            buf.push(tag_type); // no high bit => old format
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // result count
        payload.extend_from_slice(&[0u8; 16]); // file hash
        payload.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // HighID client id
        payload.extend_from_slice(&4662u16.to_le_bytes()); // client port
        payload.extend_from_slice(&7u32.to_le_bytes()); // tag count

        // FT_FILENAME (new-format string, name id 0x01)
        payload.push(0x02 | 0x80);
        payload.push(0x01);
        put_str(&mut payload, "song.mp3");
        // FT_FILESIZE (new-format uint32, name id 0x02)
        payload.push(0x03 | 0x80);
        payload.push(0x02);
        payload.extend_from_slice(&5_000_000u32.to_le_bytes());
        // media length as old-format string "length" = "3:45"
        old_name(&mut payload, 0x02, "length");
        put_str(&mut payload, "3:45");
        // bitrate as old-format uint32 "bitrate" = 192
        old_name(&mut payload, 0x03, "bitrate");
        payload.extend_from_slice(&192u32.to_le_bytes());
        // codec as old-format string "codec" = "mp3"
        old_name(&mut payload, 0x02, "codec");
        put_str(&mut payload, "mp3");
        // FT_FILERATING (new-format uint32, name id 0xF7) = 4
        payload.push(0x03 | 0x80);
        payload.push(0xF7);
        payload.extend_from_slice(&4u32.to_le_bytes());
        // FT_FILECOMMENT (new-format string, name id 0xF6)
        payload.push(0x02 | 0x80);
        payload.push(0xF6);
        put_str(&mut payload, "great rip");

        let results = parse_search_result(&payload).expect("parse");
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.file_name, "song.mp3");
        assert_eq!(r.file_size, 5_000_000);
        assert_eq!(r.media.duration, Some(3 * 60 + 45));
        assert_eq!(r.media.bitrate, Some(192));
        assert_eq!(r.media.codec.as_deref(), Some("mp3"));
        assert_eq!(r.rating, Some(4));
        assert_eq!(r.comment.as_deref(), Some("great rip"));
    }
}

// CT_SERVER_FLAGS capability bits (from eMule Opcodes.h)
const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
const SRVCAP_REQUIRECRYPT: u32 = 0x0800;

const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

fn build_login_request(user_hash: &[u8; 16], tcp_port: u16, nickname: &str, flags: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // eMule: WriteHash16 + WriteUInt32(clientID) + WriteUInt16(port)
    buf.extend_from_slice(user_hash);
    buf.extend_from_slice(&0u32.to_le_bytes()); // client ID 0 = request new
    buf.extend_from_slice(&tcp_port.to_le_bytes());

    // eMule sends exactly 4 tags
    let tag_count: u32 = 4;
    buf.extend_from_slice(&tag_count.to_le_bytes());

    // Tag 1: CT_NAME (0x01) - nickname string
    write_string_tag(&mut buf, CT_NAME, nickname);

    // Tag 2: CT_VERSION (0x11) - EDONKEYVERSION = 0x3C
    write_uint32_tag(&mut buf, CT_VERSION, 0x3C);

    // Tag 3: CT_SERVER_FLAGS (0x20) - capability flags
    write_uint32_tag(&mut buf, CT_SERVER_FLAGS, flags);

    // Tag 4: CT_EMULE_VERSION (0xFB) - (compat << 24) | (major << 17) | (minor << 10) | (update << 7)
    // Claim 0.50a (last official eMule release) — must match build_hello_inner.
    // update=1 encodes the 'a' suffix.
    let emule_version: u32 = (50u32 << 10) | (1u32 << 7);
    write_uint32_tag(&mut buf, CT_EMULE_VERSION, emule_version);

    buf
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) {
    buf.push(0x02); // TAGTYPE_STRING
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    let bytes = value.as_bytes();
    let clamped = &bytes[..bytes.len().min(u16::MAX as usize)];
    buf.extend_from_slice(&(clamped.len() as u16).to_le_bytes());
    buf.extend_from_slice(clamped);
}

fn write_uint32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    buf.extend_from_slice(&value.to_le_bytes());
}

/// Read one eMule-style tag (supports both old and "new tags" compressed format).
/// Returns (name_id, tag_type, was read successfully).
fn read_tag_header(cursor: &mut Cursor<&[u8]>) -> Option<(u8, u8, Option<String>)> {
    let raw_type = ReadBytesExt::read_u8(cursor).ok()?;

    if raw_type & 0x80 != 0 {
        // New tag format: high bit set → single-byte name follows, type is low 7 bits
        let tag_type = raw_type & 0x7F;
        let name_id = ReadBytesExt::read_u8(cursor).ok()?;
        Some((name_id, tag_type, None))
    } else {
        // Old format: u16 name length + name bytes
        let name_len = ReadBytesExt::read_u16::<LittleEndian>(cursor).ok()? as usize;
        // Cap the name length before allocating: a hostile/buggy server can
        // advertise name_len up to 65535 on every tag (256 tags/result), and
        // `vec![0u8; name_len]` is allocated before the read can fail. eMule
        // tag names are tiny; 256 matches `messages.rs` MAX_TAG_NAME_LEN.
        const MAX_TAG_NAME_LEN: usize = 256;
        if name_len > MAX_TAG_NAME_LEN {
            return None;
        }
        if name_len == 1 {
            let name_id = ReadBytesExt::read_u8(cursor).ok()?;
            Some((name_id, raw_type, None))
        } else {
            // Preserve the string name: ED2K servers send media metadata under
            // string tag names ("Artist"/"length"/"bitrate"/"codec"/...), which
            // map to no single-byte id. Lowercased so the caller can match
            // case-insensitively.
            let mut name_buf = vec![0u8; name_len];
            Read::read_exact(cursor, &mut name_buf).ok()?;
            let name = String::from_utf8_lossy(&name_buf).to_ascii_lowercase();
            Some((0u8, raw_type, Some(name)))
        }
    }
}

/// Accumulator for the per-result tags we care about (filled across the tag
/// loop, then moved into a [`ServerSearchResult`]).
#[derive(Default)]
struct ServerResultTags {
    file_name: String,
    file_size: u64,
    source_count: u32,
    complete_sources: u32,
    rating: Option<u8>,
    comment: Option<String>,
    media: crate::types::MediaMetadata,
}

/// Parse an eMule media-length string ("h:mm:ss" / "mm:ss" / "ss") into whole
/// seconds (matches `ConvertED2KTag` in eMule's SearchFile.cpp).
fn parse_media_length_str(s: &str) -> Option<u32> {
    let parts: Vec<u32> = s
        .split(':')
        .map(|p| p.trim().parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    match parts.as_slice() {
        // Saturating: a garbage wire string ("99999:99999:99999") would
        // otherwise wrap in release and report a nonsense duration.
        [h, m, sec] => Some(
            h.saturating_mul(3600)
                .saturating_add(m.saturating_mul(60))
                .saturating_add(*sec),
        ),
        [m, sec] => Some(m.saturating_mul(60).saturating_add(*sec)),
        [sec] => Some(*sec),
        _ => None,
    }
}

impl ServerResultTags {
    /// Route a decoded string value to the right field by tag id (KAD-style
    /// byte ids) or, for old-format tags, by lowercased name.
    fn apply_string(&mut self, name_id: u8, name: Option<&str>, value: String) {
        if name_id == 0x01 {
            self.file_name = value;
            return;
        }
        if value.is_empty() {
            return;
        }
        let is = |n: &str| name == Some(n);
        match name_id {
            0xF6 => self.comment = Some(value),
            0xD0 => self.media.artist = Some(value),
            0xD1 => self.media.album = Some(value),
            0xD2 => self.media.title = Some(value),
            0xD5 => self.media.codec = Some(value),
            0xD3 => self.media.duration = parse_media_length_str(&value),
            _ if is("comment") || is("description") => self.comment = Some(value),
            _ if is("artist") => self.media.artist = Some(value),
            _ if is("album") => self.media.album = Some(value),
            _ if is("title") => self.media.title = Some(value),
            _ if is("codec") => self.media.codec = Some(value),
            _ if is("length") => self.media.duration = parse_media_length_str(&value),
            _ => {}
        }
    }

    /// Route a decoded unsigned-int value to the right field by tag id or name.
    fn apply_uint(&mut self, name_id: u8, name: Option<&str>, value: u64) {
        let is = |n: &str| name == Some(n);
        match name_id {
            0x15 => self.source_count = value as u32,
            0x30 => self.complete_sources = value as u32,
            0xD3 if value > 0 => self.media.duration = Some(value as u32),
            0xD4 if value > 0 => self.media.bitrate = Some(value as u32),
            0xF7 => self.rating = Some(value as u8),
            _ if is("bitrate") && value > 0 => self.media.bitrate = Some(value as u32),
            _ if is("length") && value > 0 => self.media.duration = Some(value as u32),
            _ if (is("filerating") || is("rating")) => self.rating = Some(value as u8),
            _ => {}
        }
    }
}

/// Read and skip a tag value, extracting file metadata we care about.
/// Handles all eMule tag types including TAGTYPE_STR1..STR16 (0x11..0x20).
fn read_tag_value(
    cursor: &mut Cursor<&[u8]>,
    tag_type: u8,
    name_id: u8,
    name: Option<&str>,
    sink: &mut ServerResultTags,
) -> bool {
    match tag_type {
        // TAGTYPE_HASH (0x01)
        0x01 => {
            let mut buf = [0u8; 16];
            Read::read_exact(cursor, &mut buf).is_ok()
        }
        // TAGTYPE_STRING (0x02)
        0x02 => {
            let slen = match ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                Ok(v) => v as usize,
                Err(_) => return false,
            };
            let start = cursor.position() as usize;
            let end = start.saturating_add(slen);
            if end > cursor.get_ref().len() {
                return false;
            }
            let bytes = cursor.get_ref().get(start..end).unwrap_or(&[]);
            cursor.set_position(end as u64);
            let keep = &bytes[..bytes.len().min(8192)];
            sink.apply_string(name_id, name, String::from_utf8_lossy(keep).to_string());
            true
        }
        // TAGTYPE_UINT32 (0x03)
        0x03 => {
            let v = match ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                Ok(v) => v,
                Err(_) => return false,
            };
            match name_id {
                0x02 => sink.file_size = (sink.file_size & 0xFFFF_FFFF_0000_0000) | v as u64,
                0x3A => {
                    sink.file_size = (sink.file_size & 0x0000_0000_FFFF_FFFF) | ((v as u64) << 32)
                }
                _ => sink.apply_uint(name_id, name, v as u64),
            }
            true
        }
        // TAGTYPE_FLOAT32 (0x04)
        0x04 => {
            let mut buf = [0u8; 4];
            Read::read_exact(cursor, &mut buf).is_ok()
        }
        // TAGTYPE_BOOL (0x05)
        0x05 => {
            let _ = ReadBytesExt::read_u8(cursor);
            true
        }
        // TAGTYPE_BOOLARRAY (0x06): u16 bit count followed by ceil(count/8)
        // bytes. We don't consume the bits, but we MUST advance past them —
        // returning `false` here (as the previous `_ => false` did) aborted
        // the whole tag loop for the result, dropping the file_size/file_name
        // tags that follow. Matches `server_udp.rs`.
        0x06 => {
            if let Ok(count) = ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                let skip = (count as usize + 7) / 8;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_BLOB (0x07)
        0x07 => {
            if let Ok(blob_len) = ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                let skip = blob_len as usize;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                // checked_add: avoid pos+skip wrapping on 32-bit usize, which
                // could let a bogus length pass the `<= len` gate.
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_UINT16 (0x08)
        0x08 => {
            if let Ok(v) = ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                if name_id == 0x02 {
                    sink.file_size = v as u64;
                } else {
                    sink.apply_uint(name_id, name, v as u64);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_UINT8 (0x09)
        0x09 => {
            if let Ok(v) = ReadBytesExt::read_u8(cursor) {
                if name_id == 0x02 {
                    sink.file_size = v as u64;
                } else {
                    sink.apply_uint(name_id, name, v as u64);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_BSOB (0x0A)
        0x0A => {
            if let Ok(bsob_len) = ReadBytesExt::read_u8(cursor) {
                let skip = bsob_len as usize;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_UINT64 (0x0B)
        0x0B => {
            if let Ok(v) = ReadBytesExt::read_u64::<LittleEndian>(cursor) {
                if name_id == 0x02 {
                    // FT_FILESIZE
                    sink.file_size = v;
                } else {
                    sink.apply_uint(name_id, name, v);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_STR1..TAGTYPE_STR16 (0x11..0x20) — string with length embedded in type
        t if (0x11..=0x20).contains(&t) => {
            let slen = (t - 0x11 + 1) as usize;
            let mut sbuf = vec![0u8; slen];
            if Read::read_exact(cursor, &mut sbuf).is_err() {
                return false;
            }
            sink.apply_string(name_id, name, String::from_utf8_lossy(&sbuf).to_string());
            true
        }
        _ => false,
    }
}

fn parse_search_result(payload: &[u8]) -> anyhow::Result<Vec<ServerSearchResult>> {
    let mut cursor = Cursor::new(payload);
    let count = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor)? as usize;
    let mut results = Vec::with_capacity(count.min(1000));

    for _ in 0..count.min(1000) {
        let mut file_hash = [0u8; 16];
        if Read::read_exact(&mut cursor, &mut file_hash).is_err() {
            break;
        }
        let client_id = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let client_port = match ReadBytesExt::read_u16::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };

        let tag_count = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let mut tags = ServerResultTags::default();

        let tag_limit = tag_count.min(256);
        let mut in_sync = true;
        for _ in 0..tag_limit {
            let (name_id, tag_type, name) = match read_tag_header(&mut cursor) {
                Some(v) => v,
                None => {
                    in_sync = false;
                    break;
                }
            };
            if !read_tag_value(&mut cursor, tag_type, name_id, name.as_deref(), &mut tags) {
                in_sync = false;
                break;
            }
        }
        // A result may legitimately carry more than the cap; consume (and
        // discard) the surplus tags so the cursor stays aligned for the next
        // result record. Without this, tag_count > 256 desyncs the parser and
        // every subsequent result decodes from the wrong offset (garbage
        // hashes/names). Only safe to skip when the capped loop stayed in sync.
        if in_sync && tag_count > tag_limit {
            let mut discard = ServerResultTags::default();
            for _ in tag_limit..tag_count {
                let (name_id, tag_type, name) = match read_tag_header(&mut cursor) {
                    Some(v) => v,
                    None => {
                        in_sync = false;
                        break;
                    }
                };
                if !read_tag_value(
                    &mut cursor,
                    tag_type,
                    name_id,
                    name.as_deref(),
                    &mut discard,
                ) {
                    in_sync = false;
                    break;
                }
            }
        }

        results.push(ServerSearchResult {
            file_hash,
            client_id,
            client_port,
            file_name: tags.file_name,
            file_size: tags.file_size,
            source_count: tags.source_count,
            complete_source_count: tags.complete_sources,
            rating: tags.rating,
            comment: tags.comment,
            media: tags.media,
        });

        // If a tag failed to decode mid-record the cursor is no longer aligned
        // to the next result; stop rather than decoding subsequent entries from
        // a mid-tag offset (which would emit garbage rows). The surplus-tag
        // path above keeps us aligned on success, so only a desync forces the
        // break. Mirrors the UDP sibling in `server_udp.rs`.
        if !in_sync {
            break;
        }
    }

    Ok(results)
}

fn parse_found_sources(
    payload: &[u8],
    obfuscated: bool,
) -> anyhow::Result<([u8; 16], Vec<ServerSource>)> {
    if payload.len() < 17 {
        anyhow::bail!(
            "found_sources payload too short ({} bytes, need at least 17)",
            payload.len()
        );
    }
    let mut cursor = Cursor::new(payload);
    let mut file_hash = [0u8; 16];
    Read::read_exact(&mut cursor, &mut file_hash)?;
    let count = ReadBytesExt::read_u8(&mut cursor)? as usize;
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        // A truncated tail must not discard the sources we already parsed
        // successfully: a short/garbled final record should still leave the
        // earlier (valid) sources usable, matching eMule's tolerant parsing.
        let id = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let port = match ReadBytesExt::read_u16::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let crypt_options = if obfuscated {
            match ReadBytesExt::read_u8(&mut cursor) {
                Ok(v) => Some(v),
                Err(_) => break,
            }
        } else {
            None
        };
        let user_hash = if crypt_options.is_some_and(|opts| (opts & 0x80) != 0) {
            let mut hash = [0u8; 16];
            if Read::read_exact(&mut cursor, &mut hash).is_err() {
                break;
            }
            Some(hash)
        } else {
            None
        };
        // Strip the 0x80 "hash follows" flag — only bits 0-2 are peer connect options
        let connect_opts = crypt_options.map(|opts| opts & 0x7F);
        if id < LOWID_THRESHOLD {
            sources.push(ServerSource {
                ip: String::new(),
                port,
                client_id: id,
                crypt_options: connect_opts,
                user_hash,
            });
        } else {
            let ip = std::net::Ipv4Addr::from(id.to_le_bytes());
            sources.push(ServerSource {
                ip: ip.to_string(),
                port,
                client_id: 0,
                crypt_options: connect_opts,
                user_hash,
            });
        }
    }

    Ok((file_hash, sources))
}

async fn write_server_packet<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    opcode: u8,
    payload: &[u8],
) -> io::Result<()> {
    let wire_len = u32::try_from(1 + payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet payload too large for u32 length field",
        )
    })?;
    writer.write_u8(OP_EDONKEYHEADER).await?;
    writer.write_u32_le(wire_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_server_packet_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_server_packet(reader),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server read timed out"))?
}

const OP_PACKEDPROT: u8 = 0xD4;
const MAX_UNCOMPRESSED_SERVER_PACKET: usize = 300_000;

async fn read_server_packet<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    if protocol != OP_EDONKEYHEADER && protocol != OP_PACKEDPROT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected server protocol byte: 0x{protocol:02X}"),
        ));
    }
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 5 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid server packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = Vec::new();
    if payload_len > 0 {
        // Grow the buffer as bytes actually arrive rather than eagerly
        // allocating the full declared length (up to 5 MiB). A slow/hostile
        // server would otherwise pin that memory for the whole read window
        // before sending a single byte.
        payload.reserve(payload_len.min(64 * 1024));
        let mut remaining = payload_len;
        let mut chunk = [0u8; 32 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            reader.read_exact(&mut chunk[..want]).await?;
            payload.extend_from_slice(&chunk[..want]);
            remaining -= want;
        }
    }

    if protocol == OP_PACKEDPROT {
        let decompressed = decompress_server_payload(&payload)?;
        debug!(
            "Decompressed server packet: opcode=0x{opcode:02X}, {payload_len} -> {} bytes",
            decompressed.len()
        );
        Ok((opcode, decompressed))
    } else {
        Ok((opcode, payload))
    }
}

fn decompress_server_payload(compressed: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        decompressed.extend_from_slice(&buf[..n]);
        if decompressed.len() > MAX_UNCOMPRESSED_SERVER_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed server packet exceeds size limit",
            ));
        }
    }
    Ok(decompressed)
}
