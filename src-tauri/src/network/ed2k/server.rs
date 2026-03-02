use std::io::{self, Cursor, Read};
use std::net::SocketAddr;

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use super::messages::*;

// Server protocol opcodes (OP_EDONKEYHEADER)
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_SERVERLIST: u8 = 0x32;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_IDCHANGE: u8 = 0x40;
pub const OP_SERVERIDENT: u8 = 0x41;
pub const OP_SEARCHREQUEST: u8 = 0x16;
pub const OP_SEARCHRESULT: u8 = 0x33;
pub const OP_GETSOURCES: u8 = 0x19;
pub const OP_FOUNDSOURCES: u8 = 0x42;
pub const OP_GETSERVERLIST: u8 = 0x14;
pub const OP_REJECT: u8 = 0x05;
pub const OP_OFFERFILES: u8 = 0x15;
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
pub const OP_CALLBACK_FAIL: u8 = 0x36;

/// LowID threshold: client_id < this means LowID
pub const LOWID_THRESHOLD: u32 = 0x0100_0000;

/// A file to offer to the ed2k server via OP_OFFERFILES.
pub struct OfferFile {
    pub hash: [u8; 16],
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ServerSearchResult {
    pub file_hash: [u8; 16],
    pub file_name: String,
    pub file_size: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
}

#[derive(Debug, Clone)]
pub struct ServerSource {
    pub ip: String,
    pub port: u16,
    /// LowID client_id from the server (0 = HighID, use ip:port directly)
    pub client_id: u32,
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
}

impl Ed2kServerConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        )
        .await??;

        let (reader, writer) = stream.into_split();
        Ok(Self {
            transport: ServerTransport::Plain {
                reader: tokio::io::BufReader::new(reader),
                writer: tokio::io::BufWriter::new(writer),
            },
            session: None,
        })
    }

    pub async fn connect_encrypted(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = super::server_crypt::connect_obfuscated(addr).await?;
        Ok(Self {
            transport: ServerTransport::Encrypted(stream),
            session: None,
        })
    }

    pub async fn login(
        &mut self,
        user_hash: &[u8; 16],
        nickname: &str,
        tcp_port: u16,
    ) -> anyhow::Result<ServerSession> {
        let flags: u32 = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES
            | SRVCAP_SUPPORTCRYPT | SRVCAP_REQUESTCRYPT;
        let payload = build_login_request(user_hash, tcp_port, nickname);
        let is_encrypted = matches!(self.transport, ServerTransport::Encrypted(_));
        info!("Sending OP_LOGINREQUEST ({} bytes, encrypted={}): port={}, flags=0x{:04X}",
            payload.len(), is_encrypted, tcp_port, flags);

        // Build the full wire packet: [protocol(1)][length(4)][opcode(1)][payload]
        let mut wire_packet = Vec::with_capacity(6 + payload.len());
        wire_packet.push(OP_EDONKEYHEADER);
        wire_packet.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
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
        };

        for i in 0..50 {
            let (opcode, payload) = match self.read_packet().await {
                Ok(p) => p,
                Err(e) => {
                    info!("Server read error on packet {i}: kind={:?} msg={e}", e.kind());
                    break;
                }
            };

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
                        session.client_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if payload.len() >= 8 {
                            session.server_flags = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        }
                        info!("Server assigned client ID: {}", session.client_id);
                    }
                    self.session = Some(session.clone());
                    return Ok(session);
                }
                OP_SERVERSTATUS => {
                    if payload.len() >= 8 {
                        session.user_count = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        session.file_count = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        debug!("Server status: {} users, {} files", session.user_count, session.file_count);
                    }
                }
                OP_SERVERIDENT => {
                    // Server identification (hash + IP + port + tags)
                    debug!("Got server identification");
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

        anyhow::bail!("Login sequence did not complete (no IDCHANGE received)");
    }

    async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        match &mut self.transport {
            ServerTransport::Plain { reader, .. } => {
                read_server_packet_timeout(reader).await
            }
            ServerTransport::Encrypted(stream) => {
                stream.read_packet().await
            }
        }
    }

    async fn write_packet(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        match &mut self.transport {
            ServerTransport::Plain { writer, .. } => {
                write_server_packet(writer, opcode, payload).await
            }
            ServerTransport::Encrypted(stream) => {
                let mut wire = Vec::with_capacity(6 + payload.len());
                wire.push(OP_EDONKEYHEADER);
                wire.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
                wire.push(opcode);
                wire.extend_from_slice(payload);
                info!(
                    "Server write_packet: opcode=0x{opcode:02X}, wire={} bytes, plaintext_head={:02X?}",
                    wire.len(),
                    &wire[..wire.len().min(20)]
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
    async fn poll_read_packet(&mut self) -> Option<(u8, Vec<u8>)> {
        match &mut self.transport {
            ServerTransport::Plain { reader, .. } => {
                let has_buffered = !reader.buffer().is_empty();
                if !has_buffered {
                    let tcp = reader.get_ref();
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        tcp.readable(),
                    ).await {
                        Ok(Ok(_)) => {}
                        _ => return None,
                    }
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read_server_packet(reader),
                ).await {
                    Ok(Ok(pkt)) => {
                        info!("Server packet: opcode=0x{:02X}, {} bytes", pkt.0, pkt.1.len());
                        Some(pkt)
                    }
                    Ok(Err(e)) => {
                        warn!("Server packet read error: {e}");
                        None
                    }
                    Err(_) => None,
                }
            }
            ServerTransport::Encrypted(stream) => {
                let has_buffered = !stream.reader.buffer().is_empty();
                if !has_buffered {
                    let tcp = stream.reader.get_ref();
                    match tokio::time::timeout(
                        std::time::Duration::from_millis(50),
                        tcp.readable(),
                    ).await {
                        Ok(Ok(_)) => {}
                        _ => return None,
                    }
                }
                match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    stream.read_packet(),
                ).await {
                    Ok(Ok(pkt)) => {
                        info!("Server packet (encrypted): opcode=0x{:02X}, {} bytes", pkt.0, pkt.1.len());
                        Some(pkt)
                    }
                    Ok(Err(e)) => {
                        warn!("Server packet read error (encrypted): {e}");
                        None
                    }
                    Err(_) => None,
                }
            }
        }
    }

    /// Send a search request to the server (non-blocking).
    /// The result will arrive later via `poll_messages()` as `ServerEvent::SearchResult`.
    pub async fn send_search(&mut self, query: &str) -> anyhow::Result<Vec<ServerSearchResult>> {
        let payload = build_search_request(query);
        info!(
            "Sending OP_SEARCHREQUEST ({} bytes payload) for query '{}'",
            payload.len(), query
        );
        self.write_packet(OP_SEARCHREQUEST, &payload).await?;

        // Wait for the search response directly instead of relying on polling.
        // eMule servers typically respond within 2-5 seconds.
        for attempt in 1..=5 {
            match tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.read_packet(),
            ).await {
                Ok(Ok((opcode, resp_payload))) => {
                    info!("Search response attempt {attempt}: opcode=0x{opcode:02X}, {} bytes", resp_payload.len());
                    match opcode {
                        OP_SEARCHRESULT => {
                            match parse_search_result(&resp_payload) {
                                Ok(results) => {
                                    info!("Server returned {} search results", results.len());
                                    return Ok(results);
                                }
                                Err(e) => {
                                    warn!("Failed to parse search results: {e}");
                                    return Ok(Vec::new());
                                }
                            }
                        }
                        OP_SERVERMESSAGE => {
                            if resp_payload.len() >= 2 {
                                let len = u16::from_le_bytes([resp_payload[0], resp_payload[1]]) as usize;
                                if resp_payload.len() >= 2 + len {
                                    let msg = String::from_utf8_lossy(&resp_payload[2..2 + len]);
                                    info!("Server message during search: {msg}");
                                }
                            }
                        }
                        _ => {
                            info!("Non-search opcode 0x{opcode:02X} during search wait, continuing...");
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Search response read error: {e}");
                    return Ok(Vec::new());
                }
                Err(_) => {
                    info!("Search response timeout (attempt {attempt}/5)");
                }
            }
        }
        info!("No search response after 25 seconds");
        Ok(Vec::new())
    }

    /// Send a source request to the server (non-blocking).
    /// The result will arrive later via `poll_messages()` as `ServerEvent::FoundSources`.
    pub async fn send_get_sources(&mut self, file_hash: &[u8; 16]) -> anyhow::Result<()> {
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(file_hash);
        self.write_packet(OP_GETSOURCES, &payload).await?;
        Ok(())
    }

    pub async fn keep_alive(&mut self) -> anyhow::Result<()> {
        self.write_packet(OP_GETSERVERLIST, &[]).await?;
        Ok(())
    }

    pub async fn request_server_list(&mut self) -> anyhow::Result<()> {
        self.write_packet(OP_GETSERVERLIST, &[]).await?;
        debug!("Sent OP_GETSERVERLIST request to server");
        Ok(())
    }

    pub async fn request_callback(&mut self, client_id: u32) -> anyhow::Result<()> {
        let payload = client_id.to_le_bytes().to_vec();
        self.write_packet(OP_CALLBACKREQUEST, &payload).await?;
        info!("Sent callback request for LowID client {client_id}");
        Ok(())
    }

    /// Send OP_OFFERFILES to the server with our shared file list.
    /// eMule sends this after login (OP_IDCHANGE) and when shared files change.
    pub async fn offer_files(&mut self, files: &[OfferFile], tcp_port: u16) -> anyhow::Result<()> {
        let client_id = self.our_client_id().unwrap_or(0);
        let mut payload = Vec::with_capacity(4 + files.len() * 64);
        payload.extend_from_slice(&(files.len() as u32).to_le_bytes());
        for file in files {
            payload.extend_from_slice(&file.hash);
            payload.extend_from_slice(&client_id.to_le_bytes());
            payload.extend_from_slice(&tcp_port.to_le_bytes());
            let mut tag_count: u32 = 0;
            let mut tags = Vec::new();
            write_string_tag(&mut tags, 0x01, &file.name); // FT_FILENAME
            tag_count += 1;
            if file.size > u32::MAX as u64 {
                tags.push(0x0B); // TAGTYPE_UINT64
                tags.extend_from_slice(&1u16.to_le_bytes());
                tags.push(0x02); // FT_FILESIZE
                tags.extend_from_slice(&file.size.to_le_bytes());
            } else {
                write_uint32_tag(&mut tags, 0x02, file.size as u32); // FT_FILESIZE
            }
            tag_count += 1;
            payload.extend_from_slice(&tag_count.to_le_bytes());
            payload.extend_from_slice(&tags);
        }
        self.write_packet(OP_OFFERFILES, &payload).await?;
        info!("Sent OP_OFFERFILES with {} shared files to server", files.len());
        Ok(())
    }

    pub async fn poll_messages(&mut self) -> Vec<ServerEvent> {
        let mut events = Vec::new();
        loop {
            match self.poll_read_packet().await {
                Some((opcode, payload)) => {
                    info!("Server poll received opcode=0x{opcode:02X}, {} bytes", payload.len());
                    events.extend(parse_server_event(opcode, &payload));
                }
                None => break,
            }
        }
        events
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

    pub async fn disconnect(self) {
        match self.transport {
            ServerTransport::Plain { mut writer, .. } => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    writer.shutdown(),
                ).await;
            }
            ServerTransport::Encrypted(mut stream) => {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    stream.writer.shutdown(),
                ).await;
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    CallbackRequested { ip: String, port: u16 },
    CallbackFailed,
    Message(String),
    StatusUpdate { users: u32, files: u32 },
    ServerList { data: Vec<u8> },
    SearchResult { results: Vec<ServerSearchResult> },
    FoundSources { file_hash: [u8; 16], sources: Vec<ServerSource> },
}

fn parse_server_event(opcode: u8, payload: &[u8]) -> Vec<ServerEvent> {
    let mut events = Vec::new();
    match opcode {
        OP_CALLBACKREQUESTED => {
            if payload.len() >= 6 {
                let ip = std::net::Ipv4Addr::from(u32::from_le_bytes([
                    payload[0], payload[1], payload[2], payload[3],
                ]).to_be_bytes());
                let port = u16::from_le_bytes([payload[4], payload[5]]);
                info!("Callback requested: connect to {ip}:{port}");
                events.push(ServerEvent::CallbackRequested { ip: ip.to_string(), port });
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
        OP_SERVERLIST => {
            debug!("Got server list from server ({} bytes)", payload.len());
            events.push(ServerEvent::ServerList { data: payload.to_vec() });
        }
        OP_SEARCHRESULT => {
            match parse_search_result(payload) {
                Ok(results) => {
                    debug!("Server search result: {} files", results.len());
                    events.push(ServerEvent::SearchResult { results });
                }
                Err(e) => {
                    debug!("Failed to parse search result: {e}");
                }
            }
        }
        OP_FOUNDSOURCES => {
            match parse_found_sources(payload) {
                Ok((file_hash, sources)) => {
                    debug!("Server found {} sources for file {}", sources.len(), hex::encode(file_hash));
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

// CT_SERVER_FLAGS capability bits (from eMule Opcodes.h)
const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;

const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

fn build_login_request(user_hash: &[u8; 16], tcp_port: u16, nickname: &str) -> Vec<u8> {
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
    // REQUESTCRYPT is required by most modern servers to accept our login.
    let flags: u32 = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES
        | SRVCAP_SUPPORTCRYPT | SRVCAP_REQUESTCRYPT;
    write_uint32_tag(&mut buf, CT_SERVER_FLAGS, flags);

    // Tag 4: CT_EMULE_VERSION (0xFB) - (compat << 24) | (major << 17) | (minor << 10) | (update << 7)
    // Report as eMule 0.70b (current Community release) for server compatibility
    let emule_version: u32 = (0u32 << 24) | (0u32 << 17) | (70u32 << 10) | (1u32 << 7);
    write_uint32_tag(&mut buf, CT_EMULE_VERSION, emule_version);

    buf
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) {
    buf.push(0x02); // TAGTYPE_STRING
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
    buf.extend_from_slice(value.as_bytes());
}

fn write_uint32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    buf.extend_from_slice(&value.to_le_bytes());
}

fn build_search_request(query: &str) -> Vec<u8> {
    // Simple string search: type=1 (string), search_term
    let mut buf = Vec::new();
    buf.push(0x01); // Search type: string
    buf.extend_from_slice(&(query.len() as u16).to_le_bytes());
    buf.extend_from_slice(query.as_bytes());
    buf
}

/// Read one eMule-style tag (supports both old and "new tags" compressed format).
/// Returns (name_id, tag_type, was read successfully).
fn read_tag_header(cursor: &mut Cursor<&[u8]>) -> Option<(u8, u8)> {
    let raw_type = ReadBytesExt::read_u8(cursor).ok()?;

    if raw_type & 0x80 != 0 {
        // New tag format: high bit set → single-byte name follows, type is low 7 bits
        let tag_type = raw_type & 0x7F;
        let name_id = ReadBytesExt::read_u8(cursor).ok()?;
        Some((name_id, tag_type))
    } else {
        // Old format: u16 name length + name bytes
        let name_len = ReadBytesExt::read_u16::<LittleEndian>(cursor).ok()? as usize;
        let name_id = if name_len == 1 {
            ReadBytesExt::read_u8(cursor).ok()?
        } else {
            let mut name_buf = vec![0u8; name_len];
            Read::read_exact(cursor, &mut name_buf).ok()?;
            0u8
        };
        Some((name_id, raw_type))
    }
}

/// Read and skip a tag value, extracting file metadata we care about.
/// Handles all eMule tag types including TAGTYPE_STR1..STR16 (0x11..0x20).
fn read_tag_value(
    cursor: &mut Cursor<&[u8]>,
    tag_type: u8,
    name_id: u8,
    file_name: &mut String,
    file_size: &mut u64,
    source_count: &mut u32,
    complete_sources: &mut u32,
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
            let mut sbuf = vec![0u8; slen.min(8192)];
            if Read::read_exact(cursor, &mut sbuf).is_err() {
                return false;
            }
            if name_id == 0x01 { // FT_FILENAME
                *file_name = String::from_utf8_lossy(&sbuf).to_string();
            }
            true
        }
        // TAGTYPE_UINT32 (0x03)
        0x03 => {
            let v = match ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                Ok(v) => v,
                Err(_) => return false,
            };
            match name_id {
                0x02 => *file_size = v as u64,     // FT_FILESIZE
                0x15 => *source_count = v,          // FT_SOURCES
                0x30 => *complete_sources = v,      // FT_COMPLETE_SOURCES
                _ => {}
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
        // TAGTYPE_BLOB (0x07)
        0x07 => {
            if let Ok(blob_len) = ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                let skip = blob_len.min(1_000_000) as usize;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                if pos + skip <= len {
                    cursor.set_position((pos + skip) as u64);
                    return true;
                }
            }
            false
        }
        // TAGTYPE_UINT16 (0x08)
        0x08 => {
            if let Ok(v) = ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                match name_id {
                    0x02 => *file_size = v as u64,
                    0x15 => *source_count = v as u32,
                    0x30 => *complete_sources = v as u32,
                    _ => {}
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_UINT8 (0x09)
        0x09 => {
            if let Ok(v) = ReadBytesExt::read_u8(cursor) {
                match name_id {
                    0x02 => *file_size = v as u64,
                    0x15 => *source_count = v as u32,
                    0x30 => *complete_sources = v as u32,
                    _ => {}
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
                if pos + skip <= len {
                    cursor.set_position((pos + skip) as u64);
                    return true;
                }
            }
            false
        }
        // TAGTYPE_UINT64 (0x0B)
        0x0B => {
            if let Ok(v) = ReadBytesExt::read_u64::<LittleEndian>(cursor) {
                if name_id == 0x02 { // FT_FILESIZE
                    *file_size = v;
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
            if name_id == 0x01 { // FT_FILENAME
                *file_name = String::from_utf8_lossy(&sbuf).to_string();
            }
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
        let _client_id = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
        let _client_port = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor).unwrap_or(0);

        let tag_count = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
        let mut file_name = String::new();
        let mut file_size: u64 = 0;
        let mut source_count: u32 = 0;
        let mut complete_sources: u32 = 0;

        for _ in 0..tag_count {
            let (name_id, tag_type) = match read_tag_header(&mut cursor) {
                Some(v) => v,
                None => break,
            };
            if !read_tag_value(
                &mut cursor, tag_type, name_id,
                &mut file_name, &mut file_size, &mut source_count, &mut complete_sources,
            ) {
                break;
            }
        }

        results.push(ServerSearchResult {
            file_hash,
            file_name,
            file_size,
            source_count,
            complete_source_count: complete_sources,
        });
    }

    Ok(results)
}

fn parse_found_sources(payload: &[u8]) -> anyhow::Result<([u8; 16], Vec<ServerSource>)> {
    if payload.len() < 17 {
        return Ok(([0u8; 16], Vec::new()));
    }
    let mut cursor = Cursor::new(payload);
    let mut file_hash = [0u8; 16];
    Read::read_exact(&mut cursor, &mut file_hash)?;
    let count = ReadBytesExt::read_u8(&mut cursor)? as usize;
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        let id = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor)?;
        let port = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor)?;
        if id < LOWID_THRESHOLD {
            // LowID source: client_id is a server-assigned ID, not an IP.
            // Must use OP_CALLBACKREQUEST to reach this peer.
            sources.push(ServerSource {
                ip: String::new(),
                port,
                client_id: id,
            });
        } else {
            // HighID source: ID is the peer's public IP
            let ip = std::net::Ipv4Addr::from(id.to_be_bytes());
            sources.push(ServerSource {
                ip: ip.to_string(),
                port,
                client_id: 0,
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
    writer.write_u8(OP_EDONKEYHEADER).await?;
    writer.write_u32_le((1 + payload.len()) as u32).await?;
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

async fn read_server_packet<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    if protocol != OP_EDONKEYHEADER && protocol != OP_PACKEDPROT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected server protocol byte: 0x{protocol:02X}"),
        ));
    }
    let length = reader.read_u32_le().await? as usize;
    if length == 0 || length > 50 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid server packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = length - 1;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    if protocol == OP_PACKEDPROT {
        let decompressed = decompress_server_payload(&payload)?;
        debug!("Decompressed server packet: opcode=0x{opcode:02X}, {payload_len} -> {} bytes", decompressed.len());
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
