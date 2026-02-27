use std::io::{self, Cursor, Read};
use std::net::SocketAddr;

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

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
#[allow(dead_code)]
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
#[allow(dead_code)]
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
#[allow(dead_code)]
pub const OP_CALLBACK_FAIL: u8 = 0x36;

/// LowID threshold: client_id < this means LowID
pub const LOWID_THRESHOLD: u32 = 0x0100_0000;

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
}

pub struct Ed2kServerConnection {
    reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
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
            reader: tokio::io::BufReader::new(reader),
            writer: tokio::io::BufWriter::new(writer),
            session: None,
        })
    }

    pub async fn login(
        &mut self,
        user_hash: &[u8; 16],
        nickname: &str,
        tcp_port: u16,
    ) -> anyhow::Result<ServerSession> {
        let payload = build_login_request(user_hash, tcp_port, nickname);
        info!("Sending OP_LOGINREQUEST ({} bytes): port={}, nick={}, flags=0x{:04X}, emule_ver=0x{:X}",
            payload.len(), tcp_port, nickname,
            SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES,
            (0u32 << 17) | (50u32 << 10) | (0u32 << 7));
        write_server_packet(&mut self.writer, OP_LOGINREQUEST, &payload).await?;

        let mut session = ServerSession {
            client_id: 0,
            server_flags: 0,
            server_name: String::new(),
            user_count: 0,
            file_count: 0,
            server_list_data: None,
        };

        // Process login response sequence (may receive SERVERMESSAGE, IDCHANGE, SERVERLIST, SERVERSTATUS)
        for _ in 0..10 {
            let (opcode, payload) = match read_server_packet_timeout(&mut self.reader).await {
                Ok(p) => p,
                Err(_) => break,
            };

            match opcode {
                OP_SERVERMESSAGE => {
                    if payload.len() >= 2 {
                        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                        if payload.len() >= 2 + len {
                            let msg = String::from_utf8_lossy(&payload[2..2 + len]);
                            info!("Server MOTD: {msg}");
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

    pub async fn search(&mut self, query: &str) -> anyhow::Result<Vec<ServerSearchResult>> {
        let payload = build_search_request(query);
        write_server_packet(&mut self.writer, OP_SEARCHREQUEST, &payload).await?;

        let mut results = Vec::new();
        let (opcode, payload) = read_server_packet_timeout(&mut self.reader).await?;
        if opcode == OP_SEARCHRESULT {
            results = parse_search_result(&payload)?;
        }
        Ok(results)
    }

    pub async fn get_sources(&mut self, file_hash: &[u8; 16]) -> anyhow::Result<Vec<ServerSource>> {
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(file_hash);
        write_server_packet(&mut self.writer, OP_GETSOURCES, &payload).await?;

        let (opcode, resp) = read_server_packet_timeout(&mut self.reader).await?;
        if opcode == OP_FOUNDSOURCES {
            return parse_found_sources(&resp);
        }
        Ok(Vec::new())
    }

    pub async fn keep_alive(&mut self) -> anyhow::Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            write_server_packet(&mut self.writer, OP_GETSERVERLIST, &[]),
        ).await.map_err(|_| anyhow::anyhow!("keep_alive write timed out"))??;
        Ok(())
    }

    /// Explicitly request the server's list of known servers (OP_GETSERVERLIST).
    pub async fn request_server_list(&mut self) -> anyhow::Result<()> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            write_server_packet(&mut self.writer, OP_GETSERVERLIST, &[]),
        ).await.map_err(|_| anyhow::anyhow!("request_server_list write timed out"))??;
        debug!("Sent OP_GETSERVERLIST request to server");
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn request_callback(&mut self, client_id: u32) -> anyhow::Result<()> {
        let payload = client_id.to_le_bytes().to_vec();
        write_server_packet(&mut self.writer, OP_CALLBACKREQUEST, &payload).await?;
        info!("Sent callback request for LowID client {client_id}");
        Ok(())
    }

    pub async fn poll_messages(&mut self) -> Vec<ServerEvent> {
        let mut events = Vec::new();
        match tokio::time::timeout(
            std::time::Duration::from_millis(50),
            read_server_packet(&mut self.reader),
        ).await {
            Ok(Ok((opcode, payload))) => {
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
                        events.push(ServerEvent::ServerList { data: payload });
                    }
                    _ => {}
                }
            }
            _ => {}
        }
        events
    }

    #[allow(dead_code)]
    pub fn is_low_id(&self) -> bool {
        self.session
            .as_ref()
            .map(|s| s.client_id > 0 && s.client_id < LOWID_THRESHOLD)
            .unwrap_or(false)
    }

    #[allow(dead_code)]
    pub fn our_client_id(&self) -> Option<u32> {
        self.session.as_ref().map(|s| s.client_id)
    }

    pub async fn disconnect(mut self) {
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            self.writer.shutdown(),
        ).await;
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum ServerEvent {
    CallbackRequested { ip: String, port: u16 },
    CallbackFailed,
    Message(String),
    StatusUpdate { users: u32, files: u32 },
    ServerList { data: Vec<u8> },
}

// CT_SERVER_FLAGS capability bits (from eMule Opcodes.h)
const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;

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
    // Matches eMule: SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_LARGEFILES | SRVCAP_UNICODE
    let flags: u32 = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES;
    write_uint32_tag(&mut buf, CT_SERVER_FLAGS, flags);

    // Tag 4: CT_EMULE_VERSION (0xFB) - (major << 17) | (minor << 10) | (update << 7)
    // Identify as eMule 0.50a compatible
    let emule_version: u32 = (0u32 << 17) | (50u32 << 10) | (0u32 << 7);
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
            let tag_type = ReadBytesExt::read_u8(&mut cursor).unwrap_or(0);
            let name_len = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor).unwrap_or(0) as usize;
            let mut name_buf = vec![0u8; name_len];
            let _ = Read::read_exact(&mut cursor, &mut name_buf);
            let name_id = if name_len == 1 { name_buf[0] } else { 0 };

            match tag_type {
                0x02 => {
                    let slen = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor).unwrap_or(0) as usize;
                    let mut sbuf = vec![0u8; slen];
                    let _ = Read::read_exact(&mut cursor, &mut sbuf);
                    if name_id == 0x01 {
                        file_name = String::from_utf8_lossy(&sbuf).to_string();
                    }
                }
                0x03 => {
                    let v = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor).unwrap_or(0);
                    match name_id {
                        0x02 => file_size = v as u64,
                        0x15 => source_count = v,
                        0x30 => complete_sources = v,
                        _ => {}
                    }
                }
                0x08 => { let _ = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor); }
                0x09 => { let _ = ReadBytesExt::read_u8(&mut cursor); }
                _ => break,
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

fn parse_found_sources(payload: &[u8]) -> anyhow::Result<Vec<ServerSource>> {
    if payload.len() < 17 {
        return Ok(Vec::new());
    }
    let mut cursor = Cursor::new(payload);
    let mut _hash = [0u8; 16];
    Read::read_exact(&mut cursor, &mut _hash)?;
    let count = ReadBytesExt::read_u8(&mut cursor)? as usize;
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        let ip_bytes = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor)?;
        let port = ReadBytesExt::read_u16::<LittleEndian>(&mut cursor)?;
        let ip = std::net::Ipv4Addr::from(ip_bytes.to_be_bytes());
        sources.push(ServerSource {
            ip: ip.to_string(),
            port,
        });
    }

    Ok(sources)
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

async fn read_server_packet<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    if protocol != OP_EDONKEYHEADER {
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
    Ok((opcode, payload))
}
