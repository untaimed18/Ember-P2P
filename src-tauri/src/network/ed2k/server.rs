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
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_GETSERVERLIST: u8 = 0x14;
pub const OP_REJECT: u8 = 0x05;

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
}

pub struct Ed2kServerConnection {
    reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    pub session: Option<ServerSession>,
}

impl Ed2kServerConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(30),
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
        write_server_packet(&mut self.writer, OP_LOGINREQUEST, &payload).await?;

        let mut session = ServerSession {
            client_id: 0,
            server_flags: 0,
            server_name: String::new(),
            user_count: 0,
            file_count: 0,
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
                    debug!("Got server list from server");
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
        write_server_packet(&mut self.writer, OP_GETSERVERLIST, &[]).await?;
        Ok(())
    }

    pub async fn disconnect(mut self) {
        let _ = self.writer.shutdown().await;
    }
}

fn build_login_request(user_hash: &[u8; 16], tcp_port: u16, nickname: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(user_hash);
    // Client ID (0 = request new from server)
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&tcp_port.to_le_bytes());

    let mut tags: Vec<(u8, Ed2kTagValue)> = Vec::new();
    tags.push((0x01, Ed2kTagValue::String(nickname.to_string()))); // CT_NAME
    tags.push((0x11, Ed2kTagValue::Uint32(0x3C))); // CT_VERSION
    // CT_SERVER_FLAGS: indicate capabilities
    // Bit 0: zlib compression, Bit 1: IP in login, Bit 2: aux port,
    // Bit 3: new tags, Bit 4: unicode, Bit 9: large files
    let flags: u32 = (1 << 0) | (1 << 3) | (1 << 4) | (1 << 9);
    tags.push((0x20, Ed2kTagValue::Uint32(flags))); // CT_SERVER_FLAGS

    buf.extend_from_slice(&(tags.len() as u32).to_le_bytes());
    for (name_id, value) in &tags {
        match value {
            Ed2kTagValue::String(s) => {
                buf.push(0x02); // TAGTYPE_STRING
                buf.extend_from_slice(&1u16.to_le_bytes()); // name length
                buf.push(*name_id);
                buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
                buf.extend_from_slice(s.as_bytes());
            }
            Ed2kTagValue::Uint32(v) => {
                buf.push(0x03); // TAGTYPE_UINT32
                buf.extend_from_slice(&1u16.to_le_bytes());
                buf.push(*name_id);
                buf.extend_from_slice(&v.to_le_bytes());
            }
            _ => {}
        }
    }
    buf
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
