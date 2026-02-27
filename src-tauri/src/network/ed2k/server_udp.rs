use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, SocketAddr};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tokio::net::UdpSocket;
use tracing::{debug, info};

use super::server_list::ServerEntry;

pub const OP_EDONKEYPROT: u8 = 0xE3;

pub const OP_GLOBSEARCHREQ: u8 = 0x98;
pub const OP_GLOBSEARCHRES: u8 = 0x99;
pub const OP_GLOBGETSOURCES: u8 = 0x9A;
pub const OP_GLOBGETSOURCES2: u8 = 0x94;
pub const OP_GLOBFOUNDSOURCES: u8 = 0x9B;
pub const OP_GLOBSERVSTATREQ: u8 = 0x96;
pub const OP_GLOBSERVSTATRES: u8 = 0x97;

/// Minimum seconds between status pings to the same server
const MIN_PING_INTERVAL_SECS: i64 = 5;
/// Normal server status ping interval (4.5 hours)
pub const STAT_REASK_INTERVAL_SECS: i64 = 16200;
/// Interval between rotating global source requests to servers
pub const SOURCE_UDP_INTERVAL_SECS: i64 = 2;

pub struct ServerUdpSocket {
    socket: UdpSocket,
    last_ping_times: std::collections::HashMap<SocketAddr, i64>,
}

impl ServerUdpSocket {
    pub async fn bind(port: u16) -> anyhow::Result<Self> {
        let addr: SocketAddr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port);
        let socket = UdpSocket::bind(addr).await?;
        info!("Server UDP socket bound on port {port}");
        Ok(Self {
            socket,
            last_ping_times: std::collections::HashMap::new(),
        })
    }

    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket,
            last_ping_times: std::collections::HashMap::new(),
        }
    }

    pub async fn send_status_ping(&mut self, server: &ServerEntry) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", server.ip, server.port + 4)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

        let now = chrono::Utc::now().timestamp();
        if let Some(&last) = self.last_ping_times.get(&addr) {
            if now - last < MIN_PING_INTERVAL_SECS {
                return Ok(());
            }
        }

        let mut packet = Vec::with_capacity(2);
        packet.push(OP_EDONKEYPROT);
        packet.push(OP_GLOBSERVSTATREQ);

        self.socket.send_to(&packet, addr).await?;
        self.last_ping_times.insert(addr, now);
        debug!("Sent status ping to {}:{}", server.ip, server.port);
        Ok(())
    }

    pub async fn send_get_sources(&self, server: &ServerEntry, file_hash: &[u8; 16], file_size: u64) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", server.ip, server.port + 4)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

        let mut packet = Vec::with_capacity(22);
        packet.push(OP_EDONKEYPROT);

        if file_size > 0 {
            packet.push(OP_GLOBGETSOURCES2);
            packet.write_all(file_hash)?;
            packet.write_u32::<LittleEndian>(file_size as u32)?;
        } else {
            packet.push(OP_GLOBGETSOURCES);
            packet.write_all(file_hash)?;
        }

        self.socket.send_to(&packet, addr).await?;
        Ok(())
    }

    pub async fn send_global_search(&self, server: &ServerEntry, search_expr: &[u8]) -> anyhow::Result<()> {
        let addr: SocketAddr = format!("{}:{}", server.ip, server.port + 4)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

        let mut packet = Vec::with_capacity(2 + search_expr.len());
        packet.push(OP_EDONKEYPROT);
        packet.push(OP_GLOBSEARCHREQ);
        packet.write_all(search_expr)?;

        self.socket.send_to(&packet, addr).await?;
        Ok(())
    }

    /// Receive and process one UDP packet. Returns parsed result or None.
    pub async fn try_recv(&self) -> Option<ServerUdpResponse> {
        let mut buf = [0u8; 65536];
        match self.socket.try_recv_from(&mut buf) {
            Ok((len, addr)) => {
                if len < 2 {
                    return None;
                }
                if buf[0] != OP_EDONKEYPROT {
                    return None;
                }
                parse_server_udp_response(&buf[1..len], addr)
            }
            Err(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ServerUdpResponse {
    StatusResponse {
        addr: SocketAddr,
        user_count: u32,
        file_count: u32,
    },
    FoundSources {
        file_hash: [u8; 16],
        sources: Vec<(Ipv4Addr, u16)>,
    },
    SearchResult {
        results: Vec<ServerSearchResult>,
    },
}

#[derive(Debug)]
pub struct ServerSearchResult {
    pub file_hash: [u8; 16],
    pub client_id: u32,
    pub client_port: u16,
    pub file_name: String,
    pub file_size: u64,
}

fn parse_server_udp_response(data: &[u8], addr: SocketAddr) -> Option<ServerUdpResponse> {
    if data.is_empty() {
        return None;
    }

    let opcode = data[0];
    let payload = &data[1..];

    match opcode {
        OP_GLOBSERVSTATRES => {
            if payload.len() < 8 {
                return None;
            }
            let mut cursor = Cursor::new(payload);
            let user_count = cursor.read_u32::<LittleEndian>().ok()?;
            let file_count = cursor.read_u32::<LittleEndian>().ok()?;
            Some(ServerUdpResponse::StatusResponse {
                addr,
                user_count,
                file_count,
            })
        }
        OP_GLOBFOUNDSOURCES => {
            if payload.len() < 17 {
                return None;
            }
            let mut cursor = Cursor::new(payload);
            let mut file_hash = [0u8; 16];
            std::io::Read::read_exact(&mut cursor, &mut file_hash).ok()?;
            let source_count = cursor.read_u8().ok()? as usize;
            let mut sources = Vec::with_capacity(source_count);
            for _ in 0..source_count {
                let id = cursor.read_u32::<LittleEndian>().ok()?;
                let port = cursor.read_u16::<LittleEndian>().ok()?;
                let ip = Ipv4Addr::from(id.to_be_bytes());
                sources.push((ip, port));
            }
            Some(ServerUdpResponse::FoundSources { file_hash, sources })
        }
        OP_GLOBSEARCHRES => {
            parse_search_results(payload)
        }
        _ => None,
    }
}
fn parse_search_results(payload: &[u8]) -> Option<ServerUdpResponse> {
    let mut cursor = Cursor::new(payload);
    let mut results = Vec::new();

    while (cursor.position() as usize) < payload.len().saturating_sub(24) {
        let mut file_hash = [0u8; 16];
        if std::io::Read::read_exact(&mut cursor, &mut file_hash).is_err() {
            break;
        }
        let client_id = cursor.read_u32::<LittleEndian>().ok()?;
        let client_port = cursor.read_u16::<LittleEndian>().ok()?;
        let tag_count = cursor.read_u32::<LittleEndian>().ok()? as usize;

        let mut file_name = String::new();
        let mut file_size: u64 = 0;

        for _ in 0..tag_count.min(50) {
            let tag_type = cursor.read_u8().ok()?;
            let name_len = cursor.read_u16::<LittleEndian>().ok()? as usize;
            let mut name_buf = vec![0u8; name_len];
            std::io::Read::read_exact(&mut cursor, &mut name_buf).ok()?;
            let name_id = if name_len == 1 { name_buf[0] } else { 0 };

            match tag_type {
                0x02 => {
                    let slen = cursor.read_u16::<LittleEndian>().ok()? as usize;
                    let mut sbuf = vec![0u8; slen.min(4096)];
                    std::io::Read::read_exact(&mut cursor, &mut sbuf).ok()?;
                    if name_id == 0x01 {
                        file_name = String::from_utf8_lossy(&sbuf).to_string();
                    }
                }
                0x03 => {
                    let v = cursor.read_u32::<LittleEndian>().ok()?;
                    if name_id == 0x02 {
                        file_size = v as u64;
                    }
                }
                0x08 => { let _ = cursor.read_u16::<LittleEndian>(); }
                0x09 => { let _ = cursor.read_u8(); }
                _ => break,
            }
        }

        results.push(ServerSearchResult {
            file_hash,
            client_id,
            client_port,
            file_name,
            file_size,
        });
    }

    if results.is_empty() {
        None
    } else {
        Some(ServerUdpResponse::SearchResult { results })
    }
}

