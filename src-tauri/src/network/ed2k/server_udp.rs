use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::net::UdpSocket;
use tracing::debug;

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
    socket: Arc<UdpSocket>,
    last_ping_times: std::collections::HashMap<SocketAddr, i64>,
}

impl ServerUdpSocket {
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            last_ping_times: std::collections::HashMap::new(),
        }
    }

    /// Get a clone of the underlying socket for use in spawned tasks.
    pub fn socket_handle(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Build a get-sources packet without sending. Returns (packet, addr).
    pub fn build_get_sources_packet(server: &ServerEntry, file_hash: &[u8; 16], file_size: u64) -> Option<(Vec<u8>, SocketAddr)> {
        let addr: SocketAddr = format!("{}:{}", server.ip, server.port + 4).parse().ok()?;
        let mut packet = Vec::with_capacity(22);
        packet.push(OP_EDONKEYPROT);
        if file_size > 0 {
            packet.push(OP_GLOBGETSOURCES2);
            packet.extend_from_slice(file_hash);
            packet.extend_from_slice(&(file_size as u32).to_le_bytes());
        } else {
            packet.push(OP_GLOBGETSOURCES);
            packet.extend_from_slice(file_hash);
        }
        Some((packet, addr))
    }

    /// Build a global search packet without sending. Returns (packet, addr).
    pub fn build_global_search_packet(server: &ServerEntry, search_expr: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
        let addr: SocketAddr = format!("{}:{}", server.ip, server.port + 4).parse().ok()?;
        let mut packet = Vec::with_capacity(2 + search_expr.len());
        packet.push(OP_EDONKEYPROT);
        packet.push(OP_GLOBSEARCHREQ);
        packet.extend_from_slice(search_expr);
        Some((packet, addr))
    }

    /// Send pre-built packets on a socket handle (for use in spawned tasks).
    pub async fn send_packets(socket: &UdpSocket, packets: Vec<(Vec<u8>, SocketAddr)>) {
        for (packet, addr) in packets {
            let _ = socket.send_to(&packet, addr).await;
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
        /// (ip, port, client_id) — client_id > 0 means LowID source
        sources: Vec<(Ipv4Addr, u16, u32)>,
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
                if id < super::server::LOWID_THRESHOLD {
                    // LowID: store with client_id, IP is unspecified
                    sources.push((Ipv4Addr::UNSPECIFIED, port, id));
                } else {
                    let ip = Ipv4Addr::from(id.to_be_bytes());
                    sources.push((ip, port, 0));
                }
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
            let raw_type = cursor.read_u8().ok()?;
            let (name_id, tag_type) = if raw_type & 0x80 != 0 {
                let t = raw_type & 0x7F;
                let n = cursor.read_u8().ok()?;
                (n, t)
            } else {
                let name_len = cursor.read_u16::<LittleEndian>().ok()? as usize;
                let n = if name_len == 1 {
                    cursor.read_u8().ok()?
                } else {
                    let mut name_buf = vec![0u8; name_len];
                    std::io::Read::read_exact(&mut cursor, &mut name_buf).ok()?;
                    0u8
                };
                (n, raw_type)
            };

            let ok = match tag_type {
                0x01 => { // TAGTYPE_HASH
                    let mut buf = [0u8; 16];
                    std::io::Read::read_exact(&mut cursor, &mut buf).is_ok()
                }
                0x02 => { // TAGTYPE_STRING
                    let slen = cursor.read_u16::<LittleEndian>().ok().unwrap_or(0) as usize;
                    let mut sbuf = vec![0u8; slen.min(8192)];
                    if std::io::Read::read_exact(&mut cursor, &mut sbuf).is_ok() {
                        if name_id == 0x01 {
                            file_name = String::from_utf8_lossy(&sbuf).to_string();
                        }
                        true
                    } else { false }
                }
                0x03 => { // TAGTYPE_UINT32
                    if let Ok(v) = cursor.read_u32::<LittleEndian>() {
                        if name_id == 0x02 { file_size = v as u64; }
                        true
                    } else { false }
                }
                0x04 => { let mut b = [0u8; 4]; std::io::Read::read_exact(&mut cursor, &mut b).is_ok() }
                0x05 => { let _ = cursor.read_u8(); true }
                0x07 => { // TAGTYPE_BLOB
                    if let Ok(bl) = cursor.read_u32::<LittleEndian>() {
                        let pos = cursor.position() as usize + bl.min(1_000_000) as usize;
                        if pos <= payload.len() { cursor.set_position(pos as u64); true }
                        else { false }
                    } else { false }
                }
                0x08 => { // TAGTYPE_UINT16
                    if let Ok(v) = cursor.read_u16::<LittleEndian>() {
                        if name_id == 0x02 { file_size = v as u64; }
                        true
                    } else { false }
                }
                0x09 => { // TAGTYPE_UINT8
                    if let Ok(v) = cursor.read_u8() {
                        if name_id == 0x02 { file_size = v as u64; }
                        true
                    } else { false }
                }
                0x0A => { // TAGTYPE_BSOB
                    if let Ok(bl) = cursor.read_u8() {
                        let pos = cursor.position() as usize + bl as usize;
                        if pos <= payload.len() { cursor.set_position(pos as u64); true }
                        else { false }
                    } else { false }
                }
                0x0B => { // TAGTYPE_UINT64
                    if let Ok(v) = cursor.read_u64::<LittleEndian>() {
                        if name_id == 0x02 { file_size = v; }
                        true
                    } else { false }
                }
                t if (0x11..=0x20).contains(&t) => { // TAGTYPE_STR1..STR16
                    let slen = (t - 0x11 + 1) as usize;
                    let mut sbuf = vec![0u8; slen];
                    if std::io::Read::read_exact(&mut cursor, &mut sbuf).is_ok() {
                        if name_id == 0x01 { file_name = String::from_utf8_lossy(&sbuf).to_string(); }
                        true
                    } else { false }
                }
                _ => false,
            };
            if !ok { break; }
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

