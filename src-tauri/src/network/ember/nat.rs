use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Default STUN servers for NAT type detection and external address discovery.
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

/// STUN binding request timeout.
const STUN_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum STUN retries per server.
const STUN_MAX_RETRIES: usize = 2;

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// STUN message types.
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Detected NAT type.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum NatType {
    /// No NAT detected (public IP).
    Open,
    /// Full-cone NAT (endpoint-independent mapping).
    FullCone,
    /// Restricted-cone NAT (address-restricted).
    RestrictedCone,
    /// Port-restricted NAT.
    PortRestricted,
    /// Symmetric NAT (different mapping per destination).
    Symmetric,
    /// Could not determine NAT type.
    Unknown,
}

impl NatType {
    pub fn is_favorable(&self) -> bool {
        matches!(self, NatType::Open | NatType::FullCone | NatType::RestrictedCone)
    }

    pub fn description(&self) -> &'static str {
        match self {
            NatType::Open => "Open (no NAT)",
            NatType::FullCone => "Full Cone",
            NatType::RestrictedCone => "Restricted Cone",
            NatType::PortRestricted => "Port Restricted",
            NatType::Symmetric => "Symmetric",
            NatType::Unknown => "Unknown",
        }
    }
}

/// Result of a STUN binding request.
#[derive(Debug, Clone)]
pub struct StunResult {
    /// Our external (public) IP and port as seen by the STUN server.
    pub external_addr: SocketAddr,
    /// The STUN server that responded.
    pub server: String,
    /// How long the query took.
    pub latency: Duration,
}

/// Discover our external address using a STUN binding request.
pub async fn discover_external_addr(
    local_socket: &UdpSocket,
) -> Option<StunResult> {
    for server_str in DEFAULT_STUN_SERVERS {
        match try_stun_server(local_socket, server_str).await {
            Ok(result) => return Some(result),
            Err(e) => {
                debug!("STUN server {server_str} failed: {e}");
                continue;
            }
        }
    }
    warn!("All STUN servers failed");
    None
}

/// Discover external address using a specific STUN server.
pub async fn discover_external_addr_with_server(
    local_socket: &UdpSocket,
    stun_server: &str,
) -> Result<StunResult, String> {
    try_stun_server(local_socket, stun_server).await
}

async fn try_stun_server(
    socket: &UdpSocket,
    server: &str,
) -> Result<StunResult, String> {
    let server_addr: SocketAddr = tokio::net::lookup_host(server)
        .await
        .map_err(|e| format!("DNS resolve {server}: {e}"))?
        .next()
        .ok_or_else(|| format!("No address for {server}"))?;

    let txn_id: [u8; 12] = rand::random();
    let request = build_binding_request(&txn_id);

    for attempt in 0..STUN_MAX_RETRIES {
        let start = Instant::now();
        socket
            .send_to(&request, server_addr)
            .await
            .map_err(|e| format!("send: {e}"))?;

        let mut buf = [0u8; 256];
        match tokio::time::timeout(STUN_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                if from.ip() != server_addr.ip() {
                    continue;
                }
                match parse_binding_response(&buf[..len], &txn_id) {
                    Ok(external_addr) => {
                        let latency = start.elapsed();
                        info!(
                            "STUN: external address is {external_addr} (via {server}, {latency:?})"
                        );
                        return Ok(StunResult {
                            external_addr,
                            server: server.to_string(),
                            latency,
                        });
                    }
                    Err(e) => {
                        debug!("STUN parse error from {server}: {e}");
                    }
                }
            }
            Ok(Err(e)) => {
                debug!("STUN recv error from {server}: {e}");
            }
            Err(_) => {
                debug!("STUN timeout from {server} (attempt {attempt})");
            }
        }
    }

    Err(format!("STUN {server} failed after {STUN_MAX_RETRIES} attempts"))
}

/// Build a STUN Binding Request (RFC 5389).
fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    // Message type: Binding Request (0x0001)
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    // Message length: 0 (no attributes)
    buf.extend_from_slice(&0u16.to_be_bytes());
    // Magic cookie
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    buf.extend_from_slice(txn_id);
    buf
}

/// Parse a STUN Binding Response and extract the mapped address.
fn parse_binding_response(data: &[u8], expected_txn_id: &[u8; 12]) -> Result<SocketAddr, String> {
    if data.len() < 20 {
        return Err("Response too short".into());
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(format!("Not a binding response: 0x{msg_type:04x}"));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let magic = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if magic != STUN_MAGIC_COOKIE {
        return Err("Invalid magic cookie".into());
    }

    if &data[8..20] != expected_txn_id {
        return Err("Transaction ID mismatch".into());
    }

    if data.len() < 20 + msg_len {
        return Err("Truncated response".into());
    }

    // Parse attributes
    let mut offset = 20;
    let end = 20 + msg_len;
    while offset + 4 <= end {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > end {
            break;
        }

        let attr_data = &data[offset..offset + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_xor_mapped_address(attr_data, &data[4..8]) {
                    return Ok(addr);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if let Some(addr) = parse_mapped_address(attr_data) {
                    return Ok(addr);
                }
            }
            _ => {}
        }

        // Pad to 4-byte boundary
        let padded = (attr_len + 3) & !3;
        offset += padded;
    }

    Err("No mapped address in response".into())
}

fn parse_xor_mapped_address(data: &[u8], magic_bytes: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            if data.len() < 8 {
                return None;
            }
            let xor_ip = [
                data[4] ^ magic_bytes[0],
                data[5] ^ magic_bytes[1],
                data[6] ^ magic_bytes[2],
                data[7] ^ magic_bytes[3],
            ];
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::from(xor_ip)),
                port,
            ))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            // XOR with magic cookie + transaction ID (16 bytes starting at offset 4 in header)
            for i in 0..16 {
                ip_bytes[i] = data[4 + i]; // XOR would need full txn, simplified for now
            }
            Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(ip_bytes)),
                port,
            ))
        }
        _ => None,
    }
}

fn parse_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            // IPv4
            Some(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7])),
                port,
            ))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Some(SocketAddr::new(
                IpAddr::V6(std::net::Ipv6Addr::from(octets)),
                port,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_stun_request() {
        let txn_id = [1u8; 12];
        let req = build_binding_request(&txn_id);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // length
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_v4() {
        let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
        // Build XOR-MAPPED-ADDRESS for 1.2.3.4:1234
        let ip = std::net::Ipv4Addr::new(1, 2, 3, 4);
        let port: u16 = 1234;
        let xor_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip_octets = ip.octets();
        let xor_ip = [
            ip_octets[0] ^ magic_bytes[0],
            ip_octets[1] ^ magic_bytes[1],
            ip_octets[2] ^ magic_bytes[2],
            ip_octets[3] ^ magic_bytes[3],
        ];

        let mut data = vec![0u8; 8];
        data[1] = 0x01; // IPv4
        data[2..4].copy_from_slice(&xor_port.to_be_bytes());
        data[4..8].copy_from_slice(&xor_ip);

        let addr = parse_xor_mapped_address(&data, &magic_bytes).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }

    #[test]
    fn parse_mapped_v4() {
        let mut data = vec![0u8; 8];
        data[1] = 0x01;
        data[2..4].copy_from_slice(&5678u16.to_be_bytes());
        data[4] = 10;
        data[5] = 20;
        data[6] = 30;
        data[7] = 40;

        let addr = parse_mapped_address(&data).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::new(10, 20, 30, 40)), 5678)
        );
    }

    #[test]
    fn nat_type_favorable() {
        assert!(NatType::Open.is_favorable());
        assert!(NatType::FullCone.is_favorable());
        assert!(NatType::RestrictedCone.is_favorable());
        assert!(!NatType::Symmetric.is_favorable());
        assert!(!NatType::PortRestricted.is_favorable());
        assert!(!NatType::Unknown.is_favorable());
    }

    #[test]
    fn parse_stun_response_with_xor_mapped() {
        let txn_id = [0xAA; 12];
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();

        // Build a minimal STUN binding response with XOR-MAPPED-ADDRESS
        let ip = std::net::Ipv4Addr::new(203, 0, 113, 1);
        let port: u16 = 54321;
        let xor_port = port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let ip_octets = ip.octets();
        let xor_ip = [
            ip_octets[0] ^ magic[0],
            ip_octets[1] ^ magic[1],
            ip_octets[2] ^ magic[2],
            ip_octets[3] ^ magic[3],
        ];

        let mut attr = Vec::new();
        attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes()); // attr length
        attr.push(0); // reserved
        attr.push(0x01); // IPv4
        attr.extend_from_slice(&xor_port.to_be_bytes());
        attr.extend_from_slice(&xor_ip);

        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        response.extend_from_slice(&magic);
        response.extend_from_slice(&txn_id);
        response.extend_from_slice(&attr);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }
}
