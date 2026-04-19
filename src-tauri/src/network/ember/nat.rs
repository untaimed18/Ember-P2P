use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// STUN reflectors used for NAT detection. Listed in attempt order; the
/// probe walks the whole list so a single dead host doesn't kill the
/// probe. We deliberately mix providers: Google sometimes throttles
/// home IPs that hammer it (and is also occasionally rate-limited at
/// some ISPs), so Cloudflare and Twilio cover us when Google goes
/// quiet. This is the *primary* signal for NAT type — if every entry
/// here fails, hole-punch falls back to the HighID-derived heuristic
/// in `mod.rs`.
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
];

const STUN_TIMEOUT: Duration = Duration::from_secs(5);
const STUN_MAX_RETRIES: usize = 2;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// How often to re-probe NAT type.
const NAT_REPROBE_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum NatType {
    Open,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
    Unknown,
}

#[allow(dead_code)]
impl NatType {
    pub fn is_punchable(&self) -> bool {
        matches!(self, NatType::Open | NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted)
    }

    pub fn is_relayable(&self) -> bool {
        true
    }

    /// Whether a hole-punch between two NAT types is likely to succeed.
    pub fn can_punch_with(&self, other: &NatType) -> bool {
        match (self, other) {
            (NatType::Open, _) | (_, NatType::Open) => true,
            (NatType::FullCone, _) | (_, NatType::FullCone) => true,
            (NatType::RestrictedCone, NatType::RestrictedCone) => true,
            (NatType::RestrictedCone, NatType::PortRestricted) => true,
            (NatType::PortRestricted, NatType::RestrictedCone) => true,
            (NatType::PortRestricted, NatType::PortRestricted) => true,
            _ => false,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            NatType::Open => 0,
            NatType::FullCone => 1,
            NatType::RestrictedCone => 2,
            NatType::PortRestricted => 3,
            NatType::Symmetric => 4,
            NatType::Unknown => 5,
        }
    }

    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => NatType::Open,
            1 => NatType::FullCone,
            2 => NatType::RestrictedCone,
            3 => NatType::PortRestricted,
            4 => NatType::Symmetric,
            _ => NatType::Unknown,
        }
    }
}

/// Cached NAT detection result with auto-expiry.
#[derive(Debug, Clone)]
pub struct NatInfo {
    pub nat_type: NatType,
    pub external_addr: Option<SocketAddr>,
    pub last_probed: Instant,
}

impl NatInfo {
    pub fn unknown() -> Self {
        Self {
            nat_type: NatType::Unknown,
            external_addr: None,
            last_probed: Instant::now() - NAT_REPROBE_INTERVAL * 2,
        }
    }

    pub fn needs_reprobe(&self) -> bool {
        self.last_probed.elapsed() >= NAT_REPROBE_INTERVAL
    }

    #[allow(dead_code)]
    pub fn has_external_addr(&self) -> bool {
        self.external_addr.is_some()
    }

    /// If STUN failed but we have a confirmed external IP from another
    /// source (ed2k server HighID, KAD FirewalledRes vote, etc.) and a
    /// confirmed-open TCP connect-back, treat ourselves as
    /// `PortRestricted` with the local UDP port mirrored as the external
    /// port. This is a deliberate optimistic guess — we don't know the
    /// NAT mapping for sure, but a HighID + open TCP almost always
    /// means a cone NAT (or no NAT) rather than symmetric. Without this
    /// fallback the broker refuses to attempt hole-punch
    /// (`is_punchable() == false`), so every low-to-low connect goes
    /// straight to the relay path even on perfectly punchable links.
    ///
    /// `local_udp_port` is our own bound KAD UDP port; eMule uses the
    /// same port for inbound and the actual NAT mapping is usually
    /// 1:1 for cone NATs, so it's the best guess we can make without
    /// a real STUN reply.
    pub fn apply_highid_fallback(&mut self, external_ip: IpAddr, local_udp_port: u16) -> bool {
        if self.nat_type != NatType::Unknown || self.external_addr.is_some() {
            return false;
        }
        self.nat_type = NatType::PortRestricted;
        self.external_addr = Some(SocketAddr::new(external_ip, local_udp_port));
        self.last_probed = Instant::now();
        true
    }
}

/// Probe STUN servers to discover our external address and infer NAT type.
///
/// Stops after two successful results (enough to disambiguate symmetric
/// vs port-restricted by comparing mapped ports). Walks the entire
/// server list before giving up so a transient outage on one provider
/// doesn't poison the result. Per-server failures are surfaced in the
/// final WARN message — they used to be `debug!` only, which made
/// "all STUN servers failed" essentially undebuggable in `info`-level
/// logs.
pub async fn probe_nat(local_socket: &UdpSocket) -> NatInfo {
    let mut results = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for server_str in DEFAULT_STUN_SERVERS.iter() {
        match try_stun_server(local_socket, server_str).await {
            Ok(addr) => {
                results.push(addr);
                if results.len() >= 2 {
                    break;
                }
            }
            Err(e) => {
                debug!("STUN server {server_str} failed: {e}");
                failures.push(format!("{server_str}: {e}"));
            }
        }
    }

    if results.is_empty() {
        // Surface the first two failures in the WARN so the user can
        // tell DNS/blocked-egress/timeout apart without having to flip
        // the whole logger to debug.
        let detail = failures.iter().take(2).cloned().collect::<Vec<_>>().join("; ");
        if detail.is_empty() {
            warn!("NAT probe: all STUN servers failed");
        } else {
            warn!("NAT probe: all STUN servers failed ({detail})");
        }
        return NatInfo {
            nat_type: NatType::Unknown,
            external_addr: None,
            last_probed: Instant::now(),
        };
    }

    let external_addr = results[0];
    let local_addr = local_socket.local_addr().ok();

    let nat_type = if let Some(local) = local_addr {
        if local.ip() == external_addr.ip() && !local.ip().is_loopback() && !local.ip().is_unspecified() {
            NatType::Open
        } else if results.len() >= 2 && results[0].port() != results[1].port() {
            // Different external ports from different servers = symmetric NAT
            info!("NAT probe: symmetric NAT detected (ports {} vs {})", results[0].port(), results[1].port());
            NatType::Symmetric
        } else if results.len() >= 2 {
            // Same external port from different servers = at least port-restricted cone
            info!("NAT probe: port-restricted or better NAT (consistent port {})", external_addr.port());
            NatType::PortRestricted
        } else {
            NatType::Unknown
        }
    } else {
        NatType::Unknown
    };

    info!("NAT probe: type={:?}, external={}", nat_type, external_addr);

    NatInfo {
        nat_type,
        external_addr: Some(external_addr),
        last_probed: Instant::now(),
    }
}

async fn try_stun_server(
    socket: &UdpSocket,
    server: &str,
) -> Result<SocketAddr, String> {
    // Filter to IPv4 explicitly. The KAD UDP socket is bound IPv4-only
    // (`socket2::Domain::IPV4` in `start_network`), and on a dual-stack
    // resolver `lookup_host(...).next()` can return an IPv6 entry first
    // — `send_to` would then fail with EAFNOSUPPORT and the whole
    // attempt would silently time out. Picking the first v4 result
    // matches what every other UDP path in this codebase expects.
    let server_addr: SocketAddr = tokio::net::lookup_host(server)
        .await
        .map_err(|e| format!("DNS resolve {server}: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("No IPv4 address for {server}"))?;

    let txn_id: [u8; 12] = rand::random();
    let request = build_binding_request(&txn_id);

    for attempt in 0..STUN_MAX_RETRIES {
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
                    Ok(external_addr) => return Ok(external_addr),
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

fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txn_id);
    buf
}

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
                if let Some(addr) = parse_xor_mapped_address(attr_data) {
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

        let padded = (attr_len + 3) & !3;
        offset += padded;
    }

    Err("No mapped address in response".into())
}

fn parse_xor_mapped_address(data: &[u8]) -> Option<SocketAddr> {
    if data.len() < 8 {
        return None;
    }
    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
    let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();

    match family {
        0x01 => {
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
        0x01 => Some(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7])),
            port,
        )),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nat_type_punch_compatibility() {
        assert!(NatType::Open.can_punch_with(&NatType::Symmetric));
        assert!(NatType::FullCone.can_punch_with(&NatType::Symmetric));
        assert!(NatType::RestrictedCone.can_punch_with(&NatType::PortRestricted));
        assert!(NatType::PortRestricted.can_punch_with(&NatType::PortRestricted));
        assert!(!NatType::Symmetric.can_punch_with(&NatType::Symmetric));
        assert!(!NatType::Symmetric.can_punch_with(&NatType::PortRestricted));
        assert!(!NatType::PortRestricted.can_punch_with(&NatType::Symmetric));
    }

    #[test]
    fn nat_info_reprobe() {
        let fresh = NatInfo {
            nat_type: NatType::PortRestricted,
            external_addr: Some("1.2.3.4:1234".parse().unwrap()),
            last_probed: Instant::now(),
        };
        assert!(!fresh.needs_reprobe());

        let stale = NatInfo::unknown();
        assert!(stale.needs_reprobe());
    }

    #[test]
    fn nat_type_serialization() {
        for t in [NatType::Open, NatType::FullCone, NatType::RestrictedCone, NatType::PortRestricted, NatType::Symmetric, NatType::Unknown] {
            assert_eq!(NatType::from_u8(t.as_u8()), t);
        }
    }

    #[test]
    fn build_stun_request_format() {
        let txn_id = [1u8; 12];
        let req = build_binding_request(&txn_id);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txn_id);
    }

    #[test]
    fn parse_xor_mapped_v4() {
        let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
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
        data[1] = 0x01;
        data[2..4].copy_from_slice(&xor_port.to_be_bytes());
        data[4..8].copy_from_slice(&xor_ip);

        let addr = parse_xor_mapped_address(&data).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }

    #[test]
    fn parse_full_stun_response() {
        let txn_id = [0xAA; 12];
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
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
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0);
        attr.push(0x01);
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
