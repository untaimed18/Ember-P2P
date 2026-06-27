use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
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
pub enum NatType {
    Open,
    FullCone,
    RestrictedCone,
    PortRestricted,
    Symmetric,
    Unknown,
}

impl NatType {
    pub fn is_punchable(&self) -> bool {
        matches!(
            self,
            NatType::Open | NatType::FullCone | NatType::RestrictedCone | NatType::PortRestricted
        )
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
            last_probed: Instant::now(),
        }
    }

    pub fn needs_reprobe(&self) -> bool {
        self.nat_type == NatType::Unknown || self.last_probed.elapsed() >= NAT_REPROBE_INTERVAL
    }

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
    ///
    /// We only apply this when STUN did not discover any mapped
    /// address. A single STUN reply proves an external mapping but not
    /// whether the NAT is symmetric; upgrading that case here would
    /// undo the conservative single-vantage classification and make
    /// doomed punches run before relay fallback.
    pub fn apply_highid_fallback(&mut self, external_ip: IpAddr, local_udp_port: u16) -> bool {
        if self.nat_type != NatType::Unknown {
            return false;
        }
        if self.has_external_addr() {
            return false;
        }
        self.nat_type = NatType::PortRestricted;
        self.external_addr = Some(SocketAddr::new(external_ip, local_udp_port));
        self.last_probed = Instant::now();
        true
    }
}

/// Probe NAT using the caller-owned UDP socket for sends while receiving STUN
/// replies from the main network loop. This keeps the main loop as the only
/// `recv_from` owner, avoiding packet stealing between a background probe and
/// normal KAD/Ember processing.
pub(crate) async fn probe_nat_with_replies(
    local_socket: Arc<UdpSocket>,
    mut replies: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) -> NatInfo {
    let mut results = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for server_str in DEFAULT_STUN_SERVERS.iter() {
        match try_stun_server_with_replies(&local_socket, &mut replies, server_str).await {
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

    build_nat_info_from_results(&local_socket, results, failures)
}

fn build_nat_info_from_results(
    local_socket: &UdpSocket,
    results: Vec<SocketAddr>,
    failures: Vec<String>,
) -> NatInfo {
    if results.is_empty() {
        let detail = failures
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
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
        if local.ip() == external_addr.ip()
            && !local.ip().is_loopback()
            && !local.ip().is_unspecified()
        {
            NatType::Open
        } else if results.len() >= 2 && results[0].port() != results[1].port() {
            info!(
                "NAT probe: symmetric NAT detected (ports {} vs {})",
                results[0].port(),
                results[1].port()
            );
            NatType::Symmetric
        } else if results.len() >= 2 {
            info!(
                "NAT probe: port-restricted or better NAT (consistent port {})",
                external_addr.port()
            );
            NatType::PortRestricted
        } else {
            info!(
                "NAT probe: only 1 STUN reply (mapped {}), leaving NAT type Unknown",
                external_addr,
            );
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

pub(crate) fn is_stun_binding_response(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    u16::from_be_bytes([data[0], data[1]]) == STUN_BINDING_RESPONSE
        && u32::from_be_bytes([data[4], data[5], data[6], data[7]]) == STUN_MAGIC_COOKIE
}

async fn try_stun_server_with_replies(
    socket: &UdpSocket,
    replies: &mut mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    server: &str,
) -> Result<SocketAddr, String> {
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

        let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                debug!("STUN timeout from {server} (attempt {attempt})");
                break;
            }
            match tokio::time::timeout(remaining, replies.recv()).await {
                Ok(Some((data, from))) => {
                    if from.ip() != server_addr.ip() {
                        continue;
                    }
                    match parse_binding_response(&data, &txn_id) {
                        Ok(external_addr) => return Ok(external_addr),
                        Err(e) => {
                            debug!("STUN parse error from {server}: {e}");
                            continue;
                        }
                    }
                }
                Ok(None) => return Err("STUN reply channel closed".into()),
                Err(_) => {
                    debug!("STUN timeout from {server} (attempt {attempt})");
                    break;
                }
            }
        }
    }

    Err(format!(
        "STUN {server} failed after {STUN_MAX_RETRIES} attempts"
    ))
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
        for t in [
            NatType::Open,
            NatType::FullCone,
            NatType::RestrictedCone,
            NatType::PortRestricted,
            NatType::Symmetric,
            NatType::Unknown,
        ] {
            assert_eq!(NatType::from_u8(t.as_u8()), t);
        }
    }

    #[test]
    fn highid_fallback_upgrades_unknown_with_no_addr() {
        let mut info = NatInfo::unknown();
        let applied =
            info.apply_highid_fallback(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 4242);
        assert!(applied);
        assert_eq!(info.nat_type, NatType::PortRestricted);
        assert_eq!(info.external_addr, Some("8.8.8.8:4242".parse().unwrap()),);
    }

    #[test]
    fn highid_fallback_skips_when_stun_already_found_addr() {
        // Pre-existing external_addr (e.g. STUN got one reply but
        // couldn't classify) must not be upgraded by the HighID
        // fallback; a single STUN vantage point doesn't prove the NAT
        // is non-symmetric.
        let mut info = NatInfo {
            nat_type: NatType::Unknown,
            external_addr: Some("1.2.3.4:9999".parse().unwrap()),
            last_probed: Instant::now(),
        };
        let applied =
            info.apply_highid_fallback(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 4242);
        assert!(!applied);
        assert_eq!(info.nat_type, NatType::Unknown);
        assert_eq!(
            info.external_addr,
            Some("1.2.3.4:9999".parse().unwrap()),
            "fallback must preserve the addr STUN already discovered",
        );
    }

    #[test]
    fn highid_fallback_skips_when_already_classified() {
        let mut info = NatInfo {
            nat_type: NatType::FullCone,
            external_addr: None,
            last_probed: Instant::now(),
        };
        let applied =
            info.apply_highid_fallback(IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)), 4242);
        assert!(!applied);
        assert_eq!(info.nat_type, NatType::FullCone);
        assert_eq!(info.external_addr, None);
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
