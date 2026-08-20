use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info};

/// STUN reflectors used for NAT detection. Listed in attempt order; the
/// probe walks the whole list so a single dead host doesn't kill the
/// probe. We deliberately mix providers: Google sometimes throttles
/// home IPs that hammer it (and is also occasionally rate-limited at
/// some ISPs), so Cloudflare and Twilio cover us when Google goes
/// quiet. This is the *primary* signal for NAT type — if every entry
/// here fails, hole-punch falls back to the HighID-derived heuristic
/// in `mod.rs`.
///
/// Providers alternate rather than being grouped. Two readings only say
/// something about the NAT when they come from *different* reflector
/// addresses (see [`probe_nat_with_replies`]), and the three
/// `stunN.l.google.com` names all resolve to a single anycast address —
/// listing them consecutively meant the first two successes were routinely
/// the same host answering twice. The keep-alive in
/// [`super::mapping_keepalive`] walks this same list round-robin, so the
/// order also decides whether *its* consecutive cycles compare distinct
/// vantage points.
pub(crate) const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "global.stun.twilio.com:3478",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];

pub(crate) const STUN_TIMEOUT: Duration = Duration::from_secs(5);
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

impl Default for NatType {
    fn default() -> Self {
        NatType::Unknown
    }
}

impl NatType {
    /// Whether a hole-punch between two NAT types is likely to succeed.
    ///
    /// Retained as the reference definition of punch compatibility and
    /// covered by this module's tests. The live friend-connect gate is a
    /// narrower `!= Symmetric` check on our own type alone, since we learn
    /// the peer's type only after the punch request is already in flight.
    #[allow(dead_code)]
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
    /// fallback `external_addr` stays `None`, which fails the
    /// `Some(ext_addr)` requirement guarding the friend hole-punch in
    /// `friend_connect::connect_friend_with_fallback`, so every connect
    /// goes straight to the relay path even on perfectly punchable links.
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

/// Live, shared snapshot of the NAT-traversal inputs a friend-connect dial
/// needs: NAT type/external address (from the periodic STUN probe) and the
/// QUIC endpoint (created once, lazily, after the first external IP is
/// known). Wrapped in `Arc<std::sync::RwLock<..>>` and handed to
/// `friend_connect::connect_friend_with_fallback` so it can re-read the
/// *current* values right before attempting hole-punch — instead of a
/// snapshot captured at `tokio::spawn` time.
///
/// This matters because the TCP-first attempt each dial makes before ever
/// looking at NAT info can itself take up to ~15s (`open_and_run_friend_session`'s
/// connect timeout). A snapshot taken before that TCP attempt started can be
/// badly stale by the time the hole-punch fallback actually runs — most
/// visibly when a dial is spawned while `external_addr` is still `None`
/// (probe in flight or not yet started): the old by-value parameters would
/// permanently skip hole-punch for that dial even though the probe finishes
/// (and `quic_endpoint`/`nat_type` become usable) well within the TCP
/// timeout window. The periodic auto-retry sweep would eventually pick a
/// stale miss back up, but only after a multi-minute wait — pointless when
/// the fresh values were one lock-read away the whole time.
#[derive(Clone, Default)]
pub struct FriendNatContext {
    pub nat_type: NatType,
    pub external_addr: Option<SocketAddr>,
    pub quic_endpoint: Option<Arc<quinn::Endpoint>>,
    /// Public UDP port of `quic_endpoint`'s socket, discovered by STUN when it
    /// was created. `None` falls back to the bound port, which is only the
    /// same thing when the NAT preserves ports.
    pub quic_public_port: Option<u16>,
}

pub type SharedFriendNatContext = Arc<std::sync::RwLock<FriendNatContext>>;

pub fn new_shared_friend_nat_context() -> SharedFriendNatContext {
    Arc::new(std::sync::RwLock::new(FriendNatContext::default()))
}

/// Probe NAT using the caller-owned UDP socket for sends while receiving STUN
/// replies from the main network loop. This keeps the main loop as the only
/// `recv_from` owner, avoiding packet stealing between a background probe and
/// normal KAD/Ember processing.
pub(crate) async fn probe_nat_with_replies(
    local_socket: Arc<UdpSocket>,
    mut replies: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
) -> NatInfo {
    // `(reflector, mapped)` pairs, holding at most one entry per reflector
    // *address*.
    let mut results: Vec<(SocketAddr, SocketAddr)> = Vec::new();
    let mut failures: Vec<String> = Vec::new();

    for server_str in DEFAULT_STUN_SERVERS.iter() {
        let server_addr = match resolve_stun_server(server_str).await {
            Ok(addr) => addr,
            Err(e) => {
                debug!("STUN server {server_str} failed: {e}");
                failures.push(format!("{server_str}: {e}"));
                continue;
            }
        };
        // A symmetric NAT re-maps per destination, so a second reading from a
        // reflector we already queried proves nothing — it is the same
        // destination and therefore the same mapping. Several entries in
        // `DEFAULT_STUN_SERVERS` are aliases for one anycast address, so
        // without this the probe could finish with two readings that could
        // never disagree and classify a symmetric NAT as a cone.
        if results
            .iter()
            .any(|(prev, _)| prev.ip() == server_addr.ip())
        {
            debug!(
                "STUN server {server_str} skipped: {} already probed",
                server_addr.ip()
            );
            continue;
        }
        match try_stun_server_with_replies(&local_socket, &mut replies, server_str, server_addr)
            .await
        {
            Ok(addr) => {
                results.push((server_addr, addr));
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

    let local_ip = local_probe_ip(&local_socket, results.first().map(|(server, _)| *server));
    build_nat_info_from_results(local_ip, results, failures)
}

/// Our own address on the interface that reaches `reflector`, for the "no NAT
/// at all" comparison in [`build_nat_info_from_results`].
///
/// The KAD socket this probe borrows is bound to `0.0.0.0`, so its
/// `local_addr()` only ever reports the wildcard — which never equals a
/// STUN-mapped address, so the `Open` arm could not be reached on any host.
/// Connecting a throwaway UDP socket sends nothing; it just asks the routing
/// table which source address would be used.
fn local_probe_ip(local_socket: &UdpSocket, reflector: Option<SocketAddr>) -> Option<IpAddr> {
    match local_socket.local_addr() {
        Ok(addr) if !addr.ip().is_unspecified() => return Some(addr.ip()),
        _ => {}
    }
    let reflector = reflector?;
    let probe = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    probe.connect(reflector).ok()?;
    let addr = probe.local_addr().ok()?;
    (!addr.ip().is_unspecified()).then_some(addr.ip())
}

async fn resolve_stun_server(server: &str) -> Result<SocketAddr, String> {
    tokio::net::lookup_host(server)
        .await
        .map_err(|e| format!("DNS resolve {server}: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("No IPv4 address for {server}"))
}

fn build_nat_info_from_results(
    local_ip: Option<IpAddr>,
    results: Vec<(SocketAddr, SocketAddr)>,
    failures: Vec<String>,
) -> NatInfo {
    if results.is_empty() {
        let detail = failures
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        // Promoted from debug! to info! — this and the "type=" log below are
        // the only two possible outcomes of a probe attempt, and without
        // this one visible at the default log level, a probe that silently
        // never gets a single STUN reply back is indistinguishable from a
        // probe that never ran at all.
        if detail.is_empty() {
            info!("NAT probe: all STUN servers failed");
        } else {
            info!("NAT probe: all STUN servers failed ({detail})");
        }
        return NatInfo {
            nat_type: NatType::Unknown,
            external_addr: None,
            last_probed: Instant::now(),
        };
    }

    let external_addr = results[0].1;

    // Every entry in `results` came from a distinct reflector address, so a
    // second entry is a genuinely independent vantage point.
    let nat_type = if local_ip
        .is_some_and(|ip| ip == external_addr.ip() && !ip.is_loopback() && !ip.is_unspecified())
    {
        info!("NAT probe: local address {external_addr} is the mapped address — no NAT");
        NatType::Open
    } else if results.len() >= 2 && results[0].1.port() != results[1].1.port() {
        info!(
            "NAT probe: symmetric NAT detected (ports {} vs {})",
            results[0].1.port(),
            results[1].1.port()
        );
        NatType::Symmetric
    } else if results.len() >= 2 {
        // Deliberate simplification: comparing the mapped port across
        // two independent STUN servers can only distinguish Symmetric
        // NAT (port changes per destination) from "some cone type"
        // (port stays consistent) — it can't tell Full Cone,
        // Restricted Cone, and Port-Restricted Cone apart, since that
        // requires a STUN CHANGE-REQUEST test (asking a server to
        // reply from a different IP/port) which this prober doesn't
        // send. `PortRestricted` is used as the conservative default
        // for "consistent port, filtering unknown" — the punch gate
        // only rejects `Symmetric`, so this is treated the same as the
        // friendlier cone types and hole-punch strategy selection
        // isn't affected by not producing `FullCone`/`RestrictedCone`.
        info!(
            "NAT probe: port-restricted or better NAT (consistent port {} from {} and {})",
            external_addr.port(),
            results[0].0.ip(),
            results[1].0.ip()
        );
        NatType::PortRestricted
    } else {
        info!(
            "NAT probe: only 1 usable STUN reply (mapped {}), leaving NAT type Unknown",
            external_addr,
        );
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
    server_addr: SocketAddr,
) -> Result<SocketAddr, String> {
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
                    // Require an exact address match, not just the IP: we
                    // never send a CHANGE-REQUEST attribute, so a
                    // conformant STUN server always replies from the same
                    // `ip:port` it was queried on. Matching IP alone would
                    // accept a binding response forged (or coincidentally
                    // sent) by a different service on the same host that
                    // happens to guess/echo our 96-bit transaction ID.
                    if from != server_addr {
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

pub(crate) fn build_binding_request(txn_id: &[u8; 12]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(txn_id);
    buf
}

pub(crate) fn parse_binding_response(
    data: &[u8],
    expected_txn_id: &[u8; 12],
) -> Result<SocketAddr, String> {
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
    let mut xor_mapped = None;
    let mut mapped = None;
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
                if xor_mapped.is_none() {
                    xor_mapped = parse_xor_mapped_address(attr_data);
                }
            }
            ATTR_MAPPED_ADDRESS => {
                if mapped.is_none() {
                    mapped = parse_mapped_address(attr_data);
                }
            }
            _ => {}
        }

        let padded = (attr_len + 3) & !3;
        offset += padded;
    }

    // RFC 5389: ignore MAPPED-ADDRESS when XOR-MAPPED-ADDRESS is present.
    // Returning the first attribute we saw would prefer a rewritten
    // MAPPED-ADDRESS over the XOR encoding that middleboxes cannot cheaply
    // forge to a different value.
    xor_mapped
        .or(mapped)
        .ok_or_else(|| "No mapped address in response".into())
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

    fn reading(server: &str, mapped: &str) -> (SocketAddr, SocketAddr) {
        (server.parse().unwrap(), mapped.parse().unwrap())
    }

    /// The reflector list is walked in order and the probe stops after two
    /// readings, so grouping one provider's aliases at the front made the two
    /// readings come from a single address — which cannot disagree, and so
    /// could never expose a symmetric NAT.
    #[test]
    fn default_stun_servers_lead_with_distinct_providers() {
        let provider = |server: &str| {
            if server.contains(".l.google.com") {
                "google"
            } else if server.contains("cloudflare") {
                "cloudflare"
            } else {
                "other"
            }
        };
        assert!(DEFAULT_STUN_SERVERS.len() >= 2);
        assert_ne!(
            provider(DEFAULT_STUN_SERVERS[0]),
            provider(DEFAULT_STUN_SERVERS[1]),
        );
    }

    #[test]
    fn two_reflectors_disagreeing_on_port_is_symmetric() {
        let info = build_nat_info_from_results(
            Some("192.168.1.5".parse().unwrap()),
            vec![
                reading("74.125.250.129:19302", "1.2.3.4:5000"),
                reading("162.159.207.0:3478", "1.2.3.4:6000"),
            ],
            Vec::new(),
        );
        assert_eq!(info.nat_type, NatType::Symmetric);
        assert_eq!(info.external_addr, Some("1.2.3.4:5000".parse().unwrap()));
    }

    #[test]
    fn two_reflectors_agreeing_on_port_is_port_restricted() {
        let info = build_nat_info_from_results(
            Some("192.168.1.5".parse().unwrap()),
            vec![
                reading("74.125.250.129:19302", "1.2.3.4:5000"),
                reading("162.159.207.0:3478", "1.2.3.4:5000"),
            ],
            Vec::new(),
        );
        assert_eq!(info.nat_type, NatType::PortRestricted);
    }

    /// One vantage point says nothing about per-destination re-mapping, so the
    /// type stays `Unknown` and the address is still reported.
    #[test]
    fn a_single_reflector_leaves_the_type_unknown() {
        let info = build_nat_info_from_results(
            Some("192.168.1.5".parse().unwrap()),
            vec![reading("74.125.250.129:19302", "1.2.3.4:5000")],
            Vec::new(),
        );
        assert_eq!(info.nat_type, NatType::Unknown);
        assert_eq!(info.external_addr, Some("1.2.3.4:5000".parse().unwrap()));
    }

    /// A host whose own interface address is the mapped address has no NAT in
    /// front of it. The probe socket is bound to `0.0.0.0`, so this only works
    /// because the caller resolves the real outbound address first.
    #[test]
    fn mapped_address_equal_to_the_local_address_is_open() {
        let info = build_nat_info_from_results(
            Some("1.2.3.4".parse().unwrap()),
            vec![reading("74.125.250.129:19302", "1.2.3.4:5000")],
            Vec::new(),
        );
        assert_eq!(info.nat_type, NatType::Open);
    }

    #[test]
    fn a_wildcard_local_address_does_not_classify_as_open() {
        let info = build_nat_info_from_results(
            None,
            vec![
                reading("74.125.250.129:19302", "1.2.3.4:5000"),
                reading("162.159.207.0:3478", "1.2.3.4:5000"),
            ],
            Vec::new(),
        );
        assert_eq!(info.nat_type, NatType::PortRestricted);
    }

    #[test]
    fn no_replies_leaves_everything_unknown() {
        let info = build_nat_info_from_results(
            Some("192.168.1.5".parse().unwrap()),
            Vec::new(),
            vec!["stun.example:timeout".to_string()],
        );
        assert_eq!(info.nat_type, NatType::Unknown);
        assert_eq!(info.external_addr, None);
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

    #[test]
    fn xor_mapped_address_wins_over_a_leading_mapped_address() {
        let txn_id = [0xBB; 12];
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        let real_ip = std::net::Ipv4Addr::new(198, 51, 100, 9);
        let real_port: u16 = 41234;
        let xor_port = real_port ^ (STUN_MAGIC_COOKIE >> 16) as u16;
        let real_octets = real_ip.octets();
        let xor_ip = [
            real_octets[0] ^ magic[0],
            real_octets[1] ^ magic[1],
            real_octets[2] ^ magic[2],
            real_octets[3] ^ magic[3],
        ];

        let mut mapped_attr = Vec::new();
        mapped_attr.extend_from_slice(&ATTR_MAPPED_ADDRESS.to_be_bytes());
        mapped_attr.extend_from_slice(&8u16.to_be_bytes());
        mapped_attr.push(0);
        mapped_attr.push(0x01);
        mapped_attr.extend_from_slice(&80u16.to_be_bytes());
        mapped_attr.extend_from_slice(&[10, 0, 0, 1]);

        let mut xor_attr = Vec::new();
        xor_attr.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        xor_attr.extend_from_slice(&8u16.to_be_bytes());
        xor_attr.push(0);
        xor_attr.push(0x01);
        xor_attr.extend_from_slice(&xor_port.to_be_bytes());
        xor_attr.extend_from_slice(&xor_ip);

        let attrs_len = (mapped_attr.len() + xor_attr.len()) as u16;
        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&attrs_len.to_be_bytes());
        response.extend_from_slice(&magic);
        response.extend_from_slice(&txn_id);
        response.extend_from_slice(&mapped_attr);
        response.extend_from_slice(&xor_attr);

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(real_ip), real_port));
    }
}
