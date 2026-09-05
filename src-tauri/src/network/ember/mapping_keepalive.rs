//! NATMAP-style full-cone mapping keep-alive.
//!
//! Keeps ISP / CGNAT full-cone mappings alive on Ember's real listen ports and
//! discovers the current public mapped endpoints so we can advertise them for
//! HighID / KAD source publish without restarting the process.
//!
//! - **UDP (KAD socket):** periodic STUN Binding requests from the shared KAD
//!   UDP socket (replies routed by the network loop).
//! - **TCP listen port:** outbound TCP connect with SO_REUSEADDR from the
//!   same local TCP port (holds the TCP mapping), plus STUN-over-TCP from that
//!   same local endpoint to authoritatively learn the public TCP port.
//! - **QUIC socket:** Quinn owns that UDP socket and drops non-QUIC
//!   datagrams, so a STUN Binding sent through the endpoint cannot be
//!   read back, and a second bind on the same port cannot share it
//!   (Quinn never sets `SO_REUSEADDR`). Keep-alive is a one-datagram
//!   [`quinn::Endpoint::connect`] to a STUN reflector, dropped immediately
//!   so it emits an Initial close from the real socket and refreshes the
//!   NAT mapping. The public port is not re-sampled. Skipped until the
//!   endpoint exists.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::{debug, info, warn};

use super::nat::{
    build_binding_request, is_stun_binding_response, parse_binding_response, DEFAULT_STUN_SERVERS,
    STUN_TIMEOUT,
};

/// How often to refresh UDP/TCP mappings (NATMAP-like keep-alive cadence).
pub const MAPPING_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// TCP targets used only to establish a short-lived mapping from our listen
/// port. We intentionally send no HTTP request or identifying User-Agent.
const TCP_HOLD_TARGETS: &[(&str, u16)] = &[
    ("connectivitycheck.gstatic.com", 80),
    ("www.msftconnecttest.com", 80),
    ("cp.cloudflare.com", 80),
];

/// STUN endpoints known to accept plain STUN over TCP. Keep this separate from
/// `DEFAULT_STUN_SERVERS`: several high-quality UDP reflectors (notably
/// Google's public servers) do not listen for TCP on the same endpoint.
const TCP_STUN_SERVERS: &[&str] = &[
    "turn.cloudflare.com:3478",
    "stun.nextcloud.com:3478",
    "stun.freeswitch.org:3478",
    "global.stun.twilio.com:3478",
];

/// Cap on each `lookup_host`. Matched to [`STUN_TIMEOUT`]: a cold Windows
/// resolver on a lossy link retries `getaddrinfo` at roughly 1 s then 2 s,
/// so exceeding 2 s is a normal-but-slow outcome rather than a hang.
/// Each target is independently bounded; `tcp_mapping_cycle` has no shared
/// STUN/connect budget. The real constraint is the network loop's
/// `MAPPING_KA_WATCHDOG` (90 s). Realistic worst case is
/// 3 × (5 + 8) + 4 × (5 + 5) = 79 s (three TCP-hold DNS+connect timeouts,
/// then four TCP-STUN DNS+connect timeouts). The QUIC keep-alive is a
/// parallel DNS lookup (≤ 5 s) plus an immediate datagram; it does not
/// add to the sequential TCP total. Still inside that watchdog.
/// `tokio::time::timeout` cancels the future, not the `getaddrinfo` call
/// running on a blocking thread — that thread stays occupied until the OS
/// gives up. Bounded, not a leak.
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

async fn lookup_ipv4(
    host: impl tokio::net::ToSocketAddrs,
    label: &str,
) -> Result<SocketAddr, String> {
    let mut resolved = tokio::time::timeout(DNS_TIMEOUT, tokio::net::lookup_host(host))
        .await
        .map_err(|_| format!("DNS {label}: timed out"))?
        .map_err(|e| format!("DNS {label}: {e}"))?;
    resolved
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("No IPv4 for {label}"))
}

/// Discover the TCP server-reflexive endpoint using a real TCP STUN
/// transaction sourced from Ember's TCP listener port.
pub async fn tcp_stun_mapped_addr_on_port(local_port: u16) -> Option<SocketAddr> {
    for server in TCP_STUN_SERVERS {
        match tcp_stun_exchange(local_port, server).await {
            Ok(addr) => {
                debug!("TCP STUN {local_port} -> {addr} via {server}");
                return Some(addr);
            }
            Err(e) => debug!("TCP STUN {server} failed: {e}"),
        }
    }
    None
}

async fn tcp_stun_exchange(local_port: u16, server: &str) -> Result<SocketAddr, String> {
    let server_addr = lookup_ipv4(server, server).await?;

    let tcp = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    tcp.set_reuseaddr(true)
        .map_err(|e| format!("reuseaddr: {e}"))?;
    tcp.bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_port)))
        .map_err(|e| format!("bind {local_port}: {e}"))?;
    let mut stream = tokio::time::timeout(STUN_TIMEOUT, tcp.connect(server_addr))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

    let txn_id: [u8; 12] = rand::random();
    let request = build_binding_request(&txn_id);
    tokio::time::timeout(STUN_TIMEOUT, stream.write_all(&request))
        .await
        .map_err(|_| "write timeout".to_string())?
        .map_err(|e| format!("write: {e}"))?;

    // STUN's 20-byte header carries the payload length. TCP may split a
    // response arbitrarily, so read the header and declared body exactly
    // instead of assuming one read equals one message.
    let mut header = [0u8; 20];
    tokio::time::timeout(STUN_TIMEOUT, stream.read_exact(&mut header))
        .await
        .map_err(|_| "response header timeout".to_string())?
        .map_err(|e| format!("read header: {e}"))?;
    let body_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if !body_len.is_multiple_of(4) {
        return Err(format!("invalid STUN body length {body_len}"));
    }
    let mut response = Vec::with_capacity(20 + body_len);
    response.extend_from_slice(&header);
    response.resize(20 + body_len, 0);
    tokio::time::timeout(STUN_TIMEOUT, stream.read_exact(&mut response[20..]))
        .await
        .map_err(|_| "response body timeout".to_string())?
        .map_err(|e| format!("read body: {e}"))?;
    if !is_stun_binding_response(&response) {
        return Err("not a STUN Binding response".to_string());
    }
    parse_binding_response(&response, &txn_id)
}

/// Build a STUN Binding request for the shared KAD socket keep-alive path.
pub fn stun_keepalive_request(server_index: usize) -> ([u8; 12], Vec<u8>, &'static str) {
    let server = DEFAULT_STUN_SERVERS[server_index % DEFAULT_STUN_SERVERS.len()];
    let txn_id: [u8; 12] = rand::random();
    (txn_id, build_binding_request(&txn_id), server)
}

pub fn parse_keepalive_response(
    data: &[u8],
    from: SocketAddr,
    expected_server: SocketAddr,
    txn_id: &[u8; 12],
) -> Option<SocketAddr> {
    if from != expected_server {
        return None;
    }
    if !is_stun_binding_response(data) {
        return None;
    }
    parse_binding_response(data, txn_id).ok()
}

/// Single STUN Binding keep-alive on the shared KAD UDP socket (replies
/// routed from the main network loop).
pub(crate) async fn stun_keepalive_with_replies(
    socket: Arc<UdpSocket>,
    mut replies: tokio::sync::mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    server_index: usize,
) -> Option<SocketAddr> {
    let (txn_id, request, server) = stun_keepalive_request(server_index);
    let server_addr = match lookup_ipv4(server, server).await {
        Ok(addr) => addr,
        Err(e) => {
            debug!("STUN keepalive {e}");
            return None;
        }
    };

    if let Err(e) = socket.send_to(&request, server_addr).await {
        debug!("STUN keepalive send failed: {e}");
        return None;
    }

    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            debug!("STUN keepalive timeout from {server}");
            return None;
        }
        match tokio::time::timeout(remaining, replies.recv()).await {
            Ok(Some((data, from))) => {
                if let Some(addr) = parse_keepalive_response(&data, from, server_addr, &txn_id) {
                    return Some(addr);
                }
            }
            Ok(None) => return None,
            Err(_) => {
                debug!("STUN keepalive timeout from {server}");
                return None;
            }
        }
    }
}

/// Open an HTTP connection from the TCP listen port and retain it while the
/// TCP STUN transaction runs. Uses SO_REUSEADDR so the listener, hold, and
/// STUN connection can coexist as distinct TCP 4-tuples.
async fn open_tcp_mapping_hold(local_port: u16) -> Option<TcpStream> {
    // Reasons are carried to the warning rather than logged and dropped. The
    // per-target line below is `debug!`, so at the level anyone actually runs
    // a hold that stops working arrived as "failed for all targets" and
    // nothing else — and the candidates behind that have nothing in common.
    // An address already in use means a previous cycle's 4-tuple is still in
    // TIME_WAIT and this keep-alive is exhausting its own targets; a refusal
    // or reset means something between here and the internet drops
    // captive-portal endpoints; a DNS error means neither. One is our bug, one
    // is the user's network, one is transient, and the aggregate line could
    // not tell them apart.
    let mut failures: Vec<String> = Vec::with_capacity(TCP_HOLD_TARGETS.len());
    for &(host, port) in TCP_HOLD_TARGETS {
        match tcp_hold_connect(local_port, host, port).await {
            Ok(stream) => {
                debug!("TCP mapping hold ok via {host}:{port} from local {local_port}");
                return Some(stream);
            }
            Err(e) => {
                debug!("TCP mapping hold {host}:{port} failed: {e}");
                failures.push(format!("{host}:{port}: {e}"));
            }
        }
    }
    warn!(
        "TCP mapping hold failed for all targets (port {local_port}): {}",
        failures.join("; ")
    );
    None
}

async fn tcp_hold_connect(local_port: u16, host: &str, port: u16) -> Result<TcpStream, String> {
    let remote = lookup_ipv4((host, port), host).await?;

    let tcp = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    tcp.set_reuseaddr(true)
        .map_err(|e| format!("reuseaddr: {e}"))?;
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_port));
    tcp.bind(bind_addr)
        .map_err(|e| format!("bind {local_port}: {e}"))?;

    let stream = tokio::time::timeout(Duration::from_secs(8), tcp.connect(remote))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    Ok(stream)
}

/// Emit one UDP datagram from the QUIC endpoint so a port-restricted NAT
/// mapping does not idle out.
///
/// Quinn takes exclusive ownership of the socket and never surfaces a
/// datagram it cannot parse as QUIC, so a STUN Binding cannot be read back.
/// A sibling bind is not an option: the endpoint socket is created without
/// `SO_REUSEADDR`, so a second bind fails on every platform, and enabling
/// reuse on both would make inbound delivery indeterminate on Windows.
/// Dropping the [`quinn::Connecting`] emits a single Initial close from the
/// real socket and consumes no connection slot.
pub(crate) async fn quic_mapping_keepalive(
    endpoint: Arc<quinn::Endpoint>,
    server_index: usize,
) {
    let server = DEFAULT_STUN_SERVERS[server_index % DEFAULT_STUN_SERVERS.len()];
    let server_addr = match lookup_ipv4(server, server).await {
        Ok(addr) => addr,
        Err(e) => {
            debug!("QUIC mapping keepalive {e}");
            return;
        }
    };
    if let Err(e) = endpoint.connect(server_addr, "stun") {
        debug!("QUIC mapping keepalive endpoint transmit: {e}");
    }
}

/// Background cycle: TCP hold + TCP STUN on `tcp_port`.
pub async fn tcp_mapping_cycle(local_tcp_port: u16) -> (bool, Option<SocketAddr>) {
    let hold_stream = open_tcp_mapping_hold(local_tcp_port).await;
    let hold_ok = hold_stream.is_some();
    if hold_ok {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mapped = tcp_stun_mapped_addr_on_port(local_tcp_port).await;
    if let Some(addr) = mapped {
        info!(
            "TCP-port mapping discovered: local {local_tcp_port} -> public {addr} (hold={hold_ok})"
        );
    }
    drop(hold_stream);
    (hold_ok, mapped)
}

/// Prefer a usable public IPv4 from a STUN mapped address.
pub fn ipv4_from_mapped(addr: SocketAddr) -> Option<Ipv4Addr> {
    match addr.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_loopback() => Some(ip),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_request_is_stun_binding() {
        let (txn, req, server) = stun_keepalive_request(0);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), 0x0001);
        assert!(!server.is_empty());
        assert_eq!(txn.len(), 12);
    }

    #[test]
    fn tcp_stun_servers_exclude_known_udp_only_endpoints() {
        assert!(!TCP_STUN_SERVERS.is_empty());
        assert!(TCP_STUN_SERVERS
            .iter()
            .all(|server| !server.contains(".l.google.com")));
        assert!(!TCP_STUN_SERVERS.contains(&"stun.cloudflare.com:3478"));
    }

    #[test]
    fn tcp_hold_protocol_sends_no_identifying_plaintext() {
        let source = include_str!("mapping_keepalive.rs");
        assert!(!source.contains(concat!("User-Agent", ": ", "Ember")));
        assert!(!source.contains(concat!("HEAD ", "/", " HTTP/1.1")));
    }
}
