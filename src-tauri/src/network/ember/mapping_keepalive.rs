//! NATMAP-style full-cone mapping keep-alive.
//!
//! Keeps ISP / CGNAT full-cone mappings alive on Ember's real listen ports and
//! discovers the current public mapped endpoints so we can advertise them for
//! HighID / KAD source publish without restarting the process.
//!
//! - **UDP (KAD socket):** periodic STUN Binding requests from the shared KAD
//!   UDP socket (replies routed by the network loop).
//! - **TCP listen port:** outbound TCP connect with SO_REUSEADDR from the
//!   same local TCP port (holds the TCP mapping), plus a twin STUN probe on a
//!   UDP socket bound to that same port number to learn the public port when
//!   the NAT remaps.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, UdpSocket};
use tracing::{debug, info, warn};

use super::nat::{
    build_binding_request, is_stun_binding_response, parse_binding_response, DEFAULT_STUN_SERVERS,
    STUN_TIMEOUT,
};

/// How often to refresh UDP/TCP mappings (NATMAP-like keep-alive cadence).
pub const MAPPING_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);

/// HTTP targets used only to hold a TCP mapping from our listen port.
const TCP_HOLD_TARGETS: &[(&str, u16)] = &[
    ("connectivitycheck.gstatic.com", 80),
    ("www.msftconnecttest.com", 80),
    ("cp.cloudflare.com", 80),
];

/// One STUN Binding exchange on a dedicated UDP socket bound to `local_port`.
pub async fn stun_mapped_addr_on_port(local_port: u16) -> Option<SocketAddr> {
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_port));
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!("TCP-port twin STUN bind {local_port} failed: {e}");
            return None;
        }
    };

    for server in DEFAULT_STUN_SERVERS.iter().take(3) {
        match stun_exchange_owned(&socket, server).await {
            Ok(addr) => {
                debug!("TCP-port twin STUN {local_port} -> {addr} via {server}");
                return Some(addr);
            }
            Err(e) => debug!("TCP-port twin STUN {server} failed: {e}"),
        }
    }
    None
}

async fn stun_exchange_owned(socket: &UdpSocket, server: &str) -> Result<SocketAddr, String> {
    let server_addr: SocketAddr = tokio::net::lookup_host(server)
        .await
        .map_err(|e| format!("DNS {server}: {e}"))?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| format!("No IPv4 for {server}"))?;

    let txn_id: [u8; 12] = rand::random();
    let request = build_binding_request(&txn_id);
    socket
        .send_to(&request, server_addr)
        .await
        .map_err(|e| format!("send: {e}"))?;

    let deadline = tokio::time::Instant::now() + STUN_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err("timeout".into());
        }
        let mut buf = [0u8; 512];
        match tokio::time::timeout(remaining, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, from))) => {
                if from != server_addr {
                    continue;
                }
                if !is_stun_binding_response(&buf[..n]) {
                    continue;
                }
                return parse_binding_response(&buf[..n], &txn_id);
            }
            Ok(Err(e)) => return Err(format!("recv: {e}")),
            Err(_) => return Err("timeout".into()),
        }
    }
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
    let server_addr: SocketAddr = match tokio::net::lookup_host(server).await {
        Ok(mut iter) => match iter.find(|a| a.is_ipv4()) {
            Some(a) => a,
            None => {
                debug!("STUN keepalive: no IPv4 for {server}");
                return None;
            }
        },
        Err(e) => {
            debug!("STUN keepalive DNS {server}: {e}");
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

/// Hold the TCP NAT mapping by connecting from our listen port to a public
/// HTTP endpoint (NATMAP-style). Uses SO_REUSEADDR so this can coexist with
/// the upload TcpListener.
pub async fn hold_tcp_mapping_once(local_port: u16) -> bool {
    for &(host, port) in TCP_HOLD_TARGETS {
        match tcp_hold_connect(local_port, host, port).await {
            Ok(()) => {
                debug!("TCP mapping hold ok via {host}:{port} from local {local_port}");
                return true;
            }
            Err(e) => debug!("TCP mapping hold {host}:{port} failed: {e}"),
        }
    }
    warn!("TCP mapping hold failed for all targets (port {local_port})");
    false
}

async fn tcp_hold_connect(local_port: u16, host: &str, port: u16) -> Result<(), String> {
    let mut addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS {host}: {e}"))?
        .filter(|a| a.is_ipv4());
    let remote = addrs
        .next()
        .ok_or_else(|| format!("No IPv4 for {host}"))?;

    let tcp = TcpSocket::new_v4().map_err(|e| format!("socket: {e}"))?;
    tcp.set_reuseaddr(true)
        .map_err(|e| format!("reuseaddr: {e}"))?;
    let bind_addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, local_port));
    tcp.bind(bind_addr)
        .map_err(|e| format!("bind {local_port}: {e}"))?;

    let mut stream = tokio::time::timeout(Duration::from_secs(8), tcp.connect(remote))
        .await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;

    let req = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Ember\r\n\r\n"
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(req.as_bytes())).await;
    let mut buf = [0u8; 64];
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
    let _ = stream.shutdown().await;
    Ok(())
}

/// Background cycle: TCP hold + twin STUN on `tcp_port`.
pub async fn tcp_mapping_cycle(local_tcp_port: u16) -> (bool, Option<SocketAddr>) {
    let hold_ok = hold_tcp_mapping_once(local_tcp_port).await;
    if hold_ok {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mapped = stun_mapped_addr_on_port(local_tcp_port).await;
    if let Some(addr) = mapped {
        info!(
            "TCP-port mapping discovered: local {local_tcp_port} -> public {addr} (hold={hold_ok})"
        );
    }
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
}
