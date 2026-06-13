use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::time::Instant;
use tracing::{info, warn};

type Gw = igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>;

/// Lease requested for each mapping. Re-added by `maintain` before expiry.
const LEASE_SECS: u32 = 3600;
/// Re-add mappings once this much of the lease has elapsed (15 min margin).
const RENEW_AFTER: Duration = Duration::from_secs(45 * 60);
/// SSDP gateway discovery timeout. Kept short because discovery runs inline
/// on the network task: at startup it gates the rest of network init, and
/// during `maintain` re-discovery it stalls the select loop while it waits.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

pub struct UpnpMappings {
    gateway: Option<Gw>,
    tcp_port: u16,
    udp_port: u16,
    /// QUIC listens on its own UDP socket (often `tcp_port`, possibly a
    /// fallback). It is learned at runtime after the endpoint binds, so it's
    /// mapped separately via `map_quic_port` once known and then refreshed by
    /// `maintain`/removed by `teardown` alongside the others.
    quic_port: Option<u16>,
    tcp_mapped: bool,
    udp_mapped: bool,
    quic_mapped: bool,
    /// When the last mapping add/renew cycle ran (success or not). Mapping
    /// failures against a live gateway (e.g. UPnP disabled in the router
    /// admin) are usually persistent, so retries wait a full renew period.
    last_map_attempt: Option<Instant>,
    /// Consecutive failed gateway discoveries; drives the retry backoff.
    discovery_failures: u32,
    /// Don't retry discovery before this instant.
    next_discovery_at: Option<Instant>,
}

impl UpnpMappings {
    pub fn new(tcp_port: u16, udp_port: u16) -> Self {
        UpnpMappings {
            gateway: None,
            tcp_port,
            udp_port,
            quic_port: None,
            tcp_mapped: false,
            udp_mapped: false,
            quic_mapped: false,
            last_map_attempt: None,
            discovery_failures: 0,
            next_discovery_at: None,
        }
    }

    /// Add one port mapping, working around two common router quirks:
    /// error 725 (`OnlyPermanentLeasesSupported`) gets a retry with a
    /// permanent lease, and error 718 (`PortInUse`) — which some gateways
    /// return instead of refreshing a mapping we already own — gets a
    /// delete-then-re-add.
    async fn try_add_port(
        gateway: &Gw,
        protocol: igd_next::PortMappingProtocol,
        port: u16,
        local_ip: Ipv4Addr,
        label: &str,
    ) -> bool {
        let local = SocketAddr::V4(SocketAddrV4::new(local_ip, port));
        let proto = match protocol {
            igd_next::PortMappingProtocol::TCP => "TCP",
            igd_next::PortMappingProtocol::UDP => "UDP",
        };
        match gateway.add_port(protocol, port, local, LEASE_SECS, label).await {
            Ok(()) => {
                info!("UPnP: mapped {proto} port {port} ({label})");
                true
            }
            Err(igd_next::AddPortError::OnlyPermanentLeasesSupported) => {
                match gateway.add_port(protocol, port, local, 0, label).await {
                    Ok(()) => {
                        info!("UPnP: mapped {proto} port {port} ({label}) with permanent lease");
                        true
                    }
                    Err(e) => {
                        warn!("UPnP: permanent-lease retry failed for {proto} port {port} ({label}): {e}");
                        false
                    }
                }
            }
            Err(igd_next::AddPortError::PortInUse) => {
                let _ = gateway.remove_port(protocol, port).await;
                match gateway.add_port(protocol, port, local, LEASE_SECS, label).await {
                    Ok(()) => {
                        info!("UPnP: re-mapped {proto} port {port} ({label}) after mapping conflict");
                        true
                    }
                    Err(e) => {
                        warn!("UPnP: re-map after conflict failed for {proto} port {port} ({label}): {e}");
                        false
                    }
                }
            }
            Err(e) => {
                warn!("UPnP: failed to map {proto} port {port} ({label}): {e}");
                false
            }
        }
    }

    /// (Re-)add every known mapping — TCP, KAD UDP, and the QUIC UDP port if
    /// it has been learned — and update the mapped flags. Returns true when
    /// at least the TCP or KAD UDP mapping succeeded.
    async fn map_all(&mut self) -> bool {
        self.last_map_attempt = Some(Instant::now());
        let (tcp_ok, udp_ok, quic_ok) = {
            let Some(gateway) = &self.gateway else {
                return false;
            };
            let Some(local_ip) = local_ipv4(gateway.addr) else {
                warn!("Could not determine local IPv4 address for UPnP");
                self.tcp_mapped = false;
                self.udp_mapped = false;
                self.quic_mapped = false;
                return false;
            };
            let tcp_ok = Self::try_add_port(
                gateway,
                igd_next::PortMappingProtocol::TCP,
                self.tcp_port,
                local_ip,
                "Ember P2P TCP",
            )
            .await;
            let udp_ok = Self::try_add_port(
                gateway,
                igd_next::PortMappingProtocol::UDP,
                self.udp_port,
                local_ip,
                "Ember P2P UDP",
            )
            .await;
            let quic_ok = match self.quic_port {
                // QUIC shares the KAD UDP port: covered by the mapping above.
                Some(qp) if qp == self.udp_port => udp_ok,
                Some(qp) => {
                    Self::try_add_port(
                        gateway,
                        igd_next::PortMappingProtocol::UDP,
                        qp,
                        local_ip,
                        "Ember P2P QUIC",
                    )
                    .await
                }
                None => false,
            };
            (tcp_ok, udp_ok, quic_ok)
        };
        self.tcp_mapped = tcp_ok;
        self.udp_mapped = udp_ok;
        self.quic_mapped = quic_ok;
        tcp_ok || udp_ok
    }

    /// Map the QUIC UDP listen port. QUIC binds its own socket after `setup()`
    /// (often on `tcp_port`, possibly a fallback), so without this the QUIC
    /// listener — used for inbound relay targets and hole-punch accepts — is
    /// never forwarded even when TCP/KAD show as "open". No-op when QUIC ended
    /// up on the already-mapped KAD UDP port. The port is recorded even when
    /// no gateway is available yet so a later `maintain` discovery maps it.
    pub async fn map_quic_port(&mut self, quic_port: u16) -> bool {
        if self.quic_port == Some(quic_port) && self.quic_mapped {
            return true;
        }
        self.quic_port = Some(quic_port);
        if quic_port == self.udp_port {
            self.quic_mapped = self.udp_mapped;
            return self.udp_mapped;
        }
        let ok = {
            let Some(gateway) = &self.gateway else {
                return false;
            };
            let Some(local_ip) = local_ipv4(gateway.addr) else {
                return false;
            };
            Self::try_add_port(
                gateway,
                igd_next::PortMappingProtocol::UDP,
                quic_port,
                local_ip,
                "Ember P2P QUIC",
            )
            .await
        };
        self.quic_mapped = ok;
        ok
    }

    /// Discover the gateway and add all known mappings. Returns true when at
    /// least the TCP or KAD UDP mapping succeeded. On discovery failure the
    /// retry backoff is advanced; `maintain` retries when it elapses.
    pub async fn setup(&mut self) -> bool {
        let options = igd_next::SearchOptions {
            timeout: Some(DISCOVERY_TIMEOUT),
            ..Default::default()
        };
        let gateway = match igd_next::aio::tokio::search_gateway(options).await {
            Ok(gw) => {
                info!("UPnP gateway found: {}", gw.addr);
                gw
            }
            Err(e) => {
                warn!("UPnP gateway discovery failed: {e}");
                self.note_discovery_failure();
                return false;
            }
        };
        self.discovery_failures = 0;
        self.next_discovery_at = None;
        self.gateway = Some(gateway);
        self.map_all().await
    }

    fn note_discovery_failure(&mut self) {
        self.discovery_failures = self.discovery_failures.saturating_add(1);
        // 10 → 20 → 40 → 60 min (capped); `maintain` ticks every 10 min.
        let mins = match self.discovery_failures {
            0 | 1 => 10,
            2 => 20,
            3 => 40,
            _ => 60,
        };
        self.next_discovery_at = Some(Instant::now() + Duration::from_secs(mins * 60));
    }

    /// Periodic maintenance, intended to be called every ~10 minutes:
    /// - no gateway yet (startup discovery failed): retry discovery once the
    ///   backoff elapses, so a transient failure no longer disables UPnP for
    ///   the whole session;
    /// - gateway known and the lease is due: re-add the mappings;
    /// - renew fails for every mapping: assume the cached gateway went stale
    ///   (router reboot / control-URL change), drop it and re-discover.
    ///
    /// Returns whether the TCP or KAD UDP mapping is currently in place.
    pub async fn maintain(&mut self) -> bool {
        if self.gateway.is_none() {
            if self
                .next_discovery_at
                .is_some_and(|t| Instant::now() < t)
            {
                return false;
            }
            self.setup().await;
            return self.is_mapped();
        }
        if self
            .last_map_attempt
            .is_some_and(|t| t.elapsed() < RENEW_AFTER)
        {
            return self.is_mapped();
        }
        if !self.map_all().await {
            warn!("UPnP renew failed for all mappings; re-discovering gateway");
            self.gateway = None;
            self.setup().await;
        }
        self.is_mapped()
    }

    pub async fn teardown(&mut self) {
        if let Some(ref gateway) = self.gateway {
            if self.tcp_mapped {
                let _ = gateway.remove_port(igd_next::PortMappingProtocol::TCP, self.tcp_port).await;
            }
            if self.udp_mapped {
                let _ = gateway.remove_port(igd_next::PortMappingProtocol::UDP, self.udp_port).await;
            }
            if self.quic_mapped {
                if let Some(qp) = self.quic_port {
                    if qp != self.udp_port {
                        let _ = gateway.remove_port(igd_next::PortMappingProtocol::UDP, qp).await;
                    }
                }
            }
            if self.tcp_mapped || self.udp_mapped || self.quic_mapped {
                info!("UPnP: removed port mappings");
            }
        }
        self.gateway = None;
        self.tcp_mapped = false;
        self.udp_mapped = false;
        self.quic_mapped = false;
        self.last_map_attempt = None;
        self.next_discovery_at = None;
    }

    pub fn is_mapped(&self) -> bool {
        self.tcp_mapped || self.udp_mapped
    }
}

/// Local IPv4 on the interface that routes to the gateway. A mapping must
/// point at the LAN-facing address: on multi-homed machines (most commonly a
/// VPN with the default route through the tunnel) the default-route address
/// is not reachable from the router, so the mapping would be useless.
/// Connecting a UDP socket sends no packets; it only resolves the route.
/// Falls back to the default-internet-route interface if the gateway route
/// can't be resolved.
fn local_ipv4(gateway_addr: SocketAddr) -> Option<Ipv4Addr> {
    route_local_ipv4(gateway_addr)
        .or_else(|| route_local_ipv4(SocketAddr::from(([8, 8, 8, 8], 80))))
}

fn route_local_ipv4(target: SocketAddr) -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect(target).ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}
