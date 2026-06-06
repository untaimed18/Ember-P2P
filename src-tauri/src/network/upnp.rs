use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tracing::{info, warn};

pub struct UpnpMappings {
    gateway: Option<igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>>,
    tcp_port: u16,
    udp_port: u16,
    /// QUIC listens on its own UDP socket (often `tcp_port`, possibly a
    /// fallback). It is learned at runtime after the endpoint binds, so it's
    /// mapped separately via `map_quic_port` once known and then refreshed by
    /// `renew`/removed by `teardown` alongside the others.
    quic_port: Option<u16>,
    tcp_mapped: bool,
    udp_mapped: bool,
    quic_mapped: bool,
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
        }
    }

    async fn map_ports_inner(
        gateway: &igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
        local_ip: Ipv4Addr,
        tcp_port: u16,
        udp_port: u16,
    ) -> (bool, bool) {
        let tcp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, tcp_port));
        let udp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, udp_port));
        let lease_secs = 3600;

        let tcp_ok = match gateway
            .add_port(igd_next::PortMappingProtocol::TCP, tcp_port, tcp_local, lease_secs, "Ember P2P TCP")
            .await
        {
            Ok(()) => { info!("UPnP: mapped TCP port {tcp_port}"); true }
            Err(e) => { warn!("UPnP: failed to map TCP port {tcp_port}: {e}"); false }
        };

        let udp_ok = match gateway
            .add_port(igd_next::PortMappingProtocol::UDP, udp_port, udp_local, lease_secs, "Ember P2P UDP")
            .await
        {
            Ok(()) => { info!("UPnP: mapped UDP port {udp_port}"); true }
            Err(e) => { warn!("UPnP: failed to map UDP port {udp_port}: {e}"); false }
        };

        (tcp_ok, udp_ok)
    }

    async fn add_udp_mapping(
        gateway: &igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
        local_ip: Ipv4Addr,
        port: u16,
        label: &str,
    ) -> bool {
        let local = SocketAddr::V4(SocketAddrV4::new(local_ip, port));
        match gateway
            .add_port(igd_next::PortMappingProtocol::UDP, port, local, 3600, label)
            .await
        {
            Ok(()) => { info!("UPnP: mapped UDP port {port} ({label})"); true }
            Err(e) => { warn!("UPnP: failed to map UDP port {port} ({label}): {e}"); false }
        }
    }

    /// Map the QUIC UDP listen port. QUIC binds its own socket after `setup()`
    /// (often on `tcp_port`, possibly a fallback), so without this the QUIC
    /// listener — used for inbound relay targets and hole-punch accepts — is
    /// never forwarded even when TCP/KAD show as "open". No-op when QUIC ended
    /// up on the already-mapped KAD UDP port.
    pub async fn map_quic_port(&mut self, quic_port: u16) -> bool {
        if self.quic_port == Some(quic_port) && self.quic_mapped {
            return true;
        }
        self.quic_port = Some(quic_port);
        if quic_port == self.udp_port {
            self.quic_mapped = self.udp_mapped;
            return self.udp_mapped;
        }
        let Some(gateway) = &self.gateway else { return false; };
        let Some(local_ip) = local_ipv4() else { return false; };
        let ok = Self::add_udp_mapping(gateway, local_ip, quic_port, "Ember P2P QUIC").await;
        self.quic_mapped = ok;
        ok
    }

    pub async fn setup(&mut self) -> bool {
        let gateway = match igd_next::aio::tokio::search_gateway(Default::default()).await {
            Ok(gw) => {
                info!("UPnP gateway found: {}", gw.addr);
                gw
            }
            Err(e) => {
                warn!("UPnP gateway discovery failed: {e}");
                return false;
            }
        };

        let local_ip = match local_ipv4() {
            Some(ip) => ip,
            None => {
                warn!("Could not determine local IPv4 address for UPnP");
                return false;
            }
        };

        let (tcp_ok, udp_ok) = Self::map_ports_inner(&gateway, local_ip, self.tcp_port, self.udp_port).await;
        self.tcp_mapped = tcp_ok;
        self.udp_mapped = udp_ok;
        self.gateway = Some(gateway);
        tcp_ok || udp_ok
    }

    /// Re-add port mappings before the 1-hour lease expires.
    pub async fn renew(&mut self) -> bool {
        let gateway = match &self.gateway {
            Some(gw) => gw,
            None => return false,
        };
        let local_ip = match local_ipv4() {
            Some(ip) => ip,
            None => return false,
        };
        let (tcp_ok, udp_ok) = Self::map_ports_inner(gateway, local_ip, self.tcp_port, self.udp_port).await;
        self.tcp_mapped = tcp_ok;
        self.udp_mapped = udp_ok;
        // Refresh the QUIC mapping too (if known and distinct from KAD UDP).
        if let Some(qp) = self.quic_port {
            self.quic_mapped = if qp == self.udp_port {
                udp_ok
            } else {
                Self::add_udp_mapping(gateway, local_ip, qp, "Ember P2P QUIC").await
            };
        }
        tcp_ok || udp_ok || self.quic_mapped
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
    }

    pub fn is_mapped(&self) -> bool {
        self.tcp_mapped || self.udp_mapped
    }

    pub fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }
}

fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(v4) => Some(*v4.ip()),
        _ => None,
    }
}
