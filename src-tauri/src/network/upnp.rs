use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tracing::{info, warn};

pub struct UpnpMappings {
    gateway: Option<igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>>,
    tcp_port: u16,
    udp_port: u16,
    mapped: bool,
}

impl UpnpMappings {
    pub fn new(tcp_port: u16, udp_port: u16) -> Self {
        UpnpMappings {
            gateway: None,
            tcp_port,
            udp_port,
            mapped: false,
        }
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

        let tcp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, self.tcp_port));
        let udp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, self.udp_port));

        let mut success = true;

        match gateway
            .add_port(
                igd_next::PortMappingProtocol::TCP,
                self.tcp_port,
                tcp_local,
                3600,
                "Nexus P2P TCP",
            )
            .await
        {
            Ok(()) => info!("UPnP: mapped TCP port {}", self.tcp_port),
            Err(e) => {
                warn!("UPnP: failed to map TCP port {}: {e}", self.tcp_port);
                success = false;
            }
        }

        match gateway
            .add_port(
                igd_next::PortMappingProtocol::UDP,
                self.udp_port,
                udp_local,
                3600,
                "Nexus P2P UDP",
            )
            .await
        {
            Ok(()) => info!("UPnP: mapped UDP port {}", self.udp_port),
            Err(e) => {
                warn!("UPnP: failed to map UDP port {}: {e}", self.udp_port);
                success = false;
            }
        }

        self.gateway = Some(gateway);
        self.mapped = success;
        success
    }

    pub async fn renew(&mut self) -> bool {
        if !self.mapped {
            return false;
        }
        let Some(ref gateway) = self.gateway else {
            return false;
        };

        let local_ip = match local_ipv4() {
            Some(ip) => ip,
            None => return false,
        };

        let tcp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, self.tcp_port));
        let udp_local = SocketAddr::V4(SocketAddrV4::new(local_ip, self.udp_port));

        let mut ok = true;
        if let Err(e) = gateway
            .add_port(
                igd_next::PortMappingProtocol::TCP,
                self.tcp_port,
                tcp_local,
                3600,
                "Nexus P2P TCP",
            )
            .await
        {
            warn!("UPnP: TCP renewal failed: {e}");
            ok = false;
        }
        if let Err(e) = gateway
            .add_port(
                igd_next::PortMappingProtocol::UDP,
                self.udp_port,
                udp_local,
                3600,
                "Nexus P2P UDP",
            )
            .await
        {
            warn!("UPnP: UDP renewal failed: {e}");
            ok = false;
        }
        if ok {
            info!("UPnP: renewed port mappings");
        }
        ok
    }

    pub async fn teardown(&mut self) {
        if let Some(ref gateway) = self.gateway {
            if self.mapped {
                let _ = gateway
                    .remove_port(igd_next::PortMappingProtocol::TCP, self.tcp_port)
                    .await;
                let _ = gateway
                    .remove_port(igd_next::PortMappingProtocol::UDP, self.udp_port)
                    .await;
                info!("UPnP: removed port mappings");
            }
        }
        self.mapped = false;
    }

    pub fn is_mapped(&self) -> bool {
        self.mapped
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
