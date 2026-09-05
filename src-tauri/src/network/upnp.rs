use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::time::Instant;
use tracing::{debug, info};

type Gw = igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>;

/// Lease requested for each mapping. Re-added by `maintain` before expiry.
const LEASE_SECS: u32 = 3600;
/// Re-add mappings once this much of the lease has elapsed (15 min margin).
const RENEW_AFTER: Duration = Duration::from_secs(45 * 60);
/// SSDP gateway discovery timeout. Kept short because discovery runs inline
/// on the network task: at startup it gates the rest of network init, and
/// during `maintain` re-discovery it stalls the select loop while it waits.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MAPPING_ENTRIES_TO_INSPECT: u32 = 256;
const MAPPING_INSPECTION_TIMEOUT: Duration = Duration::from_secs(3);
/// Bound on a single add/remove SOAP round-trip to the gateway.
///
/// `igd_next` applies no timeout of its own, so a gateway that completes the
/// TCP connect and then never answers parks the caller forever — cheap IGD
/// stacks do this, and so does a router rebooted mid-session. The maintenance
/// pass runs detached on a timer, so a parked call is never observed: the
/// watchdog only clears the in-flight flag, and the next tick spawns another
/// one behind it. Generous, because this is a LAN round-trip and the cost of
/// giving up too early is a mapping that silently stops being renewed.
const SOAP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MappingOwnership {
    Missing,
    EmberOwned,
    Foreign,
    Unknown,
}

fn mapping_may_be_replaced(ownership: MappingOwnership) -> bool {
    ownership == MappingOwnership::EmberOwned
}

fn mapping_entry_is_ember_owned(
    entry: &igd_next::PortMappingEntry,
    protocol: igd_next::PortMappingProtocol,
    port: u16,
    local_ip: Ipv4Addr,
    label: &str,
) -> bool {
    entry.external_port == port
        && entry.protocol == protocol
        && entry.internal_port == port
        && entry
            .internal_client
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| ip == local_ip)
        && entry.port_mapping_description == label
}

async fn inspect_mapping(
    gateway: &Gw,
    protocol: igd_next::PortMappingProtocol,
    port: u16,
    local_ip: Ipv4Addr,
    label: &str,
) -> MappingOwnership {
    let inspect = async {
        for index in 0..MAX_MAPPING_ENTRIES_TO_INSPECT {
            match gateway.get_generic_port_mapping_entry(index).await {
                Ok(entry) if entry.external_port == port && entry.protocol == protocol => {
                    return if mapping_entry_is_ember_owned(&entry, protocol, port, local_ip, label)
                    {
                        MappingOwnership::EmberOwned
                    } else {
                        MappingOwnership::Foreign
                    };
                }
                Ok(_) => {}
                Err(igd_next::GetGenericPortMappingEntryError::SpecifiedArrayIndexInvalid) => {
                    return MappingOwnership::Missing;
                }
                Err(_) => return MappingOwnership::Unknown,
            }
        }
        MappingOwnership::Unknown
    };
    tokio::time::timeout(MAPPING_INSPECTION_TIMEOUT, inspect)
        .await
        .unwrap_or(MappingOwnership::Unknown)
}

#[derive(Clone)]
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
    revision: u64,
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
            revision: 0,
        }
    }

    /// `Gateway::add_port` under [`SOAP_TIMEOUT`]. `None` means it timed out.
    async fn add_port_bounded(
        gateway: &Gw,
        protocol: igd_next::PortMappingProtocol,
        port: u16,
        local: SocketAddr,
        lease: u32,
        label: &str,
    ) -> Option<Result<(), igd_next::AddPortError>> {
        tokio::time::timeout(
            SOAP_TIMEOUT,
            gateway.add_port(protocol, port, local, lease, label),
        )
        .await
        .ok()
    }

    /// Add one port mapping, working around two common router quirks:
    /// error 725 (`OnlyPermanentLeasesSupported`) gets a retry with a
    /// permanent lease, and error 718 (`PortInUse`) — which some gateways
    /// return instead of refreshing a mapping we already own — gets a
    /// delete-then-re-add.
    ///
    /// Every gateway round-trip here is bounded; see [`SOAP_TIMEOUT`].
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
        let Some(first) =
            Self::add_port_bounded(gateway, protocol, port, local, LEASE_SECS, label).await
        else {
            debug!("UPnP: gateway did not answer the {proto} port {port} ({label}) mapping request");
            return false;
        };
        match first {
            Ok(()) => {
                info!("UPnP: mapped {proto} port {port} ({label})");
                true
            }
            Err(igd_next::AddPortError::OnlyPermanentLeasesSupported) => {
                match Self::add_port_bounded(gateway, protocol, port, local, 0, label).await {
                    Some(Ok(())) => {
                        info!("UPnP: mapped {proto} port {port} ({label}) with permanent lease");
                        true
                    }
                    Some(Err(e)) => {
                        debug!("UPnP: permanent-lease retry failed for {proto} port {port} ({label}): {e}");
                        false
                    }
                    None => {
                        debug!("UPnP: permanent-lease retry timed out for {proto} port {port} ({label})");
                        false
                    }
                }
            }
            Err(igd_next::AddPortError::PortInUse) => {
                let ownership = {
                    let mut ownership =
                        inspect_mapping(gateway, protocol, port, local_ip, label).await;
                    // Some gateways flake on GenericPortMappingEntry; retry once
                    // before deciding we cannot prove ownership.
                    if ownership == MappingOwnership::Unknown {
                        ownership = inspect_mapping(gateway, protocol, port, local_ip, label).await;
                    }
                    ownership
                };
                match ownership {
                    MappingOwnership::EmberOwned if mapping_may_be_replaced(ownership) => {}
                    MappingOwnership::Foreign => {
                        info!("UPnP: refusing to replace foreign {proto} mapping on port {port}");
                        return false;
                    }
                    MappingOwnership::Missing => {
                        debug!(
                            "UPnP: port {port}/{proto} reported in use but no current owned mapping was found"
                        );
                        return false;
                    }
                    MappingOwnership::Unknown => {
                        debug!(
                            "UPnP: port {port}/{proto} is reported in use but current ownership cannot be proven"
                        );
                        return false;
                    }
                    MappingOwnership::EmberOwned => unreachable!("owned mapping is replaceable"),
                }
                match tokio::time::timeout(SOAP_TIMEOUT, gateway.remove_port(protocol, port)).await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => {
                        debug!(
                            "UPnP: failed to remove owned {proto} mapping on port {port}: {e}"
                        );
                        return false;
                    }
                    Err(_) => {
                        debug!("UPnP: removing owned {proto} mapping on port {port} timed out");
                        return false;
                    }
                }
                match Self::add_port_bounded(gateway, protocol, port, local, LEASE_SECS, label)
                    .await
                {
                    Some(Ok(())) => {
                        info!(
                            "UPnP: re-mapped {proto} port {port} ({label}) after mapping conflict"
                        );
                        true
                    }
                    Some(Err(e)) => {
                        debug!("UPnP: re-map after conflict failed for {proto} port {port} ({label}): {e}");
                        false
                    }
                    None => {
                        debug!("UPnP: re-map after conflict timed out for {proto} port {port} ({label})");
                        false
                    }
                }
            }
            Err(e) => {
                debug!("UPnP: failed to map {proto} port {port} ({label}): {e}");
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
                debug!("Could not determine local IPv4 address for UPnP");
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
        if self.tcp_mapped != tcp_ok || self.udp_mapped != udp_ok || self.quic_mapped != quic_ok {
            self.revision = self.revision.saturating_add(1);
        }
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
        if self.quic_port != Some(quic_port) {
            self.quic_port = Some(quic_port);
            self.revision = self.revision.saturating_add(1);
        }
        if quic_port == self.udp_port {
            if self.quic_mapped != self.udp_mapped {
                self.quic_mapped = self.udp_mapped;
                self.revision = self.revision.saturating_add(1);
            }
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
        if self.quic_mapped != ok {
            self.quic_mapped = ok;
            self.revision = self.revision.saturating_add(1);
        }
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
                debug!("UPnP gateway discovery failed: {e}");
                self.note_discovery_failure();
                return false;
            }
        };
        self.discovery_failures = 0;
        self.next_discovery_at = None;
        self.gateway = Some(gateway);
        self.revision = self.revision.saturating_add(1);
        self.map_all().await
    }

    fn note_discovery_failure(&mut self) {
        self.discovery_failures = self.discovery_failures.saturating_add(1);
        let mins = discovery_backoff_mins(self.discovery_failures);
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
            if self.next_discovery_at.is_some_and(|t| Instant::now() < t) {
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
            debug!("UPnP renew failed for all mappings; re-discovering gateway");
            self.gateway = None;
            self.setup().await;
        }
        self.is_mapped()
    }

    pub async fn teardown(&mut self) {
        if let Some(ref gateway) = self.gateway {
            let local_ip = local_ipv4(gateway.addr);
            if self.tcp_mapped {
                if let Some(local_ip) = local_ip {
                    if inspect_mapping(
                        gateway,
                        igd_next::PortMappingProtocol::TCP,
                        self.tcp_port,
                        local_ip,
                        "Ember P2P TCP",
                    )
                    .await
                        == MappingOwnership::EmberOwned
                    {
                        let _ = gateway
                            .remove_port(igd_next::PortMappingProtocol::TCP, self.tcp_port)
                            .await;
                    }
                }
            }
            if self.udp_mapped {
                if let Some(local_ip) = local_ip {
                    if inspect_mapping(
                        gateway,
                        igd_next::PortMappingProtocol::UDP,
                        self.udp_port,
                        local_ip,
                        "Ember P2P UDP",
                    )
                    .await
                        == MappingOwnership::EmberOwned
                    {
                        let _ = gateway
                            .remove_port(igd_next::PortMappingProtocol::UDP, self.udp_port)
                            .await;
                    }
                }
            }
            if self.quic_mapped {
                if let Some(qp) = self.quic_port {
                    if qp != self.udp_port {
                        if let Some(local_ip) = local_ip {
                            if inspect_mapping(
                                gateway,
                                igd_next::PortMappingProtocol::UDP,
                                qp,
                                local_ip,
                                "Ember P2P QUIC",
                            )
                            .await
                                == MappingOwnership::EmberOwned
                            {
                                let _ = gateway
                                    .remove_port(igd_next::PortMappingProtocol::UDP, qp)
                                    .await;
                            }
                        }
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
        self.revision = self.revision.saturating_add(1);
    }

    pub fn is_mapped(&self) -> bool {
        self.tcp_mapped || self.udp_mapped
    }

    /// Whether the *TCP* mapping specifically is live. [`Self::is_mapped`]
    /// is true when either protocol mapped, so it cannot answer "is our
    /// listener reachable from outside", which is what decides the port we
    /// advertise for connect-backs.
    pub fn tcp_mapped(&self) -> bool {
        self.tcp_mapped
    }

    /// Whether a gateway is currently cached. Lets the caller distinguish
    /// "no IGD/UPnP router found (or it's unreachable)" from "gateway found
    /// but it refused the mapping" when surfacing a failure to the user —
    /// the two cases need different remediation advice.
    pub fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }
}

/// Backoff (in minutes) before retrying gateway discovery after `failures`
/// consecutive failures. `maintain` ticks every 10 min, so the schedule is
/// expressed in multiples of that tick: 10 → 20 → 40 → 60 (capped).
fn discovery_backoff_mins(failures: u32) -> u64 {
    match failures {
        0 | 1 => 10,
        2 => 20,
        3 => 40,
        _ => 60,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_unmapped_with_no_gateway() {
        let m = UpnpMappings::new(4662, 4672);
        assert!(!m.is_mapped(), "fresh instance must not report a mapping");
        assert!(!m.has_gateway(), "fresh instance has no cached gateway");
        assert_eq!(m.quic_port, None);
    }

    #[test]
    fn is_mapped_tracks_tcp_or_udp_only() {
        let mut m = UpnpMappings::new(4662, 4672);
        // QUIC alone is not enough to count as "mapped": the dashboard /
        // firewall-clear logic keys off the TCP + KAD-UDP reachability path.
        m.quic_mapped = true;
        assert!(!m.is_mapped());
        m.tcp_mapped = true;
        assert!(m.is_mapped());
        m.tcp_mapped = false;
        m.udp_mapped = true;
        assert!(m.is_mapped());
    }

    #[test]
    fn discovery_backoff_follows_capped_schedule() {
        // 10 → 20 → 40 → 60, then held at 60 for every further failure.
        assert_eq!(discovery_backoff_mins(0), 10);
        assert_eq!(discovery_backoff_mins(1), 10);
        assert_eq!(discovery_backoff_mins(2), 20);
        assert_eq!(discovery_backoff_mins(3), 40);
        assert_eq!(discovery_backoff_mins(4), 60);
        assert_eq!(discovery_backoff_mins(100), 60);
    }

    #[test]
    fn ownership_requires_client_port_protocol_and_description() {
        let local_ip = Ipv4Addr::new(192, 168, 1, 20);
        let mut entry = igd_next::PortMappingEntry {
            remote_host: String::new(),
            external_port: 4662,
            protocol: igd_next::PortMappingProtocol::TCP,
            internal_port: 4662,
            internal_client: local_ip.to_string(),
            enabled: true,
            port_mapping_description: "Ember P2P TCP".to_string(),
            lease_duration: LEASE_SECS,
        };
        assert!(mapping_entry_is_ember_owned(
            &entry,
            igd_next::PortMappingProtocol::TCP,
            4662,
            local_ip,
            "Ember P2P TCP"
        ));
        entry.port_mapping_description = "Someone else's mapping".to_string();
        assert!(!mapping_entry_is_ember_owned(
            &entry,
            igd_next::PortMappingProtocol::TCP,
            4662,
            local_ip,
            "Ember P2P TCP"
        ));
        entry.port_mapping_description = "Ember P2P TCP".to_string();
        entry.internal_client = "192.168.1.21".to_string();
        assert!(!mapping_entry_is_ember_owned(
            &entry,
            igd_next::PortMappingProtocol::TCP,
            4662,
            local_ip,
            "Ember P2P TCP"
        ));
    }

    #[test]
    fn replacement_requires_positive_current_ownership() {
        assert!(mapping_may_be_replaced(MappingOwnership::EmberOwned));
        assert!(!mapping_may_be_replaced(MappingOwnership::Unknown));
        assert!(!mapping_may_be_replaced(MappingOwnership::Foreign));
        assert!(!mapping_may_be_replaced(MappingOwnership::Missing));
    }

    #[test]
    fn note_discovery_failure_increments_and_arms_backoff() {
        let mut m = UpnpMappings::new(4662, 4672);
        assert!(m.next_discovery_at.is_none());
        m.note_discovery_failure();
        assert_eq!(m.discovery_failures, 1);
        let first = m
            .next_discovery_at
            .expect("backoff armed after first failure");
        // A later failure schedules its retry no earlier than the first
        // (the schedule is monotonically non-decreasing).
        m.note_discovery_failure();
        assert_eq!(m.discovery_failures, 2);
        let second = m
            .next_discovery_at
            .expect("backoff armed after second failure");
        assert!(second >= first);
    }

    #[tokio::test]
    async fn map_quic_port_without_gateway_records_port_and_reports_failure() {
        let mut m = UpnpMappings::new(4662, 4672);
        // Distinct from the KAD UDP port → needs its own mapping, but no
        // gateway has been discovered yet, so it can't be mapped right now.
        assert!(!m.map_quic_port(5000).await);
        assert_eq!(
            m.quic_port,
            Some(5000),
            "port is recorded for a later maintain()"
        );
        assert!(!m.quic_mapped);
    }

    #[tokio::test]
    async fn map_quic_port_sharing_udp_port_inherits_udp_state() {
        let mut m = UpnpMappings::new(4662, 4672);
        // QUIC landed on the KAD UDP port: it's covered by that mapping, so
        // its state mirrors udp_mapped (false here — nothing mapped yet).
        assert!(!m.map_quic_port(4672).await);
        assert_eq!(m.quic_port, Some(4672));
        assert_eq!(m.quic_mapped, m.udp_mapped);

        // With the shared UDP port already mapped, QUIC is reported mapped
        // without issuing a second, redundant IGD call.
        m.udp_mapped = true;
        assert!(m.map_quic_port(4672).await);
        assert!(m.quic_mapped);
    }

    #[tokio::test]
    async fn teardown_clears_all_state() {
        let mut m = UpnpMappings::new(4662, 4672);
        m.tcp_mapped = true;
        m.udp_mapped = true;
        m.quic_mapped = true;
        m.quic_port = Some(5000);
        m.last_map_attempt = Some(Instant::now());
        // No gateway is set, so teardown does no network I/O but must still
        // reset every flag so a later re-setup starts from a clean slate.
        m.teardown().await;
        assert!(!m.is_mapped());
        assert!(!m.quic_mapped);
        assert!(!m.has_gateway());
        assert!(m.last_map_attempt.is_none());
        assert!(m.next_discovery_at.is_none());
    }
}
