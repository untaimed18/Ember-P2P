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
/// Consecutive maintenance passes (10 min apart) that must find the router's
/// WAN address disagreeing with the address peers see before the forwards are
/// removed. One pass could be catching an address change half-way through.
const STAND_DOWN_AFTER_PASSES: u32 = 2;

/// Whether a forward on a router whose WAN address is `wan_ip` can carry
/// traffic to us, given the address peers see us at.
///
/// Only a *public* WAN address that disagrees with what peers see is a "no":
/// our traffic leaves through something else, a VPN tunnel most often, so
/// nobody dials the router's address. A private or carrier-grade WAN address
/// is not enough on its own, because an outer router forwarding to this one
/// (a DMZ or port forward on the ISP's modem) does deliver through the inner
/// mapping. Not knowing the address peers see is not evidence either way, and
/// neither is a private one: a server on the LAN reports that as our HighID.
fn forward_reaches_us(wan_ip: Ipv4Addr, seen_ip: Option<Ipv4Addr>) -> bool {
    match seen_ip {
        Some(seen)
            if !crate::security::is_special_use_v4(wan_ip)
                && !crate::security::is_special_use_v4(seen) =>
        {
            seen == wan_ip
        }
        _ => true,
    }
}

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
    /// The gateway's own WAN address, read whenever TCP or UDP mapped.
    external_ip: Option<Ipv4Addr>,
    /// Mappings removed because they could not carry traffic (see
    /// [`forward_reaches_us`]). Nothing is mapped or renewed while set; each
    /// maintenance pass re-reads the WAN address and maps again once it is the
    /// one peers see.
    stood_down: bool,
    /// Consecutive passes that found the WAN address disagreeing with the
    /// address peers see; [`STAND_DOWN_AFTER_PASSES`] of them stand down.
    wan_disagreements: u32,
}

/// The gateway's WAN address while it forwards every Ember port, else zero.
static FORWARDED_EXTERNAL_IP: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// The router's WAN address while it forwards every port Ember listens on.
/// When that is also the address peers see us at, nothing else sits between
/// us and the internet and there is no NAT mapping to keep alive.
pub fn forwarded_external_ip() -> Option<Ipv4Addr> {
    match FORWARDED_EXTERNAL_IP.load(std::sync::atomic::Ordering::Relaxed) {
        0 => None,
        bits => Some(Ipv4Addr::from(bits)),
    }
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
            external_ip: None,
            stood_down: false,
            wan_disagreements: 0,
        }
    }

    fn publish_forwarding(&self) {
        let quic_covered = self.quic_port.is_none() || self.quic_mapped;
        let bits = match self.external_ip {
            Some(ip) if self.tcp_mapped && self.udp_mapped && quic_covered => u32::from(ip),
            _ => 0,
        };
        FORWARDED_EXTERNAL_IP.store(bits, std::sync::atomic::Ordering::Relaxed);
    }

    /// The gateway's WAN address under [`SOAP_TIMEOUT`]; `None` on any failure.
    async fn read_wan_ip(gateway: &Gw) -> Option<Ipv4Addr> {
        match tokio::time::timeout(SOAP_TIMEOUT, gateway.get_external_ip()).await {
            Ok(Ok(std::net::IpAddr::V4(ip))) => Some(ip),
            _ => None,
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
                self.publish_forwarding();
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
            let external_ip = if tcp_ok || udp_ok {
                Self::read_wan_ip(gateway).await
            } else {
                None
            };
            self.external_ip = external_ip;
            (tcp_ok, udp_ok, quic_ok)
        };
        if self.tcp_mapped != tcp_ok || self.udp_mapped != udp_ok || self.quic_mapped != quic_ok {
            self.revision = self.revision.saturating_add(1);
        }
        self.tcp_mapped = tcp_ok;
        self.udp_mapped = udp_ok;
        self.quic_mapped = quic_ok;
        self.publish_forwarding();
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
            self.publish_forwarding();
            return self.udp_mapped;
        }
        if self.stood_down {
            return false;
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
        self.publish_forwarding();
        ok
    }

    /// Record the QUIC UDP port without mapping it, so the next [`Self::maintain`]
    /// maps it: a new port makes the renewal due at once rather than a lease
    /// period later.
    ///
    /// Deliberately not a revision change. The endpoint binds while a startup
    /// or maintenance pass may still be running, and a bump would discard that
    /// pass's result, gateway discovery and all; [`Self::adopt`] carries the
    /// port into it instead.
    pub fn record_quic_port(&mut self, quic_port: u16) {
        if self.quic_port == Some(quic_port) {
            return;
        }
        self.quic_port = Some(quic_port);
        if quic_port == self.udp_port {
            self.quic_mapped = self.udp_mapped;
        } else {
            self.quic_mapped = false;
            self.last_map_attempt = None;
        }
        self.publish_forwarding();
    }

    /// Take the mappings a finished pass produced, keeping a QUIC port recorded
    /// after the pass cloned these.
    pub fn adopt(&mut self, mut finished: UpnpMappings) {
        if let Some(port) = self.quic_port {
            finished.record_quic_port(port);
        }
        *self = finished;
    }

    /// Discover the gateway and add all known mappings. Returns true when at
    /// least the TCP or KAD UDP mapping succeeded. On discovery failure the
    /// retry backoff is advanced; `maintain` retries when it elapses.
    pub async fn setup(&mut self) -> bool {
        if !self.discover().await || self.stood_down {
            return false;
        }
        self.map_all().await
    }

    /// Find the gateway and cache it. On failure the retry backoff advances.
    async fn discover(&mut self) -> bool {
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
        true
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
    ///   (router reboot / control-URL change), drop it and re-discover;
    /// - the router's WAN address is not the one peers see (`seen_ip`): remove
    ///   the mappings, which cannot carry traffic, and map again once it is.
    ///
    /// Returns whether the TCP or KAD UDP mapping is currently in place.
    pub async fn maintain(&mut self, seen_ip: Option<Ipv4Addr>) -> bool {
        if self.gateway.is_none() {
            if self.next_discovery_at.is_some_and(|t| Instant::now() < t) {
                return false;
            }
            if !self.stood_down {
                self.setup().await;
                return self.is_mapped();
            }
            if !self.discover().await {
                return false;
            }
        }
        if self.stood_down {
            if self.wan_now_reaches_us(seen_ip).await != Some(true) {
                return false;
            }
            info!("UPnP: the router's WAN address is the one peers see again; restoring port forwarding");
            self.stood_down = false;
            self.last_map_attempt = None;
            self.revision = self.revision.saturating_add(1);
        } else if self.note_wan_disagreement(seen_ip) {
            let cached_wan = self.external_ip;
            match self.wan_now_reaches_us(seen_ip).await {
                // Confirmed by a fresh read of an address that has not just
                // moved. One that moved is the router reconnecting, and the
                // address peers see may simply not have caught up yet.
                Some(false) if self.external_ip == cached_wan => {
                    self.stand_down(seen_ip).await;
                    return false;
                }
                Some(false) => self.wan_disagreements = 0,
                Some(true) | None => {}
            }
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

    /// Count this pass towards standing down: true once the cached WAN address
    /// has disagreed with `seen_ip` for [`STAND_DOWN_AFTER_PASSES`] in a row.
    fn note_wan_disagreement(&mut self, seen_ip: Option<Ipv4Addr>) -> bool {
        let disagrees = self.is_mapped()
            && self
                .external_ip
                .is_some_and(|wan| !forward_reaches_us(wan, seen_ip));
        self.wan_disagreements = if disagrees {
            self.wan_disagreements.saturating_add(1)
        } else {
            0
        };
        self.wan_disagreements >= STAND_DOWN_AFTER_PASSES
    }

    /// Re-read the WAN address and judge it against `seen_ip`; `None` when the
    /// gateway did not say, which is no verdict either way. The cached address
    /// can be up to a lease old, and a router that reconnected since may have
    /// the one peers now see. A stood-down gateway that does not answer is
    /// dropped, so the next pass re-discovers it rather than asking a stale one
    /// forever.
    async fn wan_now_reaches_us(&mut self, seen_ip: Option<Ipv4Addr>) -> Option<bool> {
        let gateway = self.gateway.as_ref()?;
        match Self::read_wan_ip(gateway).await {
            Some(wan) => {
                self.external_ip = Some(wan);
                let reaches = forward_reaches_us(wan, seen_ip);
                if reaches {
                    self.wan_disagreements = 0;
                }
                self.publish_forwarding();
                Some(reaches)
            }
            None => {
                debug!("UPnP: gateway did not report its WAN address");
                if self.stood_down {
                    self.gateway = None;
                }
                None
            }
        }
    }

    /// Remove the mappings and stop renewing them, keeping the gateway so a
    /// later pass can check whether they would work again.
    async fn stand_down(&mut self, seen_ip: Option<Ipv4Addr>) {
        info!(
            "UPnP: the router's WAN address {:?} is not the address peers see ({:?}); removing port forwarding, which cannot reach this computer",
            self.external_ip, seen_ip
        );
        self.remove_owned_mappings().await;
        self.tcp_mapped = false;
        self.udp_mapped = false;
        self.quic_mapped = false;
        self.stood_down = true;
        self.wan_disagreements = 0;
        self.revision = self.revision.saturating_add(1);
        self.publish_forwarding();
    }

    pub async fn teardown(&mut self) {
        self.remove_owned_mappings().await;
        self.gateway = None;
        self.tcp_mapped = false;
        self.udp_mapped = false;
        self.quic_mapped = false;
        self.external_ip = None;
        self.last_map_attempt = None;
        self.next_discovery_at = None;
        self.stood_down = false;
        self.wan_disagreements = 0;
        self.revision = self.revision.saturating_add(1);
        self.publish_forwarding();
    }

    /// Remove each mapping we hold and can prove is still ours.
    async fn remove_owned_mappings(&self) {
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
                        let _ = tokio::time::timeout(
                            SOAP_TIMEOUT,
                            gateway.remove_port(igd_next::PortMappingProtocol::TCP, self.tcp_port),
                        )
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
                        let _ = tokio::time::timeout(
                            SOAP_TIMEOUT,
                            gateway.remove_port(igd_next::PortMappingProtocol::UDP, self.udp_port),
                        )
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
                                let _ = tokio::time::timeout(
                                    SOAP_TIMEOUT,
                                    gateway.remove_port(igd_next::PortMappingProtocol::UDP, qp),
                                )
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

    /// Whether the mappings were removed because they could not reach us.
    /// Unlike a failure, this needs nothing from the user.
    pub fn stood_down(&self) -> bool {
        self.stood_down
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

    /// The QUIC endpoint can bind while a pass is running on a clone taken
    /// before it existed. Recording the port must leave that pass's result
    /// current, the result must keep the port, and the next maintain must map
    /// it rather than wait out the lease.
    #[test]
    fn a_quic_port_recorded_during_a_pass_survives_its_result() {
        let mut live = UpnpMappings::new(4662, 4672);
        let mut in_flight = live.clone();
        let revision = live.revision();

        live.record_quic_port(4662);
        assert_eq!(live.revision(), revision, "the running pass stays current");
        assert_eq!(live.quic_port, Some(4662));

        in_flight.tcp_mapped = true;
        in_flight.udp_mapped = true;
        in_flight.last_map_attempt = Some(Instant::now());
        in_flight.revision += 1;
        live.adopt(in_flight);
        assert!(live.tcp_mapped && live.udp_mapped, "the pass's own results are kept");
        assert_eq!(live.quic_port, Some(4662), "and so is the port it did not know");
        assert!(!live.quic_mapped);
        assert!(live.last_map_attempt.is_none(), "the next maintain maps it");
    }

    #[test]
    fn recording_the_udp_port_as_quic_needs_no_mapping_of_its_own() {
        let mut m = UpnpMappings::new(4662, 4672);
        m.udp_mapped = true;
        let attempted = Instant::now();
        m.last_map_attempt = Some(attempted);
        m.record_quic_port(4672);
        assert!(m.quic_mapped);
        assert_eq!(m.last_map_attempt, Some(attempted), "nothing new to map");
    }

    #[test]
    fn only_a_public_wan_address_peers_do_not_see_rules_a_forward_out() {
        let home = Ipv4Addr::new(81, 2, 69, 160);
        let vpn = Ipv4Addr::new(93, 184, 216, 34);
        assert!(forward_reaches_us(home, Some(home)));
        assert!(!forward_reaches_us(home, Some(vpn)), "traffic leaves through a VPN");
        assert!(forward_reaches_us(home, None), "an unknown address is no evidence");
        // An outer router can forward to this one, so these stay mapped.
        assert!(forward_reaches_us(Ipv4Addr::new(192, 168, 0, 2), Some(vpn)));
        assert!(forward_reaches_us(Ipv4Addr::new(100, 64, 3, 9), Some(vpn)));
        assert!(forward_reaches_us(Ipv4Addr::UNSPECIFIED, Some(vpn)));
        // A LAN server's HighID is a private address, not where peers see us.
        assert!(forward_reaches_us(home, Some(Ipv4Addr::new(192, 168, 1, 5))));
    }

    #[test]
    fn standing_down_takes_consecutive_disagreements_while_mapped() {
        let home = Ipv4Addr::new(81, 2, 69, 160);
        let vpn = Some(Ipv4Addr::new(93, 184, 216, 34));
        let mut m = UpnpMappings::new(4662, 4672);
        m.external_ip = Some(home);
        assert!(!m.note_wan_disagreement(vpn), "nothing mapped, nothing to remove");
        assert_eq!(m.wan_disagreements, 0);

        m.tcp_mapped = true;
        assert!(!m.note_wan_disagreement(vpn), "one pass is not enough");
        assert!(!m.note_wan_disagreement(Some(home)), "agreement resets the count");
        assert!(!m.note_wan_disagreement(vpn));
        assert!(m.note_wan_disagreement(vpn));
    }

    #[tokio::test]
    async fn a_stood_down_instance_maps_nothing_until_it_can_check_again() {
        let mut m = UpnpMappings::new(4662, 4672);
        m.stood_down = true;
        m.next_discovery_at = Some(Instant::now() + Duration::from_secs(600));
        assert!(!m.maintain(Some(Ipv4Addr::new(93, 184, 216, 34))).await);
        assert!(m.stood_down(), "still stood down without a WAN address to check");
        assert!(!m.map_quic_port(5000).await);
        assert!(!m.quic_mapped);
    }

    #[tokio::test]
    async fn teardown_clears_all_state() {
        let mut m = UpnpMappings::new(4662, 4672);
        m.tcp_mapped = true;
        m.udp_mapped = true;
        m.quic_mapped = true;
        m.quic_port = Some(5000);
        m.last_map_attempt = Some(Instant::now());
        m.stood_down = true;
        // No gateway is set, so teardown does no network I/O but must still
        // reset every flag so a later re-setup starts from a clean slate.
        m.teardown().await;
        assert!(!m.is_mapped());
        assert!(!m.quic_mapped);
        assert!(!m.has_gateway());
        assert!(m.last_map_attempt.is_none());
        assert!(m.next_discovery_at.is_none());
        assert!(!m.stood_down());
    }
}
