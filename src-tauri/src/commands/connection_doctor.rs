//! The connection doctor: what works, what does not, what Ember already does
//! about it, and the one thing worth trying next.
//!
//! Almost everything here is a reading of state the network loop already
//! holds — the Kad firewall checks, the eD2K server's ID, UPnP, the STUN NAT
//! class, the Ember DHT — put into plain words by [`assess`]. The one check of
//! its own is the outside-in probe: the rendezvous server dials our TCP port
//! and sends a UDP datagram to our Kad port (`/v4/reachability`), which answers
//! in seconds where the Kad checks need other peers. Without that endpoint the
//! doctor still finishes, from the rest.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, coded, coded_ctx};
use crate::network::NetworkCommand;
use crate::types::NetworkStats;

/// A clock this far from the rendezvous server's breaks signed records and
/// session timestamps; less is ordinary drift.
const CLOCK_SKEW_WARN_SECS: i64 = 300;
/// How long the UDP probe may take to arrive after the server says it sent it.
const UDP_PROBE_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

/// The one-line answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Peers can reach us directly.
    Reachable,
    /// eMule users reach us; Kad and Ember connections go through a buddy or
    /// relays, which works, a little slower to start.
    Relayed,
    /// eMule users who are themselves firewalled cannot download from us,
    /// and we reach fewer sources. Ember's relays still carry friends and rooms.
    Limited,
    /// Not connected to anything.
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

/// One line of the report. `id` names the check for the translated label;
/// `detail` names the outcome for the translated explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub status: CheckStatus,
    pub detail: &'static str,
}

/// A fix the doctor suggests, most likely first. `action` is set for the ones
/// it can do itself, after the user confirms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Fix {
    pub id: &'static str,
    pub action: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionReport {
    pub verdict: Verdict,
    pub checks: Vec<Check>,
    /// What Ember is already doing about it: `relay`, `buddy`, `punch`.
    pub helping: Vec<&'static str>,
    pub fixes: Vec<Fix>,
    pub tcp_port: u16,
    pub udp_port: u16,
    /// This computer's address on the local network, for port-forwarding
    /// steps; empty when it could not be read.
    pub lan_ip: String,
    /// The address peers see, as far as anyone told us.
    pub public_ip: String,
    /// Whether the outside-in probe ran.
    pub probed: bool,
}

/// What the outside-in probe found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpProbe {
    Open,
    Closed,
    Timeout,
}

/// Everything [`assess`] judges from, gathered by [`gather`].
#[derive(Debug, Clone, Default)]
pub struct Signals {
    pub kad_connected: bool,
    pub server_connected: bool,
    pub dht_contacts: u32,
    pub tcp_listen_failed: bool,
    /// The configured UDP port and the one bound, when they differ.
    pub udp_port_moved: bool,
    /// Windows only: whether the inbound rules are in place.
    pub firewall_rules: Option<bool>,
    pub upnp_enabled: bool,
    pub upnp_mapped: bool,
    pub upnp_stood_down: bool,
    /// The router's own WAN address is private or carrier-grade.
    pub router_behind_nat: bool,
    /// The router told us its WAN address.
    pub router_wan_known: bool,
    pub kad_tcp: Option<bool>,
    pub kad_udp: Option<bool>,
    pub low_id: Option<bool>,
    pub nat_symmetric: bool,
    pub nat_known: bool,
    pub buddy_connected: bool,
    pub probe_tcp: Option<TcpProbe>,
    pub probe_udp: Option<bool>,
    /// The server would have probed, but this address had used its checks
    /// for the hour.
    pub probe_rate_limited: bool,
    pub clock_skew_secs: Option<i64>,
    /// Saved ports or UPnP differ from what this session runs on, so a fix
    /// for them only takes effect at a restart.
    pub restart_pending: bool,
}

impl Signals {
    /// Whatever answers on our TCP port when Ember could not open it is
    /// another program, often eMule itself, so nothing then says it is open.
    fn tcp_open(&self) -> bool {
        !self.tcp_listen_failed
            && (self.probe_tcp == Some(TcpProbe::Open) || self.kad_tcp == Some(true) || self.low_id == Some(false))
    }

    fn udp_open(&self) -> bool {
        self.probe_udp == Some(true) || self.kad_udp == Some(true)
    }

    fn online(&self) -> bool {
        self.kad_connected || self.server_connected || self.dht_contacts > 0
    }
}

/// The verdict, the checks and the ranked fixes, from `s`. Pure, so every
/// combination the doctor can meet is under test.
pub fn assess(s: &Signals) -> (Verdict, Vec<Check>, Vec<&'static str>, Vec<Fix>) {
    use CheckStatus::*;
    let tcp_open = s.tcp_open();
    let udp_open = s.udp_open();
    let verdict = if !s.online() {
        Verdict::Offline
    } else if tcp_open && udp_open {
        Verdict::Reachable
    } else if tcp_open {
        Verdict::Relayed
    } else {
        Verdict::Limited
    };

    let mut checks = Vec::new();
    let mut check = |id, status, detail| checks.push(Check { id, status, detail });
    check(
        "listen_ports",
        if s.tcp_listen_failed { Fail } else if s.udp_port_moved { Warn } else { Pass },
        if s.tcp_listen_failed { "tcp_taken" } else if s.udp_port_moved { "udp_moved" } else { "ok" },
    );
    match s.firewall_rules {
        Some(true) => check("windows_firewall", Pass, "ok"),
        Some(false) => check("windows_firewall", Fail, "missing"),
        None => check("windows_firewall", Skip, "not_windows"),
    }
    if !s.upnp_enabled {
        check("upnp", Skip, "off");
    } else if s.upnp_stood_down {
        check("upnp", Warn, "stood_down");
    } else if s.upnp_mapped {
        check("upnp", Pass, "mapped");
    } else {
        check("upnp", Fail, "not_mapped");
    }
    if s.router_behind_nat {
        check("router_wan", Fail, "carrier_nat");
    } else if s.router_wan_known {
        check("router_wan", Pass, "public");
    } else {
        check("router_wan", Skip, "unknown");
    }
    let not_run = if s.probe_rate_limited { "rate_limited" } else { "not_run" };
    match s.probe_tcp {
        Some(TcpProbe::Open) if s.tcp_listen_failed => check("outside_tcp", Warn, "another_program"),
        Some(TcpProbe::Open) => check("outside_tcp", Pass, "open"),
        Some(TcpProbe::Closed) => check("outside_tcp", Fail, "closed"),
        Some(TcpProbe::Timeout) => check("outside_tcp", Fail, "filtered"),
        None => check("outside_tcp", Skip, not_run),
    }
    match s.probe_udp {
        Some(true) => check("outside_udp", Pass, "open"),
        Some(false) => check("outside_udp", Fail, "filtered"),
        None => check("outside_udp", Skip, not_run),
    }
    match (s.kad_tcp, s.kad_udp) {
        (Some(true), Some(true)) => check("kad_firewall", Pass, "open"),
        (None, None) => check("kad_firewall", Skip, "checking"),
        (Some(false), _) | (_, Some(false)) => check("kad_firewall", Fail, "firewalled"),
        _ => check("kad_firewall", Warn, "partly"),
    }
    match s.low_id {
        Some(false) => check("server_id", Pass, "high_id"),
        Some(true) => check("server_id", Fail, "low_id"),
        None => check("server_id", Skip, "not_connected"),
    }
    if !s.nat_known {
        check("nat_type", Skip, "unknown");
    } else if s.nat_symmetric {
        check("nat_type", Warn, "symmetric");
    } else {
        check("nat_type", Pass, "ok");
    }
    check(
        "ember_dht",
        if s.dht_contacts > 0 { Pass } else { Fail },
        if s.dht_contacts > 0 { "ok" } else { "no_contacts" },
    );
    match s.clock_skew_secs {
        Some(skew) if skew.abs() > CLOCK_SKEW_WARN_SECS => check("clock", Warn, "skewed"),
        Some(_) => check("clock", Pass, "ok"),
        None => check("clock", Skip, "unknown"),
    }

    // What Ember already does when peers cannot reach us directly.
    let mut helping = Vec::new();
    if verdict != Verdict::Offline && !(tcp_open && udp_open) {
        helping.push("relay");
        if s.buddy_connected {
            helping.push("buddy");
        }
        if !s.nat_symmetric {
            helping.push("punch");
        }
    }

    // Most likely first, at most three. Port forwarding is never suggested
    // where it cannot work: behind a carrier's NAT, or behind a VPN.
    // A change already saved and waiting on a restart comes first, and the
    // port and router fixes wait for it: judged against this session, they
    // would only say again what the saved change is about to change.
    let mut fixes = Vec::new();
    if s.restart_pending {
        fixes.push(Fix { id: "restart", action: None });
    }
    if s.tcp_listen_failed && !s.restart_pending {
        fixes.push(Fix { id: "port_in_use", action: Some("move_ports") });
    }
    if s.firewall_rules == Some(false) {
        fixes.push(Fix { id: "windows_firewall", action: Some("add_firewall_rules") });
    }
    if !(tcp_open && udp_open) && verdict != Verdict::Offline && !s.restart_pending {
        if s.router_behind_nat {
            fixes.push(Fix { id: "carrier_nat", action: None });
        } else if s.upnp_stood_down {
            fixes.push(Fix { id: "vpn", action: None });
        } else if !s.upnp_enabled {
            fixes.push(Fix { id: "enable_upnp", action: Some("enable_upnp") });
        } else if !s.upnp_mapped {
            fixes.push(Fix { id: "router_upnp", action: Some("retry_upnp") });
            fixes.push(Fix { id: "forward_ports", action: None });
        } else {
            fixes.push(Fix { id: "forward_ports", action: None });
        }
    }
    if verdict == Verdict::Offline {
        fixes.push(Fix { id: "offline", action: Some("recheck") });
    }
    if s.clock_skew_secs.is_some_and(|skew| skew.abs() > CLOCK_SKEW_WARN_SECS) {
        fixes.push(Fix { id: "clock", action: None });
    }
    fixes.truncate(3);
    (verdict, checks, helping, fixes)
}

/// Whether the router's WAN address means it is itself behind another NAT:
/// private, carrier-grade (100.64/10), DS-Lite's 192.0.0.0/24, or an address
/// no public network hands out.
fn behind_another_nat(wan: Ipv4Addr) -> bool {
    let [a, b, c, _] = wan.octets();
    wan.is_private()
        || wan.is_loopback()
        || wan.is_link_local()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (18..20).contains(&b))
}

/// This computer's address on the local network: the source address the OS
/// would use to reach the internet. Nothing is sent.
fn lan_ip() -> String {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("192.0.2.1:9")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip())
        .ok()
        .filter(|ip| !ip.is_unspecified())
        .map(|ip| ip.to_string())
        .unwrap_or_default()
}

fn status_of(text: &str) -> Option<bool> {
    match text {
        "Open" => Some(true),
        "Firewalled" => Some(false),
        _ => None,
    }
}

async fn network_stats(state: &AppState) -> Result<NetworkStats, String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    state
        .network_tx
        .try_send(NetworkCommand::GetNetworkStatsSnapshot { tx })
        .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
    await_reply(rx, "doctor_failed", "Could not read the network state").await
}

/// The ports this session runs on, which a saved change only replaces at a
/// restart: `(tcp, bound udp, configured udp, upnp)`. Saved settings stand in
/// for a network loop too old to say.
fn session_ports(stats: &NetworkStats, settings: &crate::types::AppSettings) -> (u16, u16, u16, bool) {
    if stats.session_tcp_port == 0 {
        let bound = if stats.bound_udp_port != 0 { stats.bound_udp_port } else { settings.udp_port };
        return (settings.tcp_port, bound, settings.udp_port, settings.upnp_enabled);
    }
    let bound = if stats.bound_udp_port != 0 { stats.bound_udp_port } else { stats.session_udp_port };
    (stats.session_tcp_port, bound, stats.session_udp_port, stats.session_upnp_enabled)
}

/// What gathering found besides the signals.
struct Gathered {
    signals: Signals,
    stats: NetworkStats,
    /// The ports to forward and to name: the ones this computer listens on.
    tcp_port: u16,
    udp_port: u16,
    probed: bool,
}

/// Read every signal, running the outside-in probe when `probe` is set.
async fn gather(state: &AppState, probe: bool) -> Result<Gathered, String> {
    let stats = network_stats(state).await?;
    let settings = state.config.read().await.settings.clone();
    let (tcp_port, bound_udp, session_udp, upnp_enabled) = session_ports(&stats, &settings);
    // The outside sees the ports the NAT maps ours to, when STUN said.
    let probe_tcp = if stats.public_tcp_port != 0 { stats.public_tcp_port } else { tcp_port };
    let probe_udp = if stats.public_udp_port != 0 { stats.public_udp_port } else { bound_udp };
    let wan: Option<Ipv4Addr> = stats.upnp_wan_ip.parse().ok();

    #[cfg(target_os = "windows")]
    let firewall_rules = {
        let (tcp, udp) = (tcp_port, bound_udp);
        tokio::task::spawn_blocking(move || crate::security::firewall::rules_in_place(tcp, udp))
            .await
            .ok()
    };
    #[cfg(not(target_os = "windows"))]
    let firewall_rules = None;

    let mut signals = Signals {
        kad_connected: stats.status == crate::types::NetworkStatus::Connected,
        server_connected: stats.server_status == "connected",
        dht_contacts: stats.ember_dht_verified_contacts,
        tcp_listen_failed: stats.tcp_listen_failed,
        udp_port_moved: bound_udp != session_udp,
        firewall_rules,
        upnp_enabled,
        upnp_mapped: stats.upnp_mapped,
        upnp_stood_down: stats.upnp_stood_down,
        router_behind_nat: wan.is_some_and(behind_another_nat),
        router_wan_known: wan.is_some(),
        kad_tcp: status_of(&stats.tcp_status),
        kad_udp: status_of(&stats.udp_status),
        low_id: stats.ed2k_low_id,
        nat_symmetric: stats.nat_type == "Symmetric",
        nat_known: !stats.nat_type.is_empty() && stats.nat_type != "Unknown",
        // `connected:<buddy id>` once its id is known.
        buddy_connected: stats.buddy_status.starts_with("connected"),
        restart_pending: settings.tcp_port != tcp_port
            || settings.udp_port != session_udp
            || settings.upnp_enabled != upnp_enabled,
        ..Signals::default()
    };

    let mut probed = false;
    if probe {
        use crate::network::rendezvous::Reachability;
        let url = crate::commands::channels::rendezvous_url(state).await;
        let mut nonce = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        let _expecting = crate::network::reachability::expect_probe(nonce);
        match crate::network::rendezvous::request_reachability(&url, probe_tcp, probe_udp, &nonce).await {
            // Ember listens on IPv4 only: an answer about another address
            // says nothing about the ports peers reach.
            Ok(Reachability::Probed(answer)) if answer.ip.parse::<Ipv4Addr>().is_ok() => {
                probed = true;
                signals.probe_tcp = Some(match answer.tcp.as_str() {
                    "open" => TcpProbe::Open,
                    "closed" => TcpProbe::Closed,
                    _ => TcpProbe::Timeout,
                });
                if answer.udp_sent {
                    let deadline = tokio::time::Instant::now() + UDP_PROBE_WAIT;
                    let mut arrived = crate::network::reachability::probe_received(&nonce);
                    while !arrived && tokio::time::Instant::now() < deadline {
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        arrived = crate::network::reachability::probe_received(&nonce);
                    }
                    signals.probe_udp = Some(arrived);
                }
                if answer.server_time > 0 {
                    signals.clock_skew_secs = Some(chrono::Utc::now().timestamp() - answer.server_time);
                }
            }
            Ok(Reachability::RateLimited) => signals.probe_rate_limited = true,
            Ok(Reachability::Declined { server_time }) if server_time > 0 => {
                signals.clock_skew_secs = Some(chrono::Utc::now().timestamp() - server_time);
            }
            _ => {}
        }
    }
    Ok(Gathered { signals, stats, tcp_port, udp_port: bound_udp, probed })
}

/// Run every check and say what they mean.
#[tauri::command]
pub async fn run_connection_check(state: tauri::State<'_, AppState>) -> Result<ConnectionReport, String> {
    let gathered = gather(&state, true).await?;
    let (verdict, checks, helping, fixes) = assess(&gathered.signals);
    Ok(ConnectionReport {
        verdict,
        checks,
        helping,
        fixes,
        tcp_port: gathered.tcp_port,
        udp_port: gathered.udp_port,
        lan_ip: lan_ip(),
        public_ip: gathered.stats.external_ip,
        probed: gathered.probed,
    })
}

/// Do one of the fixes a report offered. `move_ports` and `enable_upnp` are
/// settings the page changes itself; these are the ones that need the backend.
#[tauri::command]
pub async fn connection_doctor_action(state: tauri::State<'_, AppState>, action: String) -> Result<bool, String> {
    match action.as_str() {
        "retry_upnp" => {
            crate::network::UPNP_RETRY_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(true)
        }
        "recheck" => {
            let (tx, rx) = tokio::sync::oneshot::channel();
            state
                .network_tx
                .try_send(NetworkCommand::RecheckFirewall { tx })
                .map_err(|e| coded_ctx("network_busy", "Network busy", e))?;
            await_reply(rx, "doctor_failed", "Could not start the checks again").await??;
            Ok(true)
        }
        #[cfg(target_os = "windows")]
        "add_firewall_rules" => {
            // The ports the check looked for: the ones this session listens on.
            let stats = network_stats(&state).await?;
            let settings = state.config.read().await.settings.clone();
            let (tcp, udp, _, _) = session_ports(&stats, &settings);
            tokio::task::spawn_blocking(move || crate::security::firewall::add_rules_elevated(tcp, udp))
                .await
                .map_err(|e| coded_ctx("doctor_failed", "Task error", e))
        }
        _ => Err(coded("doctor_unknown_action", "That fix is not available here")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable() -> Signals {
        Signals {
            kad_connected: true,
            dht_contacts: 12,
            firewall_rules: Some(true),
            upnp_enabled: true,
            upnp_mapped: true,
            router_wan_known: true,
            kad_tcp: Some(true),
            kad_udp: Some(true),
            low_id: Some(false),
            nat_known: true,
            probe_tcp: Some(TcpProbe::Open),
            probe_udp: Some(true),
            clock_skew_secs: Some(2),
            ..Signals::default()
        }
    }

    fn fix_ids(s: &Signals) -> Vec<&'static str> {
        assess(s).3.into_iter().map(|fix| fix.id).collect()
    }

    #[test]
    fn a_reachable_computer_is_told_so_and_offered_nothing() {
        let (verdict, checks, helping, fixes) = assess(&reachable());
        assert_eq!(verdict, Verdict::Reachable);
        assert!(checks.iter().all(|c| c.status == CheckStatus::Pass), "{checks:?}");
        assert!(helping.is_empty() && fixes.is_empty());
    }

    #[test]
    fn closed_udp_alone_is_relayed_and_names_what_ember_does_about_it() {
        let s = Signals { kad_udp: Some(false), probe_udp: Some(false), buddy_connected: true, ..reachable() };
        let (verdict, _, helping, _) = assess(&s);
        assert_eq!(verdict, Verdict::Relayed);
        assert_eq!(helping, vec!["relay", "buddy", "punch"]);
    }

    #[test]
    fn a_firewalled_computer_is_limited_and_gets_the_likeliest_fix_first() {
        let closed = Signals {
            kad_tcp: Some(false),
            kad_udp: Some(false),
            low_id: Some(true),
            probe_tcp: Some(TcpProbe::Timeout),
            probe_udp: Some(false),
            upnp_mapped: false,
            ..reachable()
        };
        assert_eq!(assess(&closed).0, Verdict::Limited);
        assert_eq!(fix_ids(&closed), vec!["router_upnp", "forward_ports"]);

        let no_rules = Signals { firewall_rules: Some(false), ..closed.clone() };
        assert_eq!(fix_ids(&no_rules), vec!["windows_firewall", "router_upnp", "forward_ports"]);

        let upnp_off = Signals { upnp_enabled: false, ..closed.clone() };
        assert_eq!(fix_ids(&upnp_off), vec!["enable_upnp"]);
    }

    #[test]
    fn port_forwarding_is_never_advised_where_it_cannot_work() {
        let closed = Signals {
            kad_tcp: Some(false),
            low_id: Some(true),
            probe_tcp: Some(TcpProbe::Timeout),
            ..reachable()
        };
        let cgnat = Signals { router_behind_nat: true, ..closed.clone() };
        assert_eq!(fix_ids(&cgnat), vec!["carrier_nat"]);
        let vpn = Signals { upnp_stood_down: true, ..closed };
        assert_eq!(fix_ids(&vpn), vec!["vpn"]);
    }

    /// Whatever answers on a port Ember could not open is another program,
    /// so the probe, HighID and Kad finding it open say nothing about Ember.
    #[test]
    fn a_port_another_program_holds_is_never_called_reachable() {
        let taken = Signals { tcp_listen_failed: true, ..reachable() };
        let (verdict, checks, _, fixes) = assess(&taken);
        assert_eq!(verdict, Verdict::Limited);
        assert!(checks.iter().any(|c| c.id == "outside_tcp" && c.detail == "another_program"));
        assert_eq!(fixes[0].id, "port_in_use");
    }

    /// A saved change waiting on a restart is what to do next, and the port
    /// and router fixes, judged against this session, wait for it.
    #[test]
    fn a_change_waiting_on_a_restart_comes_before_anything_it_would_change() {
        let closed = Signals {
            kad_tcp: Some(false),
            low_id: Some(true),
            probe_tcp: Some(TcpProbe::Timeout),
            upnp_enabled: false,
            restart_pending: true,
            ..reachable()
        };
        assert_eq!(fix_ids(&closed), vec!["restart"]);
        let taken = Signals { tcp_listen_failed: true, restart_pending: true, ..reachable() };
        assert_eq!(fix_ids(&taken), vec!["restart"]);
    }

    #[test]
    fn a_check_the_server_would_not_run_this_hour_says_so() {
        let s = Signals { probe_tcp: None, probe_udp: None, probe_rate_limited: true, ..reachable() };
        let (_, checks, _, _) = assess(&s);
        assert!(checks.iter().any(|c| c.id == "outside_tcp" && c.detail == "rate_limited"));
        assert!(checks.iter().any(|c| c.id == "outside_udp" && c.detail == "rate_limited"));
    }

    #[test]
    fn a_taken_port_comes_first_and_offline_is_its_own_verdict() {
        let taken = Signals { tcp_listen_failed: true, ..reachable() };
        assert_eq!(fix_ids(&taken)[0], "port_in_use");
        let offline = Signals {
            kad_connected: false,
            server_connected: false,
            dht_contacts: 0,
            ..Signals::default()
        };
        assert_eq!(assess(&offline).0, Verdict::Offline);
        assert_eq!(fix_ids(&offline), vec!["offline"]);
    }

    #[test]
    fn a_clock_far_off_is_reported_and_a_little_drift_is_not() {
        let off = Signals { clock_skew_secs: Some(-900), ..reachable() };
        assert_eq!(fix_ids(&off), vec!["clock"]);
        let drift = Signals { clock_skew_secs: Some(40), ..reachable() };
        assert!(fix_ids(&drift).is_empty());
    }

    #[test]
    fn without_the_probe_the_kad_and_server_results_decide() {
        let s = Signals { probe_tcp: None, probe_udp: None, ..reachable() };
        let (verdict, checks, _, _) = assess(&s);
        assert_eq!(verdict, Verdict::Reachable);
        assert!(checks.iter().any(|c| c.id == "outside_tcp" && c.status == CheckStatus::Skip));
    }

    #[test]
    fn carrier_grade_and_private_wan_addresses_are_told_apart_from_public_ones() {
        assert!(behind_another_nat("100.64.1.2".parse().unwrap()));
        assert!(behind_another_nat("100.127.255.1".parse().unwrap()));
        assert!(behind_another_nat("192.168.0.2".parse().unwrap()));
        assert!(behind_another_nat("10.1.2.3".parse().unwrap()));
        assert!(behind_another_nat("192.0.0.2".parse().unwrap()), "DS-Lite");
        assert!(behind_another_nat("0.0.0.0".parse().unwrap()));
        assert!(behind_another_nat("198.18.0.1".parse().unwrap()));
        assert!(!behind_another_nat("100.128.0.1".parse().unwrap()));
        assert!(!behind_another_nat("203.0.113.5".parse().unwrap()));
        assert!(!behind_another_nat("192.0.2.1".parse().unwrap()));
    }

    /// What the doctor judges is what this session runs on; saved settings
    /// stand in only for a loop too old to say.
    #[test]
    fn the_ports_judged_are_the_ones_this_session_listens_on() {
        let settings = crate::types::AppSettings { tcp_port: 5000, udp_port: 5010, upnp_enabled: true, ..Default::default() };
        let running = NetworkStats {
            session_tcp_port: 4662,
            session_udp_port: 4672,
            bound_udp_port: 4673,
            session_upnp_enabled: false,
            ..Default::default()
        };
        assert_eq!(session_ports(&running, &settings), (4662, 4673, 4672, false));
        let old_loop = NetworkStats { bound_udp_port: 5011, ..Default::default() };
        assert_eq!(session_ports(&old_loop, &settings), (5000, 5011, 5010, true));
    }
}
