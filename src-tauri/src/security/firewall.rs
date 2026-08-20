use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{debug, info, warn};

use crate::security::filesystem::windows_system_path;

const RULE_NAME_TCP: &str = "Ember P2P (TCP)";
const RULE_NAME_UDP: &str = "Ember P2P (UDP)";
/// QUIC binds its own UDP socket, usually on `tcp_port` — a different
/// number from the KAD UDP port this module already opens. Without a
/// dedicated inbound UDP allow, Windows drops unsolicited QUIC Initial
/// packets: hole-punch accepts, relay-target connects, and `relay_for_peers`
/// all fail even when UPnP forwarded the port and TCP HighID is fine.
const RULE_NAME_QUIC_UDP: &str = "Ember P2P (QUIC UDP)";

/// Spawned by absolute path, never by bare name — see
/// [`windows_system_path`] for the planted-binary hijack this avoids.
const NETSH: &str = r"System32\netsh.exe";
const POWERSHELL: &str = r"System32\WindowsPowerShell\v1.0\powershell.exe";

/// Outcome of a single `add_firewall_rule` attempt — lets the
/// orchestrator decide how to summarise N failures at the end (one
/// "needs elevation" line is much friendlier than two raw netsh
/// stderr dumps every single startup). The full error text is logged
/// at the failure site (warn / debug); the enum only needs to carry
/// the *category* so the caller can group like-failures.
#[derive(Debug)]
enum AddRuleOutcome {
    Added,
    NeedsElevation,
    Other,
}

fn firewall_rule_exists(rule_name: &str) -> bool {
    Command::new(windows_system_path(NETSH))
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={rule_name}"),
        ])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn firewall_rule_has_port(rule_name: &str, port: u16) -> bool {
    // PowerShell exposes stable object properties regardless of the Windows
    // display language, unlike netsh's localized column labels.
    let escaped_name = rule_name.replace('\'', "''");
    let script = format!(
        "Get-NetFirewallRule -DisplayName '{escaped_name}' -ErrorAction Stop | \
         Get-NetFirewallPortFilter | ForEach-Object {{ $_.LocalPort }}"
    );
    if let Ok(output) = Command::new(windows_system_path(POWERSHELL))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x08000000)
        .output()
    {
        if output.status.success() {
            let expected = port.to_string();
            return String::from_utf8_lossy(&output.stdout)
                .split(|c: char| c.is_whitespace() || c == ',')
                .any(|value| value.trim() == expected);
        }
    }

    // Fallback for stripped-down Windows environments without the firewall
    // PowerShell module. Keep the legacy English parser rather than treating
    // every rule as stale.
    let output = Command::new(windows_system_path(NETSH))
        .args([
            "advfirewall",
            "firewall",
            "show",
            "rule",
            &format!("name={rule_name}"),
        ])
        .creation_flags(0x08000000)
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let port_str = port.to_string();
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some((_key, value)) = trimmed.split_once(':') {
                    let value = value.trim();
                    if value == port_str {
                        let key_lower = _key.trim().to_lowercase();
                        if key_lower.contains("localport") || key_lower.contains("local port") {
                            return true;
                        }
                    }
                }
            }
            false
        }
        _ => false,
    }
}

fn delete_firewall_rule(rule_name: &str) {
    let _ = Command::new(windows_system_path(NETSH))
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
        ])
        .creation_flags(0x08000000)
        .output();
}

fn add_firewall_rule(rule_name: &str, protocol: &str, port: u16) -> AddRuleOutcome {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string().replace('"', ""),
        Err(e) => {
            warn!("Cannot determine exe path, skipping firewall rule to avoid overly permissive rule: {e}");
            return AddRuleOutcome::Other;
        }
    };
    let args = vec![
        "advfirewall".to_string(),
        "firewall".to_string(),
        "add".to_string(),
        "rule".to_string(),
        format!("name={rule_name}"),
        "dir=in".to_string(),
        "action=allow".to_string(),
        format!("protocol={protocol}"),
        format!("localport={port}"),
        "enable=yes".to_string(),
        "profile=any".to_string(),
        format!("program={exe_path}"),
    ];
    let result = Command::new(windows_system_path(NETSH))
        .args(&args)
        .creation_flags(0x08000000)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            info!("Added Windows Firewall rule: {rule_name} ({protocol}/{port})");
            AddRuleOutcome::Added
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            // netsh's elevation error message is locale-dependent —
            // English: "The requested operation requires elevation",
            // German: "Der angeforderte Vorgang erfordert eine Erhöhung",
            // etc. Match on the substring that's stable across locales
            // when possible, and fall back to the English phrase. The
            // alternative — checking a Windows error code via the
            // process exit status — isn't surfaced reliably by netsh.
            let combined = format!("{} {}", stdout, stderr).to_lowercase();
            let needs_elevation = combined.contains("elevation")
                || combined.contains("erhöhung")
                || combined.contains("élévation")
                || combined.contains("elevación");
            if needs_elevation {
                debug!(
                    "Firewall rule {rule_name} needs elevation: {} {}",
                    stdout.trim(),
                    stderr.trim()
                );
                AddRuleOutcome::NeedsElevation
            } else {
                let detail = format!("{} {}", stdout.trim(), stderr.trim())
                    .trim()
                    .to_string();
                warn!("Failed to add firewall rule {rule_name}: {detail}");
                AddRuleOutcome::Other
            }
        }
        Err(e) => {
            warn!("Could not run netsh to add firewall rule: {e}");
            AddRuleOutcome::Other
        }
    }
}

/// Remove stale firewall rules whose port no longer matches, then ensure
/// inbound TCP, KAD UDP, and (when it is a distinct port) QUIC UDP rules
/// exist for the configured ports.
///
/// QUIC typically binds UDP on `tcp_port`. Opening that here at startup
/// covers the common case before the endpoint exists; [`ensure_quic_udp_firewall_rule`]
/// updates the rule if bind later falls back to a neighbour port.
///
/// When the user is *not* running elevated and the rules don't yet
/// exist, we used to emit two raw `netsh` stderr dumps every single
/// startup. Now we collapse both into a single actionable message so
/// the user knows what to do without thinking they have a bug.
pub fn ensure_firewall_rules(tcp_port: u16, udp_port: u16) {
    let mut elevation_failures: Vec<&'static str> = Vec::new();

    let tcp_outcome = ensure_one_rule(RULE_NAME_TCP, "TCP", tcp_port);
    if matches!(tcp_outcome, Some(AddRuleOutcome::NeedsElevation)) {
        elevation_failures.push("TCP");
    }

    let udp_outcome = ensure_one_rule(RULE_NAME_UDP, "UDP", udp_port);
    if matches!(udp_outcome, Some(AddRuleOutcome::NeedsElevation)) {
        elevation_failures.push("UDP");
    }

    if dedicated_quic_udp_port(tcp_port, udp_port).is_some() {
        let quic_outcome = ensure_one_rule(RULE_NAME_QUIC_UDP, "UDP", tcp_port);
        if matches!(quic_outcome, Some(AddRuleOutcome::NeedsElevation)) {
            elevation_failures.push("QUIC");
        }
    }

    // Single consolidated WARN: same information density as the old
    // "Run as administrator" line, but emitted *once* and naming both
    // protocols. Detail-per-rule lives at debug level for support.
    if !elevation_failures.is_empty() {
        let protos = elevation_failures.join("/");
        warn!(
            "Windows Firewall rules for Ember P2P ({protos}) could not be added: \
             elevation required. Inbound peer connections may be blocked until \
             you run Ember once as Administrator (one-time setup) — afterwards \
             this warning will go away.",
        );
    }
}

/// After the QUIC endpoint binds, open inbound UDP on the *actual* port.
///
/// No-op when that port is already the KAD UDP port (covered by
/// [`RULE_NAME_UDP`]) or when it matches `tcp_port` already opened by
/// [`ensure_firewall_rules`]. Recreates [`RULE_NAME_QUIC_UDP`] if bind
/// landed on a fallback neighbour (`tcp_port+1..=+4`).
pub fn ensure_quic_udp_firewall_rule(quic_udp_port: u16, kad_udp_port: u16) {
    let Some(port) = dedicated_quic_udp_port(quic_udp_port, kad_udp_port) else {
        return;
    };
    if matches!(
        ensure_one_rule(RULE_NAME_QUIC_UDP, "UDP", port),
        Some(AddRuleOutcome::NeedsElevation)
    ) {
        warn!(
            "Windows Firewall rule for Ember P2P (QUIC UDP/{port}) could not be added: \
             elevation required. Inbound hole-punch and peer-relay may be blocked until \
             you run Ember once as Administrator.",
        );
    }
}

/// Dedicated QUIC UDP allow-rule is needed when QUIC is not sharing the
/// KAD UDP port (and is actually bound).
fn dedicated_quic_udp_port(quic_udp_port: u16, kad_udp_port: u16) -> Option<u16> {
    (quic_udp_port != 0 && quic_udp_port != kad_udp_port).then_some(quic_udp_port)
}

/// Returns `Some(outcome)` when `add_firewall_rule` actually ran (rule
/// missing or stale), `None` when no action was needed (rule already
/// up to date). Lets the caller distinguish "tried and failed" from
/// "didn't need to try" for the single-line consolidated warning above.
fn ensure_one_rule(rule_name: &str, protocol: &str, port: u16) -> Option<AddRuleOutcome> {
    if firewall_rule_exists(rule_name) {
        if firewall_rule_has_port(rule_name, port) {
            debug!("Windows Firewall {protocol} rule already exists with correct port {port}");
            return None;
        }
        info!("{protocol} firewall rule has stale port, recreating for port {port}");
        delete_firewall_rule(rule_name);
    }
    Some(add_firewall_rule(rule_name, protocol, port))
}

#[cfg(test)]
mod tests {
    use super::dedicated_quic_udp_port;

    #[test]
    fn dedicated_quic_rule_skipped_when_sharing_kad_udp_port() {
        assert_eq!(dedicated_quic_udp_port(4672, 4672), None);
        assert_eq!(dedicated_quic_udp_port(0, 4672), None);
    }

    #[test]
    fn dedicated_quic_rule_needed_on_tcp_port_or_fallback() {
        assert_eq!(dedicated_quic_udp_port(4662, 4672), Some(4662));
        assert_eq!(dedicated_quic_udp_port(4663, 4672), Some(4663));
    }
}
