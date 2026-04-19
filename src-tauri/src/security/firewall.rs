use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{debug, info, warn};

const RULE_NAME_TCP: &str = "Ember P2P (TCP)";
const RULE_NAME_UDP: &str = "Ember P2P (UDP)";

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
    Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={rule_name}")])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn firewall_rule_has_port(rule_name: &str, port: u16) -> bool {
    let output = Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={rule_name}")])
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
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &format!("name={rule_name}")])
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
        "advfirewall".to_string(), "firewall".to_string(), "add".to_string(), "rule".to_string(),
        format!("name={rule_name}"),
        "dir=in".to_string(),
        "action=allow".to_string(),
        format!("protocol={protocol}"),
        format!("localport={port}"),
        "enable=yes".to_string(),
        "profile=any".to_string(),
        format!("program=\"{exe_path}\""),
    ];
    let result = Command::new("netsh")
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
                let detail = format!("{} {}", stdout.trim(), stderr.trim()).trim().to_string();
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
/// inbound TCP and UDP rules exist for the configured ports.
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
