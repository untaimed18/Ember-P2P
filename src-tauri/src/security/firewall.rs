use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{info, warn};

const RULE_NAME_TCP: &str = "Nexus P2P (TCP)";
const RULE_NAME_UDP: &str = "Nexus P2P (UDP)";

fn firewall_rule_exists(rule_name: &str) -> bool {
    Command::new("netsh")
        .args(["advfirewall", "firewall", "show", "rule", &format!("name={rule_name}")])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn add_firewall_rule(rule_name: &str, protocol: &str, port: u16) -> bool {
    let result = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule",
            &format!("name={rule_name}"),
            "dir=in",
            "action=allow",
            &format!("protocol={protocol}"),
            &format!("localport={port}"),
            "enable=yes",
            "profile=any",
        ])
        .creation_flags(0x08000000)
        .output();

    match result {
        Ok(output) if output.status.success() => {
            info!("Added Windows Firewall rule: {rule_name} ({protocol}/{port})");
            true
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            warn!(
                "Failed to add firewall rule {rule_name}: {} {}",
                stdout.trim(),
                stderr.trim()
            );
            false
        }
        Err(e) => {
            warn!("Could not run netsh to add firewall rule: {e}");
            false
        }
    }
}

/// Remove stale firewall rules whose port no longer matches, then ensure
/// inbound TCP and UDP rules exist for the configured ports.
pub fn ensure_firewall_rules(tcp_port: u16, udp_port: u16) {
    if !firewall_rule_exists(RULE_NAME_TCP) {
        add_firewall_rule(RULE_NAME_TCP, "TCP", tcp_port);
    } else {
        info!("Windows Firewall TCP rule already exists");
    }

    if !firewall_rule_exists(RULE_NAME_UDP) {
        add_firewall_rule(RULE_NAME_UDP, "UDP", udp_port);
    } else {
        info!("Windows Firewall UDP rule already exists");
    }
}
