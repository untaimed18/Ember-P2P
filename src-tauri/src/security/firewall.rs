use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{info, warn};

const RULE_NAME_TCP: &str = "Ember P2P (TCP)";
const RULE_NAME_UDP: &str = "Ember P2P (UDP)";

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

fn add_firewall_rule(rule_name: &str, protocol: &str, port: u16) -> bool {
    let exe_path = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(e) => {
            warn!("Cannot determine exe path, skipping firewall rule to avoid overly permissive rule: {e}");
            return false;
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
    if firewall_rule_exists(RULE_NAME_TCP) {
        if !firewall_rule_has_port(RULE_NAME_TCP, tcp_port) {
            info!("TCP firewall rule has stale port, recreating for port {tcp_port}");
            delete_firewall_rule(RULE_NAME_TCP);
            add_firewall_rule(RULE_NAME_TCP, "TCP", tcp_port);
        } else {
            info!("Windows Firewall TCP rule already exists with correct port");
        }
    } else {
        add_firewall_rule(RULE_NAME_TCP, "TCP", tcp_port);
    }

    if firewall_rule_exists(RULE_NAME_UDP) {
        if !firewall_rule_has_port(RULE_NAME_UDP, udp_port) {
            info!("UDP firewall rule has stale port, recreating for port {udp_port}");
            delete_firewall_rule(RULE_NAME_UDP);
            add_firewall_rule(RULE_NAME_UDP, "UDP", udp_port);
        } else {
            info!("Windows Firewall UDP rule already exists with correct port");
        }
    } else {
        add_firewall_rule(RULE_NAME_UDP, "UDP", udp_port);
    }
}
