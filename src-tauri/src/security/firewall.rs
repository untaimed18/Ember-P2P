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

/// What the rules under one name do for this program on one port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleState {
    /// An enabled inbound allow rule opens the port for this program (or for
    /// any program).
    Opens,
    /// No rule does, and none was switched off or turned into a block: absent,
    /// or naming another port or another install's executable.
    Missing,
    /// A rule under this name was disabled or set to block. Someone chose that
    /// in Windows Firewall, so startup leaves it; the doctor still reports it.
    TurnedOff,
}

/// What the rules named `rule_name` do for `port`, or `None` when no query
/// could tell.
fn firewall_rule_state(rule_name: &str, port: u16) -> Option<RuleState> {
    // PowerShell exposes stable object properties regardless of the Windows
    // display language, unlike netsh's localized column labels. A rule that
    // does not exist is an answer, told apart by its error id from a module
    // that is missing or a query that failed, which fall through to netsh.
    let escaped_name = rule_name.replace('\'', "''");
    let script = format!(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n\
         try {{ Get-NetFirewallRule -DisplayName '{escaped_name}' -ErrorAction Stop | \
         ForEach-Object {{ $rule = $_; \
         $ports = @(($rule | Get-NetFirewallPortFilter).LocalPort) -join ','; \
         $program = [Environment]::ExpandEnvironmentVariables([string]($rule | Get-NetFirewallApplicationFilter).Program); \
         \"$($rule.Enabled)|$($rule.Action)|$($rule.Direction)|$ports|$program\" }} }} \
         catch {{ if ($_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*') {{ exit 0 }} else {{ exit 1 }} }}"
    );
    if let Ok(output) = Command::new(windows_system_path(POWERSHELL))
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .creation_flags(0x08000000)
        .output()
    {
        if output.status.success() {
            let exe = std::env::current_exe().ok();
            return Some(rule_state_from_lines(
                &String::from_utf8_lossy(&output.stdout),
                port,
                exe.as_deref(),
            ));
        }
    }

    // Fallback for stripped-down Windows environments without the firewall
    // PowerShell module. netsh fails alike for a missing rule and a failed
    // query, so a failure here is no answer. Its state, action and program
    // fields are labelled in the display language too, so this reads the
    // port alone.
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
        Ok(o) if o.status.success() => netsh_rule_has_port(&String::from_utf8_lossy(&o.stdout), port)
            .map(|opens| if opens { RuleState::Opens } else { RuleState::Missing }),
        _ => None,
    }
}

/// Whether a rule named `rule_name` lets `port` in for this program:
/// `Some(false)` when none does or no such rule exists, `None` when no query
/// could tell.
fn firewall_rule_has_port(rule_name: &str, port: u16) -> Option<bool> {
    firewall_rule_state(rule_name, port).map(|state| state == RuleState::Opens)
}

/// Read the rule query's `enabled|action|direction|ports|program` lines. A
/// program of `Any` (or none) covers every program; with no `exe` to compare,
/// the port alone decides. Outbound rules under the name are ignored.
fn rule_state_from_lines(text: &str, port: u16, exe: Option<&std::path::Path>) -> RuleState {
    let expected = port.to_string();
    let exe = exe.map(|path| program_key(&path.to_string_lossy()));
    let mut turned_off = false;
    for line in text.lines() {
        let mut fields = line.splitn(5, '|');
        let (Some(enabled), Some(action), Some(direction), Some(ports), Some(program)) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !direction.trim().eq_ignore_ascii_case("inbound") {
            continue;
        }
        let enabled = enabled.trim().eq_ignore_ascii_case("true");
        let allows = action.trim().eq_ignore_ascii_case("allow");
        if !enabled || !allows {
            turned_off = true;
            continue;
        }
        let opens = ports
            .split(|c: char| c.is_whitespace() || c == ',')
            .any(|value| value.trim() == expected);
        let program = program.trim();
        let covers = program.is_empty()
            || program.eq_ignore_ascii_case("any")
            || exe.as_ref().is_none_or(|exe| program_key(program) == *exe);
        if opens && covers {
            return RuleState::Opens;
        }
    }
    if turned_off {
        RuleState::TurnedOff
    } else {
        RuleState::Missing
    }
}

/// A program path as Windows compares it: case-insensitive, either slash,
/// with or without the `\\?\` prefix.
fn program_key(path: &str) -> String {
    let path = path.trim();
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    path.replace('/', "\\").to_lowercase()
}

/// netsh's label for a rule's local port in the display languages it is
/// known in, lowercased with the spaces taken out.
const NETSH_LOCAL_PORT_KEYS: &[&str] = &[
    "localport",
    "lokalerport",
    "portlocal",
    "puertolocal",
    "portalocale",
    "portalocal",
    "локальныйпорт",
    "本地端口",
    "本機連接埠",
];

/// Whether `netsh advfirewall firewall show rule` output lists `port` as a
/// local port of a rule. `None` when no line is labelled as a local port at
/// all: the display language is one the labels are not known in, and the
/// output says nothing either way.
fn netsh_rule_has_port(text: &str, port: u16) -> Option<bool> {
    let expected = port.to_string();
    let mut labelled = false;
    for (key, value) in text.lines().filter_map(|line| line.split_once(':')) {
        let key: String = key.to_lowercase().split_whitespace().collect();
        if !NETSH_LOCAL_PORT_KEYS.contains(&key.as_str()) {
            continue;
        }
        labelled = true;
        if value.split(',').any(|listed| listed.trim() == expected) {
            return Some(true);
        }
    }
    labelled.then_some(false)
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

/// Whether inbound rules for Ember's TCP and Kad UDP ports, and for QUIC when
/// it has a UDP port of its own (`quic_port`, 0 when not bound), are in place,
/// or `None` when that could not be read. For the connection doctor: the
/// outside-in probe only reaches the Kad UDP port, so a missing QUIC rule
/// shows up here or nowhere.
pub fn rules_in_place(tcp_port: u16, udp_port: u16, quic_port: u16) -> Option<bool> {
    let tcp = firewall_rule_has_port(RULE_NAME_TCP, tcp_port);
    if tcp == Some(false) {
        return Some(false);
    }
    let kad = both_rules(tcp, firewall_rule_has_port(RULE_NAME_UDP, udp_port));
    match dedicated_quic_udp_port(quic_port, udp_port) {
        Some(port) if kad != Some(false) => both_rules(kad, firewall_rule_has_port(RULE_NAME_QUIC_UDP, port)),
        _ => kad,
    }
}

/// Either rule known missing settles it; otherwise both must be known.
fn both_rules(tcp: Option<bool>, udp: Option<bool>) -> Option<bool> {
    match (tcp, udp) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

/// Add the TCP, Kad UDP and (when QUIC has a port of its own) QUIC UDP rules
/// from an elevated `netsh`, which is one Windows permission prompt. Ember
/// does not run elevated, so this is the only way it can add them after setup;
/// the connection doctor offers it, and only when the user asks. Returns
/// whether the rules are in place afterwards, so a declined prompt reads as
/// not done.
pub fn add_rules_elevated(tcp_port: u16, udp_port: u16, quic_port: u16) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let script = elevated_rules_script(
        &exe.to_string_lossy(),
        &windows_system_path(NETSH).to_string_lossy(),
        tcp_port,
        udp_port,
        dedicated_quic_udp_port(quic_port, udp_port),
    );
    let encoded = utf16_base64(&script);
    let powershell = strip_quotes(&windows_system_path(POWERSHELL).to_string_lossy());
    let launcher = format!(
        "Start-Process -FilePath '{powershell}' -Verb RunAs -Wait -WindowStyle Hidden \
         -ArgumentList '-NoProfile','-NonInteractive','-EncodedCommand','{encoded}'"
    );
    let ran = Command::new(windows_system_path(POWERSHELL))
        .args(["-NoProfile", "-NonInteractive", "-Command", &launcher])
        .creation_flags(0x08000000)
        .output();
    if let Err(e) = ran {
        warn!("Could not ask Windows to add the firewall rules: {e}");
        return false;
    }
    rules_in_place(tcp_port, udp_port, quic_port) == Some(true)
}

/// UTF-16LE in base64, as `-EncodedCommand` and `[Text.Encoding]::Unicode`
/// take it.
fn utf16_base64(text: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>())
}

/// `text` without anything PowerShell reads as a quote: ASCII `'` and `"`,
/// and the typographic single quotes it treats exactly like `'`. Only for
/// system paths, which never hold one; the program path is passed encoded.
fn strip_quotes(text: &str) -> String {
    text.replace(['"', '\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}'], "")
}

/// The script the elevated PowerShell runs: replace the TCP and Kad UDP rules,
/// and the QUIC UDP rule when `quic_port` is given, for `exe`.
/// The program path is the one value a user or a download folder can name,
/// so it goes in base64 and is decoded into a variable: no character in it,
/// quote or otherwise, can end a string and become script.
fn elevated_rules_script(exe: &str, netsh: &str, tcp_port: u16, udp_port: u16, quic_port: Option<u16>) -> String {
    let netsh = strip_quotes(netsh);
    let rule = |name: &str, protocol: &str, port: u16| {
        format!(
            "& '{netsh}' advfirewall firewall delete rule name='{name}' | Out-Null\n\
             & '{netsh}' advfirewall firewall add rule name='{name}' dir=in action=allow \
             protocol={protocol} localport={port} enable=yes profile=any \"program=$exe\" | Out-Null\n"
        )
    };
    format!(
        "$exe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}'))\n{}{}{}",
        utf16_base64(exe),
        rule(RULE_NAME_TCP, "TCP", tcp_port),
        rule(RULE_NAME_UDP, "UDP", udp_port),
        quic_port.map(|port| rule(RULE_NAME_QUIC_UDP, "UDP", port)).unwrap_or_default()
    )
}

/// Returns `Some(outcome)` when `add_firewall_rule` actually ran (rule
/// missing or stale), `None` when no action was needed (rule already
/// up to date, or switched off by someone in Windows Firewall). Lets the
/// caller distinguish "tried and failed" from "didn't need to try" for the
/// single-line consolidated warning above.
fn ensure_one_rule(rule_name: &str, protocol: &str, port: u16) -> Option<AddRuleOutcome> {
    if firewall_rule_exists(rule_name) {
        match firewall_rule_state(rule_name, port) {
            Some(RuleState::Opens) => {
                debug!("Windows Firewall {protocol} rule already opens port {port} for Ember");
                return None;
            }
            Some(RuleState::TurnedOff) => {
                info!("Windows Firewall {protocol} rule is disabled or set to block; leaving it as it was set");
                return None;
            }
            Some(RuleState::Missing) | None => {}
        }
        info!("{protocol} firewall rule names another port or program, recreating for port {port}");
        delete_firewall_rule(rule_name);
    }
    Some(add_firewall_rule(rule_name, protocol, port))
}

#[cfg(test)]
mod tests {
    use super::{
        both_rules, dedicated_quic_udp_port, elevated_rules_script, firewall_rule_has_port, netsh_rule_has_port,
        rule_state_from_lines, utf16_base64, RuleState, POWERSHELL,
    };
    use std::path::Path;

    #[test]
    fn only_an_enabled_inbound_allow_rule_for_this_program_opens_the_port() {
        let exe = Path::new(r"C:\Program Files\Ember\ember.exe");
        let state = |text: &str| rule_state_from_lines(text, 4662, Some(exe));
        assert_eq!(state(r"True|Allow|Inbound|4662|C:\Program Files\Ember\ember.exe"), RuleState::Opens);
        assert_eq!(state(r"True|Allow|Inbound|4661,4662|c:/program files/ember/EMBER.EXE"), RuleState::Opens);
        assert_eq!(state("True|Allow|Inbound|4662|Any"), RuleState::Opens);
        assert_eq!(state(r"True|Allow|Inbound|4672|C:\Program Files\Ember\ember.exe"), RuleState::Missing, "another port");
        assert_eq!(
            state(r"True|Allow|Inbound|4662|D:\Old\Ember\ember.exe"),
            RuleState::Missing,
            "an older install's program",
        );
        assert_eq!(state(r"False|Allow|Inbound|4662|C:\Program Files\Ember\ember.exe"), RuleState::TurnedOff);
        assert_eq!(state(r"True|Block|Inbound|4662|C:\Program Files\Ember\ember.exe"), RuleState::TurnedOff);
        assert_eq!(state(r"True|Allow|Outbound|4662|C:\Program Files\Ember\ember.exe"), RuleState::Missing);
        assert_eq!(state(""), RuleState::Missing);
        assert_eq!(
            state("False|Allow|Inbound|4662|Any\r\nTrue|Allow|Inbound|4662|Any\r\n"),
            RuleState::Opens,
            "a working rule beside a disabled one opens",
        );
        assert_eq!(rule_state_from_lines(r"True|Allow|Inbound|4662|D:\x.exe", 4662, None), RuleState::Opens);
    }

    #[test]
    fn the_elevated_script_adds_the_quic_rule_only_when_quic_has_its_own_port() {
        let exe = r"C:\Program Files\Ember\ember.exe";
        let netsh = r"C:\Windows\System32\netsh.exe";
        let script = elevated_rules_script(exe, netsh, 4662, 4672, Some(4662));
        assert!(script.contains("name='Ember P2P (QUIC UDP)'") && script.contains("protocol=UDP localport=4662"));
        let script = elevated_rules_script(exe, netsh, 4662, 4672, None);
        assert!(!script.contains("QUIC"));
    }

    /// Whether this machine's PowerShell has the firewall cmdlets. Without
    /// them the query falls back to netsh, which cannot tell a missing rule
    /// from a failed query.
    fn netsecurity_module_present() -> bool {
        std::process::Command::new(crate::security::filesystem::windows_system_path(POWERSHELL))
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) { exit 0 } else { exit 1 }",
            ])
            .output()
            .is_ok_and(|output| output.status.success())
    }

    /// A rule that does not exist is missing, which is an answer; only a
    /// query that could not run is unknown. Runs PowerShell, and says
    /// nothing on a machine without its NetSecurity module.
    #[test]
    fn a_rule_that_does_not_exist_reads_as_missing_not_unknown() {
        if !netsecurity_module_present() {
            eprintln!("skipped: PowerShell has no NetSecurity module here");
            return;
        }
        assert_eq!(firewall_rule_has_port("Ember P2P (no such rule)", 4662), Some(false));
    }

    #[test]
    fn netsh_output_is_read_in_the_languages_its_labels_are_known_in() {
        let english = "Rule Name:                            Ember P2P (TCP)\r\n\
                       Protocol:                             TCP\r\n\
                       LocalPort:                            4662\r\n\
                       RemotePort:                           Any\r\n";
        assert_eq!(netsh_rule_has_port(english, 4662), Some(true));
        assert_eq!(netsh_rule_has_port(english, 4672), Some(false), "another port");
        let german = "Regelname:                            Ember P2P (TCP)\n\
                      Lokaler Port:                         4661,4662\n\
                      Remoteport:                           Beliebig\n";
        assert_eq!(netsh_rule_has_port(german, 4662), Some(true));
        let french = "Nom de la règle :                     Ember P2P (TCP)\n\
                      Port local :                          4662\n";
        assert_eq!(netsh_rule_has_port(french, 4662), Some(true));
        let remote_only = "RemotePort:                           4662\n";
        assert_eq!(netsh_rule_has_port(remote_only, 4662), None, "no local port label recognised");
        let unknown = "Kural Adı:                            Ember P2P (TCP)\n\
                       Yerel Bağlantı Noktası:               4662\n";
        assert_eq!(netsh_rule_has_port(unknown, 4662), None);
        assert_eq!(netsh_rule_has_port("", 4662), None);
    }

    #[test]
    fn either_rule_missing_settles_it_and_otherwise_both_must_be_known() {
        assert_eq!(both_rules(Some(true), Some(true)), Some(true));
        assert_eq!(both_rules(Some(false), None), Some(false));
        assert_eq!(both_rules(None, Some(false)), Some(false));
        assert_eq!(both_rules(Some(true), None), None);
        assert_eq!(both_rules(None, Some(true)), None);
        assert_eq!(both_rules(None, None), None);
    }

    /// A program path with any quote PowerShell honours reaches netsh as it
    /// is, and none of it is ever read as script.
    #[test]
    fn the_elevated_script_passes_any_program_path_through_untouched() {
        for exe in [
            r"C:\Users\O'Brien\AppData\Local\Ember\ember.exe",
            "C:\\Users\\O\u{2019}Brien\\Ember\\ember.exe",
            "C:\\Downloads\\Ember\u{2019};Start-Process calc;\u{2019}\\ember.exe",
            r#"C:\Program Files\Ember "x"\ember.exe"#,
        ] {
            let script = elevated_rules_script(exe, r"C:\Windows\System32\netsh.exe", 4662, 4672, None);
            assert!(!script.contains("Brien") && !script.contains("calc"), "{script}");
            assert!(script.contains("localport=4662") && script.contains("localport=4672"));
            // What the variable holds once PowerShell decodes it.
            let decode = format!(
                "$exe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}'))\n\
                 [Console]::OutputEncoding = [Text.Encoding]::UTF8\n[Console]::Out.Write($exe)",
                utf16_base64(exe)
            );
            let out = std::process::Command::new(crate::security::filesystem::windows_system_path(POWERSHELL))
                .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &utf16_base64(&decode)])
                .output()
                .expect("powershell runs");
            assert_eq!(String::from_utf8_lossy(&out.stdout), exe);
        }
    }

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
