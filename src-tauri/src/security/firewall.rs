use std::os::windows::process::CommandExt;
use std::process::Command;
use tracing::{debug, info, warn};

use crate::security::filesystem::windows_system_path;

/// The TCP and UDP rules open every port for Ember's own executable, as the
/// rules Windows itself writes for a program do. Ports change: a VPN hands out
/// a new forwarded port on every connect, and a rule naming the old one closes
/// the new one, which a run without elevation cannot rewrite.
///
/// Each name holds one rule per executable, and Ember only ever deletes its
/// own: a second install or a development build beside it keeps its rule
/// rather than losing it each time the other one starts.
const RULE_NAME_TCP: &str = "Ember P2P (TCP)";
const RULE_NAME_UDP: &str = "Ember P2P (UDP)";
/// QUIC binds its own UDP socket, usually on `tcp_port` — a different
/// number from the KAD UDP port. A UDP rule that opens every port covers it;
/// one written by an older Ember names the KAD UDP port alone, and without
/// this rule beside it Windows drops unsolicited QUIC Initial packets:
/// hole-punch accepts, relay-target connects, and `relay_for_peers` all fail
/// even when UPnP forwarded the port and TCP HighID is fine.
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
    /// An enabled inbound allow rule opens every port for this program (or
    /// for any program), so a port change leaves it working.
    OpensEveryPort,
    /// One opens this port but names its ports, so the next port change
    /// closes it.
    OpensThisPort,
    /// No rule does, and none was switched off or turned into a block: absent,
    /// or naming another port or another install's executable.
    Missing,
    /// A rule under this name was disabled or set to block. Someone chose that
    /// in Windows Firewall, so startup leaves it; the doctor still reports it.
    TurnedOff,
}

impl RuleState {
    fn opens(self) -> bool {
        matches!(self, RuleState::OpensEveryPort | RuleState::OpensThisPort)
    }
}

/// The rules under one name as a query returned them, to be read for any port.
enum RuleQuery {
    /// `enabled|action|direction|ports|program` lines from PowerShell.
    Rules(String),
    /// `netsh advfirewall firewall show rule` output, in the display language.
    Netsh(String),
}

impl RuleQuery {
    /// What these rules do for `port`, or `None` when the output cannot tell.
    fn state(&self, port: u16) -> Option<RuleState> {
        match self {
            RuleQuery::Rules(text) => {
                let exe = std::env::current_exe().ok();
                Some(rule_state_from_lines(text, port, exe.as_deref()))
            }
            RuleQuery::Netsh(text) => netsh_rule_state(text, port),
        }
    }
}

/// What the rules named `rule_name` do for `port`, or `None` when no query
/// could tell.
fn firewall_rule_state(rule_name: &str, port: u16) -> Option<RuleState> {
    query_rules(rule_name).and_then(|rules| rules.state(port))
}

/// The rules named `rule_name`, or `None` when no query could read them.
fn query_rules(rule_name: &str) -> Option<RuleQuery> {
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
            return Some(RuleQuery::Rules(String::from_utf8_lossy(&output.stdout).into_owned()));
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
        Ok(o) if o.status.success() => Some(RuleQuery::Netsh(String::from_utf8_lossy(&o.stdout).into_owned())),
        _ => None,
    }
}

/// Whether a rule named `rule_name` lets `port` in for this program:
/// `Some(false)` when none does or no such rule exists, `None` when no query
/// could tell.
fn firewall_rule_has_port(rule_name: &str, port: u16) -> Option<bool> {
    firewall_rule_state(rule_name, port).map(RuleState::opens)
}

/// Read the rule query's `enabled|action|direction|ports|program` lines. A
/// program of `Any` (or none) covers every program, and ports of `Any` every
/// port; with no `exe` to compare, the port alone decides. Outbound rules
/// under the name are ignored, and so are rules for another executable,
/// switched off or not.
fn rule_state_from_lines(text: &str, port: u16, exe: Option<&std::path::Path>) -> RuleState {
    let expected = port.to_string();
    let exe = exe.map(|path| program_key(&path.to_string_lossy()));
    let mut turned_off = false;
    let mut opens_this_port = false;
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
        let program = program.trim();
        let covers = program.is_empty()
            || program.eq_ignore_ascii_case("any")
            || exe.as_ref().is_none_or(|exe| program_key(program) == *exe);
        if !covers {
            continue;
        }
        let enabled = enabled.trim().eq_ignore_ascii_case("true");
        let allows = action.trim().eq_ignore_ascii_case("allow");
        if !enabled || !allows {
            turned_off = true;
            continue;
        }
        if ports.trim().eq_ignore_ascii_case("any") {
            return RuleState::OpensEveryPort;
        }
        opens_this_port |= ports
            .split(|c: char| c.is_whitespace() || c == ',')
            .any(|value| value.trim() == expected);
    }
    if opens_this_port {
        RuleState::OpensThisPort
    } else if turned_off {
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

/// What the local ports in `netsh advfirewall firewall show rule` output open
/// for `port`. A value without a digit is netsh's word for any port, in
/// whatever the display language. `None` when no line is labelled as a local
/// port at all: the display language is one the labels are not known in, and
/// the output says nothing either way.
fn netsh_rule_state(text: &str, port: u16) -> Option<RuleState> {
    let expected = port.to_string();
    let mut labelled = false;
    let mut opens_this_port = false;
    for (key, value) in text.lines().filter_map(|line| line.split_once(':')) {
        let key: String = key.to_lowercase().split_whitespace().collect();
        if !NETSH_LOCAL_PORT_KEYS.contains(&key.as_str()) {
            continue;
        }
        labelled = true;
        if !value.trim().is_empty() && !value.chars().any(|c| c.is_ascii_digit()) {
            return Some(RuleState::OpensEveryPort);
        }
        opens_this_port |= value.split(',').any(|listed| listed.trim() == expected);
    }
    labelled.then_some(if opens_this_port { RuleState::OpensThisPort } else { RuleState::Missing })
}

/// Delete this executable's rules under `rule_name`, leaving those another
/// install keeps under the same name.
fn delete_firewall_rule(rule_name: &str) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let exe_path = exe.to_string_lossy().replace('"', "");
    let _ = Command::new(windows_system_path(NETSH))
        .args([
            "advfirewall",
            "firewall",
            "delete",
            "rule",
            &format!("name={rule_name}"),
            &format!("program={exe_path}"),
        ])
        .creation_flags(0x08000000)
        .output();
}

/// Add an inbound allow for every `protocol` port of this executable.
fn add_firewall_rule(rule_name: &str, protocol: &str) -> AddRuleOutcome {
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
            info!("Added Windows Firewall rule: {rule_name} ({protocol}, every port)");
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

/// Ensure inbound TCP and UDP rules open every port for this executable,
/// replacing ones that name another program or do not open the configured
/// ports, and widening ones that name ports when this run may change rules.
///
/// QUIC typically binds UDP on `tcp_port`. While the UDP rule still names
/// ports, opening that here at startup covers the common case before the
/// endpoint exists; [`ensure_quic_udp_firewall_rule`] updates the rule if bind
/// later falls back to a neighbour port.
///
/// When the user is *not* running elevated and the rules don't yet
/// exist, we used to emit two raw `netsh` stderr dumps every single
/// startup. Now we collapse both into a single actionable message so
/// the user knows what to do without thinking they have a bug.
pub fn ensure_firewall_rules(tcp_port: u16, udp_port: u16) {
    // Each rule is its own few netsh/PowerShell launches, so TCP and UDP run
    // at once. QUIC follows UDP, which may already open its port.
    let (tcp_outcome, udp_outcome, quic_outcome) = std::thread::scope(|scope| {
        let udp = scope.spawn(|| {
            let udp = ensure_one_rule(RULE_NAME_UDP, "UDP", udp_port);
            let quic = dedicated_quic_udp_port(tcp_port, udp_port).and_then(ensure_quic_rule);
            (udp, quic)
        });
        let tcp = ensure_one_rule(RULE_NAME_TCP, "TCP", tcp_port);
        let (udp, quic) = udp.join().unwrap_or((None, None));
        (tcp, udp, quic)
    });

    let mut elevation_failures: Vec<&'static str> = Vec::new();
    for (outcome, proto) in [(tcp_outcome, "TCP"), (udp_outcome, "UDP"), (quic_outcome, "QUIC")] {
        if matches!(outcome, Some(AddRuleOutcome::NeedsElevation)) {
            elevation_failures.push(proto);
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
/// No-op when that port is already the KAD UDP port, when [`RULE_NAME_UDP`]
/// opens it, or when it matches `tcp_port` already opened by
/// [`ensure_firewall_rules`]. Recreates [`RULE_NAME_QUIC_UDP`] if bind
/// landed on a fallback neighbour (`tcp_port+1..=+4`).
pub fn ensure_quic_udp_firewall_rule(quic_udp_port: u16, kad_udp_port: u16) {
    let Some(port) = dedicated_quic_udp_port(quic_udp_port, kad_udp_port) else {
        return;
    };
    if matches!(ensure_quic_rule(port), Some(AddRuleOutcome::NeedsElevation)) {
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

/// Ensure QUIC's own UDP `port` is let in. Nothing to do when the UDP rule
/// already opens it, and nothing when that rule was switched off: a rule of
/// QUIC's own would open the UDP someone closed.
fn ensure_quic_rule(port: u16) -> Option<AddRuleOutcome> {
    if firewall_rule_state(RULE_NAME_UDP, port)
        .is_some_and(|state| state.opens() || state == RuleState::TurnedOff)
    {
        return None;
    }
    ensure_one_rule(RULE_NAME_QUIC_UDP, "UDP", port)
}

/// Whether inbound rules for Ember's TCP and Kad UDP ports, and for QUIC when
/// it has a UDP port of its own (`quic_port`, 0 when not bound), are in place,
/// or `None` when that could not be read. For the connection doctor: the
/// outside-in probe only reaches the Kad UDP port, so a missing QUIC rule
/// shows up here or nowhere.
pub fn rules_in_place(tcp_port: u16, udp_port: u16, quic_port: u16) -> Option<bool> {
    // Each query is a PowerShell launch of a second or more, so TCP and UDP
    // run at once. The UDP rules are read once for both UDP ports.
    std::thread::scope(|scope| {
        let udp = scope.spawn(|| {
            let rules = query_rules(RULE_NAME_UDP);
            let opens = |port| rules.as_ref().and_then(|rules| rules.state(port)).map(RuleState::opens);
            let quic = dedicated_quic_udp_port(quic_port, udp_port).map(|port| match opens(port) {
                Some(true) => Some(true),
                _ => firewall_rule_has_port(RULE_NAME_QUIC_UDP, port),
            });
            (opens(udp_port), quic)
        });
        let tcp = firewall_rule_has_port(RULE_NAME_TCP, tcp_port);
        let (kad_udp, quic) = udp.join().unwrap_or((None, None));
        let kad = both_rules(tcp, kad_udp);
        match quic {
            Some(quic) => both_rules(kad, quic),
            None => kad,
        }
    })
}

/// Either rule known missing settles it; otherwise both must be known.
fn both_rules(tcp: Option<bool>, udp: Option<bool>) -> Option<bool> {
    match (tcp, udp) {
        (Some(false), _) | (_, Some(false)) => Some(false),
        (Some(true), Some(true)) => Some(true),
        _ => None,
    }
}

/// Add the TCP and UDP rules, which open every port, from an elevated
/// `netsh`, which is one Windows permission prompt. Ember does not run
/// elevated, so this is the only way it can add them after setup; the
/// connection doctor offers it, and only when the user asks. `owner` is the
/// window the prompt belongs to (0 for none). Returns whether the session's
/// ports (QUIC's too, when it has a port of its own) are let in afterwards, so
/// a declined prompt reads as not done.
pub fn add_rules_elevated(tcp_port: u16, udp_port: u16, quic_port: u16, owner: isize) -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let script = elevated_rules_script(&exe.to_string_lossy(), &windows_system_path(NETSH).to_string_lossy());
    let parameters = format!(
        "-NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}",
        utf16_base64(&script)
    );
    if !run_elevated(&windows_system_path(POWERSHELL).to_string_lossy(), &parameters, owner) {
        return false;
    }
    rules_in_place(tcp_port, udp_port, quic_port) == Some(true)
}

/// How long to wait for the elevated script, which runs a few `netsh` calls.
const ELEVATED_WAIT_MS: u32 = 120_000;

/// Run `program` elevated, hidden, and wait for it. Returns whether it started;
/// a declined permission prompt is `false`.
///
/// Asked for by Ember itself through `ShellExecuteExW`, owned by `owner`, so
/// the prompt opens in front of Ember's window. A hidden helper asking instead
/// (`Start-Process -Verb RunAs` from a windowless PowerShell) has no right to
/// the foreground, and Windows showed its prompt behind Ember as a flashing
/// taskbar button.
fn run_elevated(program: &str, parameters: &str, owner: isize) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED};
    use windows_sys::Win32::System::Com::{
        CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
    };
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::UI::Shell::{
        ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    let wide = |text: &str| text.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (verb, file, parameters) = (wide("runas"), wide(program), wide(parameters));
    // SAFETY: called with no reserved pointer; a thread that already has COM
    // in another mode answers with an error, and then is not uninitialised.
    let com = unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
    // SAFETY: SHELLEXECUTEINFOW is plain data, for which all zeroes is valid.
    let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    info.hwnd = owner as _;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_HIDE;
    // SAFETY: `info` is a valid SHELLEXECUTEINFOW with `cbSize` set, and the
    // strings it points at outlive the call.
    let started = unsafe { ShellExecuteExW(&mut info) } != 0;
    if !started {
        // SAFETY: no arguments; reads this thread's last error.
        match unsafe { GetLastError() } {
            ERROR_CANCELLED => debug!("Firewall rules: the permission prompt was declined"),
            code => warn!("Could not ask Windows to add the firewall rules: error {code}"),
        }
    } else if !info.hProcess.is_null() {
        // SAFETY: a process handle ShellExecuteExW opened for us, closed once.
        unsafe {
            WaitForSingleObject(info.hProcess, ELEVATED_WAIT_MS);
            CloseHandle(info.hProcess);
        }
    }
    if com >= 0 {
        // SAFETY: balances the successful CoInitializeEx above on this thread.
        unsafe { CoUninitialize() };
    }
    started
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

/// The script the elevated PowerShell runs: replace `exe`'s TCP and UDP rules
/// with ones opening every port, and remove its QUIC UDP rule, which the UDP
/// rule now covers. Other executables' rules under the names are left alone.
/// The program path is the one value a user or a download folder can name,
/// so it goes in base64 and is decoded into a variable: no character in it,
/// quote or otherwise, can end a string and become script.
fn elevated_rules_script(exe: &str, netsh: &str) -> String {
    let netsh = strip_quotes(netsh);
    let delete =
        |name: &str| format!("& '{netsh}' advfirewall firewall delete rule name='{name}' \"program=$exe\" | Out-Null\n");
    let rule = |name: &str, protocol: &str| {
        format!(
            "{}& '{netsh}' advfirewall firewall add rule name='{name}' dir=in action=allow \
             protocol={protocol} enable=yes profile=any \"program=$exe\" | Out-Null\n",
            delete(name)
        )
    };
    format!(
        "$exe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}'))\n{}{}{}",
        utf16_base64(exe),
        rule(RULE_NAME_TCP, "TCP"),
        rule(RULE_NAME_UDP, "UDP"),
        delete(RULE_NAME_QUIC_UDP)
    )
}

/// Returns `Some(outcome)` when `add_firewall_rule` actually ran (rule
/// missing or stale), `None` when no action was needed (rule already
/// up to date, still opening `port` while it names ports, or switched off by
/// someone in Windows Firewall). Lets the caller distinguish "tried and
/// failed" from "didn't need to try" for the single-line consolidated warning
/// above.
fn ensure_one_rule(rule_name: &str, protocol: &str, port: u16) -> Option<AddRuleOutcome> {
    // Startup and the QUIC bind can both reach the QUIC rule; two check-then-
    // add passes on one name at once would leave a duplicate rule.
    static RULE_LOCKS: [std::sync::Mutex<()>; 3] =
        [std::sync::Mutex::new(()), std::sync::Mutex::new(()), std::sync::Mutex::new(())];
    let lock = match rule_name {
        RULE_NAME_TCP => &RULE_LOCKS[0],
        RULE_NAME_UDP => &RULE_LOCKS[1],
        _ => &RULE_LOCKS[2],
    };
    let _held = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if firewall_rule_exists(rule_name) {
        match firewall_rule_state(rule_name, port) {
            Some(RuleState::OpensEveryPort) => {
                debug!("Windows Firewall {protocol} rule already opens every port for Ember");
                return None;
            }
            Some(RuleState::OpensThisPort) => {
                // It still opens this port, so being refused elevation for
                // the widening is no failure.
                debug!("Windows Firewall {protocol} rule opens port {port} only; widening it to every port");
                delete_firewall_rule(rule_name);
                return match add_firewall_rule(rule_name, protocol) {
                    AddRuleOutcome::NeedsElevation => None,
                    outcome => Some(outcome),
                };
            }
            Some(RuleState::TurnedOff) => {
                info!("Windows Firewall {protocol} rule is disabled or set to block; leaving it as it was set");
                return None;
            }
            Some(RuleState::Missing) | None => {}
        }
        info!("No {protocol} firewall rule opens port {port} for this Ember; adding one for every port");
        delete_firewall_rule(rule_name);
    }
    Some(add_firewall_rule(rule_name, protocol))
}

#[cfg(test)]
mod tests {
    use super::{
        both_rules, dedicated_quic_udp_port, elevated_rules_script, firewall_rule_has_port, netsh_rule_state,
        rule_state_from_lines, utf16_base64, RuleState, POWERSHELL,
    };
    use std::path::Path;

    #[test]
    fn only_an_enabled_inbound_allow_rule_for_this_program_opens_the_port() {
        let exe = Path::new(r"C:\Program Files\Ember\ember.exe");
        let state = |text: &str| rule_state_from_lines(text, 4662, Some(exe));
        assert_eq!(state(r"True|Allow|Inbound|4662|C:\Program Files\Ember\ember.exe"), RuleState::OpensThisPort);
        assert_eq!(state(r"True|Allow|Inbound|4661,4662|c:/program files/ember/EMBER.EXE"), RuleState::OpensThisPort);
        assert_eq!(state("True|Allow|Inbound|4662|Any"), RuleState::OpensThisPort);
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
            RuleState::OpensThisPort,
            "a working rule beside a disabled one opens",
        );
        assert_eq!(rule_state_from_lines(r"True|Allow|Inbound|4662|D:\x.exe", 4662, None), RuleState::OpensThisPort);
    }

    /// A rule that opens every port keeps working when the port changes, as a
    /// VPN's forwarded port does on every connect.
    #[test]
    fn a_rule_without_ports_opens_every_port_for_its_program() {
        let exe = Path::new(r"C:\Program Files\Ember\ember.exe");
        let every_port = r"True|Allow|Inbound|Any|C:\Program Files\Ember\ember.exe";
        for port in [4662, 49091, 63291] {
            assert_eq!(rule_state_from_lines(every_port, port, Some(exe)), RuleState::OpensEveryPort);
        }
        assert_eq!(
            rule_state_from_lines(r"True|Allow|Inbound|Any|D:\Dev\target\debug\ember.exe", 4662, Some(exe)),
            RuleState::Missing,
            "another build's executable",
        );
        assert_eq!(
            rule_state_from_lines(r"False|Allow|Inbound|Any|C:\Program Files\Ember\ember.exe", 4662, Some(exe)),
            RuleState::TurnedOff,
        );
        assert_eq!(
            rule_state_from_lines(
                &format!("False|Allow|Inbound|Any|D:\\Dev\\target\\debug\\ember.exe\r\n{every_port}\r\n"),
                4662,
                Some(exe),
            ),
            RuleState::OpensEveryPort,
            "another build's rule beside ours, switched off or not, is not ours to judge",
        );
        assert_eq!(
            rule_state_from_lines(r"False|Allow|Inbound|Any|D:\Dev\target\debug\ember.exe", 4662, Some(exe)),
            RuleState::Missing,
            "another build's switched-off rule does not stop this one adding its own",
        );
        let pinned_then_every = format!("True|Allow|Inbound|4662|{}\r\n{every_port}\r\n", exe.display());
        assert_eq!(
            rule_state_from_lines(&pinned_then_every, 4662, Some(exe)),
            RuleState::OpensEveryPort,
            "a rule opening every port outranks one naming the port",
        );
    }

    #[test]
    fn the_elevated_script_opens_every_port_and_drops_the_quic_rule() {
        let script = elevated_rules_script(r"C:\Program Files\Ember\ember.exe", r"C:\Windows\System32\netsh.exe");
        assert!(script.contains("name='Ember P2P (TCP)' dir=in action=allow protocol=TCP enable=yes"));
        assert!(script.contains("name='Ember P2P (UDP)' dir=in action=allow protocol=UDP enable=yes"));
        assert!(!script.contains("localport"));
        assert!(script.contains("delete rule name='Ember P2P (QUIC UDP)' \"program=$exe\""));
        assert!(!script.contains("add rule name='Ember P2P (QUIC UDP)'"));
        assert_eq!(
            script.matches("delete rule").count(),
            script.matches("' \"program=$exe\" | Out-Null").count(),
            "every deletion is of this executable's rules only",
        );
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
        assert_eq!(netsh_rule_state(english, 4662), Some(RuleState::OpensThisPort));
        assert_eq!(netsh_rule_state(english, 4672), Some(RuleState::Missing), "another port");
        let german = "Regelname:                            Ember P2P (TCP)\n\
                      Lokaler Port:                         4661,4662\n\
                      Remoteport:                           Beliebig\n";
        assert_eq!(netsh_rule_state(german, 4662), Some(RuleState::OpensThisPort));
        let french = "Nom de la règle :                     Ember P2P (TCP)\n\
                      Port local :                          4662\n";
        assert_eq!(netsh_rule_state(french, 4662), Some(RuleState::OpensThisPort));
        let remote_only = "RemotePort:                           4662\n";
        assert_eq!(netsh_rule_state(remote_only, 4662), None, "no local port label recognised");
        let unknown = "Kural Adı:                            Ember P2P (TCP)\n\
                       Yerel Bağlantı Noktası:               4662\n";
        assert_eq!(netsh_rule_state(unknown, 4662), None);
        assert_eq!(netsh_rule_state("", 4662), None);
    }

    #[test]
    fn netsh_reads_a_local_port_without_digits_as_every_port_in_any_language() {
        let english = "Rule Name:                            Ember P2P (TCP)\r\n\
                       LocalPort:                            Any\r\n";
        assert_eq!(netsh_rule_state(english, 63291), Some(RuleState::OpensEveryPort));
        let german = "Regelname:                            Ember P2P (TCP)\n\
                      Lokaler Port:                         Beliebig\n";
        assert_eq!(netsh_rule_state(german, 63291), Some(RuleState::OpensEveryPort));
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
            let script = elevated_rules_script(exe, r"C:\Windows\System32\netsh.exe");
            assert!(!script.contains("Brien") && !script.contains("calc"), "{script}");
            assert!(script.contains("protocol=TCP") && script.contains("protocol=UDP"));
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
