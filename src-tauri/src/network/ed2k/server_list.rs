use std::io::{self, Cursor, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Historical eMule Sunrise endpoint used as the never-connected auto-connect
/// fallback when present in the downloaded server.met.
pub const EMULE_SUNRISE_IP: &str = "176.123.5.89";
pub const EMULE_SUNRISE_PORT: u16 = 4725;
pub const EMULE_SUNRISE_NAME: &str = "eMule Sunrise";

/// Persisted last successfully connected eD2K server (`last_ed2k_server.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastEd2kServer {
    pub ip: String,
    pub port: u16,
    #[serde(default)]
    pub name: String,
}

impl LastEd2kServer {
    pub fn load(path: &Path) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        let parsed: Self = serde_json::from_str(&data).ok()?;
        if parsed.ip.is_empty() || parsed.port == 0 {
            return None;
        }
        Some(parsed)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        crate::security::atomic_write(path, data.as_bytes(), true)
    }
}

/// Upper bounds on server.met tag field lengths. Each `vec![0u8; len]` is
/// sized from an unchecked on-disk `u16` and allocated before the read can
/// fail, so without a cap a crafted file could force large allocations per
/// tag (50 tags/entry, up to thousands of entries). eMule tag names are tiny;
/// server name/description strings are short in practice.
const MAX_SERVER_TAG_NAME_LEN: usize = 256;
const MAX_SERVER_TAG_STR_LEN: usize = 4096;
const MAX_SERVER_MET_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SERVER_LIST_ENTRIES: usize = 5_000;
const ST_UDPFLAGS: u8 = 0x92;
const ST_UDPKEY: u8 = 0x95;
const ST_UDPKEYIP: u8 = 0x96;
const ST_TCPPORTOBFUSCATION: u8 = 0x97;
const ST_UDPPORTOBFUSCATION: u8 = 0x98;

#[derive(Debug, Clone, Default)]
pub struct ServerMergeStats {
    pub added: usize,
    pub updated: usize,
    pub filtered: usize,
    pub at_capacity: usize,
    /// The file ended, or held something unreadable, before its last server.
    pub truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddServerOutcome {
    Added,
    Duplicate,
    Filtered,
    AtCapacity,
}

#[derive(Debug, Clone)]
pub struct ServerEntry {
    pub ip: String,
    pub port: u16,
    pub name: String,
    pub description: String,
    pub priority: ServerPriority,
    pub is_static: bool,
    pub fail_count: u32,
    pub user_count: u32,
    pub file_count: u32,
    pub max_users: u32,
    pub soft_files: u32,
    pub hard_files: u32,
    pub last_ping: i64,
    /// Timestamp of last failed connection attempt (for cooldown)
    pub last_failed_at: i64,
    pub obfuscation_port_tcp: u16,
    /// Alternate UDP port the server listens on for **obfuscated** UDP
    /// packets, learned from the extended `OP_GLOBSERVSTATRES` payload.
    /// `0` means "not advertised, fall back to TCP+4". When obfuscation
    /// is active and this is non-zero, sends go here instead of the
    /// standard UDP port (matches eMule's
    /// `pServer->GetObfuscationPortUDP()` choice in `UDPSocket.cpp`).
    pub obfuscation_port_udp: u16,
    /// Server UDP capability flags (SRV_UDPFLG_*), learned from status pings.
    pub udp_flags: u32,
    /// Per-server **BaseKey** for UDP obfuscation, learned from the
    /// extended `OP_GLOBSERVSTATRES` payload (`dwServerUDPKey`, offset
    /// 36). `0` means we haven't received it yet — caller must send
    /// plaintext until a non-zero value lands. Required for both
    /// directions (send key uses CLIENTSERVER magic, recv key uses
    /// SERVERCLIENT magic; see `server_obfuscation.rs`).
    pub server_udp_key: u32,
    /// Public IPv4 the UDP obfuscation key was issued for (ST_UDPKEYIP), in
    /// eMule's byte order (see `met_ip_u32`). eMule binds server UDP keys to
    /// the current public IP; a key learned before an IP change must be
    /// discarded instead of reused.
    pub server_udp_key_ip: u32,
    /// A key not in use until our public address is known to be the one it
    /// was issued for: read from disk, or set aside while the address is
    /// unknown. Runtime-only; saved in `server_udp_key`'s place.
    pub parked_udp_key: u32,
    /// The last status ping went out obfuscated and has not been answered.
    /// The next one goes plain, 20 s later, as in eMule: a server that lost
    /// our key would otherwise never answer again. Runtime-only.
    pub crypt_ping_pending: bool,
    /// Plain status pings sent to this server since it last answered any UDP
    /// request of ours (`record_udp_ping_sent`, cleared by
    /// `record_udp_reply`). Used by `is_eligible_udp_server` to stop wasting
    /// bandwidth on servers that no longer respond to UDP — distinct from
    /// `fail_count` which only tracks **TCP** connect failures.
    ///
    /// Background: a non-trivial portion of the public ed2k server
    /// population is TCP-reachable but UDP-dead (e.g. sysadmin
    /// firewalled the UDP port, server doesn't index every file
    /// hash, server requires UDP obfuscation we never negotiated).
    /// Without per-server UDP-failure tracking we'd keep blasting
    /// these servers for the lifetime of the process.
    pub udp_consecutive_failures: u32,
    /// Last time (Unix timestamp, seconds) this server replied to
    /// *any* of our UDP requests — status pings or source queries.
    /// Diagnostic; combined with `udp_consecutive_failures` this lets
    /// the periodic UDP-health log say "server X last responded
    /// 12 minutes ago" rather than just "silent".
    pub last_udp_reply_at: i64,
    /// Last time this server replied with `OP_GLOBFOUNDSOURCES`
    /// specifically (not status pings). A server can be perfectly
    /// status-ping-responsive yet never return source data because
    /// it doesn't index our specific file hashes — eMule servers
    /// stay silent rather than send empty `FoundSources` replies, so
    /// our `udp_discovery_replies` counter would say "0 replies"
    /// even though the servers are reachable. This field lets the
    /// health log distinguish "server is dead" from "server is
    /// alive but doesn't have what we want".
    pub last_udp_source_reply_at: i64,
    /// Last time (Unix timestamp, seconds) we SENT this server a UDP source
    /// query. Runtime-only (not persisted), diagnostic.
    pub last_udp_query_at: i64,
    /// When we last sent this server a UDP status ping, on
    /// `network::monotonic_secs`, like eMule's `CServer::GetLastPingedTime`:
    /// the per-server gate for the 4.5 h status cadence. Saved as wall-clock
    /// time (`ST_LASTPING`) so it outlasts a restart.
    pub last_udp_ping_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPriority {
    Low,
    Normal,
    High,
}

impl ServerPriority {
    /// Stable lowercase name for the IPC boundary.
    ///
    /// A name rather than eMule's wire number (`0` Normal, `1` High, `2` Low)
    /// because that encoding is neither ordered nor obvious, and it belongs to
    /// the `server.met` tag writer, not to the renderer.
    pub fn as_str(self) -> &'static str {
        match self {
            ServerPriority::Low => "low",
            ServerPriority::Normal => "normal",
            ServerPriority::High => "high",
        }
    }

    /// Parse the name the renderer sends back.
    ///
    /// Unknown values are rejected rather than normalized to `Normal`, which
    /// is what [`apply_server_int_tag`] has to do with an out-of-range tag
    /// from a third-party `server.met`. Here the value came from our own UI,
    /// so a typo should surface as a failed command instead of silently
    /// resetting the priority the user had set.
    pub fn parse_name(value: &str) -> Option<Self> {
        match value {
            "low" => Some(ServerPriority::Low),
            "normal" => Some(ServerPriority::Normal),
            "high" => Some(ServerPriority::High),
            _ => None,
        }
    }
}

impl ServerEntry {
    pub fn new(ip: String, port: u16) -> Self {
        Self {
            ip,
            port,
            name: String::new(),
            description: String::new(),
            priority: ServerPriority::Normal,
            is_static: false,
            fail_count: 0,
            user_count: 0,
            file_count: 0,
            max_users: 0,
            soft_files: 0,
            hard_files: 0,
            last_ping: 0,
            last_failed_at: 0,
            obfuscation_port_tcp: 0,
            obfuscation_port_udp: 0,
            udp_flags: 0,
            server_udp_key: 0,
            server_udp_key_ip: 0,
            parked_udp_key: 0,
            crypt_ping_pending: false,
            udp_consecutive_failures: 0,
            last_udp_reply_at: 0,
            last_udp_source_reply_at: 0,
            last_udp_query_at: 0,
            last_udp_ping_at: 0,
        }
    }
}

fn apply_server_int_tag(entry: &mut ServerEntry, name_id: u8, v: u32) {
    match name_id {
        0x0D | 0x85 => entry.fail_count = v,
        0x0E => {
            entry.priority = match v {
                0 => ServerPriority::Normal,
                1 => ServerPriority::High,
                2 => ServerPriority::Low,
                _ => ServerPriority::Normal,
            }
        }
        0x83 => entry.user_count = v,
        0x84 => entry.file_count = v,
        0x86 => entry.last_ping = v as i64,
        0x87 => entry.max_users = v,
        0x88 => entry.soft_files = v,
        0x89 => entry.hard_files = v,
        0x8A => entry.is_static = v != 0,
        ST_UDPFLAGS => entry.udp_flags = v,
        ST_UDPKEY => entry.server_udp_key = v,
        ST_UDPKEYIP => entry.server_udp_key_ip = v,
        ST_TCPPORTOBFUSCATION | 0xF1 => entry.obfuscation_port_tcp = v as u16,
        ST_UDPPORTOBFUSCATION => entry.obfuscation_port_udp = v as u16,
        // Ember-private tags persisted by `to_server_met_bytes` for UDP
        // obfuscation state. Fresh server.met files from eMule won't
        // carry these (so the fields stay 0 until the first status
        // ping); our own saves preserve them across restarts.
        0xF2 => entry.obfuscation_port_udp = v as u16,
        0xF3 => entry.server_udp_key = v,
        0xF4 => entry.udp_flags = v,
        // Ember-private: per-server UDP-responsiveness counters,
        // persisted so a server's "dead for UDP" status survives a
        // process restart (otherwise we'd waste a full
        // MAX_UDP_CONSECUTIVE_FAILURES round of queries on every
        // launch re-discovering known-dead UDP endpoints).
        0xF5 => entry.udp_consecutive_failures = v,
        0xF6 => entry.last_udp_reply_at = v as i64,
        0xF7 => entry.last_udp_source_reply_at = v as i64,
        _ => {}
    }
}

/// When a status ping was last sent (eMule's `ST_LASTPING`), as Unix seconds.
/// Saved so a restart does not ping every server again before the 4.5 h
/// interval is up.
const ST_LASTPING: u8 = 0x90;

/// A saved ping time on the clock `last_udp_ping_at` runs on, or 0 ("never")
/// when the interval it gated has already run out or the time lies ahead.
fn ping_time_from_wall(wall: i64) -> i64 {
    let age = chrono::Utc::now().timestamp() - wall;
    if wall <= 0 || !(0..super::server_udp::STAT_REASK_INTERVAL_SECS).contains(&age) {
        return 0;
    }
    (crate::network::monotonic_secs() - age).max(0)
}

/// `last_udp_ping_at` as Unix seconds, for saving.
fn ping_time_to_wall(at: i64) -> i64 {
    chrono::Utc::now().timestamp() - (crate::network::monotonic_secs() - at)
}

/// An address as eMule stores one in server.met (`ST_UDPKEYIP`): the octets in
/// network order, read as a little-endian `u32`, the same as the server IPs.
fn met_ip_u32(ip: Ipv4Addr) -> u32 {
    u32::from_le_bytes(ip.octets())
}

/// Where a server.met came from, which decides how far its tags are trusted.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MetSource {
    /// Ember's own file.
    Own,
    /// A downloaded list, or eMule's: Ember's private tags in it mean nothing
    /// Ember wrote, so they are not taken (one would make a server static).
    Foreign,
}

/// Ember's own tags: the static flag and the UDP bookkeeping.
fn is_ember_private_tag(id: u8) -> bool {
    id == 0x8A || id >= 0xF0
}

/// What a tag holds, as far as a server entry cares.
enum MetTagValue {
    Str(String),
    Int(u32),
    /// A type whose payload was stepped over.
    Other,
}

struct MetTag {
    /// The one-byte id, or 0 for a tag with a longer name.
    id: u8,
    /// The longer name, lowercased: eMule names the user and file counts in
    /// full ("users", "files").
    name: Option<String>,
    value: MetTagValue,
}

fn met_invalid(msg: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// The next `len` bytes, without copying them or allocating for a length the
/// file only claims to have.
fn met_take<'a>(cursor: &mut Cursor<&'a [u8]>, len: usize) -> io::Result<&'a [u8]> {
    let data: &'a [u8] = cursor.get_ref();
    let start = cursor.position() as usize;
    let end = start
        .checked_add(len)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "server.met ends inside a tag"))?;
    cursor.set_position(end as u64);
    Ok(&data[start..end])
}

/// Cut `text` to at most `max` bytes, on a character boundary.
fn truncate_to_bytes(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut cut = max;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    &text[..cut]
}

/// A string as eMule writes it: UTF-8 behind a byte-order mark when it is not
/// plain ASCII, or else the writer's local code page, read here as Latin-1.
/// Capped in bytes, which is what the reader checks: a cap in characters let a
/// name of replacement characters reach three times the size, and the file
/// written with it would not load.
fn decode_met_string(raw: &[u8]) -> String {
    let raw = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw);
    let text = match std::str::from_utf8(raw) {
        Ok(text) => text.to_string(),
        Err(_) => raw.iter().map(|&b| char::from(b)).collect(),
    };
    let clean = crate::security::sanitize_remote_text(&text, MAX_SERVER_TAG_STR_LEN);
    truncate_to_bytes(&clean, MAX_SERVER_TAG_STR_LEN).to_string()
}

/// Read one tag. Every type eMule defines has a known size and is stepped over
/// when it is nothing a server entry stores; only a type with no known size
/// stops the read, since nothing after it can be found.
fn read_met_tag(cursor: &mut Cursor<&[u8]>) -> io::Result<MetTag> {
    let raw_type = cursor.read_u8()?;
    // Files use the long form; the compact one (type | 0x80, then an id byte)
    // is accepted too, as eMule's reader does.
    let (tag_type, id, name) = if raw_type & 0x80 != 0 {
        (raw_type & 0x7F, cursor.read_u8()?, None)
    } else {
        let name_len = usize::from(cursor.read_u16::<LittleEndian>()?);
        if name_len > MAX_SERVER_TAG_NAME_LEN {
            return Err(met_invalid(format!("server.met tag name of {name_len} bytes")));
        }
        let raw = met_take(cursor, name_len)?;
        match raw {
            [id] => (raw_type, *id, None),
            _ => (raw_type, 0, Some(String::from_utf8_lossy(raw).to_ascii_lowercase())),
        }
    };
    let value = match tag_type {
        0x02 => {
            let len = usize::from(cursor.read_u16::<LittleEndian>()?);
            MetTagValue::Str(decode_met_string(met_take(cursor, len)?))
        }
        // TAGTYPE_STR1..STR16: the length is in the type.
        0x11..=0x20 => {
            MetTagValue::Str(decode_met_string(met_take(cursor, usize::from(tag_type - 0x10))?))
        }
        0x03 => MetTagValue::Int(cursor.read_u32::<LittleEndian>()?),
        0x08 => MetTagValue::Int(u32::from(cursor.read_u16::<LittleEndian>()?)),
        0x09 => MetTagValue::Int(u32::from(cursor.read_u8()?)),
        0x0B => {
            let v = cursor.read_u64::<LittleEndian>()?;
            MetTagValue::Int(u32::try_from(v).unwrap_or(u32::MAX))
        }
        0x01 => {
            met_take(cursor, 16)?;
            MetTagValue::Other
        }
        0x04 => {
            met_take(cursor, 4)?;
            MetTagValue::Other
        }
        0x05 => {
            met_take(cursor, 1)?;
            MetTagValue::Other
        }
        0x06 => {
            let bits = usize::from(cursor.read_u16::<LittleEndian>()?);
            met_take(cursor, bits.div_ceil(8))?;
            MetTagValue::Other
        }
        0x07 => {
            let len = cursor.read_u32::<LittleEndian>()? as usize;
            met_take(cursor, len)?;
            MetTagValue::Other
        }
        0x0A => {
            let len = usize::from(cursor.read_u8()?);
            met_take(cursor, len)?;
            MetTagValue::Other
        }
        other => return Err(met_invalid(format!("server.met tag of unknown type 0x{other:02X}"))),
    };
    Ok(MetTag { id, name, value })
}

/// Read one `<ip><port><tag_count><tags>` entry.
fn read_met_entry(cursor: &mut Cursor<&[u8]>, source: MetSource) -> io::Result<ServerEntry> {
    let ip = Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?.to_le_bytes());
    let port = cursor.read_u16::<LittleEndian>()?;
    let tag_count = cursor.read_u32::<LittleEndian>()?;
    if tag_count > 50 {
        return Err(met_invalid(format!(
            "server.met entry for {ip}:{port} declares {tag_count} tags, exceeding cap of 50"
        )));
    }
    let mut entry = ServerEntry::new(ip.to_string(), port);
    for _ in 0..tag_count {
        let tag = read_met_tag(cursor)?;
        match tag.value {
            // The first copy wins, as in eMule's `CServer::AddTagFromFile`.
            MetTagValue::Str(text) => match tag.id {
                0x01 if entry.name.is_empty() => entry.name = text,
                0x0B if entry.description.is_empty() => entry.description = text,
                _ => {}
            },
            MetTagValue::Int(v) => match (tag.id, tag.name.as_deref()) {
                (0, Some("users")) => entry.user_count = v,
                (0, Some("files")) => entry.file_count = v,
                (0, _) => {}
                // Another client's pings are no reason for ours to wait.
                (ST_LASTPING, _) if source == MetSource::Own => {
                    entry.last_udp_ping_at = ping_time_from_wall(i64::from(v));
                }
                (ST_LASTPING, _) => {}
                (id, _) if source == MetSource::Foreign && is_ember_private_tag(id) => {}
                (id, _) => apply_server_int_tag(&mut entry, id, v),
            },
            MetTagValue::Other => {}
        }
    }
    // Not usable until our public address is known and matches.
    entry.parked_udp_key = std::mem::take(&mut entry.server_udp_key);
    Ok(entry)
}

/// A blank name, a bare address, or `address:port`: a placeholder rather than
/// a label anybody chose, and so free to be replaced by what the server calls
/// itself.
fn is_placeholder_server_name(name: &str, entry_ip: &str) -> bool {
    let name = name.trim();
    let host = name.rsplit_once(':').map_or(name, |(host, port)| {
        if port.parse::<u16>().is_ok() { host } else { name }
    });
    name.is_empty()
        || name.parse::<Ipv4Addr>().is_ok()
        || host.parse::<Ipv4Addr>().is_ok()
        || name.eq_ignore_ascii_case(entry_ip)
}

pub struct ServerList {
    servers: Vec<ServerEntry>,
}

impl ServerList {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: ServerEntry) {
        if !self
            .servers
            .iter()
            .any(|s| s.ip == entry.ip && s.port == entry.port)
        {
            if self.servers.len() >= MAX_SERVER_LIST_ENTRIES {
                debug!(
                    "Ignoring server {}:{} because server list is at cap ({MAX_SERVER_LIST_ENTRIES})",
                    entry.ip, entry.port
                );
                return;
            }
            self.servers.push(entry);
        }
    }

    /// Remove all servers whose IP is blocked by the IP filter.
    /// Returns the number of servers removed.
    pub fn remove_filtered(
        &mut self,
        ip_filter: &mut crate::network::kad::ip_filter::IpFilter,
    ) -> usize {
        // While an enabled filter is still loading ranges, `is_blocked` fail-closes
        // for every public IP. Running retain in that window would wipe server.met.
        // Callers re-run after `mark_ranges_ready` (deferred load / enable).
        if ip_filter.is_enabled() && !ip_filter.ranges_ready() {
            return 0;
        }
        let before = self.servers.len();
        self.servers.retain(|s| {
            if let Ok(addr) = s.ip.parse::<Ipv4Addr>() {
                if ip_filter.is_blocked(addr) {
                    info!("Removing server {}:{} — blocked by IP filter", s.ip, s.port);
                    return false;
                }
            }
            true
        });
        before - self.servers.len()
    }

    /// Check if a server IP is blocked by the IP filter, matching eMule's FilterServerByIP.
    ///
    /// While the filter is enabled but `ipfilter.dat` has not finished loading,
    /// peer paths fail-closed. Applying that same gate here would drop every
    /// public server from `server.met` on first launch and then persist the
    /// empty list. Admit until ranges are ready; `remove_filtered` runs after
    /// the deferred load.
    pub fn is_ip_filtered(
        ip_str: &str,
        ip_filter: &mut crate::network::kad::ip_filter::IpFilter,
    ) -> bool {
        if ip_filter.is_enabled() && !ip_filter.ranges_ready() {
            return false;
        }
        if let Ok(addr) = ip_str.parse::<Ipv4Addr>() {
            ip_filter.is_blocked(addr)
        } else {
            false
        }
    }

    /// Add a server entry, checking against IP filter if enabled.
    /// Returns true if the server was added.
    pub fn add_filtered(
        &mut self,
        entry: ServerEntry,
        filter_by_ip: bool,
        ip_filter: &mut crate::network::kad::ip_filter::IpFilter,
    ) -> AddServerOutcome {
        if self
            .servers
            .iter()
            .any(|s| s.ip == entry.ip && s.port == entry.port)
        {
            return AddServerOutcome::Duplicate;
        }
        if filter_by_ip && Self::is_ip_filtered(&entry.ip, ip_filter) {
            // Per-entry filter blocks are noisy: a single push from a
            // connected server can carry 25+ entries, almost all of
            // which get filtered when a strict ipfilter.dat (e.g.
            // emule-security) is in use. The aggregate count is
            // surfaced by the caller (see `add_from_server_list_packet`),
            // so per-entry detail is debug-only.
            debug!("Server {}:{} blocked by IP filter", entry.ip, entry.port);
            return AddServerOutcome::Filtered;
        }
        if self.servers.len() >= MAX_SERVER_LIST_ENTRIES {
            debug!(
                "Ignoring server {}:{} because server list is at cap ({MAX_SERVER_LIST_ENTRIES})",
                entry.ip, entry.port
            );
            return AddServerOutcome::AtCapacity;
        }
        self.servers.push(entry);
        AddServerOutcome::Added
    }

    /// Parse an OP_SERVERLIST packet payload (count + IP/port pairs) from a connected server.
    /// Returns the list of (ip_string, port) pairs discovered.
    pub fn add_from_server_list_packet(
        &mut self,
        payload: &[u8],
        filter_by_ip: bool,
        ip_filter: &mut crate::network::kad::ip_filter::IpFilter,
    ) -> usize {
        if payload.is_empty() {
            return 0;
        }
        let mut cursor = Cursor::new(payload);
        let count = match cursor.read_u8() {
            Ok(c) => c as usize,
            Err(_) => return 0,
        };
        // Validate: 1 + count * 6 (4 bytes IP + 2 bytes port) should fit
        if payload.len() < 1 + count * 6 {
            return 0;
        }
        let mut added = 0;
        let mut filtered = 0;
        let mut unroutable = 0;
        let mut duplicate = 0;
        let mut at_capacity = 0;
        for _ in 0..count {
            let ip_raw = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let port = match cursor.read_u16::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let ip = Ipv4Addr::from(ip_raw.to_le_bytes());
            // Whatever the IP filter says, and before it has loaded: a loopback
            // or LAN address from a remote server names one of its machines,
            // never one of ours.
            if port == 0 || crate::security::is_special_use_v4(ip) {
                unroutable += 1;
                continue;
            }
            let mut entry = ServerEntry::new(ip.to_string(), port);
            entry.name = ip.to_string();
            entry.priority = ServerPriority::Low;
            match self.add_filtered(entry, filter_by_ip, ip_filter) {
                AddServerOutcome::Added => added += 1,
                AddServerOutcome::Filtered => filtered += 1,
                AddServerOutcome::Duplicate => duplicate += 1,
                AddServerOutcome::AtCapacity => at_capacity += 1,
            }
        }
        // Always summarise the push if it carried anything actionable —
        // before, a list of 27 entries that were all IP-filtered would
        // produce 27 INFO lines and no aggregate. Now: one line.
        if added > 0 || filtered > 0 || unroutable > 0 || at_capacity > 0 {
            info!(
                "Server list push: {added} added, {filtered} blocked by IP filter, \
                 {unroutable} unroutable, {duplicate} duplicate, \
                 {at_capacity} dropped at capacity (out of {count})",
            );
        }
        added
    }

    pub fn remove(&mut self, ip: &str, port: u16) -> bool {
        let before = self.servers.len();
        self.servers.retain(|s| !(s.ip == ip && s.port == port));
        self.servers.len() != before
    }

    /// Clear per-server connect cooldowns so an explicit user Connect can
    /// retry servers that recently failed. Fail counts are kept for sort
    /// preference (prefer less-failed servers) but do not block the attempt.
    pub fn clear_connect_cooldowns(&mut self) {
        for entry in &mut self.servers {
            entry.last_failed_at = 0;
        }
    }

    /// eMule MAX_SERVERFAILCOUNT = 10
    const MAX_FAIL_COUNT: u32 = 10;

    /// Count a failed connect to `ip:port`, and remove it once it has failed
    /// MAX_SERVERFAILCOUNT times unless it is static (eMule) or `keep`.
    ///
    /// `keep` is for the server auto-reconnect is still trying to reach:
    /// removing it would leave Ember dialing a server the list no longer shows.
    /// Only the server that failed is judged; a count read from an imported
    /// file is not a failure of ours, and is left until that server fails.
    pub fn record_failure(&mut self, ip: &str, port: u16, keep: bool) {
        let Some(pos) = self
            .servers
            .iter()
            .position(|s| s.ip == ip && s.port == port)
        else {
            return;
        };
        let entry = &mut self.servers[pos];
        entry.fail_count = entry.fail_count.saturating_add(1);
        entry.last_failed_at = chrono::Utc::now().timestamp();
        if !keep && !entry.is_static && entry.fail_count >= Self::MAX_FAIL_COUNT {
            info!(
                "Removing server {}:{} after {} consecutive failures",
                entry.ip, entry.port, entry.fail_count
            );
            self.servers.remove(pos);
        }
    }

    /// Record that we sent this server a UDP source query (`OP_GLOBGETSOURCES`
    /// / `OP_GLOBGETSOURCES2`).
    ///
    /// Not a failure when nothing comes back: a server with no sources for a
    /// file says nothing at all, so counting the silence shut healthy servers
    /// out of source discovery after a few rare downloads. Whether a server is
    /// alive is judged on its status pings instead (`record_udp_ping_sent`).
    pub fn record_udp_query_sent(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.last_udp_query_at = chrono::Utc::now().timestamp();
        }
    }

    /// Record a status ping sent at `at`, as eMule's `ServerStats` does. A
    /// plain ping counts as unanswered until a reply clears it
    /// (`record_udp_reply`). An obfuscated one is not counted: the server may
    /// simply not take it, so a plain ping follows 20 s later if no answer
    /// came.
    pub fn record_udp_ping_sent(&mut self, ip: &str, port: u16, at: i64, obfuscated: bool) {
        const CRYPT_PING_REPLY_WINDOW_SECS: i64 = 20;
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            if obfuscated {
                entry.crypt_ping_pending = true;
                entry.last_udp_ping_at = at
                    - super::server_udp::STAT_REASK_INTERVAL_SECS
                    + CRYPT_PING_REPLY_WINDOW_SECS;
            } else {
                entry.crypt_ping_pending = false;
                entry.last_udp_ping_at = at;
                entry.udp_consecutive_failures = entry.udp_consecutive_failures.saturating_add(1);
            }
        }
    }

    /// Record that this server sent us *any* UDP reply (status response
    /// or found-sources). Resets both failure counters, as eMule's
    /// `ResetFailedCount` on every server UDP packet does
    /// (`UDPSocket.cpp:217-220`): a server that answers is alive whatever our
    /// last TCP attempt ran into, and without this a few failed logins — or
    /// our own network being down — excluded it from UDP use and eventually
    /// deleted it. Also timestamps the reply for the periodic UDP-health log.
    pub fn record_udp_reply(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.udp_consecutive_failures = 0;
            entry.fail_count = 0;
            entry.crypt_ping_pending = false;
            entry.last_udp_reply_at = chrono::Utc::now().timestamp();
        }
    }

    /// Record that this server sent us a `OP_GLOBFOUNDSOURCES` reply
    /// specifically — meaning it actually has source data for at
    /// least one of the file hashes we asked about. Distinct from
    /// `record_udp_reply` (which fires on status pings too); this
    /// one feeds the "source-responsive" column in the periodic
    /// UDP-health log so the user can see which servers are useful
    /// for source discovery vs which are just status-ping-alive.
    pub fn record_udp_source_reply(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.last_udp_source_reply_at = chrono::Utc::now().timestamp();
        }
    }

    pub fn record_success(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.fail_count = 0;
            entry.last_ping = chrono::Utc::now().timestamp();
            entry.last_failed_at = 0;
        }
    }

    pub fn servers(&self) -> &[ServerEntry] {
        &self.servers
    }

    /// Mark a server static, or let it become prunable again.
    ///
    /// Static is eMule's "keep this one": [`Self::record_failure`] exempts it
    /// from the fail-count eviction, and `to_server_met_bytes` persists it as
    /// tag `0x8A`. `add_filtered` already sets it for a server the user typed
    /// in by hand; this is the only way a server that arrived in a downloaded
    /// `server.met` can be given the same standing without being removed and
    /// re-added.
    ///
    /// Returns whether the server was in the list.
    pub fn set_static(&mut self, ip: &str, port: u16, is_static: bool) -> bool {
        match self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            Some(entry) => {
                entry.is_static = is_static;
                true
            }
            None => false,
        }
    }

    /// Set a server's connection priority. Returns whether the server was in
    /// the list.
    pub fn set_priority(&mut self, ip: &str, port: u16, priority: ServerPriority) -> bool {
        match self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            Some(entry) => {
                entry.priority = priority;
                true
            }
            None => false,
        }
    }

    pub fn find_by_addr(&self, ip: &str, port: u16) -> Option<&ServerEntry> {
        self.servers.iter().find(|s| s.ip == ip && s.port == port)
    }

    /// Prefer the well-known Sunrise IP/port when present in the list; otherwise
    /// match the canonical display name (case-insensitive).
    pub fn find_emule_sunrise(&self) -> Option<&ServerEntry> {
        if let Some(entry) = self.find_by_addr(EMULE_SUNRISE_IP, EMULE_SUNRISE_PORT) {
            return Some(entry);
        }
        self.servers
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(EMULE_SUNRISE_NAME))
    }

    /// Resolve auto-connect target: the last successful server; else the best
    /// High-priority server; else eMule Sunrise from the current list.
    ///
    /// Priority means what it does in eMule, which picks the server to connect
    /// to by it: High is tried first and Low never chosen for you. It does not
    /// make Ember leave a server it is already trying to reach.
    pub fn resolve_auto_connect_target(data_dir: &Path, list: &Self) -> Option<(String, u16)> {
        let last_path = data_dir.join("last_ed2k_server.json");
        // Only while it is still in the list: one the user removed, or that
        // was pruned, is not somewhere to go back to.
        if let Some(last) = LastEd2kServer::load(&last_path)
            .filter(|last| list.find_by_addr(&last.ip, last.port).is_some())
        {
            info!(
                "Auto-connect target from last server: {}:{} ({})",
                last.ip,
                last.port,
                if last.name.is_empty() {
                    "unnamed"
                } else {
                    last.name.as_str()
                }
            );
            return Some((last.ip, last.port));
        }
        // The one most likely to answer: fewest failures, then most users.
        let high = list
            .servers
            .iter()
            .filter(|s| s.priority == ServerPriority::High)
            .min_by_key(|s| (s.fail_count, std::cmp::Reverse(s.user_count)));
        if let Some(server) = high {
            info!(
                "Auto-connect target from High priority: {} {}:{}",
                server.name, server.ip, server.port
            );
            return Some((server.ip.clone(), server.port));
        }
        if let Some(sunrise) = list
            .find_emule_sunrise()
            .filter(|s| s.priority != ServerPriority::Low)
        {
            info!(
                "Auto-connect target fallback: {} {}:{}",
                sunrise.name, sunrise.ip, sunrise.port
            );
            return Some((sunrise.ip.clone(), sunrise.port));
        }
        warn!("No last eD2K server, no High-priority server, and eMule Sunrise not usable");
        None
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Load servers from eMule server.met format.
    pub fn load_server_met(path: &Path) -> io::Result<Self> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_SERVER_MET_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("server.met too large (max {MAX_SERVER_MET_BYTES} bytes)"),
            ));
        }
        let data = std::fs::read(path)?;
        let list = Self::parse_server_met(&data)?;
        info!("Loaded {} servers from server.met", list.len());
        Ok(list)
    }

    /// Ember's own server.met, already read.
    fn parse_server_met(data: &[u8]) -> io::Result<Self> {
        if data.len() < 5 {
            return Ok(Self::new());
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != 0x0E && version != 0xE0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown server.met version: 0x{version:02X}"),
            ));
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;
        // Cap raised from 500 → 5000. The previous 500 cap silently
        // truncated large server lists; the next save would then
        // overwrite the file with the truncated subset, permanently
        // dropping every server beyond the cap. 5000 is generous
        // enough for any realistic eMule server.met (the current
        // public list is ~30 servers) while still bounding worst-
        // case memory and parse time. If the count exceeds the cap
        // we fail-closed so a malformed/huge file can't OOM us.
        const MAX_SERVERS: usize = 5_000;
        if count > MAX_SERVERS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "server.met declares {count} servers, exceeding cap of {MAX_SERVERS}; refusing to load to avoid silent truncation",
                ),
            ));
        }
        let mut list = Self::new();

        for _ in 0..count {
            // Structural damage fails the whole load: the caller keeps the
            // file rather than saving a partial list over it.
            let entry = read_met_entry(&mut cursor, MetSource::Own)?;
            list.add(entry);
        }
        Ok(list)
    }

    /// Merge servers from raw server.met bytes without clearing existing list.
    /// If filter_by_ip is true and ip_filter is Some, servers are checked against the IP filter.
    ///
    /// `keep_file_priorities` is for the user's own eMule list; a downloaded
    /// one's priorities are dropped, as eMule does.
    pub fn merge_from_bytes_filtered(
        &mut self,
        data: &[u8],
        filter_by_ip: bool,
        mut ip_filter: Option<&mut crate::network::kad::ip_filter::IpFilter>,
        keep_file_priorities: bool,
    ) -> anyhow::Result<ServerMergeStats> {
        if data.len() < 5 {
            return Ok(ServerMergeStats::default());
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != 0x0E && version != 0xE0 && version != 0x0C {
            anyhow::bail!("Unknown server.met version: 0x{version:02X}");
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;
        // Match load_server_met: reject absurd counts instead of silently
        // truncating. The previous `count.min(500)` cap dropped every server
        // past the 500th with no signal, so merging a large list appeared to
        // succeed while importing only a 500-entry prefix.
        const MAX_MERGE_SERVERS: usize = 5_000;
        if count > MAX_MERGE_SERVERS {
            anyhow::bail!(
                "server.met declares {count} servers, exceeding cap of {MAX_MERGE_SERVERS}; refusing to merge to avoid silent truncation"
            );
        }
        let mut stats = ServerMergeStats::default();

        for _ in 0..count {
            // A tag of a type with no known size, or a file that ends early,
            // leaves nothing after it that can be found. Keep what was read
            // and say the file was cut short.
            let mut entry = match read_met_entry(&mut cursor, MetSource::Foreign) {
                Ok(entry) => entry,
                Err(e) => {
                    debug!("server.met merge stopped early: {e}");
                    stats.truncated = true;
                    break;
                }
            };

            if let Some(existing) = self
                .servers
                .iter_mut()
                .find(|s| s.ip == entry.ip && s.port == entry.port)
            {
                // eMule takes the list's name for a server it already has. Not
                // over a name the user gave a server of their own, though.
                if !entry.name.is_empty()
                    && (!existing.is_static
                        || is_placeholder_server_name(&existing.name, &existing.ip))
                {
                    existing.name = entry.name;
                }
                if !entry.description.is_empty() {
                    existing.description = entry.description;
                }
                if entry.user_count > 0 {
                    existing.user_count = entry.user_count;
                }
                if entry.file_count > 0 {
                    existing.file_count = entry.file_count;
                }
                if entry.max_users > 0 {
                    existing.max_users = entry.max_users;
                }
                if entry.soft_files > 0 {
                    existing.soft_files = entry.soft_files;
                }
                if entry.hard_files > 0 {
                    existing.hard_files = entry.hard_files;
                }
                if entry.obfuscation_port_tcp > 0 {
                    existing.obfuscation_port_tcp = entry.obfuscation_port_tcp;
                }
                // Merge UDP-obfuscation state too: a fresh import can carry
                // material we'd otherwise lose by ignoring these fields. Not
                // the key: one from another client's file was issued to that
                // client, and ours comes with the next status reply.
                if entry.obfuscation_port_udp > 0 {
                    existing.obfuscation_port_udp = entry.obfuscation_port_udp;
                }
                if entry.udp_flags != 0 {
                    existing.udp_flags = entry.udp_flags;
                }
                // The priority on an existing server is the user's. An import
                // of their own eMule list may fill in one they never set.
                if keep_file_priorities
                    && existing.priority == ServerPriority::Normal
                    && entry.priority != ServerPriority::Normal
                {
                    existing.priority = entry.priority;
                }
                stats.updated += 1;
                continue;
            }

            // eMule drops the priority a downloaded list sets: providers have
            // shipped dead servers marked High.
            if !keep_file_priorities {
                entry.priority = ServerPriority::Normal;
            }

            // Nothing Ember will dial: connecting refuses these addresses, so
            // the row could only sit in the list and be pinged over the LAN.
            let unroutable = entry.port == 0
                || entry
                    .ip
                    .parse::<Ipv4Addr>()
                    .map_or(true, crate::security::is_special_use_v4);
            if unroutable {
                stats.filtered += 1;
                continue;
            }

            if filter_by_ip {
                if let Some(filter) = ip_filter.as_deref_mut() {
                    if Self::is_ip_filtered(&entry.ip, filter) {
                        stats.filtered += 1;
                        continue;
                    }
                }
            }

            if self.servers.len() >= MAX_SERVER_LIST_ENTRIES {
                stats.at_capacity += 1;
                continue;
            }
            self.servers.push(entry);
            stats.added += 1;
        }

        info!(
            "Merged server.met data: {} added, {} updated, {} filtered, {} dropped at capacity \
             ({} total in file)",
            stats.added, stats.updated, stats.filtered, stats.at_capacity, count
        );
        Ok(stats)
    }

    pub fn update_server_stats(
        &mut self,
        ip: &str,
        port: u16,
        users: u32,
        files: u32,
        obfuscation_port_tcp: u16,
    ) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.user_count = users;
            entry.file_count = files;
            entry.last_ping = chrono::Utc::now().timestamp();
            if obfuscation_port_tcp != 0 && entry.obfuscation_port_tcp != obfuscation_port_tcp {
                tracing::info!(
                    "Learned obfuscation TCP port {} for server {ip}:{port} from UDP ping",
                    obfuscation_port_tcp
                );
                entry.obfuscation_port_tcp = obfuscation_port_tcp;
            }
        }
    }

    /// Store the server's advertised capacity limits (from extended UDP
    /// status): user capacity and the soft/hard per-client file limits.
    ///
    /// eMule caps `OP_OFFERFILES` at `min(soft_files, 200)`, so learning and
    /// persisting that (ST_SOFTFILES) makes the cap match on later connects.
    /// `max_users` (ST_MAXUSERS) and `hard_files` (ST_HARDFILES) were parsed
    /// off the wire and thrown away, which left the Servers page unable to say
    /// how close a server was to full or how much of a large library it could
    /// actually index — so they are stored on the same footing now.
    ///
    /// Each field only overwrites with a non-zero value, so a status reply
    /// without the extended fields can't clear a previously learned limit.
    pub fn update_capacity_limits(
        &mut self,
        ip: &str,
        port: u16,
        max_users: u32,
        soft_files: u32,
        hard_files: u32,
    ) {
        if max_users == 0 && soft_files == 0 && hard_files == 0 {
            return;
        }
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            if max_users != 0 && entry.max_users != max_users {
                tracing::info!(
                    "Learned user capacity {max_users} for server {ip}:{port} from UDP status"
                );
                entry.max_users = max_users;
            }
            if soft_files != 0 && entry.soft_files != soft_files {
                tracing::info!(
                    "Learned soft file limit {soft_files} for server {ip}:{port} from UDP status"
                );
                entry.soft_files = soft_files;
            }
            if hard_files != 0 && entry.hard_files != hard_files {
                tracing::info!(
                    "Learned hard file limit {hard_files} for server {ip}:{port} from UDP status"
                );
                entry.hard_files = hard_files;
            }
        }
    }

    /// Store per-server UDP obfuscation material from extended status
    /// ping responses. Both fields are optional (servers that don't
    /// support UDP obfuscation send 0 / 0); we only overwrite a stored
    /// non-zero value if the new one is also non-zero, so that a
    /// missing-extended-fields response doesn't clear what we already
    /// learned earlier in the session.
    pub fn update_udp_obfuscation(
        &mut self,
        ip: &str,
        port: u16,
        obfuscation_port_udp: u16,
        server_udp_key: u32,
        public_ip: Option<Ipv4Addr>,
    ) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            let current = public_ip.map(met_ip_u32).unwrap_or(0);
            if obfuscation_port_udp != 0 {
                entry.obfuscation_port_udp = obfuscation_port_udp;
            }
            if server_udp_key != 0 {
                if entry.server_udp_key != server_udp_key {
                    tracing::info!(
                        "Learned UDP obfuscation key for server {ip}:{port} (key={server_udp_key:#x}, obf_port={obfuscation_port_udp})",
                    );
                }
                // Issued for the address the server saw us at, which is our
                // current one. Unknown yet, it is stamped once it is known.
                entry.server_udp_key = server_udp_key;
                entry.parked_udp_key = 0;
                entry.server_udp_key_ip = current;
            } else if current != 0
                && entry.server_udp_key != 0
                && entry.server_udp_key_ip != 0
                && entry.server_udp_key_ip != current
            {
                entry.server_udp_key = 0;
                tracing::info!(
                    "Discarded stale UDP obfuscation key for server {ip}:{port} after public IP changed",
                );
            }
        }
    }

    /// Our public address is now `public_ip`. A key is bound to the address it
    /// was issued for (eMule's `GetServerKeyUDP`): one for another address is
    /// dropped, and while ours is unknown none is used, but kept for when it
    /// is known again. Keys read from disk wait here for that check.
    pub fn invalidate_udp_keys_for_public_ip(&mut self, public_ip: Option<Ipv4Addr>) {
        let Some(public_ip) = public_ip else {
            for entry in &mut self.servers {
                if entry.server_udp_key != 0 {
                    entry.parked_udp_key = entry.server_udp_key;
                    entry.server_udp_key = 0;
                }
            }
            return;
        };
        let current = met_ip_u32(public_ip);
        for entry in &mut self.servers {
            if entry.parked_udp_key != 0 {
                if entry.server_udp_key_ip == current {
                    entry.server_udp_key = entry.parked_udp_key;
                }
                entry.parked_udp_key = 0;
            }
            if entry.server_udp_key != 0 {
                if entry.server_udp_key_ip == 0 {
                    // Learned this session while the address was unknown.
                    entry.server_udp_key_ip = current;
                } else if entry.server_udp_key_ip != current {
                    entry.server_udp_key = 0;
                }
            }
        }
    }

    /// Inverse lookup: given an inbound UDP `(src_ip, src_port)`, find
    /// which server it belongs to and return:
    ///
    /// * `base_key` — server's `dwServerUDPKey` for obfuscation, or 0 if
    ///   obfuscation isn't applicable here (still returned for the
    ///   canonicalisation path).
    /// * `tcp_port` — server's canonical TCP port, used to normalise the recv
    ///   source addr so downstream handlers' `addr.port() - 4` arithmetic
    ///   continues to give the right value even when the reply arrived from a
    ///   non-standard `obfuscation_port_udp`.
    ///
    /// Returns `None` only when no server in the list matches the
    /// given source `(ip, port)` pair via either the standard UDP
    /// port (TCP+4) or the advertised obfuscation UDP port.
    pub fn lookup_for_udp_addr(&self, ip: std::net::Ipv4Addr, src_port: u16) -> Option<(u32, u16)> {
        let ip_str = ip.to_string();
        for entry in &self.servers {
            if entry.ip != ip_str {
                continue;
            }
            let tcp_port = entry.port;
            let std_udp = tcp_port.saturating_add(4);
            let obf_udp = entry.obfuscation_port_udp;
            if src_port == std_udp || (obf_udp != 0 && src_port == obf_udp) {
                return Some((entry.server_udp_key, tcp_port));
            }
        }
        None
    }

    /// Store per-server UDP capability flags from status ping responses.
    pub fn update_udp_flags(&mut self, ip: &str, port: u16, udp_flags: u32) {
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            entry.udp_flags = udp_flags;
        }
    }

    /// Update a server display name learned from live protocol data.
    /// To avoid clobbering user-provided labels, we only replace empty/IP-like names.
    pub fn update_server_name_from_ident(&mut self, ip: &str, port: u16, name: &str) -> bool {
        let sanitized = crate::security::sanitize_remote_text(name, MAX_SERVER_TAG_STR_LEN);
        let trimmed = sanitized.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(entry) = self
            .servers
            .iter_mut()
            .find(|s| s.ip == ip && s.port == port)
        {
            if is_placeholder_server_name(&entry.name, &entry.ip) && entry.name.trim() != trimmed
            {
                entry.name = trimmed.to_string();
                return true;
            }
        }
        false
    }

    /// Whether this server still goes by a placeholder (blank, or its own
    /// address) and so would take a name if it told us one.
    pub fn has_placeholder_name(&self, ip: &str, port: u16) -> bool {
        self.find_by_addr(ip, port)
            .is_some_and(|s| is_placeholder_server_name(&s.name, &s.ip))
    }

    /// Serialize the server list to server.met bytes (no disk I/O).
    pub fn to_server_met_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        buf.write_u8(0x0E)?; // MET_HEADER
        buf.write_u32::<LittleEndian>(self.servers.len() as u32)?;

        for entry in &self.servers {
            let ip: std::net::Ipv4Addr =
                entry.ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
            buf.write_u32::<LittleEndian>(u32::from_le_bytes(ip.octets()))?;
            buf.write_u16::<LittleEndian>(entry.port)?;

            let mut tag_count: u32 = 0;
            let mut tag_buf = Vec::new();

            // CT_NAME (0x01) - string
            if !entry.name.is_empty() {
                write_met_string_tag(&mut tag_buf, 0x01, &entry.name);
                tag_count += 1;
            }

            // CT_DESCRIPTION (0x0B) - string
            if !entry.description.is_empty() {
                write_met_string_tag(&mut tag_buf, 0x0B, &entry.description);
                tag_count += 1;
            }

            // CT_SERVERPRIORITY (0x0E) - uint32 (eMule: 0=normal, 1=high, 2=low)
            {
                let prio_val: u32 = match entry.priority {
                    ServerPriority::Normal => 0,
                    ServerPriority::High => 1,
                    ServerPriority::Low => 2,
                };
                write_met_uint32_tag(&mut tag_buf, 0x0E, prio_val);
                tag_count += 1;
            }

            // ST_FAIL (0x0D) - uint32. Older Ember files used 0x85, which is
            // eMule's ST_DYNIP; the reader still accepts an integer there.
            if entry.fail_count > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x0D, entry.fail_count);
                tag_count += 1;
            }

            // "users" and "files" - uint32, named in full as eMule writes them.
            if entry.user_count > 0 {
                write_met_named_uint32_tag(&mut tag_buf, "users", entry.user_count);
                tag_count += 1;
            }
            if entry.file_count > 0 {
                write_met_named_uint32_tag(&mut tag_buf, "files", entry.file_count);
                tag_count += 1;
            }

            // CT_LASTPING (0x86) - uint32
            if entry.last_ping > 0 {
                write_met_uint32_tag(
                    &mut tag_buf,
                    0x86,
                    (entry.last_ping as u64).min(u32::MAX as u64) as u32,
                );
                tag_count += 1;
            }

            // CT_MAXUSERS (0x87) - uint32
            if entry.max_users > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x87, entry.max_users);
                tag_count += 1;
            }

            // CT_SOFTFILES (0x88) - uint32
            if entry.soft_files > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x88, entry.soft_files);
                tag_count += 1;
            }

            // CT_HARDFILES (0x89) - uint32
            if entry.hard_files > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x89, entry.hard_files);
                tag_count += 1;
            }

            // CT_PREFERENCE (0x0E via is_static flag)
            if entry.is_static {
                write_met_uint32_tag(&mut tag_buf, 0x8A, 1);
                tag_count += 1;
            }

            // ST_TCPPORTOBFUSCATION (0x97) - uint16
            if entry.obfuscation_port_tcp > 0 {
                write_met_uint16_tag(
                    &mut tag_buf,
                    ST_TCPPORTOBFUSCATION,
                    entry.obfuscation_port_tcp,
                );
                tag_count += 1;
            }

            // ST_UDPPORTOBFUSCATION (0x98) - uint16
            if entry.obfuscation_port_udp > 0 {
                write_met_uint16_tag(
                    &mut tag_buf,
                    ST_UDPPORTOBFUSCATION,
                    entry.obfuscation_port_udp,
                );
                tag_count += 1;
            }

            // ST_UDPKEY (0x95) and ST_UDPKEYIP (0x96) - uint32. A parked key
            // is still the server's, and is written so it is not lost.
            let udp_key = if entry.server_udp_key != 0 {
                entry.server_udp_key
            } else {
                entry.parked_udp_key
            };
            if udp_key != 0 {
                write_met_uint32_tag(&mut tag_buf, ST_UDPKEY, udp_key);
                tag_count += 1;
                if entry.server_udp_key_ip != 0 {
                    write_met_uint32_tag(&mut tag_buf, ST_UDPKEYIP, entry.server_udp_key_ip);
                    tag_count += 1;
                }
            }

            // ST_LASTPING (0x90) - uint32 Unix time, as eMule writes it.
            if entry.last_udp_ping_at > 0 {
                let wall = ping_time_to_wall(entry.last_udp_ping_at);
                if let Ok(wall) = u32::try_from(wall) {
                    write_met_uint32_tag(&mut tag_buf, ST_LASTPING, wall);
                    tag_count += 1;
                }
            }

            // ST_UDPFLAGS (0x92) - uint32
            if entry.udp_flags != 0 {
                write_met_uint32_tag(&mut tag_buf, ST_UDPFLAGS, entry.udp_flags);
                tag_count += 1;
            }

            // Per-server UDP-responsiveness counters (Ember-private
            // 0xF5/0xF6). Persisting `udp_consecutive_failures`
            // means a server that's been confirmed dead-for-UDP in
            // a previous session stays excluded across restarts; it
            // gets re-tried the moment any inbound UDP arrives (the
            // recv path resets the counter). Without persistence,
            // every launch wastes a full pruning round on
            // already-known-dead endpoints.
            if entry.udp_consecutive_failures > 0 {
                write_met_uint32_tag(&mut tag_buf, 0xF5, entry.udp_consecutive_failures);
                tag_count += 1;
            }
            if entry.last_udp_reply_at > 0 {
                let ts32 = entry.last_udp_reply_at.clamp(0, u32::MAX as i64) as u32;
                write_met_uint32_tag(&mut tag_buf, 0xF6, ts32);
                tag_count += 1;
            }
            if entry.last_udp_source_reply_at > 0 {
                let ts32 = entry.last_udp_source_reply_at.clamp(0, u32::MAX as i64) as u32;
                write_met_uint32_tag(&mut tag_buf, 0xF7, ts32);
                tag_count += 1;
            }

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tag_buf)?;
        }

        Ok(buf)
    }

    /// Persist server.met bytes atomically. Prefer
    /// `network::spawn_save_server_met` from the event loop so disk I/O
    /// stays off the network task.
    pub fn write_server_met_bytes(path: &Path, buf: &[u8]) -> io::Result<()> {
        // Use atomic_write so a crash mid-save can't truncate or
        // zero-out server.met. Without this, the next start could
        // load 0 servers and silently lose the persisted list.
        crate::security::atomic_write(path, buf, false)
    }
}

/// A string tag the reader takes back unchanged: within its byte cap, and
/// marked as UTF-8 when it is not plain ASCII, so eMule reads it as UTF-8 too
/// rather than in its local code page.
fn write_met_string_tag(buf: &mut Vec<u8>, tag_id: u8, value: &str) {
    const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
    buf.push(0x02); // TAGTYPE_STRING
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(tag_id);
    let text = truncate_to_bytes(value, MAX_SERVER_TAG_STR_LEN - BOM.len());
    let bom: &[u8] = if text.is_ascii() { &[] } else { &BOM };
    buf.extend_from_slice(&((bom.len() + text.len()) as u16).to_le_bytes());
    buf.extend_from_slice(bom);
    buf.extend_from_slice(text.as_bytes());
}

fn write_met_named_uint32_tag(buf: &mut Vec<u8>, name: &str, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(name.as_bytes());
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_met_uint32_tag(buf: &mut Vec<u8>, tag_id: u8, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(tag_id);
    buf.extend_from_slice(&value.to_le_bytes());
}

fn write_met_uint16_tag(buf: &mut Vec<u8>, tag_id: u8, value: u16) {
    buf.push(0x08); // TAGTYPE_UINT16
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(tag_id);
    buf.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two-server fixture: one High-priority entry and one Normal, used by
    /// cooldown tests that previously depended on `ServerList::hardcoded()`.
    fn high_then_normal_list() -> ServerList {
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "1.1.1.1".to_string(),
            port: 1000,
            name: "High Priority".to_string(),
            priority: ServerPriority::High,
            is_static: true,
            ..ServerEntry::new(String::new(), 0)
        });
        list.add(ServerEntry {
            ip: "2.2.2.2".to_string(),
            port: 2000,
            name: "Normal Priority".to_string(),
            is_static: true,
            ..ServerEntry::new(String::new(), 0)
        });
        list
    }

    #[test]
    fn a_server_named_by_its_ip_takes_the_name_it_announces() {
        let mut list = ServerList::new();
        for (ip, port, name) in [
            ("3.3.3.3", 4661, "3.3.3.3"),
            ("4.4.4.4", 4661, "4.4.4.4:4661"),
            ("5.5.5.5", 4661, ""),
        ] {
            list.add(ServerEntry {
                ip: ip.to_string(),
                port,
                name: name.to_string(),
                ..ServerEntry::new(String::new(), 0)
            });
            assert!(
                list.update_server_name_from_ident(ip, port, "Real Server"),
                "{name:?} is a placeholder"
            );
            assert_eq!(list.find_by_addr(ip, port).unwrap().name, "Real Server");
        }
    }

    #[test]
    fn a_name_somebody_chose_is_not_overwritten_by_the_ident() {
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "6.6.6.6".to_string(),
            port: 4661,
            name: "My Server".to_string(),
            ..ServerEntry::new(String::new(), 0)
        });
        assert!(!list.update_server_name_from_ident("6.6.6.6", 4661, "Announced"));
        assert_eq!(list.find_by_addr("6.6.6.6", 4661).unwrap().name, "My Server");
    }

    #[test]
    fn find_emule_sunrise_prefers_known_addr_then_name() {
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "9.9.9.9".to_string(),
            port: 1234,
            name: "eMule Sunrise".to_string(),
            ..ServerEntry::new(String::new(), 0)
        });
        let by_name = list.find_emule_sunrise().expect("name match");
        assert_eq!(by_name.ip, "9.9.9.9");

        list.add(ServerEntry {
            ip: EMULE_SUNRISE_IP.to_string(),
            port: EMULE_SUNRISE_PORT,
            name: "Other Label".to_string(),
            ..ServerEntry::new(String::new(), 0)
        });
        let by_ip = list.find_emule_sunrise().expect("ip match");
        assert_eq!(by_ip.ip, EMULE_SUNRISE_IP);
        assert_eq!(by_ip.port, EMULE_SUNRISE_PORT);
    }

    #[test]
    fn clear_connect_cooldowns_allows_retrying_high_again() {
        let mut list = high_then_normal_list();
        let failed_at = |list: &ServerList| {
            list.find_by_addr("1.1.1.1", 1000)
                .expect("fixture has the High server")
                .last_failed_at
        };
        list.record_failure("1.1.1.1", 1000, false);
        assert!(failed_at(&list) > 0, "a failed login starts the cooldown");

        list.clear_connect_cooldowns();
        assert_eq!(
            failed_at(&list),
            0,
            "an explicit Connect clears the cooldown so the High server can be retried"
        );
    }

    #[test]
    fn is_ip_filtered_admits_public_ips_while_fail_closed() {
        let mut filter = crate::network::kad::ip_filter::IpFilter::new(true, false);
        assert!(!filter.ranges_ready());
        assert!(
            !ServerList::is_ip_filtered("8.8.8.8", &mut filter),
            "fail-closed must not empty server.met on first launch"
        );
        filter.mark_ranges_ready();
        filter.add_range(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(8, 8, 8, 8),
            "blocked".to_string(),
        );
        assert!(ServerList::is_ip_filtered("8.8.8.8", &mut filter));
    }

    #[test]
    fn a_server_list_push_never_adds_special_use_addresses() {
        let pushed = [
            ([127, 0, 0, 1], 4661u16),
            ([192, 168, 1, 10], 4661),
            ([10, 0, 0, 1], 4661),
            ([169, 254, 3, 4], 4661),
            ([224, 0, 0, 1], 4661),
            ([0, 0, 0, 0], 4661),
            ([255, 255, 255, 255], 4661),
            ([8, 8, 8, 8], 0),
            ([8, 8, 8, 8], 4661),
        ];
        let mut payload = vec![pushed.len() as u8];
        for (octets, port) in pushed {
            payload.extend_from_slice(&octets);
            payload.extend_from_slice(&port.to_le_bytes());
        }
        // Neither a disabled filter nor one still loading may let them through.
        for mut filter in [
            crate::network::kad::ip_filter::IpFilter::new(false, false),
            crate::network::kad::ip_filter::IpFilter::new(true, false),
        ] {
            let mut list = ServerList::new();
            assert_eq!(list.add_from_server_list_packet(&payload, true, &mut filter), 1);
            let added: Vec<_> = list
                .servers()
                .iter()
                .map(|s| (s.ip.as_str(), s.port))
                .collect();
            assert_eq!(added, vec![("8.8.8.8", 4661)]);
        }
    }

    #[test]
    fn a_server_the_user_adds_by_hand_may_be_on_the_lan() {
        let mut filter = crate::network::kad::ip_filter::IpFilter::new(false, false);
        let mut list = ServerList::new();
        let outcome =
            list.add_filtered(ServerEntry::new("192.168.1.10".into(), 4661), true, &mut filter);
        assert!(matches!(outcome, AddServerOutcome::Added));
    }

    /// A server.met with `entries`, each `(ip octets, port, tag count, tags)`.
    fn met_file(entries: &[([u8; 4], u16, u32, Vec<u8>)]) -> Vec<u8> {
        let mut buf = vec![0xE0];
        buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for (octets, port, tag_count, tags) in entries {
            buf.extend_from_slice(octets);
            buf.extend_from_slice(&port.to_le_bytes());
            buf.extend_from_slice(&tag_count.to_le_bytes());
            buf.extend_from_slice(tags);
        }
        buf
    }

    fn string_tag(id: u8, value: &[u8]) -> Vec<u8> {
        let mut tag = vec![0x02, 1, 0, id];
        tag.extend_from_slice(&(value.len() as u16).to_le_bytes());
        tag.extend_from_slice(value);
        tag
    }

    fn int_tag(id: u8, value: u32) -> Vec<u8> {
        let mut tag = vec![0x03, 1, 0, id];
        tag.extend_from_slice(&value.to_le_bytes());
        tag
    }

    /// The reader capped strings at 4096 bytes and the writer did not, so a
    /// long description saved once made the next launch refuse the file.
    #[test]
    fn ember_reads_back_every_server_met_it_writes() {
        let mut list = ServerList::new();
        let mut entry = ServerEntry::new("8.8.4.4".into(), 4661);
        entry.name = "Ünïcode Server".into();
        entry.description = "é".repeat(MAX_SERVER_TAG_STR_LEN);
        entry.user_count = 5;
        entry.file_count = 6;
        entry.fail_count = 2;
        entry.priority = ServerPriority::Low;
        entry.is_static = true;
        list.add(entry);

        let bytes = list.to_server_met_bytes().unwrap();
        let back = ServerList::parse_server_met(&bytes).expect("Ember reads what it writes");
        let entry = back.find_by_addr("8.8.4.4", 4661).unwrap();
        assert_eq!(entry.name, "Ünïcode Server");
        assert!(entry.description.len() <= MAX_SERVER_TAG_STR_LEN);
        assert!(!entry.description.is_empty() && entry.description.chars().all(|c| c == 'é'));
        assert_eq!((entry.user_count, entry.file_count, entry.fail_count), (5, 6, 2));
        assert_eq!(entry.priority, ServerPriority::Low);
        assert!(entry.is_static);
    }

    /// A description of bytes that are not UTF-8 grew past the cap once
    /// decoded. Whatever a merged file holds, the next save still loads.
    #[test]
    fn a_merged_list_of_odd_bytes_still_saves_a_loadable_file() {
        // Latin-1 'é' bytes: each one doubles once decoded.
        let file = met_file(&[([8, 8, 8, 8], 4661, 1, string_tag(0x0B, &[0xE9; 4096]))]);
        let mut list = ServerList::new();
        list.merge_from_bytes_filtered(&file, false, None, false).unwrap();
        let bytes = list.to_server_met_bytes().unwrap();
        assert!(ServerList::parse_server_met(&bytes).is_ok());
    }

    /// The tags eMule writes: names with a byte-order mark, strings in its
    /// local code page, the counts named in full, and types Ember stores
    /// nothing from.
    #[test]
    fn an_emule_server_met_is_read_as_emule_writes_it() {
        let mut tags = Vec::new();
        tags.extend(string_tag(0x01, b"\xEF\xBB\xBFCaf\xC3\xA9"));
        tags.extend(string_tag(0x0B, b"Caf\xE9"));
        for (name, value) in [("users", 1000u32), ("files", 2000)] {
            tags.extend_from_slice(&[0x03, name.len() as u8, 0]);
            tags.extend_from_slice(name.as_bytes());
            tags.extend_from_slice(&value.to_le_bytes());
        }
        tags.extend_from_slice(&[0x04, 1, 0, 0x99, 0, 0, 0x80, 0x3F]); // a float
        tags.extend_from_slice(&[0x07, 1, 0, 0x9A, 3, 0, 0, 0, 1, 2, 3]); // a blob
        tags.extend(int_tag(0x8A, 1)); // Ember's static flag, from no Ember
        tags.extend(int_tag(0x0E, 1)); // High
        let file = met_file(&[
            ([8, 8, 8, 8], 4661, 8, tags),
            ([192, 168, 1, 1], 4661, 0, Vec::new()),
        ]);

        let mut list = ServerList::new();
        let stats = list.merge_from_bytes_filtered(&file, false, None, false).unwrap();
        assert_eq!((stats.added, stats.filtered, stats.truncated), (1, 1, false));
        let entry = list.find_by_addr("8.8.8.8", 4661).unwrap();
        assert_eq!(entry.name, "Café");
        assert_eq!(entry.description, "Café");
        assert_eq!((entry.user_count, entry.file_count), (1000, 2000));
        assert!(!entry.is_static, "a downloaded list cannot make a server static");
        assert_eq!(entry.priority, ServerPriority::Normal, "a downloaded list's priority is dropped");
        assert!(list.find_by_addr("192.168.1.1", 4661).is_none(), "a LAN address is not merged");
    }

    #[test]
    fn a_merge_keeps_what_the_user_set() {
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "1.1.1.1".into(),
            port: 4661,
            name: "Home".into(),
            priority: ServerPriority::Low,
            is_static: true,
            ..ServerEntry::new(String::new(), 0)
        });
        list.add(ServerEntry {
            ip: "2.2.2.2".into(),
            port: 4661,
            name: "Old".into(),
            priority: ServerPriority::High,
            ..ServerEntry::new(String::new(), 0)
        });
        let mut theirs = string_tag(0x01, b"Theirs");
        theirs.extend(int_tag(0x0E, 1));
        let mut renamed = string_tag(0x01, b"New");
        renamed.extend(int_tag(0x0E, 2));
        let file = met_file(&[([1, 1, 1, 1], 4661, 2, theirs), ([2, 2, 2, 2], 4661, 2, renamed)]);

        list.merge_from_bytes_filtered(&file, false, None, false).unwrap();
        let home = list.find_by_addr("1.1.1.1", 4661).unwrap();
        assert_eq!((home.name.as_str(), home.priority), ("Home", ServerPriority::Low));
        let other = list.find_by_addr("2.2.2.2", 4661).unwrap();
        assert_eq!(other.name, "New", "a server from a list takes the list's name, as in eMule");
        assert_eq!(other.priority, ServerPriority::High);
    }

    #[test]
    fn a_merge_that_runs_into_damage_says_so() {
        let file = met_file(&[
            ([8, 8, 8, 8], 4661, 0, Vec::new()),
            ([9, 9, 9, 9], 4661, 1, vec![0x55, 1, 0, 0x01]),
        ]);
        let mut list = ServerList::new();
        let stats = list.merge_from_bytes_filtered(&file, false, None, false).unwrap();
        assert_eq!((stats.added, stats.truncated), (1, true));
    }

    /// Only the server that failed is judged, and not the one auto-reconnect
    /// is still trying to reach.
    #[test]
    fn a_failure_removes_only_the_server_that_failed() {
        let mut list = ServerList::new();
        for (ip, fails) in [("1.1.1.1", 15), ("2.2.2.2", 9), ("3.3.3.3", 9)] {
            list.add(ServerEntry {
                ip: ip.into(),
                port: 4661,
                fail_count: fails,
                ..ServerEntry::new(String::new(), 0)
            });
        }
        list.record_failure("2.2.2.2", 4661, false);
        assert!(list.find_by_addr("2.2.2.2", 4661).is_none());
        assert!(list.find_by_addr("1.1.1.1", 4661).is_some(), "an imported count is not ours");
        list.record_failure("3.3.3.3", 4661, true);
        assert_eq!(list.find_by_addr("3.3.3.3", 4661).unwrap().fail_count, 10);
    }

    /// eMule's `GetServerKeyUDP`: a key is used only on the address it was
    /// issued for.
    #[test]
    fn a_saved_udp_key_waits_for_our_address_to_match() {
        let ours = Ipv4Addr::new(1, 2, 3, 4);
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "8.8.8.8".into(),
            port: 4661,
            server_udp_key: 0xABCD,
            server_udp_key_ip: met_ip_u32(ours),
            ..ServerEntry::new(String::new(), 0)
        });
        let key = |list: &ServerList| list.find_by_addr("8.8.8.8", 4661).unwrap().server_udp_key;

        let mut loaded = ServerList::parse_server_met(&list.to_server_met_bytes().unwrap()).unwrap();
        assert_eq!(key(&loaded), 0, "not used before our address is known");
        loaded.invalidate_udp_keys_for_public_ip(Some(ours));
        assert_eq!(key(&loaded), 0xABCD);
        loaded.invalidate_udp_keys_for_public_ip(None);
        assert_eq!(key(&loaded), 0, "not used while our address is unknown");
        loaded.invalidate_udp_keys_for_public_ip(Some(ours));
        assert_eq!(key(&loaded), 0xABCD, "and back once it is known again");

        let mut moved = ServerList::parse_server_met(&list.to_server_met_bytes().unwrap()).unwrap();
        moved.invalidate_udp_keys_for_public_ip(Some(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(key(&moved), 0, "a key for another address is dropped");
    }

    /// An unanswered obfuscated ping is followed by a plain one 20 s later
    /// and not counted; plain pings count until a reply.
    #[test]
    fn status_pings_are_counted_as_emule_counts_them() {
        let mut list = ServerList::new();
        list.add(ServerEntry::new("8.8.8.8".into(), 4661));
        let entry = |list: &ServerList| list.find_by_addr("8.8.8.8", 4661).unwrap().clone();
        let now = 1_000_000;

        list.record_udp_ping_sent("8.8.8.8", 4661, now, true);
        let e = entry(&list);
        assert!(e.crypt_ping_pending);
        assert_eq!(e.udp_consecutive_failures, 0);
        assert!(!super::super::server_udp::status_ping_due(&e, now + 19));
        assert!(super::super::server_udp::status_ping_due(&e, now + 20));

        list.record_udp_ping_sent("8.8.8.8", 4661, now + 20, false);
        let e = entry(&list);
        assert!(!e.crypt_ping_pending);
        assert_eq!(e.udp_consecutive_failures, 1);

        list.record_udp_reply("8.8.8.8", 4661);
        assert_eq!(entry(&list).udp_consecutive_failures, 0);
    }

    /// A last server the user removed, or that was pruned, is not dialed at
    /// the next launch.
    #[test]
    fn auto_connect_skips_a_last_server_no_longer_in_the_list() {
        let dir = std::env::temp_dir().join(format!(
            "ember-last-server-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        LastEd2kServer { ip: "9.9.9.9".into(), port: 4661, name: String::new() }
            .save(&dir.join("last_ed2k_server.json"))
            .unwrap();

        let mut list = ServerList::new();
        assert_eq!(ServerList::resolve_auto_connect_target(&dir, &list), None);
        list.add(ServerEntry::new("9.9.9.9".into(), 4661));
        assert_eq!(
            ServerList::resolve_auto_connect_target(&dir, &list),
            Some(("9.9.9.9".to_string(), 4661))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no last server, High is tried first and Low never chosen.
    #[test]
    fn auto_connect_picks_by_priority_without_a_last_server() {
        let dir = std::env::temp_dir().join(format!(
            "ember-no-last-server-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        let target = |list: &ServerList| ServerList::resolve_auto_connect_target(&dir, list);
        let server = |ip: &str, port: u16, priority, fail_count, user_count| ServerEntry {
            ip: ip.into(),
            port,
            priority,
            fail_count,
            user_count,
            ..ServerEntry::new(String::new(), 0)
        };

        let mut list = ServerList::new();
        list.add(server(EMULE_SUNRISE_IP, EMULE_SUNRISE_PORT, ServerPriority::Normal, 0, 0));
        assert_eq!(target(&list), Some((EMULE_SUNRISE_IP.to_string(), EMULE_SUNRISE_PORT)));

        list.add(server("1.1.1.1", 4661, ServerPriority::High, 3, 900));
        list.add(server("2.2.2.2", 4661, ServerPriority::High, 0, 100));
        list.add(server("3.3.3.3", 4661, ServerPriority::High, 0, 500));
        assert_eq!(target(&list), Some(("3.3.3.3".to_string(), 4661)));

        let mut low_only = ServerList::new();
        low_only.add(server(EMULE_SUNRISE_IP, EMULE_SUNRISE_PORT, ServerPriority::Low, 0, 0));
        assert_eq!(target(&low_only), None, "Low is never picked for the user");
    }

    /// A restart does not re-ping a server whose 4.5 h interval is still
    /// running, and a time from another client's file does not hold ours.
    #[test]
    fn ping_times_survive_a_restart_of_ember_only() {
        let now = crate::network::monotonic_secs();
        let mut list = ServerList::new();
        list.add(ServerEntry {
            ip: "8.8.8.8".into(),
            port: 4661,
            last_udp_ping_at: now - 100,
            ..ServerEntry::new(String::new(), 0)
        });
        list.add(ServerEntry {
            ip: "9.9.9.9".into(),
            port: 4661,
            last_udp_ping_at: now - super::super::server_udp::STAT_REASK_INTERVAL_SECS - 10,
            ..ServerEntry::new(String::new(), 0)
        });
        let bytes = list.to_server_met_bytes().unwrap();

        let back = ServerList::parse_server_met(&bytes).unwrap();
        let recent = back.find_by_addr("8.8.8.8", 4661).unwrap().last_udp_ping_at;
        assert!((recent - (now - 100)).abs() <= 2, "kept: {recent} vs {}", now - 100);
        assert_eq!(back.find_by_addr("9.9.9.9", 4661).unwrap().last_udp_ping_at, 0, "already due");

        let mut merged = ServerList::new();
        merged.merge_from_bytes_filtered(&bytes, false, None, false).unwrap();
        assert_eq!(merged.find_by_addr("8.8.8.8", 4661).unwrap().last_udp_ping_at, 0);
    }
}
