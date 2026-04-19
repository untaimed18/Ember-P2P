use std::io::{self, Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info};

#[derive(Debug, Clone, Default)]
pub struct ServerMergeStats {
    pub added: usize,
    pub updated: usize,
    pub filtered: usize,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddServerOutcome {
    Added,
    Duplicate,
    Filtered,
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
    /// Number of UDP source-discovery queries (`OP_GLOBGETSOURCES` /
    /// `OP_GLOBGETSOURCES2`) we've sent to this server since the last
    /// time it sent us *any* UDP reply. Reset to 0 on any inbound UDP
    /// packet from this server (status response or found-sources).
    /// Used by `is_eligible_udp_server` to stop wasting bandwidth on
    /// servers that no longer respond to UDP — distinct from
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPriority {
    #[allow(dead_code)]
    Low,
    Normal,
    High,
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
            udp_consecutive_failures: 0,
            last_udp_reply_at: 0,
            last_udp_source_reply_at: 0,
        }
    }
}

#[allow(dead_code)]
fn apply_server_int_tag(entry: &mut ServerEntry, name_id: u8, v: u32) {
    match name_id {
        0x0D | 0x85 => entry.fail_count = v,
        0x0E => entry.priority = match v {
            0 => ServerPriority::Normal,
            1 => ServerPriority::High,
            2 => ServerPriority::Low,
            _ => ServerPriority::Normal,
        },
        0x83 => entry.user_count = v,
        0x84 => entry.file_count = v,
        0x86 => entry.last_ping = v as i64,
        0x87 => entry.max_users = v,
        0x88 => entry.soft_files = v,
        0x89 => entry.hard_files = v,
        0x8A => entry.is_static = v != 0,
        0x97 | 0xF1 => entry.obfuscation_port_tcp = v as u16,
        // Ember-private tags persisted by `save_server_met` for UDP
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

pub struct ServerList {
    servers: Vec<ServerEntry>,
    current_index: usize,
    needs_sort: bool,
}

#[allow(dead_code)]
impl ServerList {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            current_index: 0,
            needs_sort: false,
        }
    }

    /// Built-in server list used for source discovery.
    /// eMule Security is prioritized (High) so it is tried first.
    pub fn hardcoded() -> Self {
        let servers = vec![
            ServerEntry {
                ip: "45.82.80.155".to_string(),
                port: 5687,
                name: "eMule Security".to_string(),
                priority: ServerPriority::High,
                is_static: true,
                ..ServerEntry::new(String::new(), 0)
            },
            ServerEntry {
                ip: "176.123.5.89".to_string(),
                port: 4725,
                name: "eMule Sunrise".to_string(),
                is_static: true,
                ..ServerEntry::new(String::new(), 0)
            },
            ServerEntry {
                ip: "176.123.2.239".to_string(),
                port: 4232,
                name: "!! Sharing-Devils No.1 !!".to_string(),
                is_static: true,
                ..ServerEntry::new(String::new(), 0)
            },
            ServerEntry {
                ip: "145.239.2.134".to_string(),
                port: 4661,
                name: "GrupoTS Server".to_string(),
                is_static: true,
                ..ServerEntry::new(String::new(), 0)
            },
        ];
        Self { servers, current_index: 0, needs_sort: true }
    }

    fn connect_cooldown_secs(entry: &ServerEntry) -> i64 {
        let base: i64 = match entry.priority {
            ServerPriority::High => 20,
            ServerPriority::Normal => 30,
            ServerPriority::Low => 45,
        };
        let exponent = entry.fail_count.min(5);
        let cooldown = base.saturating_mul(1_i64 << exponent);
        cooldown.min(1800)
    }

    pub fn add(&mut self, entry: ServerEntry) {
        if !self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
            self.servers.push(entry);
            self.needs_sort = true;
        }
    }

    /// Remove all servers whose IP is blocked by the IP filter.
    /// Returns the number of servers removed.
    pub fn remove_filtered(&mut self, ip_filter: &mut crate::network::kad::ip_filter::IpFilter) -> usize {
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
    pub fn is_ip_filtered(ip_str: &str, ip_filter: &mut crate::network::kad::ip_filter::IpFilter) -> bool {
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
        if self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
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
        self.servers.push(entry);
        self.needs_sort = true;
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
        let mut duplicate = 0;
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
            if ip.is_unspecified() || port == 0 {
                continue;
            }
            let mut entry = ServerEntry::new(ip.to_string(), port);
            entry.name = ip.to_string();
            entry.priority = ServerPriority::Low;
            match self.add_filtered(entry, filter_by_ip, ip_filter) {
                AddServerOutcome::Added => added += 1,
                AddServerOutcome::Filtered => filtered += 1,
                AddServerOutcome::Duplicate => duplicate += 1,
            }
        }
        // Always summarise the push if it carried anything actionable —
        // before, a list of 27 entries that were all IP-filtered would
        // produce 27 INFO lines and no aggregate. Now: one line.
        if added > 0 || filtered > 0 {
            info!(
                "Server list push: {added} added, {filtered} blocked by IP filter, {duplicate} duplicate (out of {count})",
            );
        }
        added
    }

    pub fn remove(&mut self, ip: &str, port: u16) -> bool {
        let before = self.servers.len();
        self.servers.retain(|s| !(s.ip == ip && s.port == port));
        self.servers.len() != before
    }

    pub fn get_next_server(&mut self) -> Option<&ServerEntry> {
        if self.servers.is_empty() {
            return None;
        }
        let now = chrono::Utc::now().timestamp();

        if self.needs_sort {
            self.servers.sort_by(|a, b| {
                let pa = match a.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
                let pb = match b.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
                pa.cmp(&pb).then(a.fail_count.cmp(&b.fail_count))
            });
            self.needs_sort = false;
        }

        let len = self.servers.len();
        for _ in 0..len {
            let idx = self.current_index % len;
            self.current_index = (self.current_index + 1) % len;
            let entry = &self.servers[idx];
            let cooldown = Self::connect_cooldown_secs(entry);
            if entry.last_failed_at > 0 && (now - entry.last_failed_at) < cooldown {
                continue;
            }
            return Some(entry);
        }
        None
    }

    /// eMule MAX_SERVERFAILCOUNT = 10
    const MAX_FAIL_COUNT: u32 = 10;

    pub fn record_failure(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.fail_count += 1;
            entry.last_failed_at = chrono::Utc::now().timestamp();
            self.needs_sort = true;
        }
        // eMule: remove non-static servers that exceed MAX_SERVERFAILCOUNT
        self.servers.retain(|s| {
            if s.is_static { return true; }
            if s.fail_count >= Self::MAX_FAIL_COUNT {
                info!("Removing server {}:{} after {} consecutive failures", s.ip, s.port, s.fail_count);
                return false;
            }
            true
        });
    }

    /// Record that we sent a UDP source-discovery query
    /// (`OP_GLOBGETSOURCES` / `OP_GLOBGETSOURCES2`) to this server.
    /// Bumps `udp_consecutive_failures`; the next inbound UDP packet
    /// from the same server will reset it via `record_udp_reply`.
    /// Saturating arithmetic so a long-running session against a
    /// dead server can't overflow.
    pub fn record_udp_query_sent(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.udp_consecutive_failures = entry.udp_consecutive_failures.saturating_add(1);
        }
    }

    /// Record that this server sent us *any* UDP reply (status response
    /// or found-sources). Resets the failure counter and timestamps the
    /// reply for the periodic UDP-health log.
    pub fn record_udp_reply(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            if entry.udp_consecutive_failures != 0 {
                self.needs_sort = true;
            }
            entry.udp_consecutive_failures = 0;
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
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.last_udp_source_reply_at = chrono::Utc::now().timestamp();
        }
    }

    pub fn record_success(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            if entry.fail_count != 0 {
                self.needs_sort = true;
            }
            entry.fail_count = 0;
            entry.last_ping = chrono::Utc::now().timestamp();
            entry.last_failed_at = 0;
        }
    }

    pub fn servers(&self) -> &[ServerEntry] {
        &self.servers
    }

    pub fn len(&self) -> usize {
        self.servers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Load servers from eMule server.met format.
    pub fn load_server_met(path: &Path) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() < 5 {
            return Ok(Self::new());
        }
        let mut cursor = Cursor::new(&data);
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
            let ip_raw = cursor.read_u32::<LittleEndian>()?;
            let ip = std::net::Ipv4Addr::from(ip_raw.to_le_bytes());
            let port = cursor.read_u16::<LittleEndian>()?;
            let tag_count = cursor.read_u32::<LittleEndian>()? as usize;
            if tag_count > 50 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "server.met entry for {ip}:{port} declares {tag_count} tags, exceeding cap of 50",
                    ),
                ));
            }

            let mut entry = ServerEntry::new(ip.to_string(), port);

            for _ in 0..tag_count {
                let tag_type = cursor.read_u8()?;
                let name_len = cursor.read_u16::<LittleEndian>()? as usize;
                let mut name = vec![0u8; name_len];
                cursor.read_exact(&mut name)?;
                let name_id = if name_len == 1 { name[0] } else { 0 };

                match tag_type {
                    0x02 => {
                        let slen = cursor.read_u16::<LittleEndian>()? as usize;
                        let mut sbuf = vec![0u8; slen];
                        cursor.read_exact(&mut sbuf)?;
                        match name_id {
                            0x01 => entry.name = String::from_utf8_lossy(&sbuf).to_string(),
                            0x0B => entry.description = String::from_utf8_lossy(&sbuf).to_string(),
                            _ => {}
                        }
                    }
                    0x03 => {
                        let v = cursor.read_u32::<LittleEndian>()?;
                        apply_server_int_tag(&mut entry, name_id, v);
                    }
                    0x08 => { let _ = cursor.read_u16::<LittleEndian>(); }
                    0x09 => { let _ = cursor.read_u8(); }
                    // Unknown tag type: bail the whole load. The
                    // tag's payload size depends on its type so we
                    // can't safely skip past it — `break`-ing would
                    // desync the cursor and parse the rest of the
                    // file as nonsense entries (the previous bug).
                    // Failing here keeps the on-disk file intact;
                    // the caller falls back to the seed list.
                    other => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "server.met entry for {ip}:{port} has unknown tag type 0x{other:02X}; refusing to continue (would desync parser)",
                            ),
                        ));
                    }
                }
            }

            list.add(entry);
        }

        list.needs_sort = !list.servers.is_empty();
        info!("Loaded {} servers from server.met", list.len());
        Ok(list)
    }

    /// Merge servers from raw server.met bytes without clearing existing list.
    /// If filter_by_ip is true and ip_filter is Some, servers are checked against the IP filter.
    pub fn merge_from_bytes_filtered(
        &mut self,
        data: &[u8],
        filter_by_ip: bool,
        mut ip_filter: Option<&mut crate::network::kad::ip_filter::IpFilter>,
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
        let mut stats = ServerMergeStats::default();

        for _ in 0..count.min(500) {
            let ip_raw = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let ip = Ipv4Addr::from(ip_raw.to_le_bytes());
            let port = match cursor.read_u16::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let tag_count = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v as usize,
                Err(_) => break,
            };
            if tag_count > 50 {
                debug!(
                    "server.met merge: entry {ip}:{port} declares {tag_count} tags (>50); aborting merge to avoid wasting memory or running into a hostile file",
                );
                break;
            }

            let mut entry = ServerEntry::new(ip.to_string(), port);

            // `unknown_tag` flag: when set, we abort the merge of the
            // *whole* file (not just this entry) because tag payload
            // sizes are type-specific and we'd desync the cursor by
            // continuing — the previous bug parsed every following
            // record from the wrong offset.
            // `unknown_tag` is also set on any short read — a
            // truncated or hostile fragment otherwise leaves the
            // cursor at an arbitrary position and subsequent reads
            // interpret unrelated bytes as structure (silent
            // corruption of merged entries). Mirrors the strict
            // behavior of `load_server_met`.
            let mut unknown_tag = false;
            for _ in 0..tag_count {
                let tag_type = match cursor.read_u8() {
                    Ok(v) => v,
                    Err(_) => { unknown_tag = true; break; }
                };
                let name_len = match cursor.read_u16::<LittleEndian>() {
                    Ok(v) => v as usize,
                    Err(_) => { unknown_tag = true; break; }
                };
                let mut name = vec![0u8; name_len];
                if cursor.read_exact(&mut name).is_err() {
                    unknown_tag = true;
                    break;
                }
                let name_id = if name_len == 1 { name[0] } else { 0 };

                match tag_type {
                    0x02 => {
                        let slen = match cursor.read_u16::<LittleEndian>() {
                            Ok(v) => v as usize,
                            Err(_) => { unknown_tag = true; break; }
                        };
                        let mut sbuf = vec![0u8; slen];
                        if cursor.read_exact(&mut sbuf).is_err() {
                            unknown_tag = true;
                            break;
                        }
                        match name_id {
                            0x01 => entry.name = String::from_utf8_lossy(&sbuf).to_string(),
                            0x0B => entry.description = String::from_utf8_lossy(&sbuf).to_string(),
                            _ => {}
                        }
                    }
                    0x03 => {
                        let v = match cursor.read_u32::<LittleEndian>() {
                            Ok(v) => v,
                            Err(_) => { unknown_tag = true; break; }
                        };
                        apply_server_int_tag(&mut entry, name_id, v);
                    }
                    0x08 => {
                        if cursor.read_u16::<LittleEndian>().is_err() {
                            unknown_tag = true;
                            break;
                        }
                    }
                    0x09 => {
                        if cursor.read_u8().is_err() {
                            unknown_tag = true;
                            break;
                        }
                    }
                    other => {
                        debug!(
                            "server.met merge: unknown tag type 0x{other:02X} in entry {ip}:{port}; aborting merge to avoid cursor desync",
                        );
                        unknown_tag = true;
                        break;
                    }
                }
            }
            if unknown_tag {
                break;
            }

            if let Some(existing) = self.servers.iter_mut().find(|s| s.ip == entry.ip && s.port == entry.port) {
                if !entry.name.is_empty() {
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
                // Merge UDP-obfuscation state too: a fresh import (from
                // another saved server.met or our own) can carry
                // updated material we'd otherwise lose by ignoring
                // these fields. We never overwrite a non-zero key with
                // 0 (so importing an old eMule-format file doesn't
                // wipe what we already learned).
                if entry.obfuscation_port_udp > 0 {
                    existing.obfuscation_port_udp = entry.obfuscation_port_udp;
                }
                if entry.server_udp_key != 0 {
                    existing.server_udp_key = entry.server_udp_key;
                }
                if entry.udp_flags != 0 {
                    existing.udp_flags = entry.udp_flags;
                }
                if entry.priority != ServerPriority::Normal {
                    existing.priority = entry.priority;
                }
                stats.updated += 1;
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

            self.servers.push(entry);
            stats.added += 1;
        }

        if stats.added > 0 || stats.updated > 0 {
            self.needs_sort = true;
        }
        info!(
            "Merged server.met data: {} added, {} updated, {} filtered ({} total in file)",
            stats.added, stats.updated, stats.filtered, count
        );
        Ok(stats)
    }

    /// Merge servers from raw server.met bytes without IP filtering.
    pub fn merge_from_bytes(&mut self, data: &[u8]) -> anyhow::Result<ServerMergeStats> {
        self.merge_from_bytes_filtered(data, false, None)
    }

    pub fn update_server_stats(&mut self, ip: &str, port: u16, users: u32, files: u32, obfuscation_port_tcp: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
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
    ) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            if obfuscation_port_udp != 0 {
                entry.obfuscation_port_udp = obfuscation_port_udp;
            }
            if server_udp_key != 0 && entry.server_udp_key != server_udp_key {
                tracing::info!(
                    "Learned UDP obfuscation key for server {ip}:{port} (key={server_udp_key:#x}, obf_port={obfuscation_port_udp})",
                );
                entry.server_udp_key = server_udp_key;
            }
        }
    }

    /// Look up the UDP obfuscation material for a server by `(ip, tcp_port)`.
    /// Returns `Some((base_key, obf_udp_port))` only when the server has
    /// advertised a non-zero key AND has the `SRV_UDPFLG_UDPOBFUSCATION`
    /// flag set. The caller is expected to fall back to plaintext + the
    /// regular UDP port (`tcp_port + 4`) when this returns `None`.
    pub fn get_udp_obfuscation(&self, ip: std::net::Ipv4Addr, tcp_port: u16) -> Option<(u32, u16)> {
        let ip_str = ip.to_string();
        let entry = self
            .servers
            .iter()
            .find(|s| s.ip == ip_str && s.port == tcp_port)?;
        if entry.server_udp_key == 0 {
            return None;
        }
        if entry.udp_flags & super::server_udp::SRV_UDPFLG_UDPOBFUSCATION == 0 {
            return None;
        }
        let port = if entry.obfuscation_port_udp != 0 {
            entry.obfuscation_port_udp
        } else {
            // Fall back to the standard UDP port — eMule's
            // `UDPSocket.cpp` does the same when `nUDPObfuscationPort`
            // is 0 (`if (!nPort) nPort = pServer->GetObfuscationPortUDP();`,
            // which then resolves to the standard port).
            tcp_port.saturating_add(4)
        };
        Some((entry.server_udp_key, port))
    }

    /// Inverse lookup: given an inbound UDP `(src_ip, src_port)`, find
    /// which server it belongs to and return:
    ///   * `base_key`  — server's `dwServerUDPKey` for obfuscation,
    ///                   or 0 if obfuscation isn't applicable here
    ///                   (still returned for the canonicalisation path)
    ///   * `tcp_port`  — server's canonical TCP port, used to
    ///                   normalise the recv source addr so downstream
    ///                   handlers' `addr.port() - 4` arithmetic
    ///                   continues to give the right value even when
    ///                   the reply arrived from a non-standard
    ///                   `obfuscation_port_udp`.
    ///
    /// Returns `None` only when no server in the list matches the
    /// given source `(ip, port)` pair via either the standard UDP
    /// port (TCP+4) or the advertised obfuscation UDP port.
    pub fn lookup_for_udp_addr(
        &self,
        ip: std::net::Ipv4Addr,
        src_port: u16,
    ) -> Option<(u32, u16)> {
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

    /// Backwards-compatible wrapper that returns just the BaseKey when
    /// the caller doesn't need the canonical TCP port. The canonical-
    /// port consumer ([`try_recv_with`]) uses [`lookup_for_udp_addr`]
    /// directly; this thinner wrapper is kept around for any future
    /// caller that just wants "do we have a key for this address?".
    /// Returns `None` when no server matches OR when the matching
    /// server has no key yet.
    #[allow(dead_code)]
    pub fn server_udp_key_for_addr(&self, ip: std::net::Ipv4Addr, src_port: u16) -> Option<u32> {
        let (key, _) = self.lookup_for_udp_addr(ip, src_port)?;
        if key == 0 {
            return None;
        }
        Some(key)
    }

    /// Store per-server UDP capability flags from status ping responses.
    pub fn update_udp_flags(&mut self, ip: &str, port: u16, udp_flags: u32) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.udp_flags = udp_flags;
        }
    }

    /// Update a server display name learned from live protocol data.
    /// To avoid clobbering user-provided labels, we only replace empty/IP-like names.
    pub fn update_server_name_from_ident(&mut self, ip: &str, port: u16, name: &str) -> bool {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return false;
        }
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            let existing = entry.name.trim();
            let existing_is_ip_like = existing.parse::<Ipv4Addr>().is_ok() || existing.eq_ignore_ascii_case(&entry.ip);
            if existing.is_empty() || existing_is_ip_like {
                if existing != trimmed {
                    entry.name = trimmed.to_string();
                    return true;
                }
            }
        }
        false
    }

    /// Save server list in server.met format (eMule-compatible, persists all metadata).
    pub fn save_server_met(&self, path: &Path) -> io::Result<()> {
        let mut buf = Vec::new();
        buf.write_u8(0x0E)?; // MET_HEADER
        buf.write_u32::<LittleEndian>(self.servers.len() as u32)?;

        for entry in &self.servers {
            let ip: std::net::Ipv4Addr = entry.ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
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

            // CT_FAILCOUNT (0x0D / 0x85) - uint32
            if entry.fail_count > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x85, entry.fail_count);
                tag_count += 1;
            }

            // CT_USERS (0x83) - uint32
            if entry.user_count > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x83, entry.user_count);
                tag_count += 1;
            }

            // CT_FILES (0x84) - uint32
            if entry.file_count > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x84, entry.file_count);
                tag_count += 1;
            }

            // CT_LASTPING (0x86) - uint32
            if entry.last_ping > 0 {
                write_met_uint32_tag(&mut tag_buf, 0x86, (entry.last_ping as u64).min(u32::MAX as u64) as u32);
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

            // Obfuscation TCP port (0xF1)
            if entry.obfuscation_port_tcp > 0 {
                write_met_uint32_tag(&mut tag_buf, 0xF1, entry.obfuscation_port_tcp as u32);
                tag_count += 1;
            }

            // UDP obfuscation port (Ember-private tag 0xF2). Persisted
            // alongside `server_udp_key` so we don't have to wait for
            // the next status ping after a restart before we can talk
            // obfuscated UDP. eMule's stock server.met format doesn't
            // include this — we use a private tag id in the eMule
            // private range (0xF0+); other clients ignore it.
            if entry.obfuscation_port_udp > 0 {
                write_met_uint32_tag(&mut tag_buf, 0xF2, entry.obfuscation_port_udp as u32);
                tag_count += 1;
            }

            // Per-server UDP obfuscation BaseKey (Ember-private 0xF3).
            // Stored as a u32 tag. Like the port above, persisting
            // means a fresh-start client can immediately use UDP
            // obfuscation against servers it has previously talked
            // to. Without this, every restart silently sends
            // plaintext for the first 30 seconds (until the next
            // status ping).
            if entry.server_udp_key != 0 {
                write_met_uint32_tag(&mut tag_buf, 0xF3, entry.server_udp_key);
                tag_count += 1;
            }

            // UDP capability flags (Ember-private 0xF4). Same
            // rationale: avoid losing learned capability bits across
            // restarts.
            if entry.udp_flags != 0 {
                write_met_uint32_tag(&mut tag_buf, 0xF4, entry.udp_flags);
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

        // Use atomic_write so a crash mid-save can't truncate or
        // zero-out server.met. Without this, the next start could
        // load 0 servers and silently lose the persisted list.
        crate::security::atomic_write(path, &buf, false)
    }
}

fn write_met_string_tag(buf: &mut Vec<u8>, tag_id: u8, value: &str) {
    buf.push(0x02); // TAGTYPE_STRING
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(tag_id);
    let bytes = value.as_bytes();
    let clamped = &bytes[..bytes.len().min(u16::MAX as usize)];
    buf.extend_from_slice(&(clamped.len() as u16).to_le_bytes());
    buf.extend_from_slice(clamped);
}

fn write_met_uint32_tag(buf: &mut Vec<u8>, tag_id: u8, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(tag_id);
    buf.extend_from_slice(&value.to_le_bytes());
}
