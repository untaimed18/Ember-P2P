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
    /// Server UDP capability flags (SRV_UDPFLG_*), learned from status pings.
    pub udp_flags: u32,
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
            udp_flags: 0,
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
        let mut list = Self::new();

        for _ in 0..count.min(500) {
            let ip_raw = cursor.read_u32::<LittleEndian>()?;
            let ip = std::net::Ipv4Addr::from(ip_raw.to_le_bytes());
            let port = cursor.read_u16::<LittleEndian>()?;
            let tag_count = cursor.read_u32::<LittleEndian>()? as usize;

            let mut entry = ServerEntry::new(ip.to_string(), port);

            for _ in 0..tag_count.min(50) {
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
                    _ => break,
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

            let mut entry = ServerEntry::new(ip.to_string(), port);

            for _ in 0..tag_count.min(50) {
                let tag_type = match cursor.read_u8() {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let name_len = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
                let mut name = vec![0u8; name_len];
                let _ = cursor.read_exact(&mut name);
                let name_id = if name_len == 1 { name[0] } else { 0 };

                match tag_type {
                    0x02 => {
                        let slen = cursor.read_u16::<LittleEndian>().unwrap_or(0) as usize;
                        let mut sbuf = vec![0u8; slen];
                        let _ = cursor.read_exact(&mut sbuf);
                        match name_id {
                            0x01 => entry.name = String::from_utf8_lossy(&sbuf).to_string(),
                            0x0B => entry.description = String::from_utf8_lossy(&sbuf).to_string(),
                            _ => {}
                        }
                    }
                    0x03 => {
                        let v = cursor.read_u32::<LittleEndian>().unwrap_or(0);
                        apply_server_int_tag(&mut entry, name_id, v);
                    }
                    0x08 => { let _ = cursor.read_u16::<LittleEndian>(); }
                    0x09 => { let _ = cursor.read_u8(); }
                    _ => break,
                }
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

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tag_buf)?;
        }

        std::fs::write(path, &buf)?;
        Ok(())
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
