use std::io::{self, Cursor, Read, Write};
use std::net::Ipv4Addr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::info;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerPriority {
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
        }
    }
}

fn apply_server_int_tag(entry: &mut ServerEntry, name_id: u8, v: u32) {
    match name_id {
        0x0D | 0x85 => entry.fail_count = v,
        0x0E => entry.priority = match v {
            0 => ServerPriority::Low,
            2 => ServerPriority::High,
            _ => ServerPriority::Normal,
        },
        0x83 => entry.user_count = v,
        0x84 => entry.file_count = v,
        0x86 => entry.last_ping = v as i64,
        0x87 => entry.max_users = v,
        0x88 => entry.soft_files = v,
        0x89 => entry.hard_files = v,
        0x97 => entry.obfuscation_port_tcp = v as u16,
        _ => {}
    }
}

pub struct ServerList {
    servers: Vec<ServerEntry>,
    current_index: usize,
}

impl ServerList {
    pub fn new() -> Self {
        Self {
            servers: Vec::new(),
            current_index: 0,
        }
    }

    pub fn add(&mut self, entry: ServerEntry) {
        if !self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
            self.servers.push(entry);
        }
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
    ) -> bool {
        if self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
            return false;
        }
        if filter_by_ip && Self::is_ip_filtered(&entry.ip, ip_filter) {
            info!("Server {}:{} blocked by IP filter", entry.ip, entry.port);
            return false;
        }
        self.servers.push(entry);
        true
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
            if self.add_filtered(entry, filter_by_ip, ip_filter) {
                added += 1;
            }
        }
        if added > 0 {
            info!("Added {added} new servers from connected server's server list");
        }
        added
    }

    pub fn remove(&mut self, ip: &str, port: u16) {
        self.servers.retain(|s| !(s.ip == ip && s.port == port));
    }

    pub fn get_next_server(&mut self) -> Option<&ServerEntry> {
        if self.servers.is_empty() {
            return None;
        }
        let now = chrono::Utc::now().timestamp();
        // eMule CS_RETRYCONNECTTIME = 30 seconds; scale up with fail_count
        let cooldown_base: i64 = 30;

        // Prefer high-priority servers first, then sort by lowest fail_count
        self.servers.sort_by(|a, b| {
            let pa = match a.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
            let pb = match b.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
            pa.cmp(&pb).then(a.fail_count.cmp(&b.fail_count))
        });

        let len = self.servers.len();
        for _ in 0..len {
            let idx = self.current_index % len;
            self.current_index = (self.current_index + 1) % len;
            let entry = &self.servers[idx];
            let cooldown = cooldown_base * (entry.fail_count as i64 + 1).min(10);
            if entry.last_failed_at > 0 && (now - entry.last_failed_at) < cooldown {
                continue;
            }
            return Some(entry);
        }
        None
    }

    pub fn record_failure(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.fail_count += 1;
            entry.last_failed_at = chrono::Utc::now().timestamp();
        }
    }

    pub fn record_success(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.fail_count = 0;
            entry.last_ping = chrono::Utc::now().timestamp();
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
    ) -> anyhow::Result<usize> {
        if data.len() < 5 {
            return Ok(0);
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != 0x0E && version != 0xE0 && version != 0x0C {
            anyhow::bail!("Unknown server.met version: 0x{version:02X}");
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;
        let mut added = 0;
        let mut filtered = 0;

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

            if self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
                continue;
            }

            if filter_by_ip {
                if let Some(filter) = ip_filter.as_deref_mut() {
                    if Self::is_ip_filtered(&entry.ip, filter) {
                        filtered += 1;
                        continue;
                    }
                }
            }

            self.servers.push(entry);
            added += 1;
        }

        info!("Merged {added} new servers from server.met data ({count} total in file, {filtered} filtered)");
        Ok(added)
    }

    /// Merge servers from raw server.met bytes without IP filtering.
    pub fn merge_from_bytes(&mut self, data: &[u8]) -> anyhow::Result<usize> {
        self.merge_from_bytes_filtered(data, false, None)
    }

    pub fn update_server_stats(&mut self, ip: &str, port: u16, users: u32, files: u32) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.user_count = users;
            entry.file_count = files;
            entry.last_ping = chrono::Utc::now().timestamp();
        }
    }

    /// Save server list in server.met format.
    pub fn save_server_met(&self, path: &Path) -> io::Result<()> {
        let mut buf = Vec::new();
        buf.write_u8(0x0E)?; // version
        buf.write_u32::<LittleEndian>(self.servers.len() as u32)?;

        for entry in &self.servers {
            let ip: std::net::Ipv4Addr = entry.ip.parse().unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
            buf.write_u32::<LittleEndian>(u32::from_le_bytes(ip.octets()))?;
            buf.write_u16::<LittleEndian>(entry.port)?;

            // Tags: name + priority
            let mut tag_count: u32 = 0;
            let mut tag_buf = Vec::new();

            if !entry.name.is_empty() {
                tag_buf.push(0x02); // STRING
                tag_buf.extend_from_slice(&1u16.to_le_bytes());
                tag_buf.push(0x01); // CT_NAME
                tag_buf.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
                tag_buf.extend_from_slice(entry.name.as_bytes());
                tag_count += 1;
            }

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tag_buf)?;
        }

        std::fs::write(path, &buf)?;
        Ok(())
    }
}
