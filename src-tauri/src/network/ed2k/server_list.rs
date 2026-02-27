use std::io::{self, Cursor, Read, Write};
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
    pub last_ping: i64,
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
            last_ping: 0,
        }
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

    pub fn remove(&mut self, ip: &str, port: u16) {
        self.servers.retain(|s| !(s.ip == ip && s.port == port));
    }

    pub fn get_next_server(&mut self) -> Option<&ServerEntry> {
        if self.servers.is_empty() {
            return None;
        }
        // Prefer high-priority servers first, then sort by lowest fail_count
        self.servers.sort_by(|a, b| {
            let pa = match a.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
            let pb = match b.priority { ServerPriority::High => 0, ServerPriority::Normal => 1, ServerPriority::Low => 2 };
            pa.cmp(&pb).then(a.fail_count.cmp(&b.fail_count))
        });

        let idx = self.current_index % self.servers.len();
        self.current_index = (self.current_index + 1) % self.servers.len();
        Some(&self.servers[idx])
    }

    pub fn record_failure(&mut self, ip: &str, port: u16) {
        if let Some(entry) = self.servers.iter_mut().find(|s| s.ip == ip && s.port == port) {
            entry.fail_count += 1;
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
            let ip = std::net::Ipv4Addr::from(ip_raw.to_be_bytes());
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
                        match name_id {
                            0x85 => entry.fail_count = v,
                            0x87 => entry.priority = match v { 0 => ServerPriority::Low, 2 => ServerPriority::High, _ => ServerPriority::Normal },
                            _ => {}
                        }
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
    pub fn merge_from_bytes(&mut self, data: &[u8]) -> anyhow::Result<usize> {
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

        for _ in 0..count.min(500) {
            let ip_raw = match cursor.read_u32::<LittleEndian>() {
                Ok(v) => v,
                Err(_) => break,
            };
            let ip = std::net::Ipv4Addr::from(ip_raw.to_be_bytes());
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
                        let _ = cursor.read_u32::<LittleEndian>();
                    }
                    0x08 => { let _ = cursor.read_u16::<LittleEndian>(); }
                    0x09 => { let _ = cursor.read_u8(); }
                    _ => break,
                }
            }

            if !self.servers.iter().any(|s| s.ip == entry.ip && s.port == entry.port) {
                self.servers.push(entry);
                added += 1;
            }
        }

        info!("Merged {added} new servers from server.met data ({count} total in file)");
        Ok(added)
    }

    #[allow(dead_code)]
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
            buf.write_u32::<LittleEndian>(u32::from_be_bytes(ip.octets()))?;
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
