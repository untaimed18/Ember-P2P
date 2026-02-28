use std::collections::HashMap;
use std::io::{Cursor, Read, Write};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{info, warn};

const MET_HEADER: u8 = 0x0E;
const MET_HEADER_I64TAGS: u8 = 0x0C;

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_AICH_HASH: u8 = 0x27;
const FT_ATTRANSFERRED: u8 = 0x50;
const FT_ATTRANSFERREDHI: u8 = 0x51;
const FT_ATREQUESTED: u8 = 0x52;
const FT_ATACCEPTED: u8 = 0x53;
const FT_ULPRIORITY: u8 = 0x18;
const FT_KADLASTPUBLISHSRC: u8 = 0x23;
const FT_LASTSHARED: u8 = 0x24;

const TAG_STRING: u8 = 0x02;
const TAG_UINT32: u8 = 0x03;

#[derive(Debug, Clone)]
pub struct KnownFileRecord {
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>,
    pub file_name: String,
    pub file_size: u64,
    pub file_path: String,
    pub aich_hash: String,
    pub modified_at: i64,
    pub all_time_transferred: u64,
    pub all_time_requested: u32,
    pub all_time_accepted: u32,
    pub upload_priority: u8,
    pub last_publish_src: u32,
    pub last_shared: u32,
}

pub struct KnownFileList {
    files: HashMap<[u8; 16], KnownFileRecord>,
    path_index: HashMap<String, [u8; 16]>,
    dirty: bool,
}

impl KnownFileList {
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            path_index: HashMap::new(),
            dirty: false,
        }
    }

    pub fn load(path: &Path) -> Self {
        let mut list = Self::new();
        if !path.exists() {
            return list;
        }
        match std::fs::read(path) {
            Ok(data) => {
                if let Err(e) = list.parse_known_met(&data) {
                    warn!("Failed to parse known.met: {e}");
                }
            }
            Err(e) => warn!("Failed to read known.met: {e}"),
        }
        list
    }

    fn parse_known_met(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() < 5 {
            return Ok(());
        }
        let mut cursor = Cursor::new(data);
        let version = cursor.read_u8()?;
        if version != MET_HEADER && version != MET_HEADER_I64TAGS {
            anyhow::bail!("Unknown known.met version: 0x{version:02X}");
        }
        let count = cursor.read_u32::<LittleEndian>()? as usize;

        for _ in 0..count.min(50_000) {
            if let Ok(record) = Self::read_record(&mut cursor, version) {
                let hash = record.file_hash;
                let path = record.file_path.clone();
                self.files.insert(hash, record);
                if !path.is_empty() {
                    self.path_index.insert(path, hash);
                }
            } else {
                break;
            }
        }

        info!("Loaded {} known files from known.met", self.files.len());
        Ok(())
    }

    fn read_record(cursor: &mut Cursor<&[u8]>, _version: u8) -> anyhow::Result<KnownFileRecord> {
        let modified_at = cursor.read_u32::<LittleEndian>()? as i64;

        let mut file_hash = [0u8; 16];
        cursor.read_exact(&mut file_hash)?;

        let part_count = cursor.read_u16::<LittleEndian>()? as usize;
        let mut part_hashes = Vec::with_capacity(part_count);
        for _ in 0..part_count.min(1000) {
            let mut ph = [0u8; 16];
            cursor.read_exact(&mut ph)?;
            part_hashes.push(ph);
        }

        let tag_count = cursor.read_u32::<LittleEndian>()? as usize;

        let mut record = KnownFileRecord {
            file_hash,
            part_hashes,
            file_name: String::new(),
            file_size: 0,
            file_path: String::new(),
            aich_hash: String::new(),
            modified_at,
            all_time_transferred: 0,
            all_time_requested: 0,
            all_time_accepted: 0,
            upload_priority: 0,
            last_publish_src: 0,
            last_shared: 0,
        };

        for _ in 0..tag_count.min(100) {
            let tag_type = cursor.read_u8()?;
            let name_len = cursor.read_u16::<LittleEndian>()? as usize;
            let mut name_buf = vec![0u8; name_len];
            cursor.read_exact(&mut name_buf)?;
            let name_id = if name_len == 1 { name_buf[0] } else { 0 };

            match tag_type {
                TAG_STRING => {
                    let slen = cursor.read_u16::<LittleEndian>()? as usize;
                    let mut sbuf = vec![0u8; slen];
                    cursor.read_exact(&mut sbuf)?;
                    let s = String::from_utf8_lossy(&sbuf[..slen.min(4096)]).to_string();
                    match name_id {
                        FT_FILENAME => record.file_name = s,
                        FT_AICH_HASH => record.aich_hash = s,
                        _ => {}
                    }
                }
                TAG_UINT32 => {
                    let v = cursor.read_u32::<LittleEndian>()?;
                    match name_id {
                        FT_FILESIZE => record.file_size = v as u64,
                        FT_ATTRANSFERRED => {
                            record.all_time_transferred =
                                (record.all_time_transferred & 0xFFFF_FFFF_0000_0000) | v as u64;
                        }
                        FT_ATTRANSFERREDHI => {
                            record.all_time_transferred =
                                (record.all_time_transferred & 0x0000_0000_FFFF_FFFF) | ((v as u64) << 32);
                        }
                        FT_ATREQUESTED => record.all_time_requested = v,
                        FT_ATACCEPTED => record.all_time_accepted = v,
                        FT_ULPRIORITY => record.upload_priority = v as u8,
                        FT_KADLASTPUBLISHSRC => record.last_publish_src = v,
                        FT_LASTSHARED => record.last_shared = v,
                        _ => {}
                    }
                }
                0x08 => { let _ = cursor.read_u16::<LittleEndian>(); }
                0x09 => { let _ = cursor.read_u8(); }
                0x0B => { let _ = cursor.read_u64::<LittleEndian>(); }
                _ => {
                    tracing::trace!("Skipping unknown known.met tag type 0x{:02X}", tag_type);
                    break;
                }
            }
        }

        Ok(record)
    }

    /// Look up a known file by path, size, and mtime to skip re-hashing.
    pub fn find_by_path_and_meta(&self, path: &str, size: u64, mtime: i64) -> Option<&KnownFileRecord> {
        let hash = self.path_index.get(path)?;
        let record = self.files.get(hash)?;
        if record.file_size == size && record.modified_at == mtime {
            Some(record)
        } else {
            None
        }
    }

    pub fn find_by_hash(&self, hash: &[u8; 16]) -> Option<&KnownFileRecord> {
        self.files.get(hash)
    }

    pub fn add_or_update(&mut self, record: KnownFileRecord) {
        let hash = record.file_hash;
        let path = record.file_path.clone();
        if !path.is_empty() {
            if let Some(&old_hash) = self.path_index.get(&path) {
                if old_hash != hash {
                    self.files.remove(&old_hash);
                }
            }
            self.path_index.insert(path, hash);
        }
        self.files.insert(hash, record);
        self.dirty = true;
    }

    pub fn update_stats(&mut self, hash: &[u8; 16], transferred: u64, requested: u32, accepted: u32) {
        if let Some(record) = self.files.get_mut(hash) {
            record.all_time_transferred = transferred;
            record.all_time_requested = requested;
            record.all_time_accepted = accepted;
            self.dirty = true;
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn save(&mut self, path: &Path) -> anyhow::Result<()> {
        let mut buf = Vec::new();
        buf.write_u8(MET_HEADER)?;
        buf.write_u32::<LittleEndian>(self.files.len() as u32)?;

        for record in self.files.values() {
            buf.write_u32::<LittleEndian>(record.modified_at as u32)?;

            buf.write_all(&record.file_hash)?;
            buf.write_u16::<LittleEndian>(record.part_hashes.len() as u16)?;
            for ph in &record.part_hashes {
                buf.write_all(ph)?;
            }

            let mut tags = Vec::new();
            let mut tag_count: u32 = 0;

            if !record.file_name.is_empty() {
                write_string_tag(&mut tags, FT_FILENAME, &record.file_name)?;
                tag_count += 1;
            }
            write_u32_tag(&mut tags, FT_FILESIZE, record.file_size as u32)?;
            tag_count += 1;

            if !record.aich_hash.is_empty() {
                write_string_tag(&mut tags, FT_AICH_HASH, &record.aich_hash)?;
                tag_count += 1;
            }
            if record.all_time_transferred > 0 {
                write_u32_tag(&mut tags, FT_ATTRANSFERRED, record.all_time_transferred as u32)?;
                tag_count += 1;
                let hi = (record.all_time_transferred >> 32) as u32;
                if hi > 0 {
                    write_u32_tag(&mut tags, FT_ATTRANSFERREDHI, hi)?;
                    tag_count += 1;
                }
            }
            if record.all_time_requested > 0 {
                write_u32_tag(&mut tags, FT_ATREQUESTED, record.all_time_requested)?;
                tag_count += 1;
            }
            if record.all_time_accepted > 0 {
                write_u32_tag(&mut tags, FT_ATACCEPTED, record.all_time_accepted)?;
                tag_count += 1;
            }
            if record.upload_priority > 0 {
                write_u32_tag(&mut tags, FT_ULPRIORITY, record.upload_priority as u32)?;
                tag_count += 1;
            }
            if record.last_publish_src > 0 {
                write_u32_tag(&mut tags, FT_KADLASTPUBLISHSRC, record.last_publish_src)?;
                tag_count += 1;
            }
            if record.last_shared > 0 {
                write_u32_tag(&mut tags, FT_LASTSHARED, record.last_shared)?;
                tag_count += 1;
            }

            buf.write_u32::<LittleEndian>(tag_count)?;
            buf.write_all(&tags)?;
        }

        let tmp_path = path.with_extension("met.tmp");
        std::fs::write(&tmp_path, &buf)?;
        std::fs::rename(&tmp_path, path)?;
        self.dirty = false;
        info!("Saved {} known files to known.met", self.files.len());
        Ok(())
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn all_records(&self) -> impl Iterator<Item = &KnownFileRecord> {
        self.files.values()
    }
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) -> anyhow::Result<()> {
    buf.write_u8(TAG_STRING)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u16::<LittleEndian>(value.len() as u16)?;
    buf.write_all(value.as_bytes())?;
    Ok(())
}

fn write_u32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) -> anyhow::Result<()> {
    buf.write_u8(TAG_UINT32)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u32::<LittleEndian>(value)?;
    Ok(())
}
