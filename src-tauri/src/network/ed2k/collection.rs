use std::io::{Cursor, Read, Write};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use tracing::info;

const COLLECTION_FILE_VERSION1: u32 = 0x01;
const COLLECTION_FILE_VERSION2_LARGE: u32 = 0x02;

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILEHASH: u8 = 0x28;
const FT_AICH_HASH: u8 = 0x27;
const FT_COLLECTIONAUTHOR: u8 = 0x31;
const FT_COLLECTIONAUTHORKEY: u8 = 0x32;

const TAG_STRING: u8 = 0x02;
const TAG_UINT32: u8 = 0x03;
const TAG_HASH: u8 = 0x01;
const TAG_BLOB: u8 = 0x07;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionFile {
    pub name: String,
    pub size: u64,
    pub hash: String,
    pub aich_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Collection {
    pub name: String,
    pub author: String,
    pub files: Vec<CollectionFile>,
}

impl Collection {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() < 8 {
            return Self::load_text(path);
        }

        let mut cursor = Cursor::new(&data);
        let version = cursor.read_u32::<LittleEndian>()?;

        if version == COLLECTION_FILE_VERSION1 || version == COLLECTION_FILE_VERSION2_LARGE {
            Self::load_binary(&mut cursor, version)
        } else {
            Self::load_text(path)
        }
    }

    fn load_binary(cursor: &mut Cursor<&Vec<u8>>, _version: u32) -> anyhow::Result<Self> {
        let header_tag_count = cursor.read_u32::<LittleEndian>()? as usize;

        let mut name = String::new();
        let mut author = String::new();

        let header_limit = header_tag_count.min(20);
        for _ in 0..header_limit {
            let (tag_id, tag_value) = read_tag(cursor)?;
            match tag_id {
                FT_FILENAME => {
                    if let TagValue::String(s) = tag_value {
                        name = s;
                    }
                }
                FT_COLLECTIONAUTHOR => {
                    if let TagValue::String(s) = tag_value {
                        author = s;
                    }
                }
                FT_COLLECTIONAUTHORKEY => {
                    if let TagValue::Blob(key_data) = &tag_value {
                        tracing::debug!("Collection has author key ({} bytes)", key_data.len());
                    }
                }
                _ => {}
            }
        }
        for _ in header_limit..header_tag_count {
            let _ = read_tag(cursor)?;
        }

        let file_count = cursor.read_u32::<LittleEndian>()? as usize;
        let mut files = Vec::with_capacity(file_count.min(10000));

        for _ in 0..file_count.min(10000) {
            let file_tag_count = cursor.read_u32::<LittleEndian>()? as usize;
            let mut fname = String::new();
            let mut fsize: u64 = 0;
            let mut fhash = String::new();
            let mut faich = String::new();

            let file_limit = file_tag_count.min(20);
            for _ in 0..file_limit {
                let (tag_id, tag_value) = read_tag(cursor)?;
                match tag_id {
                    FT_FILENAME => {
                        if let TagValue::String(s) = tag_value {
                            fname = s;
                        }
                    }
                    FT_FILESIZE => {
                        match tag_value {
                            TagValue::Uint32(v) => fsize = v as u64,
                            TagValue::Uint64(v) => fsize = v,
                            _ => {}
                        }
                    }
                    FT_FILEHASH => {
                        if let TagValue::Hash(h) = tag_value {
                            fhash = hex::encode(h);
                        }
                    }
                    FT_AICH_HASH => {
                        if let TagValue::String(s) = tag_value {
                            faich = s;
                        }
                    }
                    _ => {}
                }
            }
            for _ in file_limit..file_tag_count {
                let _ = read_tag(cursor)?;
            }

            files.push(CollectionFile {
                name: fname,
                size: fsize,
                hash: fhash,
                aich_hash: faich,
            });
        }

        Ok(Collection { name, author, files })
    }

    fn load_text(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut files = Vec::new();
        let name = path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("ed2k://|file|") {
                if let Some(cf) = parse_ed2k_link(line) {
                    files.push(cf);
                }
            }
        }

        Ok(Collection {
            name,
            author: String::new(),
            files,
        })
    }

    pub fn save_binary(&self, path: &Path) -> anyhow::Result<()> {
        let mut buf = Vec::new();
        buf.write_u32::<LittleEndian>(COLLECTION_FILE_VERSION2_LARGE)?;

        let mut header_tags = 0u32;
        let mut header_buf = Vec::new();
        if !self.name.is_empty() {
            write_string_tag(&mut header_buf, FT_FILENAME, &self.name)?;
            header_tags += 1;
        }
        if !self.author.is_empty() {
            write_string_tag(&mut header_buf, FT_COLLECTIONAUTHOR, &self.author)?;
            header_tags += 1;
        }
        buf.write_u32::<LittleEndian>(header_tags)?;
        buf.write_all(&header_buf)?;

        buf.write_u32::<LittleEndian>(self.files.len() as u32)?;

        for file in &self.files {
            let mut file_tags = 0u32;
            let mut file_buf = Vec::new();

            if !file.name.is_empty() {
                write_string_tag(&mut file_buf, FT_FILENAME, &file.name)?;
                file_tags += 1;
            }
            if file.size > u32::MAX as u64 {
                write_u64_tag(&mut file_buf, FT_FILESIZE, file.size)?;
            } else {
                write_u32_tag(&mut file_buf, FT_FILESIZE, file.size as u32)?;
            }
            file_tags += 1;
            if !file.hash.is_empty() {
                if let Ok(hash_bytes) = hex::decode(&file.hash) {
                    if hash_bytes.len() == 16 {
                        write_hash_tag(&mut file_buf, FT_FILEHASH, &hash_bytes)?;
                        file_tags += 1;
                    }
                }
            }
            if !file.aich_hash.is_empty() {
                write_string_tag(&mut file_buf, FT_AICH_HASH, &file.aich_hash)?;
                file_tags += 1;
            }

            buf.write_u32::<LittleEndian>(file_tags)?;
            buf.write_all(&file_buf)?;
        }

        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &buf)?;
        std::fs::rename(&tmp, path)?;
        info!("Saved collection '{}' with {} files", self.name, self.files.len());
        Ok(())
    }

    pub fn save_text(&self, path: &Path) -> anyhow::Result<()> {
        let mut content = String::new();
        for file in &self.files {
            content.push_str(&super::hash::format_ed2k_link(&file.name, file.size, &file.hash));
            content.push('\n');
        }
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &content)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

fn parse_ed2k_link(link: &str) -> Option<CollectionFile> {
    let parts: Vec<&str> = link.split('|').collect();
    if parts.len() < 6 || parts[1] != "file" {
        return None;
    }
    let name = super::hash::percent_decode_str(parts[2]);
    let size: u64 = parts[3].parse().ok()?;
    let hash = parts[4].to_lowercase();
    if hash.len() != 32 || hex::decode(&hash).is_err() {
        return None;
    }
    Some(CollectionFile {
        name,
        size,
        hash,
        aich_hash: String::new(),
    })
}

enum TagValue {
    String(String),
    Uint32(u32),
    Uint64(u64),
    Hash([u8; 16]),
    Blob(Vec<u8>),
    Unknown,
}

fn read_tag(cursor: &mut Cursor<&Vec<u8>>) -> anyhow::Result<(u8, TagValue)> {
    let tag_type = cursor.read_u8()?;

    let name_id = if tag_type & 0x80 != 0 {
        cursor.read_u8()?
    } else {
        let name_len = cursor.read_u16::<LittleEndian>()? as usize;
        let mut name_buf = vec![0u8; name_len];
        cursor.read_exact(&mut name_buf)?;
        if name_len == 1 { name_buf[0] } else { 0 }
    };

    let real_type = tag_type & 0x7F;
    let value = match real_type {
        TAG_STRING => {
            let slen = cursor.read_u16::<LittleEndian>()? as usize;
            let capped = slen.min(4096);
            let mut sbuf = vec![0u8; capped];
            cursor.read_exact(&mut sbuf)?;
            if slen > capped {
                let skip = (slen - capped) as u64;
                let new_pos = cursor.position().checked_add(skip)
                    .filter(|&p| p <= cursor.get_ref().len() as u64)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "string tag skip out of bounds"))?;
                cursor.set_position(new_pos);
            }
            TagValue::String(String::from_utf8_lossy(&sbuf).to_string())
        }
        TAG_UINT32 => {
            let v = cursor.read_u32::<LittleEndian>()?;
            TagValue::Uint32(v)
        }
        TAG_HASH => {
            let mut h = [0u8; 16];
            cursor.read_exact(&mut h)?;
            TagValue::Hash(h)
        }
        TAG_BLOB => {
            let blen = cursor.read_u32::<LittleEndian>()? as usize;
            let capped = blen.min(65536);
            let mut bbuf = vec![0u8; capped];
            cursor.read_exact(&mut bbuf)?;
            if blen > capped {
                let skip = (blen - capped) as u64;
                let new_pos = cursor.position().checked_add(skip)
                    .filter(|&p| p <= cursor.get_ref().len() as u64)
                    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "blob tag skip out of bounds"))?;
                cursor.set_position(new_pos);
            }
            TagValue::Blob(bbuf)
        }
        0x08 => {
            let _ = cursor.read_u16::<LittleEndian>();
            TagValue::Unknown
        }
        0x09 => {
            let _ = cursor.read_u8();
            TagValue::Unknown
        }
        0x0B => {
            let v = cursor.read_u64::<LittleEndian>()?;
            TagValue::Uint64(v)
        }
        t if (0x11..=0x20).contains(&t) => {
            let len = (t - 0x11 + 1) as usize;
            let mut sbuf = vec![0u8; len];
            cursor.read_exact(&mut sbuf)?;
            TagValue::String(String::from_utf8_lossy(&sbuf).to_string())
        }
        other => {
            anyhow::bail!("unknown collection tag type 0x{other:02X} at position {}", cursor.position());
        }
    };

    Ok((name_id, value))
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) -> anyhow::Result<()> {
    buf.write_u8(TAG_STRING)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    let bytes = value.as_bytes();
    let clamped = &bytes[..bytes.len().min(u16::MAX as usize)];
    buf.write_u16::<LittleEndian>(clamped.len() as u16)?;
    buf.write_all(clamped)?;
    Ok(())
}

fn write_u32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) -> anyhow::Result<()> {
    buf.write_u8(TAG_UINT32)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u32::<LittleEndian>(value)?;
    Ok(())
}

fn write_u64_tag(buf: &mut Vec<u8>, name_id: u8, value: u64) -> anyhow::Result<()> {
    buf.write_u8(0x0B)?; // TAGTYPE_UINT64
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_u64::<LittleEndian>(value)?;
    Ok(())
}

fn write_hash_tag(buf: &mut Vec<u8>, name_id: u8, hash: &[u8]) -> anyhow::Result<()> {
    buf.write_u8(TAG_HASH)?;
    buf.write_u16::<LittleEndian>(1)?;
    buf.push(name_id);
    buf.write_all(hash)?;
    Ok(())
}
