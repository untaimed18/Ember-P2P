use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info};

// --- ZIP constants ---
const ZIP_LOCAL_HEADER_MAGIC: u32 = 0x04034b50;
const ZIP_CENTRAL_DIR_MAGIC: u32 = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIR_MAGIC: u32 = 0x06054b50;
const ZIP_LOCAL_HEADER_SIZE: usize = 30;
const ZIP_CENTRAL_DIR_ENTRY_SIZE: usize = 46;

// --- RAR constants ---
const RAR_SIGNATURE_OLD: &[u8] = b"RE~^";
const RAR_SIGNATURE_NEW: &[u8] = b"Rar!\x1a\x07\x00";
const RAR_HEAD_FILE: u8 = 0x74;
const RAR_HEAD_MAIN: u8 = 0x73;
const RAR_LONG_BLOCK: u16 = 0x8000;

// --- ACE constants ---
const ACE_SIGNATURE: &[u8] = b"**ACE**";
const ACE_FILE_HEADER_TYPE: u8 = 0x01;

/// Recover a partially downloaded archive. Scans the filled byte ranges
/// of the .part file for valid archive entries and writes a reconstructed
/// archive containing only the complete, validated entries.
///
/// Returns the path to the recovered file (original name with `-rec` suffix).
pub fn recover_archive(
    part_path: &Path,
    file_name: &str,
    filled_ranges: &[(u64, u64)],
) -> anyhow::Result<PathBuf> {
    if filled_ranges.is_empty() {
        anyhow::bail!("no filled ranges available for recovery");
    }

    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let stem = Path::new(file_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| file_name.to_string());

    let output_name = format!("{stem}-rec.{ext}");
    let output_path = part_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(&output_name);

    let mut input = std::fs::File::open(part_path)?;

    let result = match ext.as_str() {
        "zip" | "cbz" | "jar" => {
            info!("Attempting ZIP recovery on {file_name}");
            let mut output = std::fs::File::create(&output_path)?;
            recover_zip(&mut input, &mut output, filled_ranges)?
        }
        "rar" | "cbr" => {
            info!("Attempting RAR recovery on {file_name}");
            let mut output = std::fs::File::create(&output_path)?;
            recover_rar(&mut input, &mut output, filled_ranges)?
        }
        "ace" => {
            info!("Attempting ACE recovery on {file_name}");
            let mut output = std::fs::File::create(&output_path)?;
            recover_ace(&mut input, &mut output, filled_ranges)?
        }
        _ => {
            anyhow::bail!("unsupported archive format: .{ext}");
        }
    };

    if result > 0 {
        info!("Archive recovery complete: {result} entries recovered to {output_name}");
        Ok(output_path)
    } else {
        let _ = std::fs::remove_file(&output_path);
        anyhow::bail!("no valid archive entries found in downloaded data");
    }
}

fn is_filled(start: u64, end: u64, filled: &[(u64, u64)]) -> bool {
    if start >= end {
        return true;
    }
    let mut cursor = start;
    for &(fs, fe) in filled {
        if fs <= cursor && fe >= end {
            return true;
        }
        if fs <= cursor && fe > cursor {
            cursor = fe;
            if cursor >= end {
                return true;
            }
        }
    }
    false
}

// ==========================================================================
// ZIP Recovery
// ==========================================================================

struct ZipLocalEntry {
    compressed_size: u32,
    uncompressed_size: u32,
    crc32: u32,
    method: u16,
    flags: u16,
    file_name: Vec<u8>,
    extra: Vec<u8>,
    mod_time: u16,
    mod_date: u16,
    data_offset: u64,
}

fn recover_zip(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();
    let mut entries: Vec<ZipLocalEntry> = Vec::new();
    let mut buf = [0u8; 4];

    // Scan filled ranges for ZIP local file headers
    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + ZIP_LOCAL_HEADER_SIZE as u64 <= range_end {
            input.seek(SeekFrom::Start(pos))?;
            if input.read_exact(&mut buf).is_err() {
                break;
            }
            let magic = u32::from_le_bytes(buf);
            if magic != ZIP_LOCAL_HEADER_MAGIC {
                pos += 1;
                continue;
            }

            input.seek(SeekFrom::Start(pos))?;
            let mut header = [0u8; ZIP_LOCAL_HEADER_SIZE];
            if input.read_exact(&mut header).is_err() {
                pos += 1;
                continue;
            }

            let mut c = Cursor::new(&header[..]);
            c.set_position(4);
            let _version = c.read_u16::<LittleEndian>()?;
            let flags = c.read_u16::<LittleEndian>()?;
            let method = c.read_u16::<LittleEndian>()?;
            let mod_time = c.read_u16::<LittleEndian>()?;
            let mod_date = c.read_u16::<LittleEndian>()?;
            let crc32 = c.read_u32::<LittleEndian>()?;
            let compressed_size = c.read_u32::<LittleEndian>()?;
            let uncompressed_size = c.read_u32::<LittleEndian>()?;
            let name_len = c.read_u16::<LittleEndian>()? as usize;
            let extra_len = c.read_u16::<LittleEndian>()? as usize;

            if name_len == 0 || name_len > 512 {
                pos += 4;
                continue;
            }

            // ZIP64 entries use 0xFFFFFFFF as sentinel — skip them since the
            // struct uses u32 and >4GB individual entries are out of scope.
            if compressed_size == 0xFFFFFFFF || uncompressed_size == 0xFFFFFFFF {
                let data_offset = pos + ZIP_LOCAL_HEADER_SIZE as u64 + name_len as u64 + extra_len as u64;
                pos = data_offset;
                continue;
            }

            let data_offset = pos + ZIP_LOCAL_HEADER_SIZE as u64 + name_len as u64 + extra_len as u64;
            let entry_end = data_offset + compressed_size as u64;

            if entry_end > file_size {
                pos += 4;
                continue;
            }

            // Read file name and extra field
            let mut file_name = vec![0u8; name_len];
            if input.read_exact(&mut file_name).is_err() {
                pos += 4;
                continue;
            }
            let mut extra = vec![0u8; extra_len];
            if extra_len > 0 {
                if input.read_exact(&mut extra).is_err() {
                    pos += 4;
                    continue;
                }
            }

            // Validate: entry data must be within filled ranges
            if compressed_size > 0 && !is_filled(data_offset, entry_end, filled) {
                debug!("ZIP entry at {pos}: data not fully downloaded, skipping");
                pos = entry_end;
                continue;
            }

            // Validate CRC32 if stored (not when using data descriptor)
            let crc_valid = if crc32 != 0 && compressed_size > 0 && (flags & 0x08) == 0 {
                validate_zip_crc(input, data_offset, compressed_size, crc32)?
            } else {
                true
            };

            if !crc_valid {
                debug!("ZIP entry at {pos}: CRC mismatch, skipping");
                pos = entry_end;
                continue;
            }

            entries.push(ZipLocalEntry {
                compressed_size,
                uncompressed_size,
                crc32,
                method,
                flags,
                file_name,
                extra,
                mod_time,
                mod_date,
                data_offset,
            });

            pos = entry_end;
        }
    }

    if entries.is_empty() {
        return Ok(0);
    }

    // Write recovered ZIP: local headers + data + central directory + EOCD
    let mut central_dir_entries: Vec<Vec<u8>> = Vec::new();
    let mut copy_buf = vec![0u8; 64 * 1024];

    for entry in &entries {
        let local_header_offset = output.stream_position()?;

        // Write local file header
        output.write_u32::<LittleEndian>(ZIP_LOCAL_HEADER_MAGIC)?;
        output.write_u16::<LittleEndian>(20)?; // version needed
        output.write_u16::<LittleEndian>(entry.flags & !0x08)?; // clear data descriptor flag
        output.write_u16::<LittleEndian>(entry.method)?;
        output.write_u16::<LittleEndian>(entry.mod_time)?;
        output.write_u16::<LittleEndian>(entry.mod_date)?;
        output.write_u32::<LittleEndian>(entry.crc32)?;
        output.write_u32::<LittleEndian>(entry.compressed_size)?;
        output.write_u32::<LittleEndian>(entry.uncompressed_size)?;
        output.write_u16::<LittleEndian>(entry.file_name.len() as u16)?;
        output.write_u16::<LittleEndian>(entry.extra.len() as u16)?;
        output.write_all(&entry.file_name)?;
        output.write_all(&entry.extra)?;

        // Copy compressed data
        input.seek(SeekFrom::Start(entry.data_offset))?;
        let mut remaining = entry.compressed_size as u64;
        while remaining > 0 {
            let to_read = (remaining as usize).min(copy_buf.len());
            let n = input.read(&mut copy_buf[..to_read])?;
            if n == 0 {
                anyhow::bail!("short read during archive recovery: {} bytes remaining", remaining);
            }
            output.write_all(&copy_buf[..n])?;
            remaining -= n as u64;
        }

        // Build central directory entry
        let mut cd = Vec::with_capacity(ZIP_CENTRAL_DIR_ENTRY_SIZE + entry.file_name.len());
        cd.write_u32::<LittleEndian>(ZIP_CENTRAL_DIR_MAGIC)?;
        cd.write_u16::<LittleEndian>(20)?; // version made by
        cd.write_u16::<LittleEndian>(20)?; // version needed
        cd.write_u16::<LittleEndian>(entry.flags & !0x08)?;
        cd.write_u16::<LittleEndian>(entry.method)?;
        cd.write_u16::<LittleEndian>(entry.mod_time)?;
        cd.write_u16::<LittleEndian>(entry.mod_date)?;
        cd.write_u32::<LittleEndian>(entry.crc32)?;
        cd.write_u32::<LittleEndian>(entry.compressed_size)?;
        cd.write_u32::<LittleEndian>(entry.uncompressed_size)?;
        cd.write_u16::<LittleEndian>(entry.file_name.len() as u16)?;
        cd.write_u16::<LittleEndian>(0)?; // extra field length
        cd.write_u16::<LittleEndian>(0)?; // file comment length
        cd.write_u16::<LittleEndian>(0)?; // disk number start
        cd.write_u16::<LittleEndian>(0)?; // internal file attributes
        cd.write_u32::<LittleEndian>(0)?; // external file attributes
        cd.write_u32::<LittleEndian>(local_header_offset as u32)?;
        cd.write_all(&entry.file_name)?;
        central_dir_entries.push(cd);
    }

    // Write central directory
    let cd_offset = output.stream_position()?;
    let mut cd_size: u64 = 0;
    for cd in &central_dir_entries {
        output.write_all(cd)?;
        cd_size += cd.len() as u64;
    }

    // Write End of Central Directory Record
    output.write_u32::<LittleEndian>(ZIP_END_OF_CENTRAL_DIR_MAGIC)?;
    output.write_u16::<LittleEndian>(0)?; // disk number
    output.write_u16::<LittleEndian>(0)?; // disk number with CD
    output.write_u16::<LittleEndian>(entries.len() as u16)?;
    output.write_u16::<LittleEndian>(entries.len() as u16)?;
    output.write_u32::<LittleEndian>(cd_size as u32)?;
    output.write_u32::<LittleEndian>(cd_offset as u32)?;
    let comment = b"Recovered by Ember";
    output.write_u16::<LittleEndian>(comment.len() as u16)?;
    output.write_all(comment)?;

    output.flush()?;
    Ok(entries.len())
}

fn validate_zip_crc(
    input: &mut std::fs::File,
    offset: u64,
    size: u32,
    expected_crc: u32,
) -> anyhow::Result<bool> {
    input.seek(SeekFrom::Start(offset))?;
    let mut hasher = crc32fast::Hasher::new();
    let mut remaining = size as u64;
    let mut buf = [0u8; 64 * 1024];
    while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = input.read(&mut buf[..to_read])?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize() == expected_crc)
}

// ==========================================================================
// RAR Recovery
// ==========================================================================

fn recover_rar(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();

    // Detect RAR signature to determine old vs new format
    let mut sig_buf = [0u8; 7];
    let is_new_format = if filled.first().map(|r| r.0).unwrap_or(0) == 0 {
        input.seek(SeekFrom::Start(0))?;
        if input.read_exact(&mut sig_buf).is_ok() {
            &sig_buf == RAR_SIGNATURE_NEW
        } else {
            true
        }
    } else {
        true
    };

    // Write RAR signature + main archive header
    if is_new_format {
        output.write_all(RAR_SIGNATURE_NEW)?;
    } else {
        output.write_all(RAR_SIGNATURE_OLD)?;
    }

    // Write minimal main archive header
    let main_header: [u8; 13] = [
        0x73, 0x00,             // HEAD_CRC (placeholder)
        RAR_HEAD_MAIN,          // HEAD_TYPE
        0x00, 0x00,             // HEAD_FLAGS
        0x0D, 0x00,             // HEAD_SIZE (13)
        0x00, 0x00,             // HighPosAv
        0x00, 0x00, 0x00, 0x00, // PosAv
    ];
    output.write_all(&main_header)?;

    // Scan for RAR file headers in filled ranges
    let mut recovered = 0usize;
    let mut buf = [0u8; 7];
    let mut copy_buf = vec![0u8; 64 * 1024];

    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + 7 <= range_end {
            input.seek(SeekFrom::Start(pos))?;
            if input.read_exact(&mut buf).is_err() {
                break;
            }

            // RAR block: [HEAD_CRC 2][HEAD_TYPE 1][HEAD_FLAGS 2][HEAD_SIZE 2]
            let head_type = buf[2];
            if head_type != RAR_HEAD_FILE {
                pos += 1;
                continue;
            }

            let head_flags = u16::from_le_bytes([buf[3], buf[4]]);
            let head_size = u16::from_le_bytes([buf[5], buf[6]]) as u64;
            if head_size < 32 || head_size > 4096 {
                pos += 1;
                continue;
            }

            // Read the full header
            input.seek(SeekFrom::Start(pos))?;
            let mut header_data = vec![0u8; head_size as usize];
            if input.read_exact(&mut header_data).is_err() {
                pos += 1;
                continue;
            }

            // Parse file header fields
            if header_data.len() < 32 {
                pos += 1;
                continue;
            }

            let pack_size = u32::from_le_bytes([header_data[7], header_data[8], header_data[9], header_data[10]]) as u64;
            let method = header_data[18];
            let name_size = u16::from_le_bytes([header_data[19], header_data[20]]) as usize;

            // Validate compression method (0x30-0x35 = store to best)
            if method < 0x30 || method > 0x35 {
                pos += 1;
                continue;
            }

            if name_size == 0 || name_size > 512 || 32 + name_size > header_data.len() {
                pos += 1;
                continue;
            }

            // High part of packed size for large files
            let high_pack = if (head_flags & RAR_LONG_BLOCK) != 0 && header_data.len() >= 36 {
                u32::from_le_bytes([header_data[32], header_data[33], header_data[34], header_data[35]]) as u64
            } else {
                0
            };
            let total_pack = pack_size | (high_pack << 32);

            let data_start = pos + head_size;
            let data_end = data_start + total_pack;

            if data_end > file_size {
                pos += 1;
                continue;
            }

            if total_pack > 0 && !is_filled(data_start, data_end, filled) {
                pos = data_end;
                continue;
            }

            // Check if it's a directory entry (skip those for count)
            let is_dir = (header_data[21] & 0xE0) == 0xE0;

            // Write header + data to output
            output.write_all(&header_data)?;
            if total_pack > 0 {
                input.seek(SeekFrom::Start(data_start))?;
                let mut remaining = total_pack;
                while remaining > 0 {
                    let to_read = (remaining as usize).min(copy_buf.len());
                    let n = input.read(&mut copy_buf[..to_read])?;
                    if n == 0 {
                        anyhow::bail!("short read during RAR recovery: {} bytes remaining", remaining);
                    }
                    output.write_all(&copy_buf[..n])?;
                    remaining -= n as u64;
                }
            }

            if !is_dir {
                recovered += 1;
            }
            pos = data_end;
        }
    }

    output.flush()?;
    Ok(recovered)
}

// ==========================================================================
// ACE Recovery
// ==========================================================================

fn recover_ace(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();

    // Try to read and copy the ACE archive header from the start
    if filled.first().map(|r| r.0).unwrap_or(u64::MAX) == 0 {
        input.seek(SeekFrom::Start(0))?;
        let mut probe = [0u8; 14];
        if input.read_exact(&mut probe).is_ok() && probe.len() >= 14 {
            let head_size = u16::from_le_bytes([probe[2], probe[3]]) as u64;
            if head_size > 0 && head_size < 4096 && probe.get(7..14).map(|s| s == ACE_SIGNATURE).unwrap_or(false) {
                let total = 4 + head_size;
                input.seek(SeekFrom::Start(0))?;
                let mut header = vec![0u8; total as usize];
                if input.read_exact(&mut header).is_ok() {
                    output.write_all(&header)?;
                }
            }
        }
    }

    // Scan for ACE file headers
    let mut recovered = 0usize;
    let mut copy_buf = vec![0u8; 64 * 1024];

    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + 10 <= range_end {
            input.seek(SeekFrom::Start(pos))?;
            let mut header_start = [0u8; 4];
            if input.read_exact(&mut header_start).is_err() {
                break;
            }

            let _head_crc = u16::from_le_bytes([header_start[0], header_start[1]]);
            let head_size = u16::from_le_bytes([header_start[2], header_start[3]]) as u64;

            if head_size < 10 || head_size > 4096 {
                pos += 1;
                continue;
            }

            // Read the rest of the header
            let mut header_body = vec![0u8; head_size as usize];
            if input.read_exact(&mut header_body).is_err() {
                pos += 1;
                continue;
            }

            if header_body.is_empty() {
                pos += 1;
                continue;
            }

            let head_type = header_body[0];
            if head_type != ACE_FILE_HEADER_TYPE {
                pos += 1;
                continue;
            }

            if header_body.len() < 21 {
                pos += 1;
                continue;
            }

            let pack_size = u32::from_le_bytes([
                header_body[5], header_body[6], header_body[7], header_body[8],
            ]) as u64;

            let data_start = pos + 4 + head_size;
            let data_end = data_start + pack_size;

            if data_end > file_size {
                pos += 1;
                continue;
            }

            if pack_size > 0 && !is_filled(data_start, data_end, filled) {
                pos = data_end;
                continue;
            }

            // Write header + data
            output.write_all(&header_start)?;
            output.write_all(&header_body)?;
            if pack_size > 0 {
                input.seek(SeekFrom::Start(data_start))?;
                let mut remaining = pack_size;
                while remaining > 0 {
                    let to_read = (remaining as usize).min(copy_buf.len());
                    let n = input.read(&mut copy_buf[..to_read])?;
                    if n == 0 {
                        anyhow::bail!("short read during ACE recovery: {} bytes remaining", remaining);
                    }
                    output.write_all(&copy_buf[..n])?;
                    remaining -= n as u64;
                }
            }

            recovered += 1;
            pos = data_end;
        }
    }

    output.flush()?;
    Ok(recovered)
}

/// Check if a file name has an archive extension we can recover.
pub fn is_recoverable_archive(file_name: &str) -> bool {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "zip" | "cbz" | "jar" | "rar" | "cbr" | "ace")
}
