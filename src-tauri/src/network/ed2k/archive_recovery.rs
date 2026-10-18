use std::collections::HashMap;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::sharing::manager::TransferControl;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{debug, info};

// --- ZIP constants ---
const ZIP_LOCAL_HEADER_MAGIC: u32 = 0x04034b50;
const ZIP_CENTRAL_DIR_MAGIC: u32 = 0x02014b50;
const ZIP_END_OF_CENTRAL_DIR_MAGIC: u32 = 0x06054b50;
const ZIP_DATA_DESCRIPTOR_MAGIC: u32 = 0x08074b50;
const ZIP_LOCAL_HEADER_SIZE: usize = 30;
const ZIP_CENTRAL_DIR_ENTRY_SIZE: usize = 46;
const ZIP_END_OF_CENTRAL_DIR_SIZE: usize = 22;
/// General-purpose bit 3: the local header's CRC and sizes are zero and the
/// real ones follow the data in a data descriptor (and the central directory).
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;

// --- RAR constants ---
const RAR_SIGNATURE_OLD: &[u8] = b"RE~^";
const RAR_SIGNATURE_NEW: &[u8] = b"Rar!\x1a\x07\x00";
const RAR5_SIGNATURE: &[u8] = b"Rar!\x1a\x07\x01\x00";
const RAR_HEAD_FILE: u8 = 0x74;
const RAR_HEAD_MAIN: u8 = 0x73;
/// `LHD_LARGE`: HIGH_PACK_SIZE and HIGH_UNP_SIZE follow the fixed header, and
/// the name moves from byte 32 to 40. Not `0x8000` (`LONG_BLOCK`), which only
/// says data follows the header and is set on every file header.
const RAR_LHD_LARGE: u16 = 0x0100;
/// `LHD_UNICODE`: the name is a plain name, a NUL, then an encoded Unicode one.
const RAR_LHD_UNICODE: u16 = 0x0200;
/// The file header fields before the name: through ATTR.
const RAR_FILE_HEAD_FIXED: usize = 32;
/// A main archive header with no flags, `HEAD_CRC` 0x90CF, exactly as WinRAR
/// writes it.
const RAR_MAIN_HEADER: [u8; 13] = [
    0xCF, 0x90, RAR_HEAD_MAIN, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// --- ACE constants ---
const ACE_SIGNATURE: &[u8] = b"**ACE**";
const ACE_FILE_HEADER_TYPE: u8 = 0x01;

const MAX_RECOVERY_INPUT_BYTES: u64 = 128 * 1024 * 1024 * 1024;
const MAX_RECOVERY_OUTPUT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_RECOVERY_ENTRY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_RECOVERY_ENTRIES: usize = 10_000;
const MAX_DECOMPRESSION_RATIO: u64 = 200;
/// Wall-clock ceiling for `recover_archive` itself. Exposed so the IPC caller
/// can size its own timeout as this plus a verification allowance, rather than
/// hardcoding a number that silently stops covering both phases.
pub(crate) const RECOVERY_WALL_TIME: std::time::Duration = std::time::Duration::from_secs(120);

struct RecoveryBudget<'a> {
    started: std::time::Instant,
    output_bytes: u64,
    entries: usize,
    cancelled: &'a AtomicBool,
}

impl<'a> RecoveryBudget<'a> {
    fn new(cancelled: &'a AtomicBool) -> Self {
        Self {
            started: std::time::Instant::now(),
            output_bytes: 0,
            entries: 0,
            cancelled,
        }
    }

    fn check(&self, control: Option<&TransferControl>) -> anyhow::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            anyhow::bail!("archive recovery cancelled");
        }
        if control.is_some_and(TransferControl::is_cancelled) {
            anyhow::bail!("archive recovery cancelled");
        }
        if self.started.elapsed() > RECOVERY_WALL_TIME {
            anyhow::bail!("archive recovery exceeded wall-time limit");
        }
        Ok(())
    }

    fn reserve_output(&mut self, bytes: u64) -> anyhow::Result<()> {
        self.output_bytes = self
            .output_bytes
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("archive recovery output size overflow"))?;
        if self.output_bytes > MAX_RECOVERY_OUTPUT_BYTES {
            anyhow::bail!("archive recovery output exceeds limit");
        }
        Ok(())
    }

    fn add_entry(&mut self) -> anyhow::Result<()> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > MAX_RECOVERY_ENTRIES {
            anyhow::bail!("archive recovery entry count exceeds limit");
        }
        Ok(())
    }
}

/// Recover a partially downloaded archive. Scans the filled byte ranges
/// of the .part file for valid archive entries and writes a reconstructed
/// archive containing only the complete, validated entries.
///
/// Returns the path to the recovered file (original name with `-rec` suffix).
pub fn recover_archive(
    part_path: &Path,
    file_name: &str,
    filled_ranges: &[(u64, u64)],
    output_dir: &Path,
    allowed_roots: &[String],
    control: Option<&TransferControl>,
    cancelled: &AtomicBool,
) -> anyhow::Result<PathBuf> {
    if filled_ranges.is_empty() {
        anyhow::bail!("no filled ranges available for recovery");
    }
    let mut previous_end = 0u64;
    for &(start, end) in filled_ranges {
        if start >= end || start < previous_end {
            anyhow::bail!("verified recovery ranges are invalid or overlap");
        }
        previous_end = end;
    }

    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let stem = Path::new(file_name)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| file_name.to_string());

    // Run the same sanitizer the download path uses on the recovered
    // archive's outer name, so a peer-supplied `file_name` like
    // `..\..\evil.zip` or one with NUL/reserved Windows names can't
    // produce a surprising path next to the `.part` file. The inner
    // archive entries are sanitized separately by
    // `sanitize_zip_entry_name` (zip path) and
    // `sanitize_archive_name_in_place` (RAR/ACE paths).
    let safe_stem_full = crate::security::sanitize_filename(&stem);
    let safe_ext = crate::security::sanitize_filename(&ext);
    let input_size = std::fs::metadata(part_path)?.len();
    if input_size > MAX_RECOVERY_INPUT_BYTES {
        anyhow::bail!("archive recovery input exceeds limit");
    }
    if previous_end > input_size {
        anyhow::bail!("verified recovery range exceeds input size");
    }
    let verified_output_dir =
        crate::security::filesystem::verify_existing_path(output_dir, allowed_roots)?;
    crate::security::filesystem::ensure_not_reparse(&verified_output_dir)?;
    let output_dir_identity = crate::security::filesystem::object_identity(&verified_output_dir)?;
    let mut output = None;
    for _ in 0..32 {
        let output_name = format!(
            "{safe_stem_full}-rec-{}.{}",
            uuid::Uuid::new_v4().simple(),
            safe_ext
        );
        if crate::security::filesystem::object_identity(&verified_output_dir)?
            != output_dir_identity
        {
            anyhow::bail!("archive recovery output directory changed identity");
        }
        match crate::security::filesystem::create_new_in_approved_parent(
            &verified_output_dir,
            std::ffi::OsStr::new(&output_name),
            allowed_roots,
        ) {
            Ok((output_path, file)) => {
                output = Some((output_path, file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (output_path, mut output_file) =
        output.ok_or_else(|| anyhow::anyhow!("could not allocate exclusive recovery output"))?;
    if let Err(error) = crate::security::restrict_open_file_permissions_checked(&output_file, false)
    {
        drop(output_file);
        let _ = crate::security::filesystem::remove_approved_file(&output_path, allowed_roots);
        return Err(error.into());
    }

    let (_, mut input) =
        crate::security::filesystem::open_existing_approved(part_path, allowed_roots, false)?;
    let mut budget = RecoveryBudget::new(cancelled);
    budget.check(control)?;

    let result: anyhow::Result<usize> = match ext.as_str() {
        "zip" | "cbz" | "jar" => {
            info!("Attempting ZIP recovery on {file_name}");
            recover_zip(
                &mut input,
                &mut output_file,
                filled_ranges,
                &mut budget,
                control,
            )
        }
        "rar" | "cbr" => {
            info!("Attempting RAR recovery on {file_name}");
            recover_rar(
                &mut input,
                &mut output_file,
                filled_ranges,
                &mut budget,
                control,
            )
        }
        "ace" => {
            info!("Attempting ACE recovery on {file_name}");
            recover_ace(
                &mut input,
                &mut output_file,
                filled_ranges,
                &mut budget,
                control,
            )
        }
        _ => Err(anyhow::anyhow!("unsupported archive format: .{ext}")),
    };
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            drop(output_file);
            let _ = crate::security::filesystem::remove_approved_file(&output_path, allowed_roots);
            return Err(error);
        }
    };

    if result > 0 {
        if crate::security::filesystem::object_identity(&verified_output_dir)?
            != output_dir_identity
        {
            drop(output_file);
            let _ = crate::security::filesystem::remove_approved_file(&output_path, allowed_roots);
            anyhow::bail!("archive recovery input/output root changed during recovery");
        }
        if let Err(error) = output_file.sync_all() {
            drop(output_file);
            let _ = crate::security::filesystem::remove_approved_file(&output_path, allowed_roots);
            return Err(error.into());
        }
        info!(
            "Archive recovery complete: {result} entries recovered to {}",
            output_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("<recovered>")
        );
        Ok(output_path)
    } else {
        drop(output_file);
        let _ = crate::security::filesystem::remove_approved_file(&output_path, allowed_roots);
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

/// What a central directory record says about the entry whose local header
/// sits at its (archive-start adjusted) offset.
struct ZipCentralEntry {
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    method: u16,
}

/// The CRC and sizes an entry is recovered with, wherever they came from.
#[derive(Clone, Copy)]
struct ZipSizes {
    crc32: u32,
    compressed_size: u32,
    uncompressed_size: u32,
    /// Bytes of data descriptor known to follow the data, so the scan can step
    /// over it.
    descriptor_len: u64,
    /// Locating the descriptor already proved the data against `crc32`.
    crc_checked: bool,
}

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn recover_zip(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
    budget: &mut RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();
    let central = read_zip_central_directory(input, file_size, filled, budget, control)?;
    let mut entries: Vec<ZipLocalEntry> = Vec::new();
    let mut buf = [0u8; 4];

    // Scan filled ranges for ZIP local file headers
    // Count iterations rather than testing `pos` alignment. The entry-skip
    // paths below jump `pos` by an archive-controlled stride, so a crafted
    // header chain can step past every 4096-aligned offset and never reach the
    // budget check — which is the only place the wall clock and the caller's
    // cancel flag are observed.
    let mut steps: u32 = 0;
    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + ZIP_LOCAL_HEADER_SIZE as u64 <= range_end {
            steps = steps.wrapping_add(1);
            if steps.is_multiple_of(1024) {
                budget.check(control)?;
            }
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
                let data_offset =
                    pos + ZIP_LOCAL_HEADER_SIZE as u64 + name_len as u64 + extra_len as u64;
                pos = data_offset;
                continue;
            }

            let data_offset =
                pos + ZIP_LOCAL_HEADER_SIZE as u64 + name_len as u64 + extra_len as u64;
            // The name and extra field are copied into the output as well, so
            // they have to be downloaded bytes just as the data does.
            if !is_filled(pos, data_offset, filled) {
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

            let central_entry = central.get(&pos).filter(|c| c.method == method);
            let local_sizes = ZipSizes {
                crc32,
                compressed_size,
                uncompressed_size,
                descriptor_len: 0,
                crc_checked: false,
            };
            let sizes = if flags & ZIP_FLAG_DATA_DESCRIPTOR == 0 {
                Some(local_sizes)
            } else if let Some(c) = central_entry {
                Some(ZipSizes {
                    crc32: c.crc32,
                    compressed_size: c.compressed_size,
                    uncompressed_size: c.uncompressed_size,
                    descriptor_len: 0,
                    crc_checked: false,
                })
            } else {
                match find_zip_data_descriptor(input, filled, data_offset, method, budget, control)?
                {
                    Some(found) => Some(found),
                    // Some writers fill in the local header despite bit 3; the
                    // CRC check below still has to pass.
                    None if compressed_size > 0 => Some(local_sizes),
                    None => None,
                }
            };
            let Some(sizes) = sizes else {
                debug!("ZIP entry at {pos}: sizes deferred to a data descriptor that cannot be located, skipping");
                pos = data_offset;
                continue;
            };
            if sizes.compressed_size == u32::MAX || sizes.uncompressed_size == u32::MAX {
                pos = data_offset;
                continue;
            }
            if sizes.compressed_size as u64 > MAX_RECOVERY_ENTRY_BYTES
                || sizes.uncompressed_size as u64 > MAX_RECOVERY_ENTRY_BYTES
                || (sizes.uncompressed_size as u64)
                    > (sizes.compressed_size as u64)
                        .max(1)
                        .saturating_mul(MAX_DECOMPRESSION_RATIO)
            {
                pos += 4;
                continue;
            }

            let entry_end = data_offset + sizes.compressed_size as u64;
            if entry_end > file_size {
                pos += 4;
                continue;
            }

            // Validate: entry data must be within filled ranges
            if sizes.compressed_size > 0 && !is_filled(data_offset, entry_end, filled) {
                debug!("ZIP entry at {pos}: data not fully downloaded, skipping");
                pos = entry_end;
                continue;
            }

            // A CRC value of zero is valid (rare, but possible).
            let crc_valid = if sizes.crc_checked {
                true
            } else if matches!(method, 0 | 8) {
                validate_zip_crc(
                    input,
                    data_offset,
                    sizes.compressed_size,
                    sizes.uncompressed_size,
                    method,
                    sizes.crc32,
                    budget,
                    control,
                )?
            } else {
                // No decoder to check the CRC with, so only a downloaded central
                // directory that agrees on every field vouches for the entry;
                // otherwise any `PK\3\4` inside compressed data whose method
                // field is not 0 or 8 passed as an entry.
                central_entry.is_some_and(|c| {
                    c.crc32 == sizes.crc32
                        && c.compressed_size == sizes.compressed_size
                        && c.uncompressed_size == sizes.uncompressed_size
                })
            };

            if !crc_valid {
                debug!("ZIP entry at {pos}: CRC mismatch, skipping");
                pos = entry_end;
                continue;
            }

            // D17: strip any leading `/`, backslashes, and `..` path
            // components from the inner entry name before carrying it into
            // the recovered archive. A malicious .zip inside the original
            // file could otherwise encode zip-slip paths (e.g.
            // `../../etc/cron.d/evil`) and whatever extractor the user
            // runs later would place them outside the extraction root.
            let safe_file_name = sanitize_zip_entry_name(&file_name);

            budget.add_entry()?;
            entries.push(ZipLocalEntry {
                compressed_size: sizes.compressed_size,
                uncompressed_size: sizes.uncompressed_size,
                crc32: sizes.crc32,
                method,
                flags,
                file_name: safe_file_name,
                extra,
                mod_time,
                mod_date,
                data_offset,
            });

            pos = entry_end + sizes.descriptor_len;
        }
    }

    if entries.is_empty() {
        return Ok(0);
    }

    // The writer below only emits classic (non-Zip64) ZIP records: entry
    // count and every offset/size are packed into u32/u16 fields with a
    // plain `as` cast. Bail rather than silently truncating — a truncated
    // offset/count still writes a "successfully recovered" file (the
    // function returns `Ok`), just one whose central directory points at
    // the wrong bytes, which is worse than an outright failure since it's
    // silent corruption discovered only when the user later tries to open
    // the archive. Large multi-GB archives / >65535-entry archives are
    // realistic for eD2k-shared ISOs, game installs, and video collections,
    // so this isn't a hypothetical edge case.
    if entries.len() > u16::MAX as usize {
        anyhow::bail!(
            "cannot recover ZIP: {} entries exceeds the {}-entry limit of the \
             non-Zip64 central directory this recovery writer emits",
            entries.len(),
            u16::MAX
        );
    }

    // Write recovered ZIP: local headers + data + central directory + EOCD
    let mut central_dir_entries: Vec<Vec<u8>> = Vec::new();
    let mut copy_buf = vec![0u8; 64 * 1024];

    for entry in &entries {
        budget.check(control)?;
        budget.reserve_output(
            ZIP_LOCAL_HEADER_SIZE as u64
                + entry.file_name.len() as u64
                + entry.extra.len() as u64
                + entry.compressed_size as u64
                + ZIP_CENTRAL_DIR_ENTRY_SIZE as u64
                + entry.file_name.len() as u64,
        )?;
        let local_header_offset = output.stream_position()?;
        if local_header_offset > u32::MAX as u64 {
            anyhow::bail!(
                "cannot recover ZIP: local header offset {local_header_offset} exceeds the \
                 4 GiB limit of the non-Zip64 central directory this recovery writer emits"
            );
        }

        // Write local file header
        output.write_u32::<LittleEndian>(ZIP_LOCAL_HEADER_MAGIC)?;
        output.write_u16::<LittleEndian>(20)?; // version needed
        output.write_u16::<LittleEndian>(entry.flags & !ZIP_FLAG_DATA_DESCRIPTOR)?;
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
            budget.check(control)?;
            let to_read = (remaining as usize).min(copy_buf.len());
            let n = input.read(&mut copy_buf[..to_read])?;
            if n == 0 {
                anyhow::bail!(
                    "short read during archive recovery: {} bytes remaining",
                    remaining
                );
            }
            output.write_all(&copy_buf[..n])?;
            remaining -= n as u64;
        }

        // Build central directory entry
        let mut cd = Vec::with_capacity(ZIP_CENTRAL_DIR_ENTRY_SIZE + entry.file_name.len());
        cd.write_u32::<LittleEndian>(ZIP_CENTRAL_DIR_MAGIC)?;
        cd.write_u16::<LittleEndian>(20)?; // version made by
        cd.write_u16::<LittleEndian>(20)?; // version needed
        cd.write_u16::<LittleEndian>(entry.flags & !ZIP_FLAG_DATA_DESCRIPTOR)?;
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
    if cd_offset > u32::MAX as u64 {
        anyhow::bail!(
            "cannot recover ZIP: central directory offset {cd_offset} exceeds the 4 GiB \
             limit of the non-Zip64 central directory this recovery writer emits"
        );
    }
    let mut cd_size: u64 = 0;
    for cd in &central_dir_entries {
        budget.check(control)?;
        output.write_all(cd)?;
        cd_size += cd.len() as u64;
    }
    if cd_size > u32::MAX as u64 {
        anyhow::bail!(
            "cannot recover ZIP: central directory size {cd_size} exceeds the 4 GiB \
             limit of the non-Zip64 central directory this recovery writer emits"
        );
    }

    // Write End of Central Directory Record
    let comment = b"Recovered by Ember";
    budget.reserve_output(22 + comment.len() as u64)?;
    output.write_u32::<LittleEndian>(ZIP_END_OF_CENTRAL_DIR_MAGIC)?;
    output.write_u16::<LittleEndian>(0)?; // disk number
    output.write_u16::<LittleEndian>(0)?; // disk number with CD
    output.write_u16::<LittleEndian>(entries.len() as u16)?;
    output.write_u16::<LittleEndian>(entries.len() as u16)?;
    output.write_u32::<LittleEndian>(cd_size as u32)?;
    output.write_u32::<LittleEndian>(cd_offset as u32)?;
    output.write_u16::<LittleEndian>(comment.len() as u16)?;
    output.write_all(comment)?;

    output.flush()?;
    Ok(entries.len())
}

/// Neutralize path-traversal bytes inside an RAR/ACE filename **in
/// place** — we can't change the byte length without rewriting the
/// surrounding header (size fields, offsets), so we keep the same
/// length and just replace dangerous bytes with `_`.
///
/// After this call:
///   * No path separators remain (`/`, `\`, `:`), so any extractor
///     interprets the name as a single filename, not a path.
///   * NUL bytes are removed (they truncate the displayed name on
///     some extractors — defensive only).
///   * Pure-`.` / pure-`..` names are turned into `_` / `__` so the
///     extractor doesn't try to write to the destination's parent
///     directory or refuse the entry.
///
/// This is the same defense the ZIP path applies via
/// `sanitize_zip_entry_name`, ported to formats where we can't rebuild
/// the header.
fn sanitize_archive_name_in_place(name: &mut [u8]) {
    for byte in name.iter_mut() {
        match *byte {
            b'/' | b'\\' | b':' | 0 => *byte = b'_',
            _ => {}
        }
    }
    // Reject pure-`.` / `..` references after separator stripping so
    // the extractor can't interpret the name as a parent-directory
    // reference. Only matches the *whole* name; embedded dots are fine
    // (e.g. `..foo` becomes itself, which is a valid filename).
    if name == b"." || name == b".." {
        for byte in name.iter_mut() {
            *byte = b'_';
        }
    }
    // Neutralize Windows reserved device names (CON, PRN, NUL, COM1…) by
    // overwriting the first byte. We can't change the length here, so we
    // mutate in place; this still breaks the reserved match so an extractor
    // on Windows doesn't choke on the recovered entry.
    if is_windows_reserved_base(name) {
        if let Some(first) = name.first_mut() {
            *first = b'_';
        }
    }
}

/// Same reserved-device check as `security::is_reserved_windows_device_name`.
/// That helper is module-private, so this copy stays here for untrusted
/// archive bytes; keep the stem rules and reserved set aligned with it.
fn is_windows_reserved_base(name: &[u8]) -> bool {
    let name = String::from_utf8_lossy(name);
    let mut stem = String::new();
    for c in name.chars() {
        if c == '.' {
            break;
        }
        let as_digit = match c {
            '\u{00B9}' => '1',
            '\u{00B2}' => '2',
            '\u{00B3}' => '3',
            other => other,
        };
        stem.extend(as_digit.to_uppercase());
    }
    matches!(
        stem.trim_end_matches(['.', ' ']),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "COM0"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT0"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

/// D17: rewrite an inner ZIP entry name so it cannot zip-slip when a
/// downstream extractor writes it out. We:
///   * strip any leading `/` or drive-letter prefix,
///   * drop backslashes (Windows path separators — ZIP spec mandates `/`),
///   * remove `..` path components so the name cannot escape the target,
///   * remove NUL bytes and other control characters.
///
/// The result is always a relative path (or a single filename). Empty
/// names fall back to `_` to keep the archive structurally valid.
fn sanitize_zip_entry_name(raw: &[u8]) -> Vec<u8> {
    // Treat as UTF-8 lossily for component splitting; write out as bytes.
    let as_str = String::from_utf8_lossy(raw);
    let mut parts: Vec<String> = Vec::new();
    for seg in as_str.split(['/', '\\']) {
        if seg.is_empty() || seg == "." || seg == ".." {
            continue;
        }
        // Strip Windows drive-letter prefix on the first segment (e.g. "C:")
        // and drop control characters / NULs defensively.
        let cleaned: String = seg
            .chars()
            .filter(|c| *c != '\0' && !c.is_control() && *c != ':')
            .collect();
        if cleaned.is_empty() {
            continue;
        }
        // Neutralize Windows reserved device names per path component so the
        // extracted tree can't contain a CON/PRN/NUL/COM1… entry.
        let cleaned = if is_windows_reserved_base(cleaned.as_bytes()) {
            format!("_{cleaned}")
        } else {
            cleaned
        };
        parts.push(cleaned);
    }
    let joined = parts.join("/");
    if joined.is_empty() {
        b"_".to_vec()
    } else {
        joined.into_bytes()
    }
}

fn validate_zip_crc(
    input: &mut std::fs::File,
    offset: u64,
    size: u32,
    uncompressed_size: u32,
    method: u16,
    expected_crc: u32,
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<bool> {
    input.seek(SeekFrom::Start(offset))?;
    let limited = input.take(size as u64);
    let actual_crc = match method {
        0 => crc32_reader_limited(limited, uncompressed_size as u64, budget, control)?,
        8 => crc32_reader_limited(
            flate2::read::DeflateDecoder::new(limited),
            uncompressed_size as u64,
            budget,
            control,
        )?,
        _ => return Ok(false),
    };
    Ok(actual_crc == Some(expected_crc))
}

/// Central directory records keyed by where each entry's local header sits in
/// the `.part`, or an empty map when the end record or the directory itself was
/// not downloaded (or is ZIP64 / multi-disk, which this does not read).
fn read_zip_central_directory(
    input: &mut std::fs::File,
    file_size: u64,
    filled: &[(u64, u64)],
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<HashMap<u64, ZipCentralEntry>> {
    let mut entries = HashMap::new();
    let tail_len = file_size.min(ZIP_END_OF_CENTRAL_DIR_SIZE as u64 + u16::MAX as u64);
    if tail_len < ZIP_END_OF_CENTRAL_DIR_SIZE as u64 {
        return Ok(entries);
    }
    let tail_start = file_size - tail_len;
    let mut tail = vec![0u8; tail_len as usize];
    input.seek(SeekFrom::Start(tail_start))?;
    input.read_exact(&mut tail)?;
    let magic = ZIP_END_OF_CENTRAL_DIR_MAGIC.to_le_bytes();
    let Some(at) = (0..=tail.len() - ZIP_END_OF_CENTRAL_DIR_SIZE).rev().find(|&i| {
        tail[i..i + 4] == magic
            && is_filled(
                tail_start + i as u64,
                tail_start + (i + ZIP_END_OF_CENTRAL_DIR_SIZE) as u64,
                filled,
            )
    }) else {
        return Ok(entries);
    };
    let record = &tail[at..at + ZIP_END_OF_CENTRAL_DIR_SIZE];
    if le_u16(record, 4) != 0 || le_u16(record, 6) != 0 {
        return Ok(entries);
    }
    let count = le_u16(record, 10) as usize;
    let cd_size = le_u32(record, 12);
    let cd_offset = le_u32(record, 16);
    if cd_size == u32::MAX || cd_offset == u32::MAX {
        return Ok(entries);
    }
    let end_record_at = tail_start + at as u64;
    // Recorded offsets count from the start of the archive, which a prepended
    // self-extractor stub moves away from the start of the file.
    let Some(cd_start) = end_record_at.checked_sub(cd_size as u64) else {
        return Ok(entries);
    };
    let Some(bias) = cd_start.checked_sub(cd_offset as u64) else {
        return Ok(entries);
    };
    if !is_filled(cd_start, end_record_at, filled) {
        return Ok(entries);
    }

    input.seek(SeekFrom::Start(cd_start))?;
    let mut reader = std::io::BufReader::new(Read::take(&mut *input, cd_size as u64));
    let mut header = [0u8; ZIP_CENTRAL_DIR_ENTRY_SIZE];
    for i in 0..count.min(MAX_RECOVERY_ENTRIES) {
        if i % 1024 == 0 {
            budget.check(control)?;
        }
        if reader.read_exact(&mut header).is_err() || le_u32(&header, 0) != ZIP_CENTRAL_DIR_MAGIC {
            break;
        }
        let variable =
            le_u16(&header, 28) as u64 + le_u16(&header, 30) as u64 + le_u16(&header, 32) as u64;
        if std::io::copy(&mut Read::take(&mut reader, variable), &mut std::io::sink())? != variable
        {
            break;
        }
        let local_offset = le_u32(&header, 42);
        if local_offset == u32::MAX {
            continue;
        }
        entries.insert(
            local_offset as u64 + bias,
            ZipCentralEntry {
                crc32: le_u32(&header, 16),
                compressed_size: le_u32(&header, 20),
                uncompressed_size: le_u32(&header, 24),
                method: le_u16(&header, 10),
            },
        );
    }
    Ok(entries)
}

/// End of the run of contiguous downloaded bytes that `at` falls in.
fn filled_run_end(at: u64, filled: &[(u64, u64)]) -> Option<u64> {
    let mut end = None;
    for &(start, stop) in filled {
        match end {
            None if start <= at && at < stop => end = Some(stop),
            Some(e) if start <= e => end = Some(stop.max(e)),
            Some(_) => break,
            None => {}
        }
    }
    end
}

/// Sizes and CRC for a bit-3 entry with no central directory to ask, read from
/// the data descriptor after its data.
///
/// Deflate marks its own end, so inflating finds where the descriptor starts.
/// Stored data does not, so the descriptor is searched for, and only the
/// signed form is accepted: an unsigned one is twelve bytes any data can
/// contain (twelve zero bytes "describe" an empty entry). Other methods cannot
/// be bounded at all. Both found forms are checked against the CRC and sizes of
/// the data they close, so a match is never taken on the descriptor's say-so.
fn find_zip_data_descriptor(
    input: &mut std::fs::File,
    filled: &[(u64, u64)],
    data_offset: u64,
    method: u16,
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<Option<ZipSizes>> {
    let Some(run_end) = filled_run_end(data_offset, filled) else {
        return Ok(None);
    };
    let limit = run_end.min(data_offset.saturating_add(MAX_RECOVERY_ENTRY_BYTES + 16));
    match method {
        8 => {
            let Some((compressed, uncompressed, crc)) =
                inflate_zip_entry(input, data_offset, limit, budget, control)?
            else {
                return Ok(None);
            };
            let (Ok(compressed), Ok(uncompressed)) =
                (u32::try_from(compressed), u32::try_from(uncompressed))
            else {
                return Ok(None);
            };
            read_zip_data_descriptor(
                input,
                data_offset + compressed as u64,
                limit,
                ZipSizes {
                    crc32: crc,
                    compressed_size: compressed,
                    uncompressed_size: uncompressed,
                    descriptor_len: 0,
                    crc_checked: true,
                },
            )
        }
        0 => find_stored_zip_data_descriptor(input, data_offset, limit, budget, control),
        _ => Ok(None),
    }
}

/// Inflate a raw deflate stream starting at `start` without reading at or past
/// `limit`: `(compressed bytes, uncompressed bytes, CRC-32)` when the stream
/// ends in time, `None` when it is corrupt or runs out of downloaded bytes.
fn inflate_zip_entry(
    input: &mut std::fs::File,
    start: u64,
    limit: u64,
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<Option<(u64, u64, u32)>> {
    let max_output = (limit - start)
        .max(1)
        .saturating_mul(MAX_DECOMPRESSION_RATIO)
        .min(MAX_RECOVERY_ENTRY_BYTES);
    let mut inflater = flate2::Decompress::new(false);
    let mut hasher = crc32fast::Hasher::new();
    let mut in_buf = vec![0u8; 64 * 1024];
    let mut out_buf = vec![0u8; 64 * 1024];
    let (mut in_pos, mut in_len) = (0usize, 0usize);
    let mut next_read = start;
    input.seek(SeekFrom::Start(start))?;
    loop {
        budget.check(control)?;
        if in_pos == in_len {
            let want = (limit - next_read).min(in_buf.len() as u64) as usize;
            if want == 0 {
                return Ok(None);
            }
            input.read_exact(&mut in_buf[..want])?;
            next_read += want as u64;
            (in_pos, in_len) = (0, want);
        }
        let (before_in, before_out) = (inflater.total_in(), inflater.total_out());
        let Ok(status) = inflater.decompress(
            &in_buf[in_pos..in_len],
            &mut out_buf,
            flate2::FlushDecompress::None,
        ) else {
            return Ok(None);
        };
        let consumed = (inflater.total_in() - before_in) as usize;
        let produced = (inflater.total_out() - before_out) as usize;
        in_pos += consumed;
        hasher.update(&out_buf[..produced]);
        if inflater.total_out() > max_output {
            return Ok(None);
        }
        if status == flate2::Status::StreamEnd {
            return Ok(Some((
                inflater.total_in(),
                inflater.total_out(),
                hasher.finalize(),
            )));
        }
        if consumed == 0 && produced == 0 && in_pos < in_len {
            return Ok(None);
        }
    }
}

/// `expected` with its descriptor length set, if the descriptor at `at`
/// (signature optional) states exactly its CRC and sizes.
fn read_zip_data_descriptor(
    input: &mut std::fs::File,
    at: u64,
    limit: u64,
    expected: ZipSizes,
) -> anyhow::Result<Option<ZipSizes>> {
    let available = limit.saturating_sub(at).min(16) as usize;
    if available < 12 {
        return Ok(None);
    }
    let mut descriptor = [0u8; 16];
    input.seek(SeekFrom::Start(at))?;
    input.read_exact(&mut descriptor[..available])?;
    let states_expected = |fields: &[u8]| {
        le_u32(fields, 0) == expected.crc32
            && le_u32(fields, 4) == expected.compressed_size
            && le_u32(fields, 8) == expected.uncompressed_size
    };
    let descriptor_len = if available == 16
        && le_u32(&descriptor, 0) == ZIP_DATA_DESCRIPTOR_MAGIC
        && states_expected(&descriptor[4..])
    {
        16
    } else if states_expected(&descriptor) {
        12
    } else {
        return Ok(None);
    };
    Ok(Some(ZipSizes {
        descriptor_len,
        ..expected
    }))
}

/// The first signed data descriptor after `data_offset` that states the CRC
/// and length of exactly the bytes before it.
fn find_stored_zip_data_descriptor(
    input: &mut std::fs::File,
    data_offset: u64,
    limit: u64,
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<Option<ZipSizes>> {
    const DESCRIPTOR_LEN: usize = 16;
    let magic = ZIP_DATA_DESCRIPTOR_MAGIC.to_le_bytes();
    // CRC of `data_offset..base` at the top of each window.
    let mut hasher = crc32fast::Hasher::new();
    let mut base = data_offset;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        budget.check(control)?;
        let available = (limit - base).min(buf.len() as u64) as usize;
        if available < DESCRIPTOR_LEN {
            return Ok(None);
        }
        input.seek(SeekFrom::Start(base))?;
        input.read_exact(&mut buf[..available])?;
        // Every offset whose whole descriptor is in `buf`; the rest are
        // examined at the start of the next window.
        let scanned = available - DESCRIPTOR_LEN + 1;
        // `hasher` is advanced only up to each candidate, so a run of fake
        // descriptors costs one pass over the window, not one per candidate.
        let mut hashed = 0;
        for i in 0..scanned {
            if buf[i..i + 4] != magic {
                continue;
            }
            let length = base + i as u64 - data_offset;
            let compressed = le_u32(&buf, i + 8);
            if compressed as u64 != length || le_u32(&buf, i + 12) != compressed {
                continue;
            }
            let crc = le_u32(&buf, i + 4);
            hasher.update(&buf[hashed..i]);
            hashed = i;
            if hasher.clone().finalize() == crc {
                return Ok(Some(ZipSizes {
                    crc32: crc,
                    compressed_size: compressed,
                    uncompressed_size: compressed,
                    descriptor_len: DESCRIPTOR_LEN as u64,
                    crc_checked: true,
                }));
            }
        }
        hasher.update(&buf[hashed..scanned]);
        base += scanned as u64;
        if base - data_offset > u32::MAX as u64 {
            return Ok(None);
        }
    }
}

/// CRC-32 of exactly `expected_size` bytes drained from `reader`, or `None`
/// when the entry doesn't produce that many bytes — either because it
/// inflates past its declared size or because it stops short.
///
/// Both are per-entry verdicts, not archive-wide failures: recovery exists to
/// salvage damaged archives, so one malformed entry must be skippable rather
/// than aborting `recover_zip` (which would delete the output and throw away
/// every entry already validated). And "size mismatch" has to be out of band
/// — this used to return `Ok(u32::MAX)` as a sentinel, but `0xFFFFFFFF` is a
/// perfectly legal CRC-32, so an entry declaring `crc32 = 0xFFFFFFFF` passed
/// validation no matter what its data was.
fn crc32_reader_limited(
    mut reader: impl Read,
    expected_size: u64,
    budget: &RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<Option<u32>> {
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        budget.check(control)?;
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > expected_size || total > MAX_RECOVERY_ENTRY_BYTES {
            debug!("ZIP entry decompressed beyond its bounded declared size, rejecting entry");
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
    if total != expected_size {
        return Ok(None);
    }
    Ok(Some(hasher.finalize()))
}

// ==========================================================================
// RAR Recovery
// ==========================================================================

fn recover_rar(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
    budget: &mut RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();

    // Only the RAR 2.x/3.x block layout is scanned for below. RAR 5 headers are
    // vint-encoded and RAR 1.x headers have a different fixed layout, so either
    // would be misparsed; and when the signature was not downloaded the header
    // CRC check is what keeps the scan from accepting their bytes.
    if is_filled(0, RAR5_SIGNATURE.len() as u64, filled) {
        let mut signature = [0u8; RAR5_SIGNATURE.len()];
        input.seek(SeekFrom::Start(0))?;
        input.read_exact(&mut signature)?;
        if signature == RAR5_SIGNATURE {
            anyhow::bail!("RAR 5 archives cannot be recovered: only RAR 2.x/3.x is supported");
        }
        if signature.starts_with(RAR_SIGNATURE_OLD) {
            anyhow::bail!("RAR 1.x archives cannot be recovered: only RAR 2.x/3.x is supported");
        }
    }

    budget.reserve_output((RAR_SIGNATURE_NEW.len() + RAR_MAIN_HEADER.len()) as u64)?;
    output.write_all(RAR_SIGNATURE_NEW)?;
    output.write_all(&RAR_MAIN_HEADER)?;

    // Scan for RAR file headers in filled ranges
    let mut recovered = 0usize;
    let mut buf = [0u8; 7];
    let mut copy_buf = vec![0u8; 64 * 1024];

    // Iteration-counted, not `pos`-aligned: the skip strides below are
    // archive-controlled and can step past every aligned offset, starving the
    // only check that observes the wall clock and the cancel flag.
    let mut steps: u32 = 0;
    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + 7 <= range_end {
            steps = steps.wrapping_add(1);
            if steps.is_multiple_of(1024) {
                budget.check(control)?;
            }
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
            if !(32..=4096).contains(&head_size) {
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

            let pack_size = u32::from_le_bytes([
                header_data[7],
                header_data[8],
                header_data[9],
                header_data[10],
            ]) as u64;
            let method = header_data[25];
            let name_size = u16::from_le_bytes([header_data[26], header_data[27]]) as usize;

            // Validate compression method (0x30-0x35 = store to best)
            if !(0x30..=0x35).contains(&method) {
                pos += 1;
                continue;
            }

            // A real header carries its CRC, as unrar checks; bytes inside
            // compressed data that merely look like one rarely do.
            if !is_filled(pos, pos + head_size, filled)
                || rar_head_crc(&header_data) != u16::from_le_bytes([header_data[0], header_data[1]])
            {
                pos += 1;
                continue;
            }

            let large = (head_flags & RAR_LHD_LARGE) != 0;
            let name_start = RAR_FILE_HEAD_FIXED + if large { 8 } else { 0 };
            if name_size == 0 || name_size > 512 || name_start + name_size > header_data.len() {
                pos += 1;
                continue;
            }

            // High part of packed size for large files
            let high_pack = if large {
                u32::from_le_bytes([
                    header_data[32],
                    header_data[33],
                    header_data[34],
                    header_data[35],
                ]) as u64
            } else {
                0
            };
            let total_pack = pack_size | (high_pack << 32);
            if total_pack > MAX_RECOVERY_ENTRY_BYTES {
                pos += 1;
                continue;
            }

            // `pack_size`/`high_pack` come straight from file bytes inside a
            // "filled" (already-downloaded) range, which can originate from
            // any source that contributed to this part of the download — a
            // crafted 0xFFFFFFFF/0xFFFFFFFF pair makes `total_pack` ==
            // `u64::MAX`, so `data_start + total_pack` can overflow a plain
            // `u64` addition. Reject the candidate header instead of letting
            // that wrap around into a bogus small `data_end` that would
            // slip past the `data_end > file_size` guard below.
            let Some(data_start) = pos.checked_add(head_size) else {
                pos += 1;
                continue;
            };
            let Some(data_end) = data_start.checked_add(total_pack) else {
                pos += 1;
                continue;
            };

            if data_end > file_size {
                pos += 1;
                continue;
            }

            if total_pack > 0 && !is_filled(data_start, data_end, filled) {
                pos = data_end;
                continue;
            }

            // Directory check: eMule uses HEAD_FLAGS bits 5-7 (0xE0)
            let is_dir = (head_flags & 0xE0) == 0xE0;

            // Sanitize the inner filename before writing the header. Without
            // this, a peer-supplied name like `..\..\x` would be carried
            // verbatim into the recovered archive, leaving a zip-slip-class
            // write for a downstream extractor (e.g. WinRAR, 7-Zip).
            let header_data =
                rar_file_header_with_safe_name(&header_data, head_flags, name_start, name_size);

            // Write header + data to output
            budget.add_entry()?;
            budget.reserve_output(header_data.len() as u64 + total_pack)?;
            output.write_all(&header_data)?;
            if total_pack > 0 {
                input.seek(SeekFrom::Start(data_start))?;
                let mut remaining = total_pack;
                while remaining > 0 {
                    budget.check(control)?;
                    let to_read = (remaining as usize).min(copy_buf.len());
                    let n = input.read(&mut copy_buf[..to_read])?;
                    if n == 0 {
                        anyhow::bail!(
                            "short read during RAR recovery: {} bytes remaining",
                            remaining
                        );
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

/// `header` rebuilt around a sanitized name, with a `HEAD_CRC` that matches.
///
/// A Unicode name keeps only its plain part: the encoded part after the NUL is
/// what extractors prefer, it cannot be sanitized as bytes, and blanking the
/// NUL in place left a name neither half of which decoded. Its flag goes with
/// it, and `NAME_SIZE` and `HEAD_SIZE` follow the shorter name. A Unicode name
/// with no NUL is all UTF-8 (as unrar reads it) and keeps the flag: replacing
/// ASCII bytes leaves it valid UTF-8. Subfolder separators become `_` like any
/// other, which changes the bytes the CRC covers: without recomputing it,
/// every such entry read as a corrupt header.
fn rar_file_header_with_safe_name(
    header: &[u8],
    head_flags: u16,
    name_start: usize,
    name_size: usize,
) -> Vec<u8> {
    let raw_name = &header[name_start..name_start + name_size];
    let mut flags = head_flags;
    let mut name = raw_name.to_vec();
    if flags & RAR_LHD_UNICODE != 0 {
        if let Some(nul) = raw_name.iter().position(|&b| b == 0) {
            name.truncate(nul);
            flags &= !RAR_LHD_UNICODE;
        }
    }
    if name.is_empty() {
        name.push(b'_');
    }
    sanitize_archive_name_in_place(&mut name);

    let mut out = Vec::with_capacity(header.len());
    out.extend_from_slice(&header[..name_start]);
    out.extend_from_slice(&name);
    out.extend_from_slice(&header[name_start + name_size..]);
    out[3..5].copy_from_slice(&flags.to_le_bytes());
    // Bounded by the caller's 4096-byte HEAD_SIZE and 512-byte name, and the
    // name only ever gets shorter.
    let head_size = out.len() as u16;
    out[5..7].copy_from_slice(&head_size.to_le_bytes());
    out[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
    let crc = rar_head_crc(&out);
    out[0..2].copy_from_slice(&crc.to_le_bytes());
    out
}

/// RAR 2.x/3.x `HEAD_CRC`: the low 16 bits of CRC-32 over the header from
/// `HEAD_TYPE` on.
fn rar_head_crc(header: &[u8]) -> u16 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&header[2..]);
    (hasher.finalize() & 0xFFFF) as u16
}

// ==========================================================================
// ACE Recovery
// ==========================================================================

fn recover_ace(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
    budget: &mut RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();

    // Try to read and copy the ACE archive header from the start
    if filled.first().map(|r| r.0).unwrap_or(u64::MAX) == 0 {
        input.seek(SeekFrom::Start(0))?;
        let mut probe = [0u8; 14];
        if input.read_exact(&mut probe).is_ok() && probe.len() >= 14 {
            let head_size = u16::from_le_bytes([probe[2], probe[3]]) as u64;
            if head_size > 0
                && head_size < 4096
                && probe
                    .get(7..14)
                    .map(|s| s == ACE_SIGNATURE)
                    .unwrap_or(false)
            {
                let total = 4 + head_size;
                input.seek(SeekFrom::Start(0))?;
                let mut header = vec![0u8; total as usize];
                if input.read_exact(&mut header).is_ok() {
                    budget.reserve_output(header.len() as u64)?;
                    output.write_all(&header)?;
                }
            }
        }
    }

    // Scan for ACE file headers
    let mut recovered = 0usize;
    let mut copy_buf = vec![0u8; 64 * 1024];

    // Iteration-counted, not `pos`-aligned: the skip strides below are
    // archive-controlled and can step past every aligned offset, starving the
    // only check that observes the wall clock and the cancel flag.
    let mut steps: u32 = 0;
    for &(range_start, range_end) in filled {
        let mut pos = range_start;
        while pos + 10 <= range_end {
            steps = steps.wrapping_add(1);
            if steps.is_multiple_of(1024) {
                budget.check(control)?;
            }
            input.seek(SeekFrom::Start(pos))?;
            let mut header_start = [0u8; 4];
            if input.read_exact(&mut header_start).is_err() {
                break;
            }

            let head_crc = u16::from_le_bytes([header_start[0], header_start[1]]);
            let head_size = u16::from_le_bytes([header_start[2], header_start[3]]) as u64;

            if !(10..=4096).contains(&head_size) {
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

            if header_body.len() < 31 {
                pos += 1;
                continue;
            }

            // unace rejects a header whose CRC does not match, and checking it
            // here keeps look-alike bytes inside packed data from being taken
            // for headers.
            if !is_filled(pos, pos + 4 + head_size, filled) || ace_head_crc(&header_body) != head_crc
            {
                pos += 1;
                continue;
            }

            let pack_size = u32::from_le_bytes([
                header_body[3],
                header_body[4],
                header_body[5],
                header_body[6],
            ]) as u64;
            if pack_size > MAX_RECOVERY_ENTRY_BYTES {
                pos += 1;
                continue;
            }

            let Some(data_start) = pos
                .checked_add(4)
                .and_then(|value| value.checked_add(head_size))
            else {
                pos += 1;
                continue;
            };
            let Some(data_end) = data_start.checked_add(pack_size) else {
                pos += 1;
                continue;
            };

            if data_end > file_size {
                pos += 1;
                continue;
            }

            if pack_size > 0 && !is_filled(data_start, data_end, filled) {
                pos = data_end;
                continue;
            }

            // Sanitize the embedded filename before writing. ACE FILE32
            // headers carry `FNAME_SIZE` at bytes 29..31 of the body
            // (the 1-byte HEAD_TYPE prefix shifts the spec offsets by
            // one) followed by the filename. Mutated in place to keep all
            // surrounding offsets valid; any change has to be followed by a
            // new HEAD_CRC, or unace rejects the entry as a corrupt header.
            let fname_size = u16::from_le_bytes([header_body[29], header_body[30]]) as usize;
            let fname_start = 31usize;
            let fname_end = fname_start.saturating_add(fname_size);
            if fname_size > 0 && fname_end <= header_body.len() {
                sanitize_archive_name_in_place(&mut header_body[fname_start..fname_end]);
            }
            let header_start = {
                let mut rebuilt = header_start;
                rebuilt[0..2].copy_from_slice(&ace_head_crc(&header_body).to_le_bytes());
                rebuilt
            };

            // Write header + data
            budget.add_entry()?;
            budget.reserve_output(4 + header_body.len() as u64 + pack_size)?;
            output.write_all(&header_start)?;
            output.write_all(&header_body)?;
            if pack_size > 0 {
                input.seek(SeekFrom::Start(data_start))?;
                let mut remaining = pack_size;
                while remaining > 0 {
                    budget.check(control)?;
                    let to_read = (remaining as usize).min(copy_buf.len());
                    let n = input.read(&mut copy_buf[..to_read])?;
                    if n == 0 {
                        anyhow::bail!(
                            "short read during ACE recovery: {} bytes remaining",
                            remaining
                        );
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

/// ACE `HEAD_CRC`: the low 16 bits of unace's CRC-32 (initial value all ones,
/// no final inversion) over the `HEAD_SIZE` bytes from `HEAD_TYPE` on.
fn ace_head_crc(body: &[u8]) -> u16 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(body);
    (!hasher.finalize() & 0xFFFF) as u16
}

/// Check if a file name has an archive extension we can recover.
pub fn is_recoverable_archive(file_name: &str) -> bool {
    let ext = Path::new(file_name)
        .extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(ext.as_str(), "zip" | "cbz" | "jar" | "rar" | "cbr" | "ace")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stored RAR 3 file header as WinRAR writes it: `LONG_BLOCK` set,
    /// `HEAD_CRC` valid.
    fn rar_file_entry(name: &[u8], flags: u16, data: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8, 0, RAR_HEAD_FILE];
        h.extend_from_slice(&(0x8000 | flags).to_le_bytes());
        h.extend_from_slice(&((RAR_FILE_HEAD_FIXED + name.len()) as u16).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.extend_from_slice(&(data.len() as u32).to_le_bytes());
        h.push(2); // HOST_OS: Win32
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(data);
        h.extend_from_slice(&hasher.finalize().to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // FTIME
        h.push(29); // UNP_VER
        h.push(0x30); // METHOD: store
        h.extend_from_slice(&(name.len() as u16).to_le_bytes());
        h.extend_from_slice(&0x20u32.to_le_bytes()); // ATTR
        h.extend_from_slice(name);
        let crc = rar_head_crc(&h);
        h[0..2].copy_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(data);
        h
    }

    #[test]
    fn rar_entries_are_recovered_with_valid_headers_and_safe_names() {
        let base = std::env::temp_dir().join(format!(
            "ember-rar-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let mut archive = RAR_SIGNATURE_NEW.to_vec();
        archive.extend_from_slice(&RAR_MAIN_HEADER);
        archive.extend_from_slice(&rar_file_entry(b"movie.avi", 0, b"frames"));
        archive.extend_from_slice(&rar_file_entry(
            b"dir\\..\\x.txt\0\x01\x02",
            RAR_LHD_UNICODE,
            b"text",
        ));
        let input_path = base.join("in.rar");
        let output_path = base.join("out.rar");
        std::fs::write(&input_path, &archive).unwrap();
        let mut input = std::fs::File::open(&input_path).unwrap();
        let mut output = std::fs::File::create(&output_path).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut budget = RecoveryBudget::new(&cancelled);

        let recovered = recover_rar(
            &mut input,
            &mut output,
            &[(0, archive.len() as u64)],
            &mut budget,
            None,
        )
        .unwrap();
        drop(output);
        assert_eq!(recovered, 2, "a name of four bytes or more is not a size");

        let out = std::fs::read(&output_path).unwrap();
        assert_eq!(&out[..7], RAR_SIGNATURE_NEW);
        assert_eq!(&out[7..20], &RAR_MAIN_HEADER);
        let mut at = 20;
        let mut names = Vec::new();
        while at < out.len() {
            let head_size = u16::from_le_bytes([out[at + 5], out[at + 6]]) as usize;
            let header = &out[at..at + head_size];
            assert_eq!(
                rar_head_crc(header),
                u16::from_le_bytes([header[0], header[1]]),
                "every header written carries a CRC that matches it"
            );
            let flags = u16::from_le_bytes([header[3], header[4]]);
            assert_eq!(flags & RAR_LHD_UNICODE, 0);
            let name_size = u16::from_le_bytes([header[26], header[27]]) as usize;
            names.push(header[32..32 + name_size].to_vec());
            let pack = u32::from_le_bytes([header[7], header[8], header[9], header[10]]) as usize;
            at += head_size + pack;
        }
        assert_eq!(names, vec![b"movie.avi".to_vec(), b"dir_.._x.txt".to_vec()]);

        let _ = std::fs::remove_dir_all(&base);
    }

    type RawRecovery = fn(
        &mut std::fs::File,
        &mut std::fs::File,
        &[(u64, u64)],
        &mut RecoveryBudget,
        Option<&TransferControl>,
    ) -> anyhow::Result<usize>;

    /// Run one format's recovery over the whole of `archive`; the result and
    /// the bytes it wrote.
    fn recover_raw(
        label: &str,
        archive: &[u8],
        recover: RawRecovery,
    ) -> (anyhow::Result<usize>, Vec<u8>) {
        let base = std::env::temp_dir().join(format!(
            "ember-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&base).unwrap();
        let input_path = base.join("in");
        let output_path = base.join("out");
        std::fs::write(&input_path, archive).unwrap();
        let mut input = std::fs::File::open(&input_path).unwrap();
        let mut output = std::fs::File::create(&output_path).unwrap();
        let cancelled = AtomicBool::new(false);
        let mut budget = RecoveryBudget::new(&cancelled);
        let result = recover(
            &mut input,
            &mut output,
            &[(0, archive.len() as u64)],
            &mut budget,
            None,
        );
        drop((input, output));
        let written = std::fs::read(&output_path).unwrap();
        let _ = std::fs::remove_dir_all(&base);
        (result, written)
    }

    /// RAR 5 headers are vint-encoded; read as RAR 3 blocks they are garbage,
    /// so a recognisable RAR 5 archive is refused up front, even when it holds
    /// bytes that would pass for a RAR 3 file header.
    #[test]
    fn rar5_and_rar1_archives_fail_closed() {
        for (signature, version) in [
            (RAR5_SIGNATURE, "RAR 5"),
            (b"RE~^\0\0\0\0".as_slice(), "RAR 1.x"),
        ] {
            let mut archive = signature.to_vec();
            archive.extend_from_slice(&rar_file_entry(b"movie.avi", 0, b"frames"));
            let (result, _) = recover_raw("rar-version", &archive, recover_rar);
            let error = result.expect_err("an unsupported RAR version must not be scanned");
            assert!(error.to_string().contains(version), "{error}");
        }
    }

    /// With `LHD_UNICODE` and no NUL the whole name is UTF-8, which survives
    /// byte-level sanitizing, so the flag that says so has to stay.
    #[test]
    fn a_utf8_rar_name_keeps_its_unicode_flag() {
        let name = "dossier/été.txt".as_bytes();
        let entry = rar_file_entry(name, RAR_LHD_UNICODE, b"");
        let header =
            rar_file_header_with_safe_name(&entry, 0x8000 | RAR_LHD_UNICODE, 32, name.len());
        let flags = u16::from_le_bytes([header[3], header[4]]);
        assert_ne!(flags & RAR_LHD_UNICODE, 0);
        assert_eq!(&header[32..], "dossier_été.txt".as_bytes());
        assert_eq!(rar_head_crc(&header), u16::from_le_bytes([header[0], header[1]]));
    }

    /// A stored ACE FILE32 header and its data, `HEAD_CRC` valid.
    fn ace_file_entry(name: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = vec![ACE_FILE_HEADER_TYPE];
        body.extend_from_slice(&0x0001u16.to_le_bytes()); // HEAD_FLAGS: ADDSIZE
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // PACK_SIZE
        body.extend_from_slice(&(data.len() as u32).to_le_bytes()); // ORIG_SIZE
        body.extend_from_slice(&0u32.to_le_bytes()); // FTIME
        body.extend_from_slice(&0x20u32.to_le_bytes()); // ATTR
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(data);
        body.extend_from_slice(&(!hasher.finalize()).to_le_bytes()); // CRC32
        body.extend_from_slice(&0u32.to_le_bytes()); // TECH_INFO: stored
        body.extend_from_slice(&0u16.to_le_bytes()); // RESERVED
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(name);
        let mut entry = ace_head_crc(&body).to_le_bytes().to_vec();
        entry.extend_from_slice(&(body.len() as u16).to_le_bytes());
        entry.extend_from_slice(&body);
        entry.extend_from_slice(data);
        entry
    }

    /// Sanitizing an ACE name changes bytes `HEAD_CRC` covers, and it used to be
    /// written back unchanged, so unace rejected every entry whose name had a
    /// separator in it. Headers whose CRC does not match are not entries.
    #[test]
    fn ace_entries_are_recovered_with_valid_headers_and_safe_names() {
        let mut archive = ace_file_entry(b"..\\evil.txt", b"payload");
        let mut corrupt = ace_file_entry(b"other.txt", b"more");
        corrupt[0] ^= 0xFF;
        archive.extend_from_slice(&corrupt);

        let (result, out) = recover_raw("ace", &archive, recover_ace);
        assert_eq!(result.unwrap(), 1, "the header with a bad CRC is not an entry");
        let head_size = u16::from_le_bytes([out[2], out[3]]) as usize;
        let body = &out[4..4 + head_size];
        assert_eq!(ace_head_crc(body), u16::from_le_bytes([out[0], out[1]]));
        assert_eq!(&body[31..], b".._evil.txt");
        assert_eq!(&out[4 + head_size..], b"payload");
    }

    fn crc32_of(data: &[u8]) -> u32 {
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(data);
        hasher.finalize()
    }

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    /// A local header with bit 3 set and zero CRC and sizes, as streaming
    /// writers produce, followed by `data` and the descriptor closing it.
    fn zip_descriptor_entry(
        name: &[u8],
        method: u16,
        data: &[u8],
        plain: &[u8],
        signed: bool,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes
            .write_u32::<LittleEndian>(ZIP_LOCAL_HEADER_MAGIC)
            .unwrap();
        bytes.write_u16::<LittleEndian>(20).unwrap();
        bytes
            .write_u16::<LittleEndian>(ZIP_FLAG_DATA_DESCRIPTOR)
            .unwrap();
        bytes.write_u16::<LittleEndian>(method).unwrap();
        bytes.extend_from_slice(&[0u8; 16]); // time, date, CRC, sizes
        bytes.write_u16::<LittleEndian>(name.len() as u16).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(data);
        if signed {
            bytes
                .write_u32::<LittleEndian>(ZIP_DATA_DESCRIPTOR_MAGIC)
                .unwrap();
        }
        bytes.write_u32::<LittleEndian>(crc32_of(plain)).unwrap();
        bytes.write_u32::<LittleEndian>(data.len() as u32).unwrap();
        bytes.write_u32::<LittleEndian>(plain.len() as u32).unwrap();
        bytes
    }

    struct CentralRecord<'a> {
        local_offset: u32,
        name: &'a [u8],
        method: u16,
        flags: u16,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
    }

    /// A central directory plus end record, placed at `cd_offset` as the
    /// archive records it.
    fn zip_central_directory(records: &[CentralRecord], cd_offset: u32) -> Vec<u8> {
        let mut cd = Vec::new();
        for r in records {
            cd.write_u32::<LittleEndian>(ZIP_CENTRAL_DIR_MAGIC).unwrap();
            cd.write_u16::<LittleEndian>(20).unwrap();
            cd.write_u16::<LittleEndian>(20).unwrap();
            cd.write_u16::<LittleEndian>(r.flags).unwrap();
            cd.write_u16::<LittleEndian>(r.method).unwrap();
            cd.write_u32::<LittleEndian>(0).unwrap(); // time + date
            cd.write_u32::<LittleEndian>(r.crc32).unwrap();
            cd.write_u32::<LittleEndian>(r.compressed_size).unwrap();
            cd.write_u32::<LittleEndian>(r.uncompressed_size).unwrap();
            cd.write_u16::<LittleEndian>(r.name.len() as u16).unwrap();
            cd.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attributes
            cd.write_u32::<LittleEndian>(r.local_offset).unwrap();
            cd.extend_from_slice(r.name);
        }
        let mut bytes = cd.clone();
        bytes
            .write_u32::<LittleEndian>(ZIP_END_OF_CENTRAL_DIR_MAGIC)
            .unwrap();
        bytes.write_u32::<LittleEndian>(0).unwrap(); // disk numbers
        bytes.write_u16::<LittleEndian>(records.len() as u16).unwrap();
        bytes.write_u16::<LittleEndian>(records.len() as u16).unwrap();
        bytes.write_u32::<LittleEndian>(cd.len() as u32).unwrap();
        bytes.write_u32::<LittleEndian>(cd_offset).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes
    }

    /// `recover_archive` over `bytes` with `filled` verified, then `inspect`
    /// on the recovered archive.
    fn recover_zip_and<T>(
        label: &str,
        bytes: &[u8],
        filled: &[(u64, u64)],
        inspect: impl FnOnce(&Path) -> T,
    ) -> anyhow::Result<T> {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, allowed, base) = approved_recovery_dir(label);
        let part = root.join("input.part");
        std::fs::write(&part, bytes).unwrap();
        let result = recover_archive(
            &part,
            "sample.zip",
            filled,
            &root,
            &allowed,
            None,
            &AtomicBool::new(false),
        )
        .map(|path| inspect(&path));
        let _ = std::fs::remove_dir_all(base);
        result
    }

    /// Every entry's name and contents, read back through the `zip` crate,
    /// which checks each one's CRC as it reads.
    fn zip_contents(path: &Path) -> Vec<(String, Vec<u8>)> {
        let mut archive = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        (0..archive.len())
            .map(|i| {
                let mut file = archive.by_index(i).unwrap();
                let name = file.name().to_string();
                let mut data = Vec::new();
                file.read_to_end(&mut data).unwrap();
                (name, data)
            })
            .collect()
    }

    /// Bit 3 leaves CRC and sizes zero in the local header. Recovery used to
    /// copy those zeros, skip the CRC check, and write every such entry as an
    /// empty file it then counted as recovered.
    #[test]
    fn zip_data_descriptor_entries_keep_their_contents() {
        let plain = b"compressible text ".repeat(64);
        let deflated = deflate(&plain);
        let mut bytes = zip_descriptor_entry(b"signed.txt", 8, &deflated, &plain, true);
        bytes.extend_from_slice(&zip_descriptor_entry(
            b"unsigned.txt",
            8,
            &deflated,
            &plain,
            false,
        ));
        bytes.extend_from_slice(&zip_descriptor_entry(
            b"stored.bin",
            0,
            b"STORED",
            b"STORED",
            true,
        ));

        let filled = [(0, bytes.len() as u64)];
        let entries = recover_zip_and("descriptor", &bytes, &filled, zip_contents)
            .expect("descriptor entries are recoverable");
        assert_eq!(
            entries,
            vec![
                ("signed.txt".to_string(), plain.clone()),
                ("unsigned.txt".to_string(), plain),
                ("stored.bin".to_string(), b"STORED".to_vec()),
            ]
        );
    }

    /// Stored data may hold any number of signed descriptors whose sizes fit
    /// but whose CRC does not; the real one after them is still found, across
    /// read windows, with each candidate checked against the running CRC.
    #[test]
    fn a_stored_descriptor_is_found_past_a_run_of_fake_ones() {
        let magic = ZIP_DATA_DESCRIPTOR_MAGIC.to_le_bytes();
        let mut data = vec![0x5au8; 150_000];
        for at in (1000..data.len() - 16).step_by(997) {
            let len = (at as u32).to_le_bytes();
            data[at..at + 4].copy_from_slice(&magic);
            data[at + 4..at + 8].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
            data[at + 8..at + 12].copy_from_slice(&len);
            data[at + 12..at + 16].copy_from_slice(&len);
        }
        let mut bytes = data.clone();
        bytes.extend_from_slice(&magic);
        bytes.extend_from_slice(&crc32_of(&data).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());

        let path = std::env::temp_dir().join(format!(
            "ember-fake-descriptors-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, &bytes).unwrap();
        let mut input = std::fs::File::open(&path).unwrap();
        let cancelled = AtomicBool::new(false);
        let budget = RecoveryBudget::new(&cancelled);
        let found =
            find_stored_zip_data_descriptor(&mut input, 0, bytes.len() as u64, &budget, None)
                .unwrap()
                .expect("the real descriptor is found");
        drop(input);
        let _ = std::fs::remove_file(&path);
        assert_eq!(found.compressed_size, data.len() as u32);
        assert_eq!(found.crc32, crc32_of(&data));
    }

    /// Stored data does not mark its own end and an unsigned descriptor can be
    /// any twelve bytes, so only a downloaded central directory can size such
    /// an entry; without one it is skipped rather than emptied. The directory's
    /// offsets are relative to the archive, which here sits behind a stub.
    #[test]
    fn an_unsigned_stored_descriptor_entry_needs_the_central_directory() {
        let data = b"STORED BYTES";
        let local = zip_descriptor_entry(b"stored.bin", 0, data, data, false);
        assert!(
            recover_zip_and("nocd", &local, &[(0, local.len() as u64)], |_| ()).is_err(),
            "an entry that cannot be sized must not be recovered"
        );

        let mut bytes = b"MZstub!".to_vec();
        bytes.extend_from_slice(&local);
        bytes.extend_from_slice(&zip_central_directory(
            &[CentralRecord {
                local_offset: 0,
                name: b"stored.bin",
                method: 0,
                flags: ZIP_FLAG_DATA_DESCRIPTOR,
                crc32: crc32_of(data),
                compressed_size: data.len() as u32,
                uncompressed_size: data.len() as u32,
            }],
            local.len() as u32,
        ));
        let entries = recover_zip_and("cd", &bytes, &[(0, bytes.len() as u64)], zip_contents)
            .expect("the central directory sizes the entry");
        assert_eq!(entries, vec![("stored.bin".to_string(), data.to_vec())]);
    }

    /// The name and extra field are copied into the output, so bytes that were
    /// never downloaded must not supply them.
    #[test]
    fn zip_entry_name_must_be_downloaded() {
        let bytes = stored_zip_entry();
        let name_end = (ZIP_LOCAL_HEADER_SIZE + b"a.txt".len()) as u64;
        assert!(recover_zip_and(
            "name",
            &bytes,
            &[(0, ZIP_LOCAL_HEADER_SIZE as u64), (name_end, bytes.len() as u64)],
            |_| (),
        )
        .is_err());
    }

    /// A method this code cannot decode has no CRC check, so it is only
    /// trusted when the central directory describes the same entry.
    #[test]
    fn an_undecodable_zip_method_needs_central_directory_agreement() {
        const BZIP2: u16 = 12;
        let data = b"BZh9 not really";
        let crc = crc32_of(b"the plain text");
        let local = zip_local_entry(b"c.bin", data, BZIP2, 14, crc);
        assert!(recover_zip_and("method", &local, &[(0, local.len() as u64)], |_| ()).is_err());

        let mut bytes = local.clone();
        bytes.extend_from_slice(&zip_central_directory(
            &[CentralRecord {
                local_offset: 0,
                name: b"c.bin",
                method: BZIP2,
                flags: 0,
                crc32: crc,
                compressed_size: data.len() as u32,
                uncompressed_size: 14,
            }],
            local.len() as u32,
        ));
        let count = recover_zip_and("method-cd", &bytes, &[(0, bytes.len() as u64)], |path| {
            zip::ZipArchive::new(std::fs::File::open(path).unwrap())
                .unwrap()
                .len()
        })
        .expect("a corroborated entry is kept");
        assert_eq!(count, 1);
    }

    fn stored_zip_entry() -> Vec<u8> {
        let data = b"TEST";
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(data);
        let crc = hasher.finalize();
        let mut bytes = Vec::new();
        bytes
            .write_u32::<LittleEndian>(ZIP_LOCAL_HEADER_MAGIC)
            .unwrap();
        bytes.write_u16::<LittleEndian>(20).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u32::<LittleEndian>(crc).unwrap();
        bytes.write_u32::<LittleEndian>(data.len() as u32).unwrap();
        bytes.write_u32::<LittleEndian>(data.len() as u32).unwrap();
        bytes.write_u16::<LittleEndian>(5).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.extend_from_slice(b"a.txt");
        bytes.extend_from_slice(data);
        bytes
    }

    /// Hand-built local file header + payload, so a test can declare a
    /// `crc32`/`uncompressed_size` that deliberately disagrees with `data`.
    fn zip_local_entry(
        name: &[u8],
        data: &[u8],
        method: u16,
        uncompressed_size: u32,
        crc: u32,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes
            .write_u32::<LittleEndian>(ZIP_LOCAL_HEADER_MAGIC)
            .unwrap();
        bytes.write_u16::<LittleEndian>(20).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u16::<LittleEndian>(method).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.write_u32::<LittleEndian>(crc).unwrap();
        bytes.write_u32::<LittleEndian>(data.len() as u32).unwrap();
        bytes.write_u32::<LittleEndian>(uncompressed_size).unwrap();
        bytes.write_u16::<LittleEndian>(name.len() as u16).unwrap();
        bytes.write_u16::<LittleEndian>(0).unwrap();
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(data);
        bytes
    }

    fn approved_recovery_dir(label: &str) -> (std::path::PathBuf, Vec<String>, std::path::PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "ember-archive-{label}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let root = base.join("root");
        let data = base.join("data");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&data).unwrap();
        let root_s = root.to_string_lossy().into_owned();
        crate::security::filesystem::initialize_approved_roots(
            &data,
            std::slice::from_ref(&root_s),
        )
        .unwrap();
        (root, vec![root_s], base)
    }

    #[test]
    fn manual_zip_recovery_accepts_only_verified_range() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, allowed, base) = approved_recovery_dir("range");
        let part = root.join("input.part");
        let bytes = stored_zip_entry();
        std::fs::write(&part, &bytes).unwrap();

        let recovered = recover_archive(
            &part,
            "sample.zip",
            &[(0, bytes.len() as u64)],
            &root,
            &allowed,
            None,
            &AtomicBool::new(false),
        )
        .expect("recover verified entry");
        let archive = zip::ZipArchive::new(std::fs::File::open(&recovered).unwrap()).unwrap();
        assert_eq!(archive.len(), 1);

        let denied = recover_archive(
            &part,
            "sample.zip",
            &[(0, ZIP_LOCAL_HEADER_SIZE as u64)],
            &root,
            &allowed,
            None,
            &AtomicBool::new(false),
        );
        assert!(
            denied.is_err(),
            "entry data outside verified range must be rejected"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn recovery_honors_cancellation() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, allowed, base) = approved_recovery_dir("cancel");
        let part = root.join("input.part");
        let bytes = stored_zip_entry();
        std::fs::write(&part, &bytes).unwrap();
        let control = TransferControl::new();
        control.cancel();
        assert!(recover_archive(
            &part,
            "sample.zip",
            &[(0, bytes.len() as u64)],
            &root,
            &allowed,
            Some(&control),
            &AtomicBool::new(false),
        )
        .is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    /// `crc32_reader_limited` used to report "size mismatch" as
    /// `Ok(u32::MAX)`, and the caller compared that straight against the
    /// declared CRC — so an entry claiming `crc32 = 0xFFFFFFFF` (a legal
    /// CRC-32 value) validated regardless of its contents.
    #[test]
    fn zip_entry_cannot_pass_crc_via_all_ones_sentinel() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, allowed, base) = approved_recovery_dir("crcsentinel");
        let part = root.join("input.part");
        // Four bytes of stored data, but the header declares five
        // uncompressed bytes — the size-mismatch path.
        let bytes = zip_local_entry(b"a.txt", b"TEST", 0, 5, u32::MAX);
        std::fs::write(&part, &bytes).unwrap();

        let denied = recover_archive(
            &part,
            "sample.zip",
            &[(0, bytes.len() as u64)],
            &root,
            &allowed,
            None,
            &AtomicBool::new(false),
        );
        assert!(
            denied.is_err(),
            "an entry declaring crc32=0xFFFFFFFF must not validate on the size-mismatch path"
        );
        let _ = std::fs::remove_dir_all(base);
    }

    /// Recovery exists to salvage damaged archives, so one entry that
    /// inflates past its declared size must be skipped like any other
    /// rejected entry. It used to `bail!`, which propagated out of
    /// `recover_zip` and made `recover_archive` delete the output —
    /// discarding every entry already validated.
    #[test]
    fn over_inflating_zip_entry_is_skipped_not_fatal() {
        let _registry_guard = crate::security::filesystem::test_registry_lock();
        let (root, allowed, base) = approved_recovery_dir("overinflate");
        let part = root.join("input.part");

        let mut bytes = stored_zip_entry();
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[0x5Au8; 64]).unwrap();
        let deflated = encoder.finish().unwrap();
        // Declares 16 uncompressed bytes but decompresses to 64.
        bytes.extend_from_slice(&zip_local_entry(b"b.txt", &deflated, 8, 16, 0));
        std::fs::write(&part, &bytes).unwrap();

        let recovered = recover_archive(
            &part,
            "sample.zip",
            &[(0, bytes.len() as u64)],
            &root,
            &allowed,
            None,
            &AtomicBool::new(false),
        )
        .expect("the valid entry must survive a malformed sibling");
        let archive = zip::ZipArchive::new(std::fs::File::open(&recovered).unwrap()).unwrap();
        assert_eq!(archive.len(), 1, "only the valid entry is carried over");
        let _ = std::fs::remove_dir_all(base);
    }
}
