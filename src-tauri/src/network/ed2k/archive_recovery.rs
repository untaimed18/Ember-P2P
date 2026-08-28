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

fn recover_zip(
    input: &mut std::fs::File,
    output: &mut std::fs::File,
    filled: &[(u64, u64)],
    budget: &mut RecoveryBudget,
    control: Option<&TransferControl>,
) -> anyhow::Result<usize> {
    let file_size = input.metadata()?.len();
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
            if compressed_size as u64 > MAX_RECOVERY_ENTRY_BYTES
                || uncompressed_size as u64 > MAX_RECOVERY_ENTRY_BYTES
                || (uncompressed_size as u64)
                    > (compressed_size as u64)
                        .max(1)
                        .saturating_mul(MAX_DECOMPRESSION_RATIO)
            {
                pos += 4;
                continue;
            }

            let data_offset =
                pos + ZIP_LOCAL_HEADER_SIZE as u64 + name_len as u64 + extra_len as u64;
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

            // A CRC value of zero is valid (rare, but possible). Skip local
            // header validation only when bit 3 says the authoritative CRC is
            // carried in a following data descriptor.
            let crc_valid = if (flags & 0x08) == 0 {
                validate_zip_crc(
                    input,
                    data_offset,
                    compressed_size,
                    uncompressed_size,
                    method,
                    crc32,
                    budget,
                    control,
                )?
            } else {
                true
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
                compressed_size,
                uncompressed_size,
                crc32,
                method,
                flags,
                file_name: safe_file_name,
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
        // Recovery preserves unsupported methods verbatim, but cannot verify
        // their uncompressed CRC without a decoder.
        _ => return Ok(true),
    };
    Ok(actual_crc == Some(expected_crc))
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

    // Detect RAR signature to determine old vs new format
    let mut sig_buf = [0u8; 7];
    let is_new_format = if filled.first().map(|r| r.0).unwrap_or(0) == 0 {
        input.seek(SeekFrom::Start(0))?;
        if input.read_exact(&mut sig_buf).is_ok() {
            sig_buf == RAR_SIGNATURE_NEW
        } else {
            true
        }
    } else {
        true
    };

    // Write RAR signature + main archive header
    if is_new_format {
        budget.reserve_output(RAR_SIGNATURE_NEW.len() as u64)?;
        output.write_all(RAR_SIGNATURE_NEW)?;
    } else {
        budget.reserve_output(RAR_SIGNATURE_OLD.len() as u64)?;
        output.write_all(RAR_SIGNATURE_OLD)?;
    }

    // Write minimal main archive header
    let main_header: [u8; 13] = [
        0x73,
        0x00,          // HEAD_CRC (placeholder)
        RAR_HEAD_MAIN, // HEAD_TYPE
        0x00,
        0x00, // HEAD_FLAGS
        0x0D,
        0x00, // HEAD_SIZE (13)
        0x00,
        0x00, // HighPosAv
        0x00,
        0x00,
        0x00,
        0x00, // PosAv
    ];
    budget.reserve_output(main_header.len() as u64)?;
    output.write_all(&main_header)?;

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

            if name_size == 0 || name_size > 512 || 32 + name_size > header_data.len() {
                pos += 1;
                continue;
            }

            // High part of packed size for large files
            let high_pack = if (head_flags & RAR_LONG_BLOCK) != 0 && header_data.len() >= 36 {
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

            // Sanitize the inner filename in place before writing the
            // header. The filename sits at byte 32 in the file header
            // with `name_size` bytes; we already validated the bounds
            // above. Without this, a peer-supplied name like `..\..\x`
            // would be carried verbatim into the recovered archive,
            // leaving a zip-slip-class write for a downstream
            // extractor (e.g. WinRAR, 7-Zip).
            let name_start = 32usize;
            let name_end = name_start + name_size;
            if name_end <= header_data.len() {
                sanitize_archive_name_in_place(&mut header_data[name_start..name_end]);
            }

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

            let _head_crc = u16::from_le_bytes([header_start[0], header_start[1]]);
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
            // one) followed by the filename. As with RAR above, we
            // mutate in place to keep all surrounding offsets valid.
            if header_body.len() >= 31 {
                let fname_size = u16::from_le_bytes([header_body[29], header_body[30]]) as usize;
                let fname_start = 31usize;
                let fname_end = fname_start.saturating_add(fname_size);
                if fname_size > 0 && fname_end <= header_body.len() {
                    sanitize_archive_name_in_place(&mut header_body[fname_start..fname_end]);
                }
            }

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
