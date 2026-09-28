//! Readers for the eMule and aMule files Ember has no reader for of its own.
//!
//! `known.met`, `known2_64.met`, `server.met`, `nodes.dat`, `ipfilter.dat`
//! and `.part.met` already share eMule's formats and are read by the modules
//! that own them. What is here is the rest: the two preference files, the
//! shared-folder list, and the credit file, whose layout differs from Ember's.

use std::path::{Path, PathBuf};

/// Decode an eMule text file. eMule writes `preferences.ini` and
/// `shareddir.dat` as UTF-16LE with a BOM; aMule and older eMule builds write
/// UTF-8 or the ANSI code page, which is read as Latin-1 when it is not UTF-8.
pub fn decode_text(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return utf16(rest, u16::from_be_bytes);
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_string(),
        Err(_) => bytes.iter().map(|&b| b as char).collect(),
    }
}

fn utf16(bytes: &[u8], word: fn([u8; 2]) -> u16) -> String {
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| word([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

/// The preferences an import can carry over, from eMule's `preferences.ini`
/// or aMule's `amule.conf` (both keep them in an `[eMule]` section).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EmulePrefs {
    pub nickname: Option<String>,
    pub tcp_port: Option<u16>,
    pub udp_port: Option<u16>,
    pub incoming_dir: Option<PathBuf>,
    pub temp_dirs: Vec<PathBuf>,
    /// Bytes per second; `Some(0)` is unlimited.
    pub max_upload: Option<u64>,
    pub max_download: Option<u64>,
    pub max_sources_per_file: Option<u32>,
    pub obfuscation: Option<bool>,
}

/// eMule's `UNLIMITED` for a speed limit.
const EMULE_UNLIMITED_KIB: u64 = 0xFFFF;
/// `validate_settings` refuses a longer nickname.
const MAX_NICKNAME_BYTES: usize = 128;

pub fn parse_preferences(text: &str, base_dir: &Path) -> EmulePrefs {
    let mut prefs = EmulePrefs::default();
    let mut in_emule = false;
    let path = |value: &str| -> Option<PathBuf> {
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            return None;
        }
        let p = PathBuf::from(value);
        Some(if p.is_absolute() { p } else { base_dir.join(p) })
    };
    // Recent eMule builds write an unlimited speed as -1.
    let speed = |value: &str| -> Option<u64> {
        let kib = value.trim().parse::<i64>().ok()?;
        Some(if kib <= 0 || kib as u64 >= EMULE_UNLIMITED_KIB { 0 } else { kib as u64 * 1024 })
    };
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_emule = line.eq_ignore_ascii_case("[eMule]");
            continue;
        }
        if !in_emule || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key.trim().to_ascii_lowercase().as_str() {
            "nick" => {
                // Ember's limit is in bytes; cut on a character boundary.
                let mut nick = value.trim();
                if nick.len() > MAX_NICKNAME_BYTES {
                    let mut cut = MAX_NICKNAME_BYTES;
                    while !nick.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    nick = nick[..cut].trim_end();
                }
                // eMule's default nickname is its project's web address.
                let default_nick = nick.to_ascii_lowercase().contains("emule-project.");
                if !nick.is_empty() && !default_nick {
                    prefs.nickname = Some(nick.to_string());
                }
            }
            "port" => prefs.tcp_port = value.trim().parse().ok().filter(|p| *p != 0),
            "udpport" => prefs.udp_port = value.trim().parse().ok().filter(|p| *p != 0),
            "incomingdir" => prefs.incoming_dir = path(value),
            "tempdir" => prefs.temp_dirs.extend(path(value)),
            // eMule's extra temp folders, `|`-separated.
            "tempdirs" => prefs.temp_dirs.extend(value.split('|').filter_map(path)),
            "maxupload" => prefs.max_upload = speed(value),
            "maxdownload" => prefs.max_download = speed(value),
            "maxsourcesperfile" => prefs.max_sources_per_file = value.trim().parse().ok(),
            "cryptlayerrequested" => prefs.obfuscation = Some(value.trim() != "0"),
            _ => {}
        }
    }
    let mut seen = std::collections::HashSet::new();
    prefs.temp_dirs.retain(|dir| seen.insert(dir.clone()));
    prefs
}

/// The eD2K user hash from `preferences.dat`: a version byte, then the hash.
/// Peers hold the credits they owe this user against it.
pub fn parse_user_hash(preferences_dat: &[u8]) -> Option<[u8; 16]> {
    let bytes = preferences_dat.get(1..17)?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(bytes);
    (hash != [0u8; 16]).then_some(hash)
}

/// Folders listed in `shareddir.dat`, one per line.
pub fn parse_shared_dirs(text: &str) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    text.lines()
        .map(|line| line.trim().trim_end_matches(['\\', '/']))
        .filter(|line| !line.is_empty())
        .map(|line| {
            // `C:` alone is what trimming the separator off `C:\` leaves.
            if line.len() == 2 && line.ends_with(':') {
                PathBuf::from(format!("{line}\\"))
            } else {
                PathBuf::from(line)
            }
        })
        .filter(|path| path.is_absolute() && seen.insert(path.clone()))
        .collect()
}

/// One record of eMule's `clients.met`: what one peer's credit stands at.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EmuleCredit {
    pub user_hash: [u8; 16],
    /// Bytes we uploaded to the peer.
    pub uploaded: u64,
    /// Bytes we downloaded from the peer.
    pub downloaded: u64,
    pub last_seen: i64,
    /// The peer's SecIdent public key. eMule only stores one after the peer
    /// has proved it owns it, so a key here is a verified key.
    pub public_key: Vec<u8>,
}

/// `CREDITFILE_VERSION`: records carry the peer's SecIdent key.
const CREDITFILE_VERSION: u8 = 0x12;
/// `CREDITFILE_VERSION_29`: eMule 0.29-era records without a key.
const CREDITFILE_VERSION_29: u8 = 0x11;
/// `sizeof(CreditStruct_29a)`: key, four u32 counters split lo/hi, last seen,
/// and a reserved u16.
const RECORD_29_LEN: usize = 16 + 4 * 5 + 2;
/// `sizeof(CreditStruct)`: the above plus a key-size byte and `MAXPUBKEYSIZE`.
const RECORD_LEN: usize = RECORD_29_LEN + 1 + 80;

/// Parse eMule's or aMule's `clients.met` (`CClientCreditsList::LoadList`).
pub fn parse_clients_met(data: &[u8]) -> anyhow::Result<Vec<EmuleCredit>> {
    let version = *data.first().ok_or_else(|| anyhow::anyhow!("empty clients.met"))?;
    let record_len = match version {
        CREDITFILE_VERSION => RECORD_LEN,
        CREDITFILE_VERSION_29 => RECORD_29_LEN,
        other => anyhow::bail!("not an eMule clients.met (version 0x{other:02X})"),
    };
    let count = data
        .get(1..5)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
        .ok_or_else(|| anyhow::anyhow!("truncated clients.met header"))?;
    let body = &data[5..];
    let available = body.len() / record_len;
    let u32_at = |r: &[u8], at: usize| u32::from_le_bytes([r[at], r[at + 1], r[at + 2], r[at + 3]]);
    let mut credits = Vec::with_capacity(count.min(available));
    for record in body.chunks_exact(record_len).take(count) {
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&record[..16]);
        let uploaded = u64::from(u32_at(record, 16)) | (u64::from(u32_at(record, 28)) << 32);
        let downloaded = u64::from(u32_at(record, 20)) | (u64::from(u32_at(record, 32)) << 32);
        let last_seen = i64::from(u32_at(record, 24));
        let public_key = if record_len == RECORD_LEN {
            let key_size = (record[RECORD_29_LEN] as usize).min(80);
            record[RECORD_29_LEN + 1..RECORD_29_LEN + 1 + key_size].to_vec()
        } else {
            Vec::new()
        };
        if user_hash == [0u8; 16] {
            continue;
        }
        credits.push(EmuleCredit {
            user_hash,
            uploaded,
            downloaded,
            last_seen,
            public_key,
        });
    }
    Ok(credits)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        let mut out = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out
    }

    #[test]
    fn preferences_read_from_a_utf16_ini_with_relative_and_extra_temp_dirs() {
        let base = if cfg!(windows) { r"C:\eMule" } else { "/opt/emule" };
        let (incoming, temp, extra) = if cfg!(windows) {
            (r"D:\Incoming", r"D:\Temp", r"E:\Temp2|F:\Temp3")
        } else {
            ("/data/incoming", "/data/temp", "/data/t2|/data/t3")
        };
        let ini = format!(
            "[General]\r\nNick=ignored\r\n[eMule]\r\nNick=Aoife\r\nPort=4662\r\nUDPPort=4672\r\n\
             IncomingDir={incoming}\r\nTempDir={temp}\r\nTempDirs={extra}|{temp}\r\n\
             MaxUpload=50\r\nMaxDownload=65535\r\nMaxSourcesPerFile=600\r\nCryptLayerRequested=1\r\n"
        );
        let prefs = parse_preferences(&decode_text(&utf16le(&ini)), Path::new(base));
        assert_eq!(prefs.nickname.as_deref(), Some("Aoife"));
        assert_eq!((prefs.tcp_port, prefs.udp_port), (Some(4662), Some(4672)));
        assert_eq!(prefs.incoming_dir, Some(PathBuf::from(incoming)));
        assert_eq!(prefs.temp_dirs.len(), 3, "the duplicate temp dir is folded");
        assert_eq!(prefs.max_upload, Some(50 * 1024));
        assert_eq!(prefs.max_download, Some(0), "65535 is eMule's unlimited");
        assert_eq!(prefs.max_sources_per_file, Some(600));
        assert_eq!(prefs.obfuscation, Some(true));

        let relative = parse_preferences("[eMule]\nIncomingDir=Incoming\n", Path::new(base));
        assert_eq!(relative.incoming_dir, Some(Path::new(base).join("Incoming")));
    }

    #[test]
    fn unlimited_speeds_and_the_default_nickname_come_through_as_unset() {
        let prefs = parse_preferences(
            "[eMule]\nNick=https://www.emule-project.org\nMaxUpload=-1\nMaxDownload=-1\n",
            Path::new("."),
        );
        assert_eq!(prefs.nickname, None, "eMule's default is not the user's nickname");
        assert_eq!((prefs.max_upload, prefs.max_download), (Some(0), Some(0)));

        // 50 three-byte characters: 150 bytes, over Ember's 128-byte limit.
        let long = "猫".repeat(50);
        let prefs = parse_preferences(&format!("[eMule]\nNick={long}\n"), Path::new("."));
        let nick = prefs.nickname.unwrap();
        assert_eq!(nick, "猫".repeat(42), "cut on a character boundary, within 128 bytes");
    }

    #[test]
    fn shared_dirs_keep_drive_roots_and_drop_relative_lines() {
        let listing = if cfg!(windows) {
            "T:\\\r\nD:\\Films\\\r\nrelative\r\n\r\nD:\\Films\r\n"
        } else {
            "/mnt/t/\n/mnt/films\nrelative\n\n/mnt/films/\n"
        };
        let dirs = parse_shared_dirs(listing);
        assert_eq!(dirs.len(), 2);
        if cfg!(windows) {
            assert_eq!(dirs[0], PathBuf::from("T:\\"));
        }
    }

    #[test]
    fn the_user_hash_is_the_sixteen_bytes_after_the_version() {
        let mut dat = vec![0x14];
        dat.extend_from_slice(&[0xAB; 16]);
        dat.extend_from_slice(&[0; 40]);
        assert_eq!(parse_user_hash(&dat), Some([0xAB; 16]));
        assert_eq!(parse_user_hash(&[0x14; 5]), None);
    }

    fn credit_record(hash: u8, up: u64, down: u64, key: &[u8]) -> Vec<u8> {
        let mut r = vec![hash; 16];
        r.extend_from_slice(&(up as u32).to_le_bytes());
        r.extend_from_slice(&(down as u32).to_le_bytes());
        r.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        r.extend_from_slice(&((up >> 32) as u32).to_le_bytes());
        r.extend_from_slice(&((down >> 32) as u32).to_le_bytes());
        r.extend_from_slice(&0u16.to_le_bytes());
        r.push(key.len() as u8);
        let mut ident = [0u8; 80];
        ident[..key.len()].copy_from_slice(key);
        r.extend_from_slice(&ident);
        r
    }

    #[test]
    fn clients_met_records_rebuild_64_bit_totals_and_keep_the_key() {
        let mut data = vec![CREDITFILE_VERSION];
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend(credit_record(1, 5 << 32 | 7, 9, &[0x30, 0x4C]));
        data.extend(credit_record(2, 3, 4, &[]));
        let credits = parse_clients_met(&data).unwrap();
        assert_eq!(credits.len(), 2);
        assert_eq!(credits[0].uploaded, 5 << 32 | 7);
        assert_eq!(credits[0].downloaded, 9);
        assert_eq!(credits[0].last_seen, 1_700_000_000);
        assert_eq!(credits[0].public_key, vec![0x30, 0x4C]);
        assert!(credits[1].public_key.is_empty());
    }

    #[test]
    fn a_version_29_clients_met_has_no_keys() {
        let mut data = vec![CREDITFILE_VERSION_29];
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&credit_record(3, 10, 20, &[])[..RECORD_29_LEN]);
        let credits = parse_clients_met(&data).unwrap();
        assert_eq!(credits.len(), 1);
        assert_eq!((credits[0].uploaded, credits[0].downloaded), (10, 20));
        assert!(parse_clients_met(&[0xE3, 0, 0, 0, 0]).is_err(), "Ember's own format is not eMule's");
    }
}
