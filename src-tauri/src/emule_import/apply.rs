//! Applying a staged eMule import at launch, before anything reads the files
//! it changes. Each part is recorded in a report rather than aborting the rest,
//! and each is safe to repeat: a crash midway runs it again at the next launch.

use super::*;
use crate::storage::config::AppConfig;
use crate::storage::database::Database;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportItem {
    pub kind: String,
    pub ok: bool,
    pub count: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportReport {
    pub applied_at: i64,
    pub source_dir: String,
    pub items: Vec<ReportItem>,
    /// Set once the UI has shown the post-launch notice.
    #[serde(default)]
    pub seen: bool,
}

/// What the rest of startup needs from an apply.
#[derive(Debug, Default)]
pub struct Applied {
    /// Folders the user approved in the import preview, which
    /// `initialize_approved_roots` must now approve as explicit additions.
    pub new_roots: Vec<String>,
}

/// Folders an applied import shares, kept until the approved-root registry has
/// taken them. The staging folder is gone by then, and a launch that fails
/// before approving them would leave them configured but unapproved, which
/// fails closed.
const ROOTS_FILE: &str = "emule-import-roots.json";

/// Roots an applied import still needs approved: this launch's and any a
/// failed earlier launch did not get to.
pub fn pending_root_additions(data_dir: &Path, applied: Option<&Applied>) -> Vec<String> {
    let mut roots: Vec<String> = std::fs::read(data_dir.join(ROOTS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    for root in applied.map_or(&[][..], |a| &a.new_roots) {
        if !roots.contains(root) {
            roots.push(root.clone());
        }
    }
    roots
}

/// The registry has the roots [`pending_root_additions`] named.
pub fn root_additions_approved(data_dir: &Path) {
    match std::fs::remove_file(data_dir.join(ROOTS_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            tracing::warn!("eMule import: could not remove {ROOTS_FILE}: {e}")
        }
        _ => {}
    }
}

fn remember_root_additions(data_dir: &Path, roots: &[String]) {
    let all = pending_root_additions(
        data_dir,
        Some(&Applied {
            new_roots: roots.to_vec(),
        }),
    );
    let written = serde_json::to_vec(&all)
        .map_err(std::io::Error::other)
        .and_then(|bytes| crate::security::atomic_write(&data_dir.join(ROOTS_FILE), &bytes, true));
    if let Err(e) = written {
        tracing::warn!("eMule import: could not record the folders to approve: {e}");
    }
}

pub fn read_report(data_dir: &Path) -> Option<ImportReport> {
    serde_json::from_slice(&std::fs::read(data_dir.join(REPORT_FILE)).ok()?).ok()
}

pub fn mark_report_seen(data_dir: &Path) {
    if let Some(mut report) = read_report(data_dir) {
        report.seen = true;
        if let Ok(bytes) = serde_json::to_vec_pretty(&report) {
            let _ = crate::security::atomic_write(&data_dir.join(REPORT_FILE), &bytes, false);
        }
    }
}

struct Report(Vec<ReportItem>);

impl Report {
    fn record(&mut self, kind: &str, result: anyhow::Result<u64>) {
        let item = match result {
            Ok(count) => ReportItem {
                kind: kind.to_string(),
                ok: true,
                count,
                detail: None,
            },
            Err(e) => {
                tracing::warn!("eMule import: {kind} failed: {e:#}");
                ReportItem {
                    kind: kind.to_string(),
                    ok: false,
                    count: 0,
                    detail: Some(format!("{e:#}")),
                }
            }
        };
        self.0.push(item);
    }
}

/// Apply `emule-import-pending/` if there is one. `None` when nothing was staged.
pub fn apply_pending(data_dir: &Path, db: &Database, config: &mut AppConfig) -> Option<Applied> {
    set_aside_unreadable(data_dir);
    let config_path = config.config_path().to_path_buf();
    apply_manifest(data_dir, db, &mut config.settings, &config_path)
}

fn apply_manifest(
    data_dir: &Path,
    db: &Database,
    settings: &mut crate::types::AppSettings,
    config_path: &Path,
) -> Option<Applied> {
    let manifest = read_manifest(data_dir)?;
    let pending = pending_dir(data_dir);
    let mut report = Report(Vec::new());
    let mut applied = Applied::default();
    tracing::info!("Applying the eMule import staged from {}", manifest.source_dir);

    if manifest.version != MANIFEST_VERSION || !manifest.complete {
        let reason = if manifest.version != MANIFEST_VERSION {
            format!("staged by an incompatible build (version {})", manifest.version)
        } else {
            "Ember closed while the import was being prepared, so it was undone".to_string()
        };
        report.record("manifest", Err(anyhow::anyhow!(reason)));
        // Hands any moved downloads back to eMule.
        if let Err(e) = discard(data_dir) {
            tracing::warn!("eMule import: could not undo the staged import: {e}");
        }
    } else {
        let backup = data_dir.join(format!(
            "pre-emule-import-{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ));
        if manifest.cryptkey {
            report.record("identity", apply_identity(data_dir, &pending, &backup, &manifest));
        }
        if manifest.credits {
            report.record("credits", apply_credits(&pending, db));
        }
        if manifest.known_met {
            report.record("known_files", apply_known_met(data_dir, &pending));
        }
        if manifest.known2 {
            report.record("aich_hashes", apply_known2(data_dir, &pending));
        }
        if manifest.server_met {
            report.record("servers", apply_server_met(data_dir, &pending));
        }
        if manifest.nodes_dat {
            report.record("nodes", apply_nodes_dat(data_dir, &pending));
        }
        if manifest.ipfilter_dat {
            report.record("ipfilter", apply_ipfilter(data_dir, &pending, &backup));
        }
        let changes_settings = manifest.settings != SettingsChanges::default()
            || !manifest.shared_folders.is_empty();
        if changes_settings {
            let result = apply_settings(settings, config_path, &manifest, &mut applied);
            if !applied.new_roots.is_empty() {
                remember_root_additions(data_dir, &applied.new_roots);
            }
            let folders = applied.new_roots.len() as u64;
            report.record("settings", result.map(|()| folders));
        }
        if !manifest.downloads.is_empty() {
            report.record("downloads", apply_downloads(db, &settings.download_folder, &manifest));
        }
    }

    let result = ImportReport {
        applied_at: chrono::Utc::now().timestamp(),
        source_dir: manifest.source_dir.clone(),
        items: report.0,
        seen: false,
    };
    match serde_json::to_vec_pretty(&result) {
        Ok(bytes) => {
            if let Err(e) = crate::security::atomic_write(&data_dir.join(REPORT_FILE), &bytes, false) {
                tracing::warn!("eMule import: could not write the report: {e}");
            }
        }
        Err(e) => tracing::warn!("eMule import: could not serialize the report: {e}"),
    }
    // Removed even when an item failed: every step above is idempotent, but
    // re-applying a failed one at every launch would only repeat its error.
    match std::fs::remove_dir_all(&pending) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            tracing::warn!("eMule import: could not remove {}: {e}", pending.display())
        }
        _ => {}
    }
    Some(applied)
}

fn back_up(file: &Path, backup_dir: &Path) -> anyhow::Result<()> {
    if file.exists() {
        std::fs::create_dir_all(backup_dir)?;
        let name = file.file_name().ok_or_else(|| anyhow::anyhow!("no file name"))?;
        let target = backup_dir.join(name);
        std::fs::copy(file, &target)?;
        crate::security::restrict_file_permissions(&target);
    }
    Ok(())
}

/// eMule's user hash and SecIdent key together: the identity peers hold this
/// user's credits against. Ember's previous identity is kept in the backup.
fn apply_identity(
    data_dir: &Path,
    pending: &Path,
    backup: &Path,
    manifest: &Manifest,
) -> anyhow::Result<u64> {
    let hash_hex = manifest
        .user_hash
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("no user hash staged"))?;
    let hash: [u8; 16] = hex::decode(hash_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("staged user hash is not 16 bytes"))?;
    for name in ["identity.json", "identity.protected", "cryptkey.dat"] {
        back_up(&data_dir.join(name), backup)?;
    }
    let key = std::fs::read(pending.join("cryptkey.dat"))?;
    let key_path = data_dir.join("cryptkey.dat");
    crate::security::atomic_write(&key_path, &key, true)?;
    if let Err(e) = crate::storage::identity::NodeIdentity::replace_user_hash(data_dir, hash) {
        // eMule's key beside Ember's hash is neither identity; put Ember's back.
        let restored = match std::fs::read(backup.join("cryptkey.dat")) {
            Ok(previous) => crate::security::atomic_write(&key_path, &previous, true),
            Err(_) => std::fs::remove_file(&key_path),
        };
        if let Err(restore) = restored {
            tracing::warn!("eMule import: could not restore Ember's cryptkey.dat: {restore}");
        }
        return Err(e);
    }
    Ok(1)
}

/// Merge eMule's credits into the database: the larger total and the later
/// time win, and a peer key eMule verified is kept with its anchor set, or the
/// anti-theft reset would wipe the totals at the peer's next verification.
fn apply_credits(pending: &Path, db: &Database) -> anyhow::Result<u64> {
    use crate::network::ed2k::credits::IdentState;
    let imported: Vec<formats::EmuleCredit> =
        serde_json::from_slice(&std::fs::read(pending.join("credits.json"))?)?;
    let mut rows = db.load_credits()?;
    let mut by_hash: std::collections::HashMap<[u8; 16], usize> =
        rows.iter().enumerate().map(|(i, row)| (row.0, i)).collect();
    let verified = IdentState::Verified.to_u8();
    for credit in &imported {
        let has_key = !credit.public_key.is_empty();
        match by_hash.get(&credit.user_hash) {
            Some(&i) => {
                let row = &mut rows[i];
                row.1 = row.1.max(credit.uploaded);
                row.2 = row.2.max(credit.downloaded);
                row.3 = row.3.max(credit.last_seen);
                if row.4.is_empty() && has_key {
                    row.4 = credit.public_key.clone();
                    row.6 = verified;
                    row.8 = true;
                }
            }
            None => {
                by_hash.insert(credit.user_hash, rows.len());
                rows.push((
                    credit.user_hash,
                    credit.uploaded,
                    credit.downloaded,
                    credit.last_seen,
                    credit.public_key.clone(),
                    0,
                    if has_key { verified } else { IdentState::Unknown.to_u8() },
                    None,
                    has_key,
                    String::new(),
                    String::new(),
                    0,
                ));
            }
        }
    }
    let ember = db.load_ember_credits()?;
    let refs: Vec<crate::storage::database::CreditRowRef<'_>> = rows
        .iter()
        .map(|(h, u, d, l, p, ip, st, eh, cv, name, software, seen)| {
            (h, *u, *d, *l, p.as_slice(), *ip, *st, eh.as_ref(), *cv, name.as_str(), software.as_str(), *seen)
        })
        .collect();
    let ember_refs: Vec<(&[u8; 32], u64, u64, i64, i64, u32, u32, u64, i64, bool)> = ember
        .iter()
        .map(|(pk, u, d, lu, ld, c, t, s, ls, v)| (pk, *u, *d, *lu, *ld, *c, *t, *s, *ls, *v))
        .collect();
    db.save_all_credits_with_ember(&refs, &ember_refs)?;
    Ok(imported.len() as u64)
}

fn apply_known_met(data_dir: &Path, pending: &Path) -> anyhow::Result<u64> {
    use crate::storage::known_files::KnownFileList;
    let path = data_dir.join("known.met");
    let mut ours = KnownFileList::load_checked(&path)?;
    let theirs = KnownFileList::from_bytes(&std::fs::read(pending.join("known.met"))?)?;
    let before = ours.file_count();
    ours.absorb_missing_from(theirs);
    // Held before the save, which is where pathless records get pruned.
    crate::storage::known_files::hold_pruning(data_dir)?;
    // Counted after: a catalog that would outgrow what loads back sheds its
    // oldest pathless records while saving.
    ours.save(&path)?;
    Ok(ours.file_count().saturating_sub(before) as u64)
}

/// Staging built a copy of Ember's `known2_64.met` with eMule's sets added, so
/// this swaps it in, after taking over what Ember saved since that copy.
fn apply_known2(data_dir: &Path, pending: &Path) -> anyhow::Result<u64> {
    use crate::network::ed2k::aich::Known2Store;
    let ours = data_dir.join("known2_64.met");
    let staged = pending.join("known2_64.met");
    crate::security::recover_interrupted_replace(&ours);
    if !staged.exists() {
        // Swapped in by an earlier run of this apply that did not finish.
        return Ok(Known2Store::open(&ours)?.len() as u64);
    }
    if ours.is_file() {
        Known2Store::open(&staged)?.copy_missing_from(&ours, &mut |_, _| {})?;
    }
    // The staging folder sits in the data directory, so this is a rename.
    std::fs::rename(&staged, &ours)?;
    Ok(Known2Store::open(&ours)?.len() as u64)
}

fn apply_server_met(data_dir: &Path, pending: &Path) -> anyhow::Result<u64> {
    use crate::network::ed2k::server_list::ServerList;
    let path = data_dir.join("server.met");
    let mut list = ServerList::load_server_met(&path).unwrap_or_else(|_| ServerList::new());
    let stats = list.merge_from_bytes_filtered(&std::fs::read(pending.join("server.met"))?, false, None)?;
    ServerList::write_server_met_bytes(&path, &list.to_server_met_bytes()?)?;
    Ok(stats.added as u64)
}

/// eMule's contacts replace Ember's only when there are more of them: both are
/// the same bootstrap list, and the bigger one reaches the network sooner.
fn apply_nodes_dat(data_dir: &Path, pending: &Path) -> anyhow::Result<u64> {
    use crate::network::kad::bootstrap::load_nodes_dat;
    let path = data_dir.join("nodes.dat");
    let staged = pending.join("nodes.dat");
    let theirs = load_nodes_dat(&staged)?.len();
    let ours = load_nodes_dat(&path).map_or(0, |c| c.len());
    if theirs > ours {
        std::fs::copy(&staged, &path)?;
        Ok(theirs as u64)
    } else {
        Ok(0)
    }
}

fn apply_ipfilter(data_dir: &Path, pending: &Path, backup: &Path) -> anyhow::Result<u64> {
    let path = data_dir.join("ipfilter.dat");
    let staged = pending.join("ipfilter.dat");
    // Refuse a file the loader cannot read rather than swap a working filter for it.
    let ranges = crate::network::kad::ip_filter::IpFilter::new(true, false)
        .load_from_file(&staged)
        .filter(|&n| n > 0)
        .ok_or_else(|| anyhow::anyhow!("eMule's ipfilter.dat has no ranges Ember can read"))?;
    back_up(&path, backup)?;
    std::fs::copy(&staged, &path)?;
    Ok(ranges as u64)
}

fn apply_settings(
    current: &mut crate::types::AppSettings,
    config_path: &Path,
    manifest: &Manifest,
    applied: &mut Applied,
) -> anyhow::Result<()> {
    let changes = &manifest.settings;
    let mut settings = current.clone();
    if let Some(nickname) = changes.nickname.as_deref().map(str::trim).filter(|n| !n.is_empty()) {
        settings.nickname = nickname.to_string();
    }
    if let Some(port) = changes.tcp_port {
        settings.tcp_port = port;
    }
    if let Some(port) = changes.udp_port {
        settings.udp_port = port;
    }
    if let Some(speed) = changes.max_upload_speed {
        settings.max_upload_speed = speed;
    }
    if let Some(speed) = changes.max_download_speed {
        settings.max_download_speed = speed;
    }
    if let Some(max) = changes.max_sources_per_file {
        settings.max_sources_per_file = max;
    }
    if let Some(enabled) = changes.obfuscation_enabled {
        settings.obfuscation_enabled = enabled;
    }
    if let Some(enabled) = changes.ip_filter_enabled {
        settings.ip_filter_enabled = enabled;
    }
    let mut new_roots = Vec::new();
    if let Some(folder) = changes.download_folder.clone() {
        if folder != settings.download_folder {
            settings.download_folder = folder.clone();
            new_roots.push(folder);
        }
    }
    // Staged folders are canonical; a configured one may be spelled without
    // the `\\?\` prefix or in another case, and would not compare equal.
    let canonical = |p: &str| Path::new(p).canonicalize().unwrap_or_else(|_| PathBuf::from(p));
    for folder in &manifest.shared_folders {
        let path = canonical(folder);
        // An overlap either way is skipped, as the Library refuses one: the
        // folder is already covered, or taking it would widen a narrower share.
        if settings.shared_folders.iter().any(|existing| {
            let existing = canonical(existing);
            path.starts_with(&existing) || existing.starts_with(&path)
        }) {
            continue;
        }
        settings.shared_folders.push(folder.clone());
        new_roots.push(folder.clone());
    }
    // eMule's values come in from its own ranges: an unlimited upload with
    // Upload Speed Sense on, or more sources than Ember allows, would otherwise
    // fail validation and take the shared folders down with them.
    crate::commands::settings::soft_repair_settings(&mut settings);
    crate::commands::settings::validate_settings(&settings).map_err(|e| anyhow::anyhow!(e))?;
    settings.settings_revision = settings.settings_revision.saturating_add(1);
    let data = serde_json::to_string_pretty(&settings)?;
    AppConfig::write_to_disk(&data, config_path, config_path)?;
    *current = settings;
    applied.new_roots = new_roots;
    Ok(())
}

/// Give each staged download its transfer row, then its real name. The row
/// comes first: until it exists the part keeps its staging prefix, which the
/// orphan sweep leaves alone.
fn apply_downloads(db: &Database, download_folder: &str, manifest: &Manifest) -> anyhow::Result<u64> {
    let temp = Path::new(download_folder).join("Temp");
    std::fs::create_dir_all(&temp)?;
    let mut placed = 0u64;
    let mut failures = Vec::new();
    for download in &manifest.downloads {
        let final_part = temp.join(format!("{}.part", download.id));
        let final_met = temp.join(format!("{}.part.met", download.id));
        let (part, met) = (staged_part(download), staged_met(download));
        let result = (|| -> anyhow::Result<()> {
            db.save_transfer(&imported_transfer(download))?;
            if !final_part.exists() && !part.exists() {
                anyhow::bail!("staged data for {} is missing", download.file_name);
            }
            // Each file on its own: a run cut short may have placed one and
            // not the other. A file under its final name is complete, since
            // copies land there by rename. The download folder may have
            // changed since staging, which is when this copies.
            for (staged, at_final) in [(&part, &final_part), (&met, &final_met)] {
                if !at_final.exists() && staged.exists() {
                    move_or_copy(staged, at_final, &mut |_| {})?;
                }
                if at_final.exists() {
                    let _ = std::fs::remove_file(staged);
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => placed += 1,
            Err(e) => {
                // Undo what reached the final names: a partial copy is dropped
                // while its source is still staged, a finished move goes back.
                for (staged, at_final) in [(&part, &final_part), (&met, &final_met)] {
                    let drop_final = staged.exists()
                        || (at_final.exists()
                            && move_or_copy(at_final, staged, &mut |_| {}).is_ok());
                    if drop_final {
                        let _ = std::fs::remove_file(at_final);
                    }
                }
                if let Err(e) = return_download(download) {
                    tracing::warn!("eMule import: could not return {}: {e}", download.file_name);
                }
                // A part still under its final name keeps its row, or the
                // orphan sweep would delete it as unowned.
                if !final_part.exists() {
                    let _ = db.remove_transfer(&download.id);
                }
                failures.push(format!("{e:#}"));
            }
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "{placed} of {} placed; {}",
            manifest.downloads.len(),
            failures.join("; ")
        );
    }
    Ok(placed)
}

fn imported_transfer(download: &StagedDownload) -> crate::types::Transfer {
    use crate::types::{Transfer, TransferDirection, TransferHealth, TransferStatus};
    let progress = if download.file_size == 0 {
        0.0
    } else {
        download.completed as f64 / download.file_size as f64 * 100.0
    };
    Transfer {
        id: download.id.clone(),
        file_name: download.file_name.clone(),
        file_hash: download.file_hash.clone(),
        peer_id: String::new(),
        peer_name: String::new(),
        direction: TransferDirection::Download,
        status: if download.paused {
            TransferStatus::Paused
        } else {
            TransferStatus::Searching
        },
        progress,
        speed: 0,
        total_size: download.file_size,
        transferred: download.completed,
        completed_size: download.completed,
        started_at: chrono::Utc::now().timestamp(),
        failure_reason: None,
        failure_code: None,
        failure_kind: None,
        failure_stage: None,
        priority: "auto".to_string(),
        sources: 0,
        active_sources: 0,
        queued_sources: 0,
        queue_rank: None,
        last_seen_complete: None,
        last_received: None,
        health: TransferHealth::Healthy,
        health_reason: None,
        health_code: None,
        stalled_since: None,
        category: String::new(),
        wait_time: 0,
        upload_time: 0,
        a4af_sources: 0,
        max_sources: 0,
        preview_priority: false,
        preview_ready: false,
        ember_sources: 0,
        client_software: String::new(),
        country_code: None,
        user_hash: None,
        ember_hash: None,
        expected_aich: None,
        ember_file_hash: None,
        completed_path: None,
        up_part_status: None,
        up_part_count: None,
        up_peer_part_status: None,
        ember_verified: false,
        friends_only: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Outside the system temp folder on purpose: on Windows that sits under
    /// `AppData`, which `validate_settings` refuses as a download or share root.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("emule-import-{name}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// `scan` keeps one preview for the whole process, as the app has one
    /// import screen; tests that scan must not replace each other's.
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn emule_cryptkey() -> Vec<u8> {
        use base64::Engine as _;
        use rsa::pkcs8::EncodePrivateKey;
        let key = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 384).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(key.to_pkcs8_der().unwrap().as_bytes());
        // Crypto++ breaks its base64 every 72 columns.
        encoded
            .as_bytes()
            .chunks(72)
            .flat_map(|line| line.iter().copied().chain(*b"\n"))
            .collect()
    }

    fn known_met_with_one_file(hash: [u8; 16], name: &str, size: u32) -> Vec<u8> {
        let mut buf = vec![0x0E];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        buf.extend_from_slice(&hash);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&[0x02, 1, 0, 0x01]);
        buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&[0x03, 1, 0, 0x02]);
        buf.extend_from_slice(&size.to_le_bytes());
        buf
    }

    /// The whole path a migrating user takes: an eMule folder is scanned,
    /// staged, and applied at "launch" into a fresh profile.
    #[test]
    fn an_emule_profile_is_staged_and_applied_at_launch() {
        let _serial = serial();
        let root = scratch("e2e");
        let emule = root.join("eMule").join("config");
        let temp = root.join("eMule").join("Temp");
        let incoming = root.join("eMule").join("Incoming");
        let shared = root.join("Archive");
        let data = root.join("data");
        let downloads = root.join("EmberDownloads");
        for dir in [&emule, &temp, &incoming, &shared, &data, &downloads] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let ini = format!(
            "[eMule]\nNick=Migrant\nPort=4711\nUDPPort=4721\nIncomingDir={}\nTempDir={}\n",
            incoming.display(),
            temp.display()
        );
        std::fs::write(emule.join("preferences.ini"), ini).unwrap();
        let mut dat = vec![0x14];
        dat.extend_from_slice(&[0x5A; 16]);
        std::fs::write(emule.join("preferences.dat"), dat).unwrap();
        std::fs::write(emule.join("cryptkey.dat"), emule_cryptkey()).unwrap();
        let mut clients = vec![0x12];
        clients.extend_from_slice(&1u32.to_le_bytes());
        let mut record = vec![0x33; 16];
        for value in [100u32, 200, chrono::Utc::now().timestamp() as u32, 0, 0] {
            record.extend_from_slice(&value.to_le_bytes());
        }
        record.extend_from_slice(&[0, 0, 0]);
        record.extend_from_slice(&[0u8; 80]);
        clients.extend(record);
        std::fs::write(emule.join("clients.met"), clients).unwrap();
        std::fs::write(emule.join("shareddir.dat"), format!("{}\n", shared.display())).unwrap();
        std::fs::write(emule.join("known.met"), known_met_with_one_file([0x44; 16], "old.mkv", 1234)).unwrap();

        let part = temp.join("001.part");
        std::fs::write(&part, vec![0u8; 1000]).unwrap();
        let mut tracker = PartTracker::new(1000, &part);
        tracker.set_file_hash([0x77; 16]);
        tracker.set_file_name("movie.avi");
        tracker.save();

        let source = register_source(&root.join("eMule")).expect("found through the install folder");
        let ctx = ScanContext {
            data_dir: data.clone(),
            ..ScanContext::default()
        };
        let preview = scan(source.id, &ctx).unwrap();
        assert!(preview.identity);
        assert_eq!(preview.credits, 1);
        assert_eq!(preview.known_files, 1);
        assert_eq!(preview.downloads.len(), 1);
        assert_eq!(preview.downloads[0].status, DownloadStatus::Ready);
        let archive = preview
            .shared_folders
            .iter()
            .position(|f| f.status == FolderStatus::Ready && f.path.ends_with("Archive"))
            .expect("the shared folder is importable");

        let selection = EmuleImportSelection {
            token: preview.token,
            preferences: true,
            library: true,
            shared_folders: vec![archive],
            identity: true,
            credits: true,
            downloads: vec![0],
            ..EmuleImportSelection::default()
        };
        let downloads_str = downloads.to_string_lossy().into_owned();
        let summary = stage(&data, &downloads_str, &selection, &mut |_| {}).unwrap();
        assert_eq!(summary.downloads, 1);
        assert!(!part.exists(), "a download on the same drive is moved, not copied");

        let db = Database::open_at(&data.join("ember.db")).unwrap();
        let mut settings = crate::types::AppSettings {
            download_folder: downloads_str.clone(),
            shared_folders: Vec::new(),
            ..crate::types::AppSettings::default()
        };
        let config_path = data.join("config.json");
        let applied = apply_manifest(&data, &db, &mut settings, &config_path).expect("staged");

        assert_eq!(settings.nickname, "Migrant");
        assert_eq!((settings.tcp_port, settings.udp_port), (4711, 4721));
        assert!(settings.shared_folders.iter().any(|f| f.ends_with("Archive")));
        assert_eq!(applied.new_roots.len(), 1);
        assert!(config_path.exists());

        let credits = db.load_credits().unwrap();
        assert!(credits.iter().any(|row| row.0 == [0x33; 16] && row.1 == 100 && row.2 == 200));

        let known = crate::storage::known_files::KnownFileList::load_checked(&data.join("known.met")).unwrap();
        assert!(known.find_by_hash(&[0x44; 16]).is_some());

        let transfers = db.get_incomplete_downloads().unwrap();
        assert_eq!(transfers.len(), 1);
        let id = &transfers[0].id;
        assert!(downloads.join("Temp").join(format!("{id}.part")).exists());
        assert!(downloads.join("Temp").join(format!("{id}.part.met")).exists());

        let report = read_report(&data).expect("a report is written");
        assert!(report.items.iter().all(|item| item.ok), "{:?}", report.items);
        assert!(!data.join(PENDING_DIR).exists(), "staging is cleared once applied");

        let mut cm = crate::network::ed2k::credits::CreditManager::new();
        cm.load_or_create_keypair(&data);
        assert!(!cm.crypto_unreadable(), "the imported key loads as Ember's own");
        assert!(!cm.our_public_key().is_empty());

        drop(db);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_discarded_import_puts_moved_downloads_back() {
        let _serial = serial();
        let (root, part, data, downloads, preview) = one_download_profile("discard");
        let temp = part.parent().unwrap().to_path_buf();
        let selection = EmuleImportSelection {
            token: preview.token,
            downloads: vec![0],
            ..EmuleImportSelection::default()
        };
        stage(&data, &downloads.to_string_lossy(), &selection, &mut |_| {}).unwrap();
        assert!(!part.exists());

        discard(&data).unwrap();
        assert!(part.exists(), "the part file is back where eMule keeps it");
        assert!(temp.join("002.part.met").exists());
        assert!(read_manifest(&data).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An eMule folder holding one unfinished download, scanned. Returns the
    /// scratch root, the `.part`, the data and download folders, and the preview.
    fn one_download_profile(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf, EmulePreview) {
        let root = scratch(name);
        let emule = root.join("config");
        let temp = root.join("Temp");
        let data = root.join("data");
        let downloads = root.join("dl");
        for dir in [&emule, &temp, &data, &downloads] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(
            emule.join("preferences.ini"),
            format!("[eMule]\nTempDir={}\n", temp.display()),
        )
        .unwrap();
        let part = temp.join("002.part");
        std::fs::write(&part, vec![1u8; 500]).unwrap();
        let mut tracker = PartTracker::new(500, &part);
        tracker.set_file_hash([0x78; 16]);
        tracker.set_file_name("keep.iso");
        tracker.save();

        let source = register_source(&emule).unwrap();
        let preview = scan(
            source.id,
            &ScanContext {
                data_dir: data.clone(),
                ..ScanContext::default()
            },
        )
        .unwrap();
        (root, part, data, downloads, preview)
    }

    #[test]
    fn a_stage_that_did_not_finish_is_undone_at_launch() {
        let _serial = serial();
        let (root, part, data, downloads, preview) = one_download_profile("interrupted");
        let selection = EmuleImportSelection {
            token: preview.token,
            downloads: vec![0],
            ..EmuleImportSelection::default()
        };
        stage(&data, &downloads.to_string_lossy(), &selection, &mut |_| {}).unwrap();
        assert!(!part.exists());
        // What a stage killed after moving the download leaves behind.
        let mut manifest = read_manifest(&data).unwrap();
        manifest.complete = false;
        write_manifest(&pending_dir(&data), &manifest).unwrap();

        let db = Database::open_at(&data.join("ember.db")).unwrap();
        let mut settings = crate::types::AppSettings {
            download_folder: downloads.to_string_lossy().into_owned(),
            ..crate::types::AppSettings::default()
        };
        apply_manifest(&data, &db, &mut settings, &data.join("config.json")).unwrap();

        assert!(part.exists(), "the download went back to eMule");
        assert!(db.get_incomplete_downloads().unwrap().is_empty());
        let report = read_report(&data).unwrap();
        assert!(report.items.iter().any(|item| item.kind == "manifest" && !item.ok));
        assert!(!data.join(PENDING_DIR).exists());
        drop(db);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn hash_sets_ember_saves_after_staging_survive_the_swap() {
        use crate::network::ed2k::aich::{AICHRecoveryHashSet, Known2Store};
        let _serial = serial();
        let set = |n: u8| AICHRecoveryHashSet {
            root_hash: [n; 20],
            leaf_hashes: vec![[n; 20]; 2],
            file_size: 2 * 184_320,
        };
        let root = scratch("known2");
        let emule = root.join("config");
        let data = root.join("data");
        for dir in [&emule, &data] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(emule.join("preferences.ini"), "[eMule]\n").unwrap();
        Known2Store::open(&emule.join("known2_64.met")).unwrap().append(&[set(1)]).unwrap();
        let ours = data.join("known2_64.met");
        Known2Store::open(&ours).unwrap().append(&[set(2)]).unwrap();

        let source = register_source(&emule).unwrap();
        let preview = scan(
            source.id,
            &ScanContext {
                data_dir: data.clone(),
                ..ScanContext::default()
            },
        )
        .unwrap();
        let selection = EmuleImportSelection {
            token: preview.token,
            library: true,
            ..EmuleImportSelection::default()
        };
        stage(&data, "", &selection, &mut |_| {}).unwrap();
        // Saved by the running app between staging and the restart.
        Known2Store::open(&ours).unwrap().append(&[set(3)]).unwrap();

        let db = Database::open_at(&data.join("ember.db")).unwrap();
        let mut settings = crate::types::AppSettings::default();
        apply_manifest(&data, &db, &mut settings, &data.join("config.json")).unwrap();

        let merged = Known2Store::open(&ours).unwrap();
        assert!([1, 2, 3].iter().all(|&n| merged.contains(&[n; 20])));
        assert_eq!(merged.len(), 3);
        drop(db);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_utf8_name_emule_writes_first_is_the_one_kept() {
        let hash = [0x21; 16];
        let mut buf = vec![0x0E];
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&1_700_000_000u32.to_le_bytes());
        buf.extend_from_slice(&hash);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&3u32.to_le_bytes());
        let utf8 = [&[0xEF, 0xBB, 0xBF][..], "Café.mkv".as_bytes()].concat();
        let ansi = b"Caf\xE9.mkv".to_vec();
        for name in [utf8, ansi] {
            buf.extend_from_slice(&[0x02, 1, 0, 0x01]);
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(&name);
        }
        buf.extend_from_slice(&[0x03, 1, 0, 0x02]);
        buf.extend_from_slice(&1234u32.to_le_bytes());

        let list = crate::storage::known_files::KnownFileList::from_bytes(&buf).unwrap();
        assert_eq!(list.find_by_hash(&hash).unwrap().file_name, "Café.mkv");
    }

    #[test]
    fn a_stale_or_failed_stage_leaves_the_preview_usable() {
        let _serial = serial();
        let (root, part, data, downloads, preview) = one_download_profile("retry");
        let downloads = downloads.to_string_lossy().into_owned();
        let selection = EmuleImportSelection {
            token: preview.token,
            downloads: vec![0],
            ..EmuleImportSelection::default()
        };

        let stale = EmuleImportSelection {
            token: preview.token ^ 1,
            ..selection.clone()
        };
        assert!(stage(&data, &downloads, &stale, &mut |_| {}).is_err());
        assert!(
            stage(&data, "", &selection, &mut |_| {}).is_err(),
            "nowhere to place the download"
        );
        assert!(part.exists(), "a failed stage moves nothing");

        stage(&data, &downloads, &selection, &mut |_| {}).expect("the same preview stages");
        assert!(!part.exists());
        assert!(
            stage(&data, &downloads, &selection, &mut |_| {}).is_err(),
            "a preview whose downloads were moved cannot be staged twice"
        );
        assert!(read_manifest(&data).is_some(), "and the refused retry leaves the staged import alone");

        discard(&data).unwrap();
        assert!(part.exists());
        let _ = std::fs::remove_dir_all(&root);
    }
}
