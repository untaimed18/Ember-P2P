//! Commands behind "Import from eMule" (issue 126). The work is in
//! [`crate::emule_import`]; these gather what Ember already has and run it off
//! the async runtime.

use std::collections::HashSet;

use tauri::Emitter;
use tauri_plugin_dialog::DialogExt;

use crate::app_state::AppState;
use crate::commands::errors::{coded, coded_ctx};
use crate::emule_import::{
    self, apply::ImportReport, EmuleImportSelection, EmuleInstall, EmulePreview, StageProgress,
    StageSummary,
};

fn task_failed(e: impl std::fmt::Display) -> String {
    coded_ctx("emule_import_task_failed", "The import task failed", e)
}

/// eMule and aMule folders in their default places.
#[tauri::command]
pub async fn detect_emule_installs() -> Result<Vec<EmuleInstall>, String> {
    tokio::task::spawn_blocking(emule_import::detect)
        .await
        .map_err(task_failed)
}

/// Choose an eMule folder (its install folder or its `config` folder) in a
/// native dialog. The renderer gets back an id, never a path to hand back.
#[tauri::command]
pub async fn pick_emule_folder(
    app: tauri::AppHandle,
    window: tauri::WebviewWindow,
) -> Result<Option<EmuleInstall>, String> {
    if window.label() != "main" {
        return Err(coded(
            "emule_import_wrong_window",
            "The eMule folder can only be chosen from the main window",
        ));
    }
    let picked = tokio::task::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Choose your eMule or aMule folder")
            .blocking_pick_folder()
            .and_then(|folder| folder.into_path().ok())
    })
    .await
    .map_err(task_failed)?;
    let Some(path) = picked else {
        return Ok(None);
    };
    tokio::task::spawn_blocking(move || emule_import::register_source(&path))
        .await
        .map_err(task_failed)?
        .map(Some)
        .ok_or_else(|| {
            coded(
                "emule_import_not_an_emule_folder",
                "That folder has no eMule or aMule settings in it",
            )
        })
}

fn parse_hash(hex_hash: &str) -> Option<[u8; 16]> {
    hex::decode(hex_hash).ok()?.try_into().ok()
}

/// Read an eMule folder and describe what importing it would bring.
#[tauri::command]
pub async fn preview_emule_import(
    state: tauri::State<'_, AppState>,
    source_id: u32,
) -> Result<EmulePreview, String> {
    let (shared_folders, download_folder) = {
        let config = state.config.read().await;
        (config.settings.shared_folders.clone(), config.settings.download_folder.clone())
    };
    let downloading: HashSet<[u8; 16]> = state
        .transfer_manager
        .read()
        .await
        .get_all()
        .iter()
        .filter(|t| {
            t.direction == crate::types::TransferDirection::Download
                && t.status != crate::types::TransferStatus::Completed
        })
        .filter_map(|t| parse_hash(&t.file_hash))
        .collect();
    let library: HashSet<[u8; 16]> = state
        .local_index
        .read()
        .await
        .all_hashes()
        .iter()
        .filter_map(|h| parse_hash(h))
        .collect();
    let ctx = emule_import::ScanContext {
        data_dir: crate::storage::paths::resolve_data_dir(),
        download_folder,
        shared_folders,
        downloading,
        library,
    };
    tokio::task::spawn_blocking(move || emule_import::scan(source_id, &ctx))
        .await
        .map_err(task_failed)?
        .map_err(|e| coded_ctx("emule_import_preview_failed", "Could not read the eMule folder", e))
}

/// Convert and place what `selection` chose, ready for the next launch.
/// Streams `emule-import-progress` while it copies.
#[tauri::command]
pub async fn stage_emule_import(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    mut selection: EmuleImportSelection,
) -> Result<StageSummary, String> {
    // A whole drive is confirmed natively, as adding one in the Library is:
    // the preview's checkbox alone is only the renderer's word for it.
    for (index, root) in emule_import::selected_drive_roots(&selection) {
        if !crate::commands::sharing::confirm_drive_root_share(&app, &root).await {
            selection.shared_folders.retain(|&i| i != index);
        }
    }
    let download_folder = state.config.read().await.settings.download_folder.clone();
    let data_dir = crate::storage::paths::resolve_data_dir();
    tokio::task::spawn_blocking(move || {
        let mut last = std::time::Instant::now() - std::time::Duration::from_secs(1);
        emule_import::stage(&data_dir, &download_folder, &selection, &mut |p: StageProgress| {
            if p.done >= p.total || last.elapsed() >= std::time::Duration::from_millis(150) {
                last = std::time::Instant::now();
                let _ = app.emit("emule-import-progress", &p);
            }
        })
    })
    .await
    .map_err(task_failed)?
    .map_err(|e| coded_ctx("emule_import_stage_failed", "Could not prepare the import", e))
}

/// Undo a staged import before it is applied, putting moved downloads back.
#[tauri::command]
pub async fn discard_emule_import() -> Result<(), String> {
    let data_dir = crate::storage::paths::resolve_data_dir();
    tokio::task::spawn_blocking(move || emule_import::discard(&data_dir))
        .await
        .map_err(task_failed)?
        .map_err(|e| coded_ctx("emule_import_discard_failed", "Could not undo the staged import", e))
}

/// Whether an import is staged and waiting for a restart.
#[tauri::command]
pub async fn pending_emule_import() -> Result<bool, String> {
    let data_dir = crate::storage::paths::resolve_data_dir();
    tokio::task::spawn_blocking(move || emule_import::read_manifest(&data_dir).is_some())
        .await
        .map_err(task_failed)
}

/// The report of the last applied import. `mark_seen` records that the
/// post-launch notice was shown, so it appears once.
#[tauri::command]
pub async fn get_emule_import_report(mark_seen: bool) -> Result<Option<ImportReport>, String> {
    let data_dir = crate::storage::paths::resolve_data_dir();
    tokio::task::spawn_blocking(move || {
        let report = emule_import::apply::read_report(&data_dir);
        if mark_seen && report.as_ref().is_some_and(|r| !r.seen) {
            emule_import::apply::mark_report_seen(&data_dir);
        }
        report
    })
    .await
    .map_err(task_failed)
}
