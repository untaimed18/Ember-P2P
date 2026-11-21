//! Room libraries: the user's own for each private room, and browsing and
//! fetching from other members'. See `sharing::room_library` for what a
//! library holds and how it is kept apart from sharing, and
//! `network::room_library` for the wire.

#[cfg(feature = "desktop")]
use tauri_plugin_dialog::DialogExt;

use crate::app_state::AppState;
use crate::commands::errors::{bounded_send, coded, coded_ctx};
use crate::network::ember::room_library::{EntryKind, LibraryAnswer, LibraryRequest, ENTRY_ID_LEN, QUERY_MAX_BYTES};
use crate::network::NetworkCommand;
use crate::sharing::room_library::{CatalogStats, RoomLibrary};

use super::channels::{
    channel_transfer_recipient, load_joined_channel, parse_channel_id, self_banned_from,
};

/// The user's own library for one room.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoomLibraryInfo {
    pub open: bool,
    pub folders: Vec<String>,
    pub stats: CatalogStats,
}

/// One row of a member's library, as shown.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RoomLibraryEntryInfo {
    pub id: String,
    pub is_folder: bool,
    pub name: String,
    /// A file's size; 0 for a folder.
    pub size: u64,
    /// How many folders and files a folder holds; 0 for a file.
    pub items: u32,
    pub modified: i64,
    /// For a search result, the folder it is in.
    pub folder: String,
    pub risky: bool,
}

/// A page of a member's library.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RoomLibraryPage {
    /// Their library is not open to this room.
    pub closed: bool,
    /// The folder is no longer in it.
    pub missing: bool,
    pub total: u32,
    pub offset: u32,
    pub entries: Vec<RoomLibraryEntryInfo>,
}

/// What another member's frame says, made safe to show: no control or
/// direction-changing characters, which could dress one name up as another.
fn shown(text: &str) -> String {
    text.chars()
        .filter(|ch| {
            !ch.is_control() && !matches!(*ch as u32, 0x200B..=0x200F | 0x202A..=0x202E | 0x2066..=0x2069 | 0xFEFF)
        })
        .collect()
}

fn parse_channel_bytes(channel_id: &str) -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(channel_id, &mut out).map_err(|_| coded("channels_not_found", "Channel not found"))?;
    Ok(out)
}

fn parse_entry_id(hex_str: &str) -> Result<[u8; ENTRY_ID_LEN], String> {
    let mut out = [0u8; ENTRY_ID_LEN];
    hex::decode_to_slice(hex_str.trim().to_ascii_lowercase(), &mut out)
        .map_err(|_| coded("room_library_folder_gone", "That is no longer in their library"))?;
    Ok(out)
}

/// The room, if it is a private one this device is in.
async fn private_room(state: &AppState, channel_id: &str) -> Result<crate::storage::database::StoredChannel, String> {
    let channel_id = parse_channel_id(channel_id)?;
    let row = load_joined_channel(state, &channel_id).await?;
    if row.visibility != crate::network::ember::channel::CHANNEL_KIND_PRIVATE {
        return Err(coded("room_library_public_room", "Room libraries are only for private rooms"));
    }
    Ok(row)
}

async fn library_info(state: &AppState, channel_id: &str) -> Result<RoomLibraryInfo, String> {
    let db = state.db.clone();
    let id = channel_id.to_string();
    let (library, stats) = tokio::task::spawn_blocking(move || -> anyhow::Result<(RoomLibrary, CatalogStats)> {
        let library = db.room_library(&id)?;
        let stats = if library.folders.is_empty() {
            CatalogStats::default()
        } else {
            crate::sharing::room_library::catalog(&id).stats.clone()
        };
        Ok((library, stats))
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("room_library_failed", "Could not read the room library", e))?;
    Ok(RoomLibraryInfo {
        open: library.open,
        folders: library.folders,
        stats,
    })
}

/// Tell the network task the library changed, and wait until it has told
/// the room. Best effort: the library itself is already saved.
async fn library_changed(state: &AppState, channel_id: &str) {
    let Ok(channel_id) = parse_channel_bytes(channel_id) else {
        return;
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    if bounded_send(&state.network_tx, NetworkCommand::RoomLibraryChanged { channel_id, tx })
        .await
        .is_ok()
    {
        let _ = tokio::time::timeout(crate::commands::errors::CMD_REPLY_TIMEOUT, rx).await;
    }
}

/// Close the room's library, if it is open, before the room is left.
pub(crate) async fn close_for_leave(state: &AppState, channel_id: &str) {
    if !crate::sharing::room_library::get(channel_id).open {
        return;
    }
    let db = state.db.clone();
    let id = channel_id.to_string();
    let closed = tokio::task::spawn_blocking(move || db.set_room_library_open(&id, false)).await;
    if !matches!(closed, Ok(Ok(_))) {
        tracing::warn!("Could not close a room library as its room was left");
        return;
    }
    library_changed(state, channel_id).await;
}

/// The user's own library for a private room: whether it is open, its
/// folders, and what they hold.
#[ember_macros::command]
pub async fn get_room_library(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
) -> Result<RoomLibraryInfo, String> {
    let row = private_room(&state, &channel_id).await?;
    library_info(&state, &row.channel_id).await
}

/// Open the user's library to a private room, or close it.
#[ember_macros::command]
pub async fn set_room_library_open(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    open: bool,
) -> Result<RoomLibraryInfo, String> {
    super::channels::require_ember(&state).await?;
    let row = private_room(&state, &channel_id).await?;
    if open && self_banned_from(&state, &row, "room_library_failed").await? {
        return Err(coded("channels_banned", "You are banned from this channel"));
    }
    let db = state.db.clone();
    let id = row.channel_id.clone();
    tokio::task::spawn_blocking(move || db.set_room_library_open(&id, open))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("room_library_failed", "Could not save the room library", e))?;
    library_changed(&state, &row.channel_id).await;
    library_info(&state, &row.channel_id).await
}

/// Add the folder at `path` to the room's library, once it is checked to be
/// apart from every shared and download folder.
async fn add_folder(state: &AppState, channel_id: &str, path: std::path::PathBuf) -> Result<RoomLibraryInfo, String> {
    let row = private_room(state, channel_id).await?;
    let (shared, room) = {
        let config = state.config.read().await;
        (
            config.settings.configured_roots(),
            crate::sharing::room_library::get(&row.channel_id).folders,
        )
    };
    let checked = tokio::task::spawn_blocking(move || {
        crate::sharing::room_library::check_new_folder(&path, &crate::sharing::room_library::KeptApart {
            shared: &shared,
            room: &room,
        })
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    .map_err(|refusal| refusal.coded())?;
    let db = state.db.clone();
    let id = row.channel_id.clone();
    let now = chrono::Utc::now().timestamp();
    tokio::task::spawn_blocking(move || db.add_room_library_folder(&id, &checked, now))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("room_library_failed", "Could not save the room library", e))?;
    library_info(state, &row.channel_id).await
}

/// Pick a folder to add to the room's library. `Ok(None)` means the user
/// dismissed the picker.
///
/// The folder is chosen in the native dialog here rather than taken as a
/// path from the renderer, as every folder the app shares is: picking it is
/// the user's authorization, a path arriving over IPC is not.
#[ember_macros::command(desktop)]
pub async fn pick_room_library_folder(
    app: crate::host::AppHandle,
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    title: Option<String>,
) -> Result<Option<RoomLibraryInfo>, String> {
    private_room(&state, &channel_id).await?;
    let dialog_title = super::picker_title(title, "Choose a folder for this room's library");
    let picker = app.clone();
    let picked = tokio::task::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title(dialog_title)
            .blocking_pick_folder()
            .map(|folder| folder.into_path())
    })
    .await
    .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?;
    let Some(picked) = picked else {
        return Ok(None);
    };
    let picked = picked.map_err(|e| coded_ctx("room_library_folder_missing", "That folder does not exist", e))?;
    add_folder(&state, &channel_id, picked).await.map(Some)
}

/// emberd: add a folder on the server to the room's library, typed in the
/// browser. Only under the folders its config lists in `browse_under`, the
/// same bound its folder browser keeps to for sharing.
#[ember_macros::command(server)]
pub async fn add_room_library_folder_path(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    path: String,
) -> Result<RoomLibraryInfo, String> {
    if path.len() > 4096 || crate::security::is_network_path(&path) {
        return Err(coded("room_library_folder_not_allowed", "That folder is not one emberd may use"));
    }
    let path = std::path::PathBuf::from(path.trim());
    let outside = {
        let path = path.clone();
        tokio::task::spawn_blocking(move || super::share_browser::outside_browse_roots(&path))
            .await
            .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
    };
    if outside {
        return Err(coded("room_library_folder_not_allowed", "That folder is not one emberd may use"));
    }
    add_folder(&state, &channel_id, path).await
}

/// Take a folder out of the room's library, named as the library lists it.
///
/// Whatever state the room is in, unlike adding one: taking a folder out only
/// narrows what is offered, and leaving a room is no reason to keep one in.
/// Telling the room does nothing for a room this device is not in.
#[ember_macros::command]
pub async fn remove_room_library_folder(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    path: String,
) -> Result<RoomLibraryInfo, String> {
    let channel_id = parse_channel_id(&channel_id)?;
    let db = state.db.clone();
    let id = channel_id.clone();
    tokio::task::spawn_blocking(move || db.remove_room_library_folder(&id, &path))
        .await
        .map_err(|e| coded_ctx("channels_task_error", "Task error", e))?
        .map_err(|e| coded_ctx("room_library_failed", "Could not save the room library", e))?;
    library_changed(&state, &channel_id).await;
    library_info(&state, &channel_id).await
}

/// Members of a room whose libraries are open to it.
#[ember_macros::command]
pub async fn list_room_library_members(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
) -> Result<Vec<String>, String> {
    if !state.config.read().await.settings.ember_native_enabled {
        return Ok(Vec::new());
    }
    let channel_id = parse_channel_bytes(&parse_channel_id(&channel_id)?)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(&state.network_tx, NetworkCommand::ListRoomLibraries { channel_id, tx }).await?;
    let members = crate::commands::errors::await_reply(rx, "room_library_failed", "No response from network").await?;
    Ok(members.iter().map(hex::encode).collect())
}

/// The member of a private room a library request is for.
async fn library_member(state: &AppState, channel_id: &str, member_pubkey: &str) -> Result<([u8; 16], [u8; 32]), String> {
    let row = private_room(state, channel_id).await?;
    if self_banned_from(state, &row, "room_library_failed").await? {
        return Err(coded("channels_banned", "You are banned from this channel"));
    }
    let (channel_id, peer) = channel_transfer_recipient(state, &row.channel_id, member_pubkey).await?;
    Ok((parse_channel_bytes(&channel_id)?, peer))
}

/// A page of a member's library: of the folder `folder`, of the top when it
/// is `None`, or with a `query`, of the files anywhere in it that match.
#[ember_macros::command]
pub async fn browse_room_library(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
    folder: Option<String>,
    query: Option<String>,
    offset: u32,
) -> Result<RoomLibraryPage, String> {
    let (channel_id, peer) = library_member(&state, &channel_id, &member_pubkey).await?;
    let folder = folder.as_deref().map(parse_entry_id).transpose()?;
    let mut query = query.unwrap_or_default().trim().to_string();
    while query.len() > QUERY_MAX_BYTES {
        query.pop();
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::AskRoomLibrary {
            channel_id,
            peer,
            request: LibraryRequest::List { folder, offset, query },
            tx,
        },
    )
    .await?;
    let no_answer = || coded("room_library_no_answer", "They did not answer. They may be offline.");
    let answer = tokio::time::timeout(crate::network::room_library::ASK_WAIT + std::time::Duration::from_secs(3), rx)
        .await
        .map_err(|_| no_answer())?
        .map_err(|_| no_answer())??;
    match answer {
        LibraryAnswer::Page(page) => Ok(RoomLibraryPage {
            total: page.total,
            offset: page.offset,
            entries: page
                .entries
                .into_iter()
                .filter_map(|entry| {
                    let (is_folder, size, items) = match entry.kind {
                        EntryKind::Folder { items } => (true, 0, items),
                        EntryKind::File { size } => (false, size, 0),
                    };
                    let name = crate::security::sanitize_filename(&entry.name);
                    (!name.is_empty()).then(|| RoomLibraryEntryInfo {
                        id: hex::encode(entry.id),
                        is_folder,
                        risky: !is_folder && crate::security::is_dangerous_extension(&name),
                        name,
                        size,
                        items,
                        modified: entry.modified,
                        folder: shown(&entry.folder),
                    })
                })
                .collect(),
            ..Default::default()
        }),
        LibraryAnswer::Closed => Ok(RoomLibraryPage { closed: true, ..Default::default() }),
        LibraryAnswer::Missing => Ok(RoomLibraryPage { missing: true, ..Default::default() }),
        LibraryAnswer::Preparing | LibraryAnswer::Refused(_) => Err(no_answer()),
    }
}

/// Fetch a file from a member's library. It arrives as a room transfer, in
/// Channel Files; the transfer id is returned.
#[ember_macros::command]
pub async fn fetch_room_library_file(
    state: crate::host::State<'_, AppState>,
    channel_id: String,
    member_pubkey: String,
    entry_id: String,
    name: String,
    size: u64,
) -> Result<String, String> {
    let (channel_id, peer) = library_member(&state, &channel_id, &member_pubkey).await?;
    let file = parse_entry_id(&entry_id)?;
    if name.len() > 1024 {
        return Err(coded("channels_xfer_failed", "That file cannot be fetched"));
    }
    let download_folder = {
        let config = state.config.read().await;
        std::path::PathBuf::from(&config.settings.download_folder)
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::PullRoomLibraryFile {
            request: crate::network::room_library::PullRequest {
                channel_id,
                peer,
                file,
                name,
                size,
                download_folder,
            },
            tx,
        },
    )
    .await?;
    let xfer_id = crate::commands::errors::await_reply(rx, "channels_xfer_failed", "No response from network").await??;
    Ok(hex::encode(xfer_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shown_text_loses_controls_and_direction_marks() {
        assert_eq!(shown("Music/Live\u{202E}gpj.exe"), "Music/Livegpj.exe");
        assert_eq!(shown("a\nb\tc\u{200B}d"), "abcd");
        assert_eq!(shown("Ünïcödé/日本"), "Ünïcödé/日本");
    }
}
