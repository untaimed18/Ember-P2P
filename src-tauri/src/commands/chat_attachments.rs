//! Sending a friend a file in chat, and doing something with one they sent.
//!
//! The picker, the size check and the hash all run here, off the network task:
//! hashing is a read of the whole file, and the network task also drives every
//! socket and timer the app has. What reaches the network task is a file that
//! has already been chosen, checked and committed to by its BLAKE3 root.

use rand::rngs::OsRng;
use rand::RngCore;
use tauri_plugin_dialog::DialogExt;

use crate::app_state::AppState;
use crate::commands::errors::{await_reply, bounded_send, coded, coded_ctx};
use crate::network::chat_attach::{ChatAttachmentInfo, CHAT_FILES_DIR};
use crate::network::ember::attach::{ATTACH_MAX_BYTES, ATTACH_NAME_MAX};
use crate::network::NetworkCommand;

/// Transcript rows loaded per conversation. Attachments are rarer than chat
/// lines, so this reaches back further than the chat page does.
const ATTACHMENT_HISTORY_LIMIT: i64 = 500;

fn parse_friend(hex_str: &str) -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(hex_str.trim().to_ascii_lowercase(), &mut out)
        .map_err(|_| coded("peers_not_friend", "Can only send files to friends"))?;
    Ok(out)
}

fn parse_xfer_id(hex_str: &str) -> Result<[u8; 16], String> {
    let mut out = [0u8; 16];
    hex::decode_to_slice(hex_str.trim().to_ascii_lowercase(), &mut out).map_err(|_| {
        coded(
            "peers_attach_not_found",
            "That file transfer is no longer running",
        )
    })?;
    Ok(out)
}

/// Trim a file name to what the wire carries, keeping its extension.
///
/// The extension is the part a recipient's file manager and the "open or
/// reveal" check both read, so a long name loses characters from the stem, and
/// always on a character boundary so the peer never receives half of one.
fn clamp_attachment_name(name: &str) -> String {
    if name.len() <= ATTACH_NAME_MAX {
        return name.to_string();
    }
    let (stem, ext) = match name.rfind('.') {
        Some(dot) if dot > 0 && name.len() - dot <= 16 => (&name[..dot], &name[dot..]),
        _ => (name, ""),
    };
    let mut end = ATTACH_NAME_MAX.saturating_sub(ext.len());
    while end > 0 && !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{ext}", &stem[..end.min(stem.len())])
}

/// Pick a file and offer it to a friend. `Ok(None)` means the user dismissed
/// the picker.
///
/// The path comes from the native dialog, never from the renderer: a path the
/// webview sent would let anything that can run script in it read any file the
/// user can and hand it to a friend. The same reason the room transfer picks
/// its own file.
#[tauri::command]
pub async fn pick_and_send_chat_attachment(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<Option<ChatAttachmentInfo>, String> {
    let friend = parse_friend(&user_hash_hex)?;
    if !state.friend_hashes.read().await.contains(&friend) {
        return Err(coded("peers_not_friend", "Can only send files to friends"));
    }
    if state.config.read().await.settings.friend_chat_disabled {
        return Err(coded(
            "peers_attach_disabled",
            "Chatting with friends is turned off in Settings",
        ));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::ChatAttachmentPreflight {
            ember_hash: friend,
            tx,
        },
    )
    .await?;
    await_reply(rx, "peers_no_response", "No response").await??;

    let picker = app.clone();
    let picked = tokio::task::spawn_blocking(move || {
        picker
            .dialog()
            .file()
            .set_title("Choose a file to send")
            .blocking_pick_file()
            .map(|file| {
                file.into_path()
                    .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))
            })
            .transpose()
    })
    .await
    .map_err(|e| coded_ctx("peers_task_error", "Task error", e))??;
    let Some(picked) = picked else {
        return Ok(None);
    };

    let prepared = tokio::task::spawn_blocking(move || {
        let canonical = picked
            .canonicalize()
            .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
        if !canonical.is_file() {
            return Err(coded_ctx(
                "peers_attach_failed",
                "Could not send that file",
                "that is not a file",
            ));
        }
        // A reparse point here would let the path the grant records resolve
        // somewhere else by the time a friend reads it.
        crate::security::filesystem::ensure_not_reparse(&canonical)
            .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
        let meta = std::fs::metadata(&canonical)
            .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
        if meta.len() == 0 || meta.len() > ATTACH_MAX_BYTES {
            return Err(coded(
                "peers_attach_too_large",
                "Files must be between 1 byte and 2 GB",
            ));
        }
        let name = clamp_attachment_name(&crate::security::sanitize_filename(
            canonical
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file"),
        ));
        let tree = std::fs::File::open(&canonical)
            .and_then(|f| {
                crate::network::ember::transfer::HashTree::from_reader(std::io::BufReader::new(f))
            })
            .map_err(|e| coded_ctx("peers_attach_failed", "Could not send that file", e))?;
        if tree.file_size != meta.len() {
            return Err(coded_ctx(
                "peers_attach_failed",
                "Could not send that file",
                "it changed while it was being prepared",
            ));
        }
        Ok((canonical, name, meta.len(), tree.root_hash))
    })
    .await
    .map_err(|e| coded_ctx("peers_task_error", "Task error", e))??;
    let (path, name, size, root) = prepared;

    let mut xfer_id = [0u8; 16];
    OsRng.fill_bytes(&mut xfer_id);
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::SendChatAttachment {
            ember_hash: friend,
            xfer_id,
            path,
            name,
            size,
            root,
            tx,
        },
    )
    .await?;
    let info = await_reply(rx, "peers_no_response", "No response").await??;
    Ok(Some(info))
}

/// Accept or decline a file a friend offered.
#[tauri::command]
pub async fn respond_chat_attachment(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
    accept: bool,
) -> Result<(), String> {
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::RespondChatAttachment {
            xfer_id,
            accept,
            tx,
        },
    )
    .await?;
    await_reply(rx, "peers_no_response", "No response").await?
}

/// Stop a transfer in either direction, and tell the friend.
#[tauri::command]
pub async fn cancel_chat_attachment(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
) -> Result<(), String> {
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    bounded_send(
        &state.network_tx,
        NetworkCommand::CancelChatAttachment { xfer_id, tx },
    )
    .await?;
    await_reply(rx, "peers_no_response", "No response").await?
}

/// Every attachment in one conversation, newest first.
///
/// Read straight from the database rather than through the network task: this
/// is history, and a busy network loop is no reason for a conversation to open
/// without its files.
#[tauri::command]
pub async fn list_chat_attachments(
    state: tauri::State<'_, AppState>,
    user_hash_hex: String,
) -> Result<Vec<ChatAttachmentInfo>, String> {
    let friend = parse_friend(&user_hash_hex)?;
    let friend_hex = hex::encode(friend);
    let db = state.db.clone();
    let rows = tokio::task::spawn_blocking(move || {
        // Lapsed offers are settled on read, so a conversation opened long after
        // an offer went unanswered says so instead of showing it still pending.
        let _ = db.expire_chat_attachments(chrono::Utc::now().timestamp());
        db.chat_attachments_for_friend(&friend_hex, ATTACHMENT_HISTORY_LIMIT)
    })
    .await
    .map_err(|e| coded_ctx("peers_task_error", "Task error", e))?
    .map_err(|e| coded_ctx("peers_attach_failed", "Could not load files", e))?;
    Ok(rows.iter().map(ChatAttachmentInfo::from_row).collect())
}

/// Open a received file, or show it in its folder.
///
/// Opening goes through the same check `open_file` applies to downloads: a
/// type whose content does not match its name, or an executable, is revealed
/// rather than launched. A friend's file is still a file from somebody else's
/// machine, and "open" on a disguised executable is how that goes wrong.
#[tauri::command]
pub async fn open_chat_attachment(
    state: tauri::State<'_, AppState>,
    xfer_id: String,
    reveal: bool,
) -> Result<(), String> {
    let xfer_id = parse_xfer_id(&xfer_id)?;
    let row = {
        let db = state.db.clone();
        let id = hex::encode(xfer_id);
        tokio::task::spawn_blocking(move || db.chat_attachment(&id))
            .await
            .map_err(|e| coded_ctx("peers_task_error", "Task error", e))?
    };
    let Some(row) = row else {
        return Err(coded(
            "peers_attach_not_found",
            "That file transfer is no longer running",
        ));
    };
    let Some(dest) = row
        .dest_path
        .filter(|_| row.direction == "received" && row.status == "complete")
    else {
        return Err(coded(
            "transfers_download_not_finished",
            "Download has not finished yet",
        ));
    };
    let dl_folder = state.config.read().await.settings.download_folder.clone();
    let name = row.file_name;
    tokio::task::spawn_blocking(move || {
        // Confined to the download folder, and re-resolved now rather than
        // trusted from the row: the file may have been moved or replaced since.
        let canonical = crate::security::filesystem::verify_existing_path(
            std::path::Path::new(&dest),
            std::slice::from_ref(&dl_folder),
        )
        .map_err(|e| coded_ctx("transfers_invalid_path", "Invalid or changed download path", e))?;
        // And within that, to Chat Files, where every received attachment
        // lands: a row is never a way to open anything else in Downloads.
        let in_chat_files = std::path::Path::new(&dl_folder)
            .join(CHAT_FILES_DIR)
            .canonicalize()
            .is_ok_and(|chat_files| canonical.starts_with(chat_files));
        if !in_chat_files {
            return Err(coded(
                "transfers_invalid_path",
                "Invalid or changed download path",
            ));
        }
        if reveal {
            return crate::security::filesystem::reveal_in_file_manager(&canonical).map_err(|e| {
                coded_ctx("transfers_open_explorer_failed", "Failed to reveal file", e)
            });
        }
        if crate::security::filesystem::passive_type_agrees(&name, &canonical) {
            crate::security::filesystem::open_with_default_app(&canonical)
                .map_err(|e| coded_ctx("transfers_open_file_failed", "Failed to open file", e))
        } else {
            crate::security::filesystem::reveal_in_file_manager(&canonical).map_err(|e| {
                coded_ctx(
                    "transfers_reveal_unsafe_file_failed",
                    "This file type was revealed instead of opened",
                    e,
                )
            })
        }
    })
    .await
    .map_err(|e| coded_ctx("peers_task_error", "Task error", e))?
}

/// Open the Chat Files folder itself.
#[tauri::command]
pub async fn open_chat_files_folder(state: tauri::State<'_, AppState>) -> Result<(), String> {
    let dl_folder = state.config.read().await.settings.download_folder.clone();
    tokio::task::spawn_blocking(move || {
        let allowed = vec![dl_folder.clone()];
        let dir = crate::security::filesystem::prepare_approved_subdir(
            std::path::Path::new(&dl_folder),
            CHAT_FILES_DIR,
            &allowed,
        )
        .map_err(|e| coded_ctx("transfers_invalid_path", "Invalid or changed download path", e))?;
        crate::security::filesystem::open_with_default_app(&dir).map_err(|e| {
            coded_ctx(
                "transfers_open_explorer_failed",
                "Failed to open the Chat Files folder",
                e,
            )
        })
    })
    .await
    .map_err(|e| coded_ctx("peers_task_error", "Task error", e))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_name_is_left_alone() {
        assert_eq!(clamp_attachment_name("holiday.zip"), "holiday.zip");
    }

    /// The extension is what the recipient's "open or reveal" check reads, so a
    /// long name gives up characters from its stem, not its type.
    #[test]
    fn a_long_name_keeps_its_extension() {
        let long = format!("{}.tar.gz", "a".repeat(400));
        let clamped = clamp_attachment_name(&long);
        assert!(clamped.len() <= ATTACH_NAME_MAX);
        assert!(clamped.ends_with(".gz"), "{clamped}");
    }

    #[test]
    fn a_long_name_is_cut_on_a_character_boundary() {
        let long = format!("{}.txt", "日".repeat(200));
        let clamped = clamp_attachment_name(&long);
        assert!(clamped.len() <= ATTACH_NAME_MAX);
        assert!(clamped.ends_with(".txt"));
        assert!(clamped.trim_end_matches(".txt").chars().all(|c| c == '日'));
    }

    #[test]
    fn a_long_name_without_an_extension_is_just_cut() {
        let clamped = clamp_attachment_name(&"b".repeat(400));
        assert_eq!(clamped.len(), ATTACH_NAME_MAX);
    }
}
