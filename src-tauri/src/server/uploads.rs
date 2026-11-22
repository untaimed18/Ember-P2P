//! Files sent from the browser's computer, for what the desktop app opens with
//! a native picker: an IP filter, a collection or a web services list to
//! read, or a file to send to a friend or a room.
//!
//! Each arrives as `<data>/emberd-uploads/<id>/<name>`, readable by emberd
//! alone, and is named to the command that uses it by its id. One to read is
//! read where it is, and the folder is cleared at the next start. One to send
//! moves to `<data>/emberd-sent/<id>/<name>`, where it stays while the
//! recipient may still fetch it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt as _;
use rand::RngCore as _;
use tokio::io::AsyncWriteExt as _;

use crate::commands::errors::coded;

pub const UPLOADS_DIR: &str = "emberd-uploads";
pub const SENT_DIR: &str = "emberd-sent";

/// Largest upload: a file for a friend or a room is at most 2 GB, and
/// nothing read from an upload is larger.
pub const MAX_UPLOAD: u64 = 2 * 1024 * 1024 * 1024;

/// How long a file sent from the browser is kept: a friend has a week to
/// take a chat attachment, a room member minutes; this is twice the longer.
const KEEP_SENT: Duration = Duration::from_secs(14 * 24 * 60 * 60);

pub enum Refused {
    TooLarge,
    Failed,
}

fn data_dir() -> PathBuf {
    crate::storage::paths::resolve_data_dir()
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The name the file keeps: the one it had, made safe to be a file name here
/// and on a friend's computer.
pub(super) fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("").trim().trim_matches('.');
    if base.is_empty() {
        return "file".to_string();
    }
    let clean = crate::security::sanitize_filename(base);
    let clean = clean.trim().trim_matches('.');
    if clean.is_empty() {
        "file".to_string()
    } else {
        crate::commands::chat_attachments::clamp_file_name_keep_extension(clean, 200)
    }
}

/// Receive `body` as `name`, returning the id that names it.
pub async fn receive(body: axum::body::Body, name: &str) -> Result<String, Refused> {
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    let id = hex::encode(id);
    let folder = data_dir().join(UPLOADS_DIR).join(&id);
    private_dir(&folder).map_err(|_| Refused::Failed)?;
    let path = folder.join(safe_name(name));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let file = options.open(&path).map_err(|_| Refused::Failed)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut stream = body.into_data_stream();
    let mut total = 0u64;
    let outcome = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Refused::Failed)?;
            total += chunk.len() as u64;
            if total > MAX_UPLOAD {
                return Err(Refused::TooLarge);
            }
            file.write_all(&chunk).await.map_err(|_| Refused::Failed)?;
        }
        if total == 0 {
            return Err(Refused::Failed);
        }
        file.flush().await.map_err(|_| Refused::Failed)
    }
    .await;
    drop(file);
    match outcome {
        Ok(()) => Ok(id),
        Err(why) => {
            let _ = std::fs::remove_dir_all(&folder);
            Err(why)
        }
    }
}

fn unknown() -> String {
    coded("server_upload_unknown", "That file is no longer on the server; send it again")
}

/// The one file in `<dir>/<id>`, for an id of the shape `receive` makes.
fn file_in(dir: &Path, id: &str) -> Result<PathBuf, String> {
    if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(unknown());
    }
    let folder = dir.join(id);
    let mut entries = std::fs::read_dir(&folder).map_err(|_| unknown())?;
    let file = entries.next().and_then(Result::ok).ok_or_else(unknown)?;
    let path = file.path();
    if !file.file_type().map(|t| t.is_file()).unwrap_or(false) {
        return Err(unknown());
    }
    Ok(path)
}

/// The uploaded file `id` names, to read.
pub(crate) fn uploaded(id: &str) -> Result<PathBuf, String> {
    file_in(&data_dir().join(UPLOADS_DIR), id)
}

/// Forget an upload that has been read.
pub(crate) fn discard(id: &str) {
    if let Ok(path) = uploaded(id) {
        if let Some(folder) = path.parent() {
            let _ = std::fs::remove_dir_all(folder);
        }
    }
}

/// The uploaded file `id` names, moved where a file being sent is kept.
pub(crate) fn keep(id: &str) -> Result<PathBuf, String> {
    let from = uploaded(id)?;
    let name = from.file_name().map(|n| n.to_os_string()).ok_or_else(unknown)?;
    let folder = data_dir().join(SENT_DIR).join(id);
    let keep_failed = |e: std::io::Error| crate::commands::errors::coded_ctx("server_upload_failed", "The file could not be kept", e);
    private_dir(&folder).map_err(keep_failed)?;
    let to = folder.join(name);
    std::fs::rename(&from, &to).map_err(keep_failed)?;
    if let Some(old) = from.parent() {
        let _ = std::fs::remove_dir(old);
    }
    Ok(to)
}

/// At the start: what was sent for reading last time has been read, and what
/// was kept for sending is kept no longer than [`KEEP_SENT`].
pub fn tidy(data_dir: &Path) {
    let _ = std::fs::remove_dir_all(data_dir.join(UPLOADS_DIR));
    tidy_sent(data_dir);
}

/// Files sent from the browser older than [`KEEP_SENT`] go, and uploads no
/// command took within [`KEEP_UNCLAIMED`]: one the command refused, or one
/// a page sent and never named.
pub fn tidy_sent(data_dir: &Path) {
    remove_older(&data_dir.join(SENT_DIR), KEEP_SENT);
    remove_older(&data_dir.join(UPLOADS_DIR), KEEP_UNCLAIMED);
}

/// How long an upload waits for the command that reads or sends it. A page
/// names it in the request right after it arrives.
const KEEP_UNCLAIMED: Duration = Duration::from_secs(60 * 60);

fn remove_older(dir: &Path, keep: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > keep);
        if old {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_from_the_browser_cannot_leave_its_folder() {
        assert_eq!(safe_name("holiday photos.zip"), "holiday photos.zip");
        assert!(!safe_name("../../etc/passwd").contains(['/', '\\']));
        assert_eq!(safe_name("C:\\Users\\me\\list.dat"), "list.dat", "the browser's own path is not kept");
        assert_eq!(safe_name(""), "file");
        assert_eq!(safe_name(".."), "file");
        assert!(safe_name(&"x".repeat(500)).len() <= 200);
    }

    #[test]
    fn only_an_id_of_the_shape_it_was_given_names_a_file() {
        let dir = std::env::temp_dir().join(format!("emberd-uploads-{}", std::process::id()));
        let id = "0123456789abcdef0123456789abcdef";
        std::fs::create_dir_all(dir.join(id)).unwrap();
        std::fs::write(dir.join(id).join("a.dat"), b"x").unwrap();
        assert_eq!(file_in(&dir, id).unwrap(), dir.join(id).join("a.dat"));
        for wrong in ["", "..", "../x", "0123456789ABCDEF0123456789ABCDEF", "0123456789abcdef0123456789abcde", "ffffffffffffffffffffffffffffffff"] {
            assert!(file_in(&dir, wrong).is_err(), "{wrong:?}");
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
