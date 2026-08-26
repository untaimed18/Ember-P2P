//! Persistent uniqueness store for Channel usernames and room names.
//!
//! This is a directory, not an authority over chat: the file records who
//! claimed a handle and which public names are listed. Join secrets, content
//! keys, and author signatures stay on the clients.

use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

pub const USERNAME_MAX: usize = 32;
pub const CHANNEL_NAME_MAX: usize = 64;
pub const USERNAME_MIN: usize = 2;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelNameRecord {
    pub channel_id: String,
    pub pubkey: String,
    pub private: bool,
    pub deleted: bool,
    /// Original casing after stripping controls. Empty in files written
    /// before this field existed; the directory then falls back to the
    /// normalised map key.
    #[serde(default)]
    pub display: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DirectoryListing {
    pub channel_id: String,
    pub pubkey: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RegistryFile {
    #[serde(default)]
    usernames: HashMap<String, String>,
    #[serde(default)]
    names: HashMap<String, ChannelNameRecord>,
    #[serde(default)]
    deleted: HashSet<String>,
}

#[derive(Clone, Debug)]
pub struct ChannelRegistry {
    path: Option<PathBuf>,
    usernames: HashMap<String, String>,
    by_pubkey: HashMap<String, String>,
    names: HashMap<String, ChannelNameRecord>,
    deleted: HashSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    InvalidName,
    Taken,
    Forbidden,
}

impl ChannelRegistry {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            usernames: HashMap::new(),
            by_pubkey: HashMap::new(),
            names: HashMap::new(),
            deleted: HashSet::new(),
        }
    }

    pub fn load(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let parsed = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RegistryFile>(&bytes).ok())
            .unwrap_or_default();
        let mut by_pubkey = HashMap::new();
        for (name, pubkey) in &parsed.usernames {
            by_pubkey.insert(pubkey.to_ascii_lowercase(), name.clone());
        }
        Self {
            path: Some(path),
            usernames: parsed.usernames,
            by_pubkey,
            names: parsed.names,
            deleted: parsed.deleted,
        }
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let file = RegistryFile {
            usernames: self.usernames.clone(),
            names: self.names.clone(),
            deleted: self.deleted.clone(),
        };
        let Ok(json) = serde_json::to_vec_pretty(&file) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if atomic_write(&tmp, path, &json).is_err() {
            tracing::warn!(path = %path.display(), "could not persist the channels registry");
        }
    }

    pub fn claim_username(&mut self, pubkey_hex: &str, name: &str) -> Result<(), RegistryError> {
        let normalized = normalize_username(name).ok_or(RegistryError::InvalidName)?;
        let pk = pubkey_hex.to_ascii_lowercase();
        if pk.len() != 64 || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32 {
            return Err(RegistryError::InvalidName);
        }
        if let Some(owner) = self.usernames.get(&normalized) {
            if owner.eq_ignore_ascii_case(&pk) {
                return Ok(());
            }
            return Err(RegistryError::Taken);
        }
        if let Some(old) = self.by_pubkey.remove(&pk) {
            self.usernames.remove(&old);
        }
        self.usernames.insert(normalized.clone(), pk.clone());
        self.by_pubkey.insert(pk, normalized);
        self.persist();
        Ok(())
    }

    pub fn claim_channel_name(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
    ) -> Result<(), RegistryError> {
        let display = strip_invisible(name);
        let normalized = normalize_channel_name(name).ok_or(RegistryError::InvalidName)?;
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        if id.len() != 32
            || pk.len() != 64
            || hex::decode(&id).map(|b| b.len()).unwrap_or(0) != 16
            || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32
        {
            return Err(RegistryError::InvalidName);
        }
        if self.deleted.contains(&id) {
            return Err(RegistryError::Taken);
        }
        for (existing_name, rec) in &self.names {
            if rec.deleted || !rec.channel_id.eq_ignore_ascii_case(&id) {
                continue;
            }
            if existing_name == &normalized {
                return Ok(());
            }
            return Err(RegistryError::Taken);
        }
        if let Some(existing) = self.names.get(&normalized) {
            if existing.deleted {
                return Err(RegistryError::Taken);
            }
            if existing.channel_id.eq_ignore_ascii_case(&id)
                && existing.pubkey.eq_ignore_ascii_case(&pk)
            {
                return Ok(());
            }
            return Err(RegistryError::Taken);
        }
        self.names.insert(
            normalized,
            ChannelNameRecord {
                channel_id: id,
                pubkey: pk,
                private,
                deleted: false,
                display,
            },
        );
        self.persist();
        Ok(())
    }

    pub fn delete_channel(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
    ) -> Result<(), RegistryError> {
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        let mut found = false;
        for rec in self.names.values_mut() {
            if rec.channel_id.eq_ignore_ascii_case(&id) {
                if !rec.pubkey.eq_ignore_ascii_case(&pk) {
                    return Err(RegistryError::Forbidden);
                }
                rec.deleted = true;
                found = true;
            }
        }
        if !found && self.deleted.contains(&id) {
            return Ok(());
        }
        if !found {
            // Owner can tombstone an id even if the name claim never landed,
            // so Discover cannot keep serving a room they have destroyed.
            self.deleted.insert(id);
            self.persist();
            return Ok(());
        }
        self.deleted.insert(id);
        self.persist();
        Ok(())
    }

    pub fn public_directory(&self) -> Vec<DirectoryListing> {
        let mut out: Vec<DirectoryListing> = self
            .names
            .iter()
            .filter(|(_, rec)| !rec.private && !rec.deleted && !self.deleted.contains(&rec.channel_id))
            .map(|(name, rec)| DirectoryListing {
                channel_id: rec.channel_id.clone(),
                pubkey: rec.pubkey.clone(),
                name: if rec.display.is_empty() {
                    name.clone()
                } else {
                    rec.display.clone()
                },
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    pub fn deleted_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.deleted.iter().cloned().collect();
        for rec in self.names.values() {
            if rec.deleted {
                ids.push(rec.channel_id.clone());
            }
        }
        ids.sort();
        ids.dedup();
        ids
    }
}

fn atomic_write(tmp: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        let mut file = fs::File::create(tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // Windows cannot rename over an existing file. On Unix, rename replaces
    // atomically — deleting first opens a window where a crash loses the
    // registry.
    #[cfg(windows)]
    if dest.exists() {
        fs::remove_file(dest)?;
    }
    fs::rename(tmp, dest)?;
    Ok(())
}

pub fn normalize_username(raw: &str) -> Option<String> {
    let cleaned = strip_invisible(raw);
    if cleaned.len() < USERNAME_MIN || cleaned.len() > USERNAME_MAX {
        return None;
    }
    if cleaned.eq_ignore_ascii_case("anonymous") {
        return None;
    }
    Some(cleaned.to_lowercase())
}

pub fn normalize_channel_name(raw: &str) -> Option<String> {
    let cleaned = strip_invisible(raw);
    if cleaned.is_empty() || cleaned.len() > CHANNEL_NAME_MAX {
        return None;
    }
    if cleaned.eq_ignore_ascii_case("anonymous") {
        return None;
    }
    Some(cleaned.to_lowercase())
}

fn strip_invisible(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && *c != '\0' && !is_bidi_or_zero_width(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn is_bidi_or_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}'
            | '\u{061C}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn username_first_write_wins_and_rename_releases_the_old_name() {
        let mut reg = ChannelRegistry::in_memory();
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        assert!(reg.claim_username(&alice, "Ada").is_ok());
        assert_eq!(reg.claim_username(&bob, "ada"), Err(RegistryError::Taken));
        assert!(reg.claim_username(&alice, "Ada Lovelace").is_ok());
        assert!(reg.claim_username(&bob, "Ada").is_ok());
    }

    #[test]
    fn channel_name_conflict_hides_whether_the_room_is_private() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", true).is_ok());
        assert!(reg
            .public_directory()
            .is_empty(), "private names stay off the directory");
        let other = "33".repeat(16);
        let other_pk = "44".repeat(32);
        assert_eq!(
            reg.claim_channel_name(&other, &other_pk, "lobby", false),
            Err(RegistryError::Taken)
        );
    }

    #[test]
    fn delete_requires_the_channel_key_and_retires_the_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert_eq!(
            reg.delete_channel(&id, &"99".repeat(32)),
            Err(RegistryError::Forbidden)
        );
        assert!(reg.delete_channel(&id, &pk).is_ok());
        assert!(reg.public_directory().is_empty());
        assert!(reg.deleted_ids().contains(&id));
        assert_eq!(
            reg.claim_channel_name(&"aa".repeat(16), &"bb".repeat(32), "Lobby", false),
            Err(RegistryError::Taken),
            "a deleted name must not be reclaimable"
        );
    }

    #[test]
    fn public_directory_omits_deleted_and_private_rooms() {
        let mut reg = ChannelRegistry::in_memory();
        let pub_id = "11".repeat(16);
        let pub_pk = "22".repeat(32);
        let priv_id = "33".repeat(16);
        let priv_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&pub_id, &pub_pk, "Open", false).is_ok());
        assert!(reg.claim_channel_name(&priv_id, &priv_pk, "Secret", true).is_ok());
        assert_eq!(reg.public_directory().len(), 1);
        assert_eq!(reg.public_directory()[0].channel_id, pub_id);
        assert_eq!(
            reg.public_directory()[0].name, "Open",
            "the directory must keep the owner's casing"
        );
        assert!(reg.delete_channel(&pub_id, &pub_pk).is_ok());
        assert!(reg.public_directory().is_empty());
    }

    #[test]
    fn one_channel_cannot_claim_a_second_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert_eq!(
            reg.claim_channel_name(&id, &pk, "Elsewhere", false),
            Err(RegistryError::Taken)
        );
    }

    #[test]
    fn persist_round_trip_keeps_claims() {
        let path = std::env::temp_dir().join(format!(
            "ember-channels-registry-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_file(&path);
        let alice = "aa".repeat(32);
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        {
            let mut reg = ChannelRegistry::load(path.clone());
            assert!(reg.claim_username(&alice, "Ada").is_ok());
            assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        }
        let mut reloaded = ChannelRegistry::load(path.clone());
        assert_eq!(reloaded.public_directory().len(), 1);
        assert_eq!(
            reloaded.claim_username(&"bb".repeat(32), "Ada"),
            Err(RegistryError::Taken)
        );
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("json.tmp"));
    }
}
