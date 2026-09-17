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

pub const USERNAME_MAX: usize = 12;
pub const CHANNEL_NAME_MAX: usize = 64;
pub const USERNAME_MIN: usize = 2;
/// Drop a quiet public listing from Discover after this long. The name stays
/// reserved until [`NAME_RELEASE_SECS`] so a successor still has the year-long
/// claim window, without leaving dead rooms in the directory forever.
pub const CHANNEL_DIRECTORY_STALE_SECS: i64 = 7 * 24 * 60 * 60;
/// Free an abandoned room name after this long without an owner refresh, so a
/// dead room cannot reserve a word forever. Matches the longest succession
/// window, which is the most silence an owner can ask members to tolerate.
pub const NAME_RELEASE_SECS: i64 = 365 * 24 * 60 * 60;
/// Free a Channel username that has not been seen in a room for this long.
pub const USERNAME_IDLE_SECS: i64 = 365 * 24 * 60 * 60;
/// Silence windows a nomination may carry, mirroring the range the clients
/// clamp to. Outside it the registry and the members would disagree about when
/// a room has actually changed hands.
pub const CLAIM_AFTER_DAYS_MIN: u32 = 7;
pub const CLAIM_AFTER_DAYS_MAX: u32 = 365;

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
    /// Unix seconds of the last signed name claim. 0 in files written before
    /// this field existed; load grandfathers those to "now" so a deploy does
    /// not reap every existing room.
    #[serde(default)]
    pub refreshed_at: i64,
    /// User pubkey (64-char hex) the owner nominated to inherit the room, or
    /// empty. Lets the nominee move the name to their successor room once the
    /// owner has been silent for `claim_after_days`, mirroring the takeover
    /// rule the members enforce over the DHT.
    #[serde(default)]
    pub nominee: String,
    /// Days of owner silence before `nominee` may move the name. 0 disables it.
    #[serde(default)]
    pub claim_after_days: u32,
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
    /// Last activity per user pubkey (64-char hex). Missing keys are
    /// grandfathered on load.
    #[serde(default)]
    username_activity: HashMap<String, i64>,
}

/// Borrowed mirror of [`RegistryFile`] used for writing.
///
/// `persist` runs on every claim, nomination, delete and reap, and building an
/// owned `RegistryFile` copied all four maps each time — including `deleted`,
/// which is a permanent tombstone set that only ever grows, so the cost of a
/// save climbed with the server's whole deletion history. Serde emits an
/// identical document either way.
///
/// The tombstones themselves are deliberately kept forever: only an owner can
/// destroy a room, and `owner_delete_keeps_the_name_retired` pins that such a
/// name must never become claimable again. Expiring them would be a policy
/// change, not a leak fix.
#[derive(Serialize)]
struct RegistryFileRef<'a> {
    usernames: &'a HashMap<String, String>,
    names: &'a HashMap<String, ChannelNameRecord>,
    deleted: &'a HashSet<String>,
    username_activity: &'a HashMap<String, i64>,
}

#[derive(Clone, Debug)]
pub struct ChannelRegistry {
    path: Option<PathBuf>,
    usernames: HashMap<String, String>,
    by_pubkey: HashMap<String, String>,
    names: HashMap<String, ChannelNameRecord>,
    deleted: HashSet<String>,
    username_activity: HashMap<String, i64>,
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
            username_activity: HashMap::new(),
        }
    }

    pub fn load(path: PathBuf) -> Self {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        // A previous run may have been interrupted between moving the old
        // registry aside and renaming the new one into place. Reading that as
        // a first run would silently release every claim on record.
        recover_interrupted_write(&path);
        let parsed = fs::read(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RegistryFile>(&bytes).ok())
            .unwrap_or_default();
        let mut by_pubkey = HashMap::new();
        for (name, pubkey) in &parsed.usernames {
            by_pubkey.insert(pubkey.to_ascii_lowercase(), name.clone());
        }
        let mut reg = Self {
            path: Some(path),
            usernames: parsed.usernames,
            by_pubkey,
            names: parsed.names,
            deleted: parsed.deleted,
            username_activity: parsed.username_activity,
        };
        if reg.grandfather_legacy_timestamps(unix_now()) {
            reg.persist();
        }
        reg
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let file = RegistryFileRef {
            usernames: &self.usernames,
            names: &self.names,
            deleted: &self.deleted,
            username_activity: &self.username_activity,
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
        self.claim_username_at(pubkey_hex, name, unix_now())
    }

    pub fn claim_username_at(
        &mut self,
        pubkey_hex: &str,
        name: &str,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.reap_stale(now);
        let normalized = normalize_username(name).ok_or(RegistryError::InvalidName)?;
        let pk = pubkey_hex.to_ascii_lowercase();
        if pk.len() != 64 || hex::decode(&pk).map(|b| b.len()).unwrap_or(0) != 32 {
            return Err(RegistryError::InvalidName);
        }
        if let Some(owner) = self.usernames.get(&normalized) {
            if owner.eq_ignore_ascii_case(&pk) {
                self.username_activity.insert(pk, now);
                self.persist();
                return Ok(());
            }
            return Err(RegistryError::Taken);
        }
        if let Some(old) = self.by_pubkey.remove(&pk) {
            self.usernames.remove(&old);
        }
        self.usernames.insert(normalized.clone(), pk.clone());
        self.by_pubkey.insert(pk.clone(), normalized);
        self.username_activity.insert(pk, now);
        self.persist();
        Ok(())
    }

    /// Whether this room already holds a name here.
    ///
    /// Lets the creation budget charge for standing a room up without charging
    /// its owner for keeping it: a re-claim of a name the room already has is
    /// the refresh path, and refusing that would eventually free the name of a
    /// room that is very much alive.
    pub fn has_channel(&self, channel_id: &str) -> bool {
        let id = channel_id.to_ascii_lowercase();
        self.names
            .values()
            .any(|rec| !rec.deleted && rec.channel_id.eq_ignore_ascii_case(&id))
    }

    pub fn claim_channel_name(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
    ) -> Result<(), RegistryError> {
        self.claim_channel_name_at(channel_id, pubkey_hex, name, private, unix_now())
    }

    pub fn claim_channel_name_at(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        name: &str,
        private: bool,
        now: i64,
    ) -> Result<(), RegistryError> {
        self.reap_stale(now);
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
            if existing_name != &normalized {
                return Err(RegistryError::Taken);
            }
            break;
        }
        // Reject a name that merely *looks* like one already on record. Scoped
        // to other rooms, so an owner refreshing or re-casing its own claim
        // still passes, and skipped when the exact key already exists because
        // the block below handles that case with the owner check it needs.
        if !self.names.contains_key(&normalized) {
            let candidate = confusable_key(&normalized);
            // Tombstones count. The exact-key path below refuses a
            // owner-deleted name permanently, so exempting those rows here
            // would have left a homoglyph of a retired name claimable while
            // the name itself never comes back — the impersonation this check
            // exists to stop, aimed at a room that no longer has an owner to
            // notice.
            if self.names.iter().any(|(existing_name, rec)| {
                !rec.channel_id.eq_ignore_ascii_case(&id)
                    && confusable_key(existing_name) == candidate
            }) {
                return Err(RegistryError::Taken);
            }
        }
        if let Some(existing) = self.names.get_mut(&normalized) {
            if existing.deleted {
                return Err(RegistryError::Taken);
            }
            if existing.channel_id.eq_ignore_ascii_case(&id)
                && existing.pubkey.eq_ignore_ascii_case(&pk)
            {
                existing.private = private;
                existing.display = display;
                existing.refreshed_at = now;
                self.persist();
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
                refreshed_at: now,
                nominee: String::new(),
                claim_after_days: 0,
            },
        );
        self.persist();
        Ok(())
    }

    /// Record who may inherit this room's name, signed by the channel key.
    /// An empty nominee or a zero window clears the nomination.
    pub fn set_channel_nominee(
        &mut self,
        channel_id: &str,
        pubkey_hex: &str,
        nominee_hex: &str,
        claim_after_days: u32,
    ) -> Result<(), RegistryError> {
        let id = channel_id.to_ascii_lowercase();
        let pk = pubkey_hex.to_ascii_lowercase();
        let nominee = nominee_hex.to_ascii_lowercase();
        let clearing = nominee.is_empty() || claim_after_days == 0;
        if !clearing
            && (nominee.len() != 64
                || hex::decode(&nominee).is_err()
                || !(CLAIM_AFTER_DAYS_MIN..=CLAIM_AFTER_DAYS_MAX).contains(&claim_after_days))
        {
            return Err(RegistryError::InvalidName);
        }
        let Some(rec) = self
            .names
            .values_mut()
            .find(|rec| !rec.deleted && rec.channel_id.eq_ignore_ascii_case(&id))
        else {
            return Err(RegistryError::InvalidName);
        };
        if !rec.pubkey.eq_ignore_ascii_case(&pk) {
            return Err(RegistryError::Forbidden);
        }
        if clearing {
            rec.nominee = String::new();
            rec.claim_after_days = 0;
        } else {
            rec.nominee = nominee;
            rec.claim_after_days = claim_after_days;
        }
        self.persist();
        Ok(())
    }

    /// Move a name from the room that holds it to its successor.
    ///
    /// A handoff mints a fresh channel key, so the successor room has an id the
    /// name has never been bound to and cannot claim it while the old record
    /// stands. `signer_hex` is authorized two ways, matching the two ways a room
    /// changes hands: the outgoing owner's channel key signs an explicit
    /// transfer, or the nominee's user key signs a takeover once the owner has
    /// been silent for the window they published.
    pub fn handover_channel_name(
        &mut self,
        old_channel_id: &str,
        new_channel_id: &str,
        new_pubkey_hex: &str,
        signer_hex: &str,
        now: i64,
    ) -> Result<(), RegistryError> {
        let old_id = old_channel_id.to_ascii_lowercase();
        let new_id = new_channel_id.to_ascii_lowercase();
        let new_pk = new_pubkey_hex.to_ascii_lowercase();
        let signer = signer_hex.to_ascii_lowercase();
        if new_id.len() != 32
            || new_pk.len() != 64
            || hex::decode(&new_id).map(|b| b.len()).unwrap_or(0) != 16
            || hex::decode(&new_pk).map(|b| b.len()).unwrap_or(0) != 32
        {
            return Err(RegistryError::InvalidName);
        }
        if new_id == old_id {
            return Err(RegistryError::InvalidName);
        }
        // A destroyed room does not get to pass its name on, and the successor
        // must not already be holding one — the same one-name-per-room rule
        // `claim_channel_name_at` enforces.
        if self.deleted.contains(&old_id) || self.deleted.contains(&new_id) {
            return Err(RegistryError::Taken);
        }
        if self
            .names
            .values()
            .any(|rec| !rec.deleted && rec.channel_id.eq_ignore_ascii_case(&new_id))
        {
            return Err(RegistryError::Taken);
        }
        let Some(rec) = self
            .names
            .values_mut()
            .find(|rec| !rec.deleted && rec.channel_id.eq_ignore_ascii_case(&old_id))
        else {
            return Err(RegistryError::InvalidName);
        };
        let by_owner = rec.pubkey.eq_ignore_ascii_case(&signer);
        let by_nominee = rec.claim_after_days > 0
            && !rec.nominee.is_empty()
            && rec.nominee.eq_ignore_ascii_case(&signer)
            && now.saturating_sub(rec.refreshed_at)
                >= i64::from(rec.claim_after_days).saturating_mul(86_400);
        if !by_owner && !by_nominee {
            return Err(RegistryError::Forbidden);
        }
        rec.channel_id = new_id;
        rec.pubkey = new_pk;
        rec.refreshed_at = now;
        // The nomination belonged to the previous owner; the new one publishes
        // their own, and leaving it would let the old nominee take the name a
        // second time.
        rec.nominee = String::new();
        rec.claim_after_days = 0;
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
        self.public_directory_at(unix_now())
    }

    pub fn public_directory_at(&self, now: i64) -> Vec<DirectoryListing> {
        let mut out: Vec<DirectoryListing> = self
            .names
            .iter()
            .filter(|(_, rec)| {
                !rec.private
                    && !rec.deleted
                    && !self.deleted.contains(&rec.channel_id)
                    && now.saturating_sub(rec.refreshed_at) <= CHANNEL_DIRECTORY_STALE_SECS
            })
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

    /// Drop abandoned usernames and room names. Owner-deleted names stay
    /// retired; abandoned ones are forgotten so someone else can claim them.
    ///
    /// Deliberately *not* a tombstone. Only the owner can destroy a room, and
    /// a silent owner is not proof the room is dead — its members may still be
    /// talking. Forgetting the claim frees the name and takes the room out of
    /// the directory without evicting anyone, and it keeps the tombstone list
    /// bounded by real deletions instead of growing forever.
    pub fn reap_stale(&mut self, now: i64) -> bool {
        let mut changed = self.grandfather_legacy_timestamps(now);
        let idle_names: Vec<String> = self
            .usernames
            .iter()
            .filter_map(|(name, pk)| {
                let ts = self.username_activity.get(pk).copied().unwrap_or(now);
                (now.saturating_sub(ts) > USERNAME_IDLE_SECS).then(|| name.clone())
            })
            .collect();
        for name in idle_names {
            if let Some(pk) = self.usernames.remove(&name) {
                self.by_pubkey.remove(&pk);
                self.username_activity.remove(&pk);
                changed = true;
            }
        }
        let abandoned: Vec<String> = self
            .names
            .iter()
            .filter_map(|(name, rec)| {
                if rec.deleted {
                    return None;
                }
                let ts = if rec.refreshed_at > 0 {
                    rec.refreshed_at
                } else {
                    now
                };
                (now.saturating_sub(ts) > NAME_RELEASE_SECS).then(|| name.clone())
            })
            .collect();
        for name in abandoned {
            if self.names.remove(&name).is_some() {
                changed = true;
            }
        }
        if changed {
            self.persist();
        }
        changed
    }

    fn grandfather_legacy_timestamps(&mut self, now: i64) -> bool {
        let mut changed = false;
        for rec in self.names.values_mut() {
            if rec.deleted || rec.refreshed_at > 0 {
                continue;
            }
            rec.refreshed_at = now;
            changed = true;
        }
        for pk in self.usernames.values() {
            if self.username_activity.contains_key(pk) {
                continue;
            }
            self.username_activity.insert(pk.clone(), now);
            changed = true;
        }
        changed
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

/// Where [`atomic_write`] parks the previous copy while it swaps in a new one.
fn backup_path(dest: &Path) -> PathBuf {
    let mut name = dest.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    dest.with_file_name(name)
}

/// Restore a registry left behind by an interrupted [`atomic_write`].
///
/// Only ever fires on Windows, and only for the narrow window in which the
/// destination has been moved aside but the replacement has not landed. A
/// backup sitting next to a destination that already exists is ordinary
/// leftover and is cleaned up rather than restored.
pub(crate) fn recover_interrupted_write(dest: &Path) {
    let backup = backup_path(dest);
    if !backup.exists() {
        return;
    }
    if dest.exists() {
        let _ = fs::remove_file(&backup);
        return;
    }
    if fs::rename(&backup, dest).is_ok() {
        tracing::warn!(
            path = %dest.display(),
            "restored the channels registry from its backup after an interrupted write"
        );
    }
}

fn atomic_write(tmp: &Path, dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    {
        let mut file = fs::File::create(tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    // On Unix, `rename` replaces atomically and there is nothing to arrange.
    #[cfg(not(windows))]
    {
        fs::rename(tmp, dest)?;
        Ok(())
    }

    // Windows cannot rename over an existing file. Deleting the destination
    // first is the obvious workaround and the dangerous one: if the rename
    // then fails — a scanner or backup agent holding a handle, a transient
    // sharing violation, the process dying inside the window — the
    // destination is already gone and the new content is still parked under
    // the temp name. The server comes back with no registry at all, which
    // releases every username and channel-name claim for anyone to re-take.
    //
    // So move the old copy aside instead of destroying it: at every point
    // between here and the end of the function, the previous registry exists
    // under either `dest` or `backup`, and `recover_interrupted_write` picks
    // it up on the next load.
    #[cfg(windows)]
    {
        let backup = backup_path(dest);
        let parked = if dest.exists() {
            let _ = fs::remove_file(&backup);
            fs::rename(dest, &backup)?;
            true
        } else {
            false
        };
        match fs::rename(tmp, dest) {
            Ok(()) => {
                if parked {
                    let _ = fs::remove_file(&backup);
                }
                Ok(())
            }
            Err(e) => {
                // Put the original back rather than leaving nothing at `dest`.
                // If even this fails the backup stays put, which is exactly
                // what the recovery path on next load looks for.
                if parked {
                    let _ = fs::rename(&backup, dest);
                }
                Err(e)
            }
        }
    }
}

pub fn normalize_username(raw: &str) -> Option<String> {
    let cleaned = strip_invisible(raw);
    if cleaned.len() < USERNAME_MIN || cleaned.len() > USERNAME_MAX {
        return None;
    }
    if !cleaned.chars().all(|c| c.is_ascii_alphanumeric()) {
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

/// Fold a channel name to its Unicode confusable skeleton (UTS #39), for
/// deciding whether two names would look the same to a user.
///
/// [`normalize_channel_name`] case-folds and nothing else, so `"Lobby"` and
/// `"Lοbby"` — the second with a Greek omicron — are distinct keys and both
/// claimable. Since creating a room is unprivileged, anyone could register a
/// name visually identical to an established one, have it served to every
/// client's Discover directory, and (because the directory sorts by name) land
/// it directly beside the room it mimics. Usernames were never exposed to
/// this: `normalize_username` requires `is_ascii_alphanumeric`, which removes
/// the homoglyph primitive outright.
///
/// This is deliberately kept *separate* from the map key rather than replacing
/// it. Re-keying would strand every name already on record under its old key —
/// making each one look unclaimed and therefore re-claimable, which is a far
/// worse version of the problem being fixed — and the skeleton is a matching
/// form, not a display form: it maps `l`, `1` and `I` onto one representative,
/// so a legacy record with no stored `display` would render as mojibake in the
/// directory's fallback path.
fn confusable_key(name: &str) -> String {
    use unicode_security::confusable_detection::skeleton;
    skeleton(&name.to_lowercase()).collect()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub(crate) fn strip_invisible(raw: &str) -> String {
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
        assert!(reg.claim_username(&alice, "Lovelace").is_ok());
        assert!(reg.claim_username(&bob, "Ada").is_ok());
    }

    #[test]
    fn username_allows_only_short_ascii_alphanumerics() {
        assert_eq!(normalize_username("Ada"), Some("ada".into()));
        assert_eq!(normalize_username("Ada1"), Some("ada1".into()));
        assert_eq!(normalize_username("A"), None);
        assert_eq!(normalize_username("Ada Lovelace"), None);
        assert_eq!(normalize_username("Ada_1"), None);
        assert_eq!(normalize_username(&"x".repeat(13)), None);
        assert_eq!(normalize_username("Anonymous"), None);
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

    /// A name that merely looks like one already taken must be refused, or
    /// anyone can stand up a visually identical room beside an established one
    /// in Discover.
    #[test]
    fn a_confusable_channel_name_cannot_be_claimed() {
        let mut reg = ChannelRegistry::in_memory();
        assert!(reg
            .claim_channel_name(&"11".repeat(16), &"22".repeat(32), "Lobby", false)
            .is_ok());

        // Greek omicron (U+03BF) for the Latin "o".
        assert_eq!(
            reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), "L\u{03BF}bby", false),
            Err(RegistryError::Taken),
            "a homoglyph of a taken name must not be claimable"
        );
        // Cyrillic small "о" (U+043E).
        assert_eq!(
            reg.claim_channel_name(&"55".repeat(16), &"66".repeat(32), "L\u{043E}bby", false),
            Err(RegistryError::Taken)
        );
        // A genuinely different name is unaffected.
        assert!(reg
            .claim_channel_name(&"77".repeat(16), &"88".repeat(32), "Lounge", false)
            .is_ok());
    }

    /// `persist` writes through a borrowed mirror of `RegistryFile` to avoid
    /// cloning four maps — one of them the permanent tombstone set — on every
    /// claim, nomination, delete and reap. The two must serialise identically
    /// or the next load reads a different file than the one that was written.
    #[test]
    fn the_borrowed_write_form_serialises_exactly_like_the_owned_one() {
        let mut reg = ChannelRegistry::in_memory();
        assert!(reg.claim_username(&"aa".repeat(32), "Ada").is_ok());
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg
            .set_channel_nominee(&id, &pk, &"bb".repeat(32), 7)
            .is_ok());
        let gone = "33".repeat(16);
        let gone_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&gone, &gone_pk, "Gone", false).is_ok());
        assert!(reg.delete_channel(&gone, &gone_pk).is_ok());

        let borrowed = serde_json::to_vec_pretty(&RegistryFileRef {
            usernames: &reg.usernames,
            names: &reg.names,
            deleted: &reg.deleted,
            username_activity: &reg.username_activity,
        })
        .expect("borrowed form serialises");
        let owned = serde_json::to_vec_pretty(&RegistryFile {
            usernames: reg.usernames.clone(),
            names: reg.names.clone(),
            deleted: reg.deleted.clone(),
            username_activity: reg.username_activity.clone(),
        })
        .expect("owned form serialises");

        assert_eq!(
            String::from_utf8(borrowed).unwrap(),
            String::from_utf8(owned).unwrap()
        );
    }

    /// A handoff moves the name's record rather than re-claiming it, so it
    /// must not be exposed to the confusable scan — the successor is taking
    /// the *same* name, which necessarily collides with itself. Pinned because
    /// the scan and the handover live in different functions and nothing else
    /// would notice if handover started routing through the claim path.
    #[test]
    fn a_handover_keeps_the_name_and_is_not_blocked_by_the_confusable_scan() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&old_id, &old_pk, "Lobby", false).is_ok());

        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, unix_now())
            .is_ok());

        let listing = reg.public_directory();
        assert_eq!(listing.len(), 1, "the name moved rather than duplicating");
        assert_eq!(listing[0].channel_id, new_id);
        assert_eq!(listing[0].name, "Lobby");

        // And the successor, now the holder, can still refresh its own claim —
        // the scan skips same-channel rows, so its own name is not a lookalike
        // of itself.
        assert!(reg
            .claim_channel_name(&new_id, &new_pk, "Lobby", false)
            .is_ok());
    }

    /// The predecessor's record is gone after a handoff, so a successor that
    /// wants a *different* name is judged against every other room and not
    /// against the room it replaced.
    #[test]
    fn a_successor_can_take_a_different_name_after_a_handover() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        assert!(reg.claim_channel_name(&old_id, &old_pk, "Lobby", false).is_ok());
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, unix_now())
            .is_ok());

        // One name per room, so the successor must release "Lobby" first; that
        // is the pre-existing rule, not something the confusable scan added.
        assert_eq!(
            reg.claim_channel_name(&new_id, &new_pk, "Lounge", false),
            Err(RegistryError::Taken)
        );
        assert!(reg.delete_channel(&new_id, &new_pk).is_ok());
    }

    /// An owner-deleted name never comes back, so a lookalike of one must not
    /// either — otherwise the retirement just moves the name one homoglyph
    /// away, to a room whose owner is gone and cannot object.
    #[test]
    fn a_confusable_of_a_retired_name_is_also_refused() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(reg.delete_channel(&id, &pk).is_ok());

        assert_eq!(
            reg.claim_channel_name(&"33".repeat(16), &"44".repeat(32), "Lobby", false),
            Err(RegistryError::Taken),
            "the exact retired name stays retired"
        );
        assert_eq!(
            reg.claim_channel_name(&"55".repeat(16), &"66".repeat(32), "L\u{03BF}bby", false),
            Err(RegistryError::Taken),
            "and so does a homoglyph of it"
        );
    }

    /// The confusable check is scoped to *other* rooms, so an owner refreshing
    /// or re-casing its own claim still succeeds.
    #[test]
    fn an_owner_can_still_refresh_its_own_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        assert!(reg.claim_channel_name(&id, &pk, "Lobby", false).is_ok());
        assert!(
            reg.claim_channel_name(&id, &pk, "LOBBY", false).is_ok(),
            "re-casing is a refresh of the same normalised key"
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

    #[test]
    fn abandoned_room_leaves_the_directory_then_frees_the_name() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(reg.public_directory_at(t0).len(), 1);
        assert!(
            reg.public_directory_at(t0 + CHANNEL_DIRECTORY_STALE_SECS + 1)
                .is_empty(),
            "a quiet listing must drop out of Discover after a week"
        );
        let other = "33".repeat(16);
        let other_pk = "44".repeat(32);
        assert_eq!(
            reg.claim_channel_name_at(&other, &other_pk, "Lobby", false, t0 + CHANNEL_DIRECTORY_STALE_SECS + 1),
            Err(RegistryError::Taken),
            "the name stays reserved through the succession window"
        );
        let release_at = t0 + NAME_RELEASE_SECS + 1;
        assert!(reg.reap_stale(release_at));
        assert!(
            !reg.deleted_ids().contains(&id),
            "reaping frees a name; it must not tombstone a room nobody deleted"
        );
        assert!(
            reg.claim_channel_name_at(&other, &other_pk, "Lobby", false, release_at)
                .is_ok(),
            "an abandoned name must be claimable again"
        );
        assert_eq!(
            reg.claim_channel_name_at(&id, &pk, "Lobby", false, release_at),
            Err(RegistryError::Taken),
            "the returning owner cannot take a name somebody else now holds"
        );
        assert!(
            reg.claim_channel_name_at(&id, &pk, "Elsewhere", false, release_at)
                .is_ok(),
            "a returning owner can still list their room under a free name"
        );
    }

    #[test]
    fn owner_delete_keeps_the_name_retired() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert!(reg.delete_channel(&id, &pk).is_ok());
        let later = t0 + NAME_RELEASE_SECS + 1;
        reg.reap_stale(later);
        assert_eq!(
            reg.claim_channel_name_at(&"33".repeat(16), &"44".repeat(32), "Lobby", false, later),
            Err(RegistryError::Taken),
            "an owner-deleted name must not come back"
        );
    }

    /// A transfer mints a new channel key, so without a handover the name stays
    /// bound to the room the members have already left behind.
    #[test]
    fn the_outgoing_owner_can_hand_the_name_to_the_successor() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &"99".repeat(32), t0),
            Err(RegistryError::Forbidden),
            "a stranger cannot move somebody else's name"
        );
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &old_pk, t0)
            .is_ok());
        let dir = reg.public_directory_at(t0);
        assert_eq!(dir.len(), 1);
        assert_eq!(dir[0].channel_id, new_id, "the listing follows the room");
        assert_eq!(dir[0].name, "Lobby");
        assert!(
            reg.claim_channel_name_at(&new_id, &new_pk, "Lobby", false, t0)
                .is_ok(),
            "the new owner's own refresh keeps working"
        );
    }

    /// Succession happens precisely because the owner is gone, so the nominee
    /// they published has to be able to move the name without them.
    #[test]
    fn the_nominee_can_take_the_name_only_after_the_published_silence() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let new_id = "33".repeat(16);
        let new_pk = "44".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0),
            Err(RegistryError::Forbidden),
            "an unregistered nominee has no authority"
        );
        assert!(reg.set_channel_nominee(&old_id, &old_pk, &nominee, 7).is_ok());
        assert_eq!(
            reg.handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0 + 6 * 86_400),
            Err(RegistryError::Forbidden),
            "the window has not elapsed"
        );
        assert!(reg
            .handover_channel_name(&old_id, &new_id, &new_pk, &nominee, t0 + 7 * 86_400)
            .is_ok());
        // The nomination must not carry over, or the same key could walk the
        // name onward from the room it just handed it to.
        let third_id = "66".repeat(16);
        let third_pk = "77".repeat(32);
        assert_eq!(
            reg.handover_channel_name(&old_id, &third_id, &third_pk, &nominee, t0 + 400 * 86_400),
            Err(RegistryError::InvalidName),
            "the old room no longer holds the name"
        );
        assert_eq!(
            reg.handover_channel_name(&new_id, &third_id, &third_pk, &nominee, t0 + 400 * 86_400),
            Err(RegistryError::Forbidden),
            "the nomination did not survive the handover"
        );
    }

    /// An owner who is still refreshing has not been succeeded, and the server
    /// must reach the same verdict the members do over the DHT.
    #[test]
    fn a_live_owner_keeps_the_name_from_their_nominee() {
        let mut reg = ChannelRegistry::in_memory();
        let old_id = "11".repeat(16);
        let old_pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&old_id, &old_pk, "Lobby", false, t0).is_ok());
        assert!(reg.set_channel_nominee(&old_id, &old_pk, &nominee, 7).is_ok());
        let much_later = t0 + 300 * 86_400;
        assert!(reg
            .claim_channel_name_at(&old_id, &old_pk, "Lobby", false, much_later)
            .is_ok());
        assert_eq!(
            reg.handover_channel_name(
                &old_id,
                &"33".repeat(16),
                &"44".repeat(32),
                &nominee,
                much_later + 86_400
            ),
            Err(RegistryError::Forbidden),
            "refreshing the claim resets the silence the nominee needs"
        );
    }

    /// The members refuse a takeover outside 7–365 days, so a nomination the
    /// registry would honour sooner could move the name off a room nobody has
    /// actually left.
    #[test]
    fn a_nomination_window_outside_the_agreed_range_is_refused() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let nominee = "55".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.set_channel_nominee(&id, &pk, &nominee, 1),
            Err(RegistryError::InvalidName)
        );
        assert_eq!(
            reg.set_channel_nominee(&id, &pk, &nominee, 366),
            Err(RegistryError::InvalidName)
        );
        assert!(reg
            .set_channel_nominee(&id, &pk, &nominee, CLAIM_AFTER_DAYS_MIN)
            .is_ok());
        assert!(reg
            .set_channel_nominee(&id, &pk, &nominee, CLAIM_AFTER_DAYS_MAX)
            .is_ok());
    }

    #[test]
    fn a_nominee_cannot_be_set_by_anyone_but_the_room_key() {
        let mut reg = ChannelRegistry::in_memory();
        let id = "11".repeat(16);
        let pk = "22".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_channel_name_at(&id, &pk, "Lobby", false, t0).is_ok());
        assert_eq!(
            reg.set_channel_nominee(&id, &"99".repeat(32), &"55".repeat(32), 7),
            Err(RegistryError::Forbidden)
        );
        assert!(reg.set_channel_nominee(&id, &pk, &"55".repeat(32), 7).is_ok());
        assert!(reg.set_channel_nominee(&id, &pk, "", 0).is_ok());
        assert_eq!(
            reg.handover_channel_name(&id, &"33".repeat(16), &"44".repeat(32), &"55".repeat(32), t0 + 400 * 86_400),
            Err(RegistryError::Forbidden),
            "a withdrawn nomination confers nothing"
        );
    }

    #[test]
    fn idle_username_is_released_after_a_year() {
        let mut reg = ChannelRegistry::in_memory();
        let alice = "aa".repeat(32);
        let bob = "bb".repeat(32);
        let t0 = 1_700_000_000;
        assert!(reg.claim_username_at(&alice, "Ada", t0).is_ok());
        assert_eq!(
            reg.claim_username_at(&bob, "Ada", t0 + 10),
            Err(RegistryError::Taken)
        );
        assert!(reg.claim_username_at(&alice, "Ada", t0 + 10).is_ok());
        let still_held = t0 + 10 + USERNAME_IDLE_SECS;
        assert_eq!(
            reg.claim_username_at(&bob, "Ada", still_held),
            Err(RegistryError::Taken),
            "activity must reset the idle clock"
        );
        let released = still_held + USERNAME_IDLE_SECS + 1;
        assert!(
            reg.claim_username_at(&bob, "Ada", released).is_ok(),
            "a year without activity frees the handle"
        );
    }
}
