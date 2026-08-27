use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use tracing::{info, warn};

use super::peer_cache::CachedContact;
use super::{EmberContact, EmberNodeId};

const NODES_EMBER_MAGIC: u32 = 0x454D_4233; // "EMB3" in LE
/// v2 appends a per-entry miss count, so how many consecutive sessions have
/// failed to reach an address survives the restart it is counting. v1 files
/// still load — every entry simply starts with a clean slate.
const NODES_EMBER_VERSION: u8 = 2;
const NODES_EMBER_VERSION_WITHOUT_MISSES: u8 = 1;
/// Contacts `load_nodes` will parse from one file, whatever its header claims.
///
/// Same reasoning as [`MAX_PERSISTED_RECORDS`], and taken from the same place —
/// the ceiling the save path is called with — so the two cannot drift. The
/// header field is a `u16`, so without this a hand-edited or corrupt file buys
/// 65,535 parse iterations, as many Ed25519 point decompressions and as many
/// `add_contact` calls, all on the startup path.
const MAX_PERSISTED_CONTACTS: usize = crate::network::EMBER_PERSIST_MAX_CONTACTS;

/// Byte ceiling on `nodes_ember.dat` before it is read at all.
///
/// The parse loop is already capped, so a forged header cannot drive an
/// allocation — but `std::fs::read` happens first and will happily pull a
/// hand-edited or corrupted multi-gigabyte file entirely into memory on the
/// startup path. `MAX_PERSISTED_CONTACTS` (200) contacts of roughly a hundred
/// bytes each is about 20 KB, so this is orders of magnitude of slack while
/// still bounding the read. `kad/bootstrap.rs` guards its own loader the same
/// way.
const MAX_NODES_EMBER_BYTES: u64 = 4 * 1024 * 1024;

/// Byte ceiling on `store_ember.dat`, for the same reason. 20,000 records at
/// roughly 1.3 KB each is about 26 MB, so this leaves room to grow.
const MAX_STORE_EMBER_BYTES: u64 = 64 * 1024 * 1024;

/// Copy the current file aside before it is replaced.
///
/// Deliberately best-effort and silent: we would rather commit the new file
/// than refuse the save because a backup could not be made. This is what makes
/// a thinned-table write recoverable — `save_nodes` only refuses to overwrite
/// when the table is *empty*, so a table cut to a handful of contacts by
/// `evict_filtered_contacts`, a `block_private_ips` toggle, or `remove_stale`
/// after an outage will legitimately be persisted over a healthy 200-contact
/// file, and without this the previous contents were unrecoverable. Mirrors
/// `kad/bootstrap.rs`, which has kept a `.bak` for `nodes.dat` all along.
fn backup_before_overwrite(path: &Path) {
    if !path.exists() {
        return;
    }
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    let bak = path.with_file_name(name);
    if let Err(e) = std::fs::copy(path, &bak) {
        tracing::debug!("Could not back up {} before overwrite: {e}", path.display());
    }
}

/// Persist the bootstrap cache to `nodes_ember.dat`.
///
/// Format:
///   magic(4) + version(1) + count(u16 LE) +
///   for each contact:
///     node_id(16) + addr_type(1) + ip(4 or 16) + port(2 BE) +
///     noise_pub(32) + ed25519_pub(32) + last_seen(i64 LE) + misses(1)
pub fn save_nodes(
    path: &Path,
    contacts: &[CachedContact],
    nodes_were_loaded: bool,
) -> anyhow::Result<()> {
    // Never trade a usable bootstrap file for an empty one. A table can be
    // momentarily empty (startup, the transport toggled off, a network drop),
    // and overwriting the file at that moment leaves the next launch with no
    // way back into the network at all.
    if contacts.is_empty() && path.exists() {
        info!(
            "Skipping Ember nodes save: routing table empty but {} already exists",
            path.display()
        );
        return Ok(());
    }

    // A file we could not read is not a file with nothing in it. `load_nodes`
    // fails with the contents perfectly intact on a version downgrade, a bad
    // magic, an oversized file, or — routinely on Windows — a sharing violation
    // from antivirus, the indexer or backup software. The cache then starts
    // empty, nothing re-reads the file, and the next save would overwrite two
    // hundred remembered peers with whatever this one session managed to find.
    // `save_store` has taken the same flag for the same reason all along.
    if !nodes_were_loaded && path.exists() {
        info!(
            "Skipping Ember nodes save: this session never loaded {}, so what it \
             holds cannot be compared with what is there",
            path.display()
        );
        return Ok(());
    }

    // Build the full file in memory first, then commit via
    // `atomic_write`. The previous implementation did
    // `File::create -> write -> drop -> rename` without `sync_all`,
    // which on a Windows or pre-fsync Linux crash can leave the
    // renamed file with zero / partial bytes. `atomic_write` does
    // tmp + write + sync + rename + dir-sync (Unix), matching what
    // `nodes.dat` and `known.met` use elsewhere.
    let mut buf: Vec<u8> = Vec::with_capacity(8 + contacts.len() * 100);
    buf.write_u32::<LittleEndian>(NODES_EMBER_MAGIC)?;
    buf.write_u8(NODES_EMBER_VERSION)?;
    let count = contacts.len().min(u16::MAX as usize);
    buf.write_u16::<LittleEndian>(count as u16)?;

    for entry in contacts.iter().take(count) {
        let contact = &entry.contact;
        buf.write_all(&contact.node_id.0)?;

        match contact.addr.ip() {
            std::net::IpAddr::V4(ip) => {
                buf.write_u8(4)?;
                buf.write_all(&ip.octets())?;
            }
            std::net::IpAddr::V6(ip) => {
                buf.write_u8(6)?;
                buf.write_all(&ip.octets())?;
            }
        }
        buf.write_u16::<byteorder::BigEndian>(contact.addr.port())?;
        buf.write_all(&contact.noise_pub)?;
        buf.write_all(&contact.ed25519_pub)?;
        buf.write_i64::<LittleEndian>(contact.last_seen)?;
        buf.write_u8(entry.misses)?;
    }

    backup_before_overwrite(path);
    crate::security::atomic_write(path, &buf, false)?;
    info!("Saved {} Ember DHT contacts to {}", count, path.display());
    Ok(())
}

/// Load remembered contacts from `nodes_ember.dat`.
///
/// The persisted `last_seen` is returned as written, because the bootstrap
/// cache ranks by it and decides on it whether a session reached the peer. It
/// must not reach the routing table, which needs every restored entry to look
/// unproven — [`super::peer_cache::BootstrapCache::seed_batch`] is what
/// enforces that, and is the only supported way to get contacts from here into
/// a table.
pub fn load_nodes(path: &Path) -> anyhow::Result<Vec<CachedContact>> {
    crate::security::recover_interrupted_replace(path);
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_NODES_EMBER_BYTES {
            anyhow::bail!(
                "nodes_ember.dat too large ({} bytes, max {MAX_NODES_EMBER_BYTES})",
                meta.len()
            );
        }
    }
    let data = std::fs::read(path)?;
    if data.len() < 7 {
        anyhow::bail!("nodes_ember.dat too small");
    }

    let mut cursor = std::io::Cursor::new(&data);
    let magic = cursor.read_u32::<LittleEndian>()?;
    if magic != NODES_EMBER_MAGIC {
        anyhow::bail!("Invalid nodes_ember.dat magic: 0x{magic:08x}");
    }

    let version = cursor.read_u8()?;
    if version > NODES_EMBER_VERSION {
        anyhow::bail!("Unsupported nodes_ember.dat version {version}");
    }

    let declared = cursor.read_u16::<LittleEndian>()? as usize;
    if declared > MAX_PERSISTED_CONTACTS {
        warn!(
            "nodes_ember.dat declares {declared} contacts, more than this build writes; \
             reading the first {MAX_PERSISTED_CONTACTS}"
        );
    }
    let count = declared.min(MAX_PERSISTED_CONTACTS);
    let mut contacts = Vec::with_capacity(count);
    // Contacts dropped because their persisted Ed25519 key was unusable. Tracked
    // separately so the truncation check below doesn't misfire when we
    // legitimately skip a corrupt entry mid-file.
    let mut dropped = 0usize;

    for _ in 0..count {
        let mut node_id = [0u8; 16];
        if cursor.read_exact(&mut node_id).is_err() {
            break;
        }

        let addr_type = match cursor.read_u8() {
            Ok(t) => t,
            Err(_) => break,
        };
        let ip = match addr_type {
            4 => {
                let mut octets = [0u8; 4];
                if cursor.read_exact(&mut octets).is_err() {
                    break;
                }
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets))
            }
            6 => {
                let mut octets = [0u8; 16];
                if cursor.read_exact(&mut octets).is_err() {
                    break;
                }
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => {
                warn!("Unknown address type {addr_type} in nodes_ember.dat, stopping");
                break;
            }
        };

        let port = match cursor.read_u16::<byteorder::BigEndian>() {
            Ok(p) => p,
            Err(_) => break,
        };

        let mut noise_pub = [0u8; 32];
        let mut ed25519_pub = [0u8; 32];
        if cursor.read_exact(&mut noise_pub).is_err()
            || cursor.read_exact(&mut ed25519_pub).is_err()
        {
            break;
        }

        // When the *previous* session last heard from this contact. Kept for
        // the cache, which needs it to tell a session that reached the peer
        // from one that only remembered it, and stripped on the way into the
        // routing table, which needs every restored entry to look unproven.
        //
        // Kept raw here; the clamp belongs to the cache, which is the only
        // thing that knows what "before this session" means. Clamping to
        // wall-clock now would not have worked: `load_nodes` runs *after*
        // `BootstrapCache::new` stamps the session start, so "now" is at or
        // past it, and a future-dated entry would still satisfy "did we reach
        // anybody this run" — the exact guard the clamp was meant to protect.
        // After an NTP correction on a machine whose clock was fast, that is
        // every entry in the file at once.
        let persisted_last_seen = cursor.read_i64::<LittleEndian>().unwrap_or(0);

        // Absent in v1, where every entry starts even.
        let misses = if version > NODES_EMBER_VERSION_WITHOUT_MISSES {
            match cursor.read_u8() {
                Ok(m) => m,
                Err(_) => break,
            }
        } else {
            0
        };

        // Re-derive the node id from the persisted Ed25519 key rather than
        // trusting the on-disk `node_id`. If the file was tampered with (or
        // corrupted), a mismatched id must not let a contact masquerade under
        // an identity it doesn't control — the derived id is authoritative and
        // matches what the first PING will re-verify.
        let Some(derived) = crate::network::ember::crypto::node_id_from_ed25519_bytes(&ed25519_pub)
        else {
            warn!("Skipping nodes_ember.dat contact with invalid Ed25519 key");
            dropped += 1;
            continue;
        };
        let _ = node_id; // persisted id is advisory; derived id is authoritative

        contacts.push(CachedContact {
            contact: EmberContact {
                node_id: EmberNodeId(derived),
                addr: SocketAddr::new(ip, port),
                noise_pub,
                ed25519_pub,
                last_seen: persisted_last_seen,
                failed_queries: 0,
            },
            misses,
        });
    }

    // Detect partial/truncated load. The header declared `count`
    // contacts but the loop bailed early on the first short read,
    // leaving us with fewer. Without this check, the next save would
    // silently overwrite the on-disk file with the truncated list,
    // permanently shrinking the persisted DHT bootstrap set.
    // Mirrors `kad::bootstrap::backup_if_short_load`. `dropped` entries were
    // parsed successfully but discarded for an invalid key, so they don't count
    // as truncation.
    if contacts.len() + dropped < count {
        warn!(
            "Ember DHT nodes file declared {count} contacts but only {} loaded; \
             likely a corrupted or truncated file. Backing up before next save.",
            contacts.len(),
        );
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak = path.with_extension(format!("dat.bak.{ts}"));
        if let Err(e) = std::fs::copy(path, &bak) {
            warn!(
                "Failed to back up partial nodes_ember.dat to {}: {e}",
                bak.display(),
            );
        } else {
            info!("Backed up partial nodes_ember.dat to {}", bak.display());
        }
    }

    info!(
        "Loaded {} Ember DHT contacts from {}",
        contacts.len(),
        path.display()
    );
    Ok(contacts)
}

const STORE_EMBER_MAGIC: u32 = 0x454D_5331; // "EMS1" in LE
const STORE_EMBER_VERSION: u8 = 1;
/// Largest record body accepted from the file. A record has to fit an Ember
/// datagram to have arrived over the wire in the first place, so anything larger
/// on disk is corruption or tampering.
const MAX_PERSISTED_RECORD_BYTES: usize = 4096;
/// Records `load_store` will parse from one file, whatever its header claims.
///
/// Taken from the ceiling the save path writes under rather than restated, so the
/// two cannot drift apart and start discarding records a file we wrote really did
/// contain.
const MAX_PERSISTED_RECORDS: usize = crate::network::EMBER_PERSIST_MAX_RECORDS;

/// Persist the local record store to `store_ember.dat`.
///
/// Written on shutdown only, not on a timer. The store can be several megabytes
/// and a periodic write of that size is exactly the every-few-minutes disk hitch
/// that was removed from the peer-list save; an abnormal exit falls back to what
/// happens today, which is replication refilling the store within the hour.
///
/// Format:
///   magic(4) + version(1) + count(u32 LE) +
///   for each record:
///     key(16) + created_at(i64 LE) + publisher_key(32) + signature(64) +
///     ip_present(1) + ip(4, only when present) + data_len(u32 LE) + data
pub fn save_store(
    path: &Path,
    records: &[super::store::PersistedRecord],
    store_was_loaded: bool,
) -> anyhow::Result<()> {
    if records.is_empty() {
        // Nothing resident. Whether that is worth acting on depends entirely on
        // whether this session ever managed to read the file, which is why the
        // caller has to say so rather than have it inferred here.
        //
        // Deleting unconditionally destroyed the one copy at the worst moment: a
        // corrupt or locked file, or one written by a build this cannot read,
        // leaves the store empty, and the old code then removed the file it had
        // failed to load. Keeping it unconditionally is no better in the other
        // direction — an all-lapsed file can never make the store non-empty again,
        // so nothing would ever rewrite it, and every launch would pay a signature
        // check per record to reject all of them, forever.
        if !store_was_loaded {
            if path.exists() {
                info!(
                    "Skipping Ember store save: this session never loaded {}",
                    path.display()
                );
            }
            return Ok(());
        }
        if path.exists() {
            info!(
                "Removing {}: the store it held is gone or entirely lapsed",
                path.display()
            );
            let _ = std::fs::remove_file(path);
        }
        return Ok(());
    }

    let mut buf: Vec<u8> = Vec::with_capacity(64 + records.len() * 160);
    buf.write_u32::<LittleEndian>(STORE_EMBER_MAGIC)?;
    buf.write_u8(STORE_EMBER_VERSION)?;
    buf.write_u32::<LittleEndian>(records.len() as u32)?;

    for record in records {
        buf.write_all(&record.key)?;
        buf.write_i64::<LittleEndian>(record.created_at)?;
        buf.write_all(&record.publisher_key)?;
        buf.write_all(&record.signature)?;
        match record.attributed_ip {
            Some(ip) => {
                buf.write_u8(1)?;
                buf.write_all(&ip.octets())?;
            }
            None => buf.write_u8(0)?,
        }
        buf.write_u32::<LittleEndian>(record.data.len() as u32)?;
        buf.write_all(&record.data)?;
    }

    backup_before_overwrite(path);
    crate::security::atomic_write(path, &buf, false)?;
    info!(
        "Saved {} Ember DHT records to {}",
        records.len(),
        path.display()
    );
    Ok(())
}

/// Load records from `store_ember.dat`.
///
/// Nothing here is trusted: every record goes back through
/// [`super::store::DhtStore::restore`], which re-verifies its publisher
/// signature and recomputes expiry from the signed creation time. A short or
/// malformed file yields whatever parsed cleanly before the damage.
pub fn load_store(path: &Path) -> anyhow::Result<Vec<super::store::PersistedRecord>> {
    crate::security::recover_interrupted_replace(path);
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_STORE_EMBER_BYTES {
            anyhow::bail!(
                "store_ember.dat too large ({} bytes, max {MAX_STORE_EMBER_BYTES})",
                meta.len()
            );
        }
    }
    let data = std::fs::read(path)?;
    if data.len() < 9 {
        anyhow::bail!("store_ember.dat too small");
    }

    let mut cursor = std::io::Cursor::new(&data);
    let magic = cursor.read_u32::<LittleEndian>()?;
    if magic != STORE_EMBER_MAGIC {
        anyhow::bail!("Invalid store_ember.dat magic: 0x{magic:08x}");
    }
    let version = cursor.read_u8()?;
    if version > STORE_EMBER_VERSION {
        anyhow::bail!("Unsupported store_ember.dat version {version}");
    }

    // The declared count sizes nothing up front — a forged header must not be able
    // to ask for an allocation the file cannot possibly fill — and it is also
    // capped, because the loop it bounds is what decides how many records the
    // caller then verifies. A file crafted with millions of small records would
    // otherwise turn one launch into millions of signature checks on the startup
    // path. Anything past the ceiling this build writes is content we would refuse
    // to store anyway.
    let declared = cursor.read_u32::<LittleEndian>()? as usize;
    if declared > MAX_PERSISTED_RECORDS {
        warn!(
            "store_ember.dat declares {declared} records, more than this build writes; \
             reading the first {MAX_PERSISTED_RECORDS}"
        );
    }
    let count = declared.min(MAX_PERSISTED_RECORDS);
    let mut out: Vec<super::store::PersistedRecord> = Vec::new();
    for _ in 0..count {
        let mut key = [0u8; 16];
        if cursor.read_exact(&mut key).is_err() {
            break;
        }
        let Ok(created_at) = cursor.read_i64::<LittleEndian>() else {
            break;
        };
        let mut publisher_key = [0u8; 32];
        if cursor.read_exact(&mut publisher_key).is_err() {
            break;
        }
        let mut signature = [0u8; 64];
        if cursor.read_exact(&mut signature).is_err() {
            break;
        }
        let Ok(ip_present) = cursor.read_u8() else {
            break;
        };
        let attributed_ip = if ip_present == 1 {
            let mut octets = [0u8; 4];
            if cursor.read_exact(&mut octets).is_err() {
                break;
            }
            Some(std::net::Ipv4Addr::from(octets))
        } else {
            None
        };
        let Ok(len) = cursor.read_u32::<LittleEndian>() else {
            break;
        };
        let len = len as usize;
        if len == 0 || len > MAX_PERSISTED_RECORD_BYTES {
            warn!("store_ember.dat declares a {len}-byte record; stopping there");
            break;
        }
        let mut body = vec![0u8; len];
        if cursor.read_exact(&mut body).is_err() {
            break;
        }
        out.push(super::store::PersistedRecord {
            key,
            data: body,
            signature,
            publisher_key,
            created_at,
            attributed_ip,
        });
    }

    if out.len() < count {
        warn!(
            "store_ember.dat declared {count} records but {} parsed; \
             likely a corrupted or truncated file. Backing up before next save.",
            out.len()
        );
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bak = path.with_extension(format!("dat.bak.{ts}"));
        if let Err(e) = std::fs::copy(path, &bak) {
            warn!(
                "Failed to back up partial store_ember.dat to {}: {e}",
                bak.display(),
            );
        } else {
            info!("Backed up partial store_ember.dat to {}", bak.display());
        }
    }
    info!(
        "Loaded {} Ember DHT records from {}",
        out.len(),
        path.display()
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_contact(id: u8) -> CachedContact {
        // `load_nodes` re-derives the node id from the Ed25519 key and drops
        // contacts whose key isn't a valid curve point, so use a real keypair
        // (any 32 bytes is a valid Ed25519 seed).
        let sk = ed25519_dalek::SigningKey::from_bytes(&[id; 32]);
        let vk = sk.verifying_key();
        CachedContact {
            contact: EmberContact {
                node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(&vk)),
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 2, id)), 4662),
                noise_pub: [id; 32],
                ed25519_pub: vk.to_bytes(),
                last_seen: 1000 + id as i64,
                failed_queries: 0,
            },
            misses: id % 3,
        }
    }

    #[test]
    fn save_load_round_trip() {
        let dir = std::env::temp_dir().join("ember_test_nodes");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        let contacts = vec![make_contact(1), make_contact(2), make_contact(3)];
        save_nodes(&path, &contacts, true).unwrap();
        let loaded = load_nodes(&path).unwrap();

        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded[0].contact.node_id, contacts[0].contact.node_id);
        assert_eq!(loaded[0].contact.addr, contacts[0].contact.addr);
        assert_eq!(loaded[0].contact.noise_pub, contacts[0].contact.noise_pub);
        assert_eq!(loaded[2].contact.node_id, contacts[2].contact.node_id);
        // The cache keeps the real timestamp — it is what tells a session that
        // reached the peer from one that only remembered it. Stripping it is
        // `BootstrapCache::seed_batch`'s job, on the way into the table.
        assert!(loaded
            .iter()
            .zip(&contacts)
            .all(|(l, c)| l.contact.last_seen == c.contact.last_seen));
        // Miss counts have to survive the restart they are counting, or an
        // address can never be retired.
        assert!(loaded
            .iter()
            .zip(&contacts)
            .all(|(l, c)| l.misses == c.misses));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A file we could not read is not a file with nothing in it. `load_nodes`
    /// fails with the contents intact on a version downgrade, a bad magic, an
    /// oversized file, or a Windows sharing violation from antivirus or backup
    /// software — and the next save would then bury two hundred remembered
    /// peers under whatever one session happened to find.
    #[test]
    fn a_session_that_could_not_read_the_file_must_not_overwrite_it() {
        let dir = std::env::temp_dir().join("ember_test_nodes_unread");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        let book: Vec<CachedContact> = (1..=8).map(make_contact).collect();
        save_nodes(&path, &book, true).unwrap();
        let before = std::fs::read(&path).unwrap();

        // This session never loaded it and found one peer of its own.
        save_nodes(&path, &[make_contact(9)], false).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the unread book must survive untouched"
        );
        assert_eq!(load_nodes(&path).unwrap().len(), 8);

        // A session that did read it is free to rewrite it.
        save_nodes(&path, &[make_contact(9)], true).unwrap();
        assert_eq!(load_nodes(&path).unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The same flag must not stop a brand-new profile from ever saving: with
    /// no file to protect there is nothing to lose.
    #[test]
    fn a_missing_file_is_still_written_even_if_nothing_was_loaded() {
        let dir = std::env::temp_dir().join("ember_test_nodes_fresh");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");
        let _ = std::fs::remove_file(&path);

        save_nodes(&path, &[make_contact(3)], false).unwrap();
        assert_eq!(load_nodes(&path).unwrap().len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The loader reports what the file says, including a nonsensical
    /// timestamp. Deciding what counts as "before this session" needs the
    /// session start, which only the cache knows, so the clamp lives there —
    /// see `BootstrapCache::load` and its
    /// `a_future_dated_entry_cannot_fake_having_been_reached` test.
    #[test]
    fn the_loader_reports_the_timestamp_the_file_carries() {
        let dir = std::env::temp_dir().join("ember_test_nodes_future");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        let mut ahead = make_contact(5);
        let far_future = chrono::Utc::now().timestamp() + 86_400;
        ahead.contact.last_seen = far_future;
        save_nodes(&path, &[ahead], true).unwrap();

        let loaded = load_nodes(&path).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].contact.last_seen, far_future);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// v1 files predate the miss count. They must still load, with every entry
    /// starting even rather than being refused or misparsed.
    #[test]
    fn a_v1_file_loads_with_a_clean_slate() {
        let dir = std::env::temp_dir().join("ember_test_nodes_v1");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        let contacts = [make_contact(7), make_contact(8)];
        let mut buf: Vec<u8> = Vec::new();
        buf.write_u32::<LittleEndian>(NODES_EMBER_MAGIC).unwrap();
        buf.write_u8(NODES_EMBER_VERSION_WITHOUT_MISSES).unwrap();
        buf.write_u16::<LittleEndian>(contacts.len() as u16).unwrap();
        for entry in &contacts {
            let c = &entry.contact;
            buf.write_all(&c.node_id.0).unwrap();
            buf.write_u8(4).unwrap();
            let std::net::IpAddr::V4(ip) = c.addr.ip() else {
                unreachable!()
            };
            buf.write_all(&ip.octets()).unwrap();
            buf.write_u16::<byteorder::BigEndian>(c.addr.port()).unwrap();
            buf.write_all(&c.noise_pub).unwrap();
            buf.write_all(&c.ed25519_pub).unwrap();
            buf.write_i64::<LittleEndian>(c.last_seen).unwrap();
        }
        std::fs::write(&path, &buf).unwrap();

        let loaded = load_nodes(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].contact.node_id, contacts[0].contact.node_id);
        assert_eq!(loaded[1].contact.addr, contacts[1].contact.addr);
        assert!(loaded.iter().all(|c| c.misses == 0));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The header count is a `u16` and the save path never writes more than
    /// `EMBER_PERSIST_MAX_CONTACTS`, so anything above that is a corrupt or
    /// hand-edited file asking the startup path for up to 65,535 key
    /// decompressions and `add_contact` calls.
    #[test]
    fn a_file_declaring_more_contacts_than_we_write_is_capped() {
        let dir = std::env::temp_dir().join("ember_test_nodes_overlong");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember.dat");

        // Distinct real keypairs: the loader re-derives each id from its key,
        // and duplicates would be indistinguishable from a shorter file.
        let overlong: Vec<CachedContact> = (0..(MAX_PERSISTED_CONTACTS as u16 + 5))
            .map(|i| {
                let mut seed = [0u8; 32];
                seed[..2].copy_from_slice(&i.to_le_bytes());
                let vk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
                CachedContact::new(EmberContact {
                    node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(
                        &vk,
                    )),
                    addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(80, 1, 2, 3)), 4662 + i),
                    noise_pub: [1u8; 32],
                    ed25519_pub: vk.to_bytes(),
                    last_seen: 1000,
                    failed_queries: 0,
                })
            })
            .collect();
        save_nodes(&path, &overlong, true).unwrap();

        let loaded = load_nodes(&path).unwrap();
        assert_eq!(
            loaded.len(),
            MAX_PERSISTED_CONTACTS,
            "the loader must stop at the ceiling the save path writes under"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_load_with_ipv6() {
        let dir = std::env::temp_dir().join("ember_test_nodes_v6");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("nodes_ember_v6.dat");

        let sk = ed25519_dalek::SigningKey::from_bytes(&[0xCC; 32]);
        let vk = sk.verifying_key();
        let contacts = vec![CachedContact::new(EmberContact {
            node_id: EmberNodeId(crate::network::ember::crypto::node_id_from_public_key(&vk)),
            addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999,
            ),
            noise_pub: [0xBB; 32],
            ed25519_pub: vk.to_bytes(),
            last_seen: 42,
            failed_queries: 0,
        })];
        save_nodes(&path, &contacts, true).unwrap();
        let loaded = load_nodes(&path).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].contact.node_id, contacts[0].contact.node_id);
        assert_eq!(
            loaded[0].contact.addr,
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                9999
            )
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
