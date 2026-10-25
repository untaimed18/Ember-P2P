//! Feeds: the ones this identity publishes, with their items, and the ones it
//! follows, with the items of the list it holds. See `network::ember::feed`.
//!
//! Everything here is public by design — a feed is published under its
//! publisher's identity, and its list is served to anyone — so none of it is
//! sealed with the chat key.

use super::*;

/// Items a publisher removed that a follower keeps showing, per feed.
const REMOVED_ITEMS_KEPT: i64 = 2_000;

/// The window auto-download's per-day cap counts over, in seconds: the last
/// 24 hours, not the calendar day, so a cap is not spent twice across
/// midnight.
pub const FEED_AUTO_WINDOW_SECS: i64 = 24 * 3600;

/// Auto-download's caps for a feed just followed, in MiB, matching the
/// column defaults of `feeds_followed`.
const FEED_AUTO_DEFAULT_ITEM_MIB: i64 = 1024;
const FEED_AUTO_DEFAULT_DAY_MIB: i64 = 4096;

/// `feeds_followed_items.downloaded` for an item whose download the user
/// cancelled from the feed: still nonzero, so it reads as asked for.
const DOWNLOAD_CANCELLED: i64 = 2;

/// A feed this identity publishes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OwnFeed {
    /// The feed's salt, lowercase hex.
    pub salt: String,
    pub title: String,
    pub description: String,
    /// The sequence of the last head published; 0 before the first.
    pub sequence: i64,
    /// The list that head names: eD2K hash, BLAKE3 and size; empty before
    /// the first publish.
    pub list_ed2k: String,
    pub list_blake3: String,
    pub list_size: i64,
    pub item_count: i64,
    pub created_at: i64,
    /// When the user last published it.
    pub published_at: i64,
    /// When the service last signed and sent its head again; 0 if not since
    /// it was published.
    #[serde(skip)]
    pub refreshed_at: i64,
    /// The title and description the last head carried, which a republish
    /// signs again: an edit not yet published stays unpublished.
    #[serde(skip)]
    pub published_title: String,
    #[serde(skip)]
    pub published_description: String,
    /// Details or items edited since the last publish.
    pub changed: bool,
    /// A head newer than the last, whose publish ended without knowing
    /// whether any node stored it. Its list is served all the same, as
    /// storers may hold the head; at most one per feed.
    #[serde(skip)]
    pub pending: Option<OwnPublish>,
    /// Listed in the public feed index, for anyone to find in Discover, as
    /// well as by its link.
    pub listed: bool,
    /// The stamp of the last listing of it sent, not a withdrawal; 0 if none
    /// ever was. Once it is taken out, its withdrawal is sent until that
    /// listing has lapsed, and never for a feed no listing named.
    #[serde(skip)]
    pub listing_sent_at: i64,
}

/// A listing or withdrawal of a feed of ours to sign and send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueListing {
    pub salt: String,
    pub withdrawn: bool,
    /// Its timestamp: past every one sent for the feed before, so it
    /// outranks them.
    pub stamp: i64,
}

/// A public feed the index listed, as Discover last found it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DiscoveredFeed {
    pub publisher: String,
    pub salt: String,
    pub title: String,
    pub description: String,
    pub item_count: i64,
    pub list_size: i64,
    /// The head's sequence: the publisher's clock, in milliseconds, at its
    /// last publish.
    pub sequence: i64,
    /// When the publisher last signed its listing, which it does with every
    /// publish and daily while it runs.
    pub listed_at: i64,
    /// When this side first found it in the index.
    pub first_seen: i64,
}

/// One file in a feed, published or followed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeedItem {
    pub ed2k: String,
    pub name: String,
    pub size: i64,
    #[serde(default)]
    pub aich: String,
    pub blake3: String,
    #[serde(default)]
    pub note: String,
}

/// A feed this identity follows.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FollowedFeed {
    pub publisher: String,
    pub salt: String,
    pub title: String,
    pub description: String,
    /// The highest sequence accepted; a head with a lower one is ignored.
    pub sequence: i64,
    pub list_ed2k: String,
    pub list_blake3: String,
    pub list_size: i64,
    pub item_count: i64,
    /// `"waiting"` (no list yet), `"ok"`, `"fetching"` (a newer list on its
    /// way) or `"broken"` (the list did not match its head, or did not parse).
    pub state: String,
    /// The sequence of the list held, which may trail `sequence` while a
    /// newer one is fetched.
    pub list_sequence: i64,
    /// The list held, which `list_*` stops naming once a newer head is
    /// taken up: what is served to other followers meanwhile.
    pub held_ed2k: String,
    pub held_blake3: String,
    pub held_size: i64,
    pub unread: i64,
    pub followed_at: i64,
    pub checked_at: i64,
    pub auto_download: bool,
    /// Per item, in MiB; 0 for no cap. [`FEED_AUTO_DEFAULT_ITEM_MIB`] for
    /// a new follow.
    pub auto_max_item_mib: i64,
    /// Per [`FEED_AUTO_WINDOW_SECS`], in MiB; 0 for no cap.
    /// [`FEED_AUTO_DEFAULT_DAY_MIB`] for a new follow.
    pub auto_max_day_mib: i64,
    pub auto_category: String,
    /// The folder in `Feeds` its files finish in, fixed by the first one
    /// downloaded; empty before.
    pub folder: String,
    /// When auto-download was last turned on: it takes the files first seen
    /// since. 0 when it was turned on before this was kept.
    pub auto_since: i64,
    /// When a head of the feed was last found, newer or not: by a lookup or
    /// pushed by a friend. 0 before the first.
    pub seen_at: i64,
}

/// An item of a followed feed's list, with what this side knows of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FollowedItem {
    #[serde(flatten)]
    pub item: FeedItem,
    /// When this side first saw it in the feed.
    pub first_seen: i64,
    /// Not read yet.
    pub is_new: bool,
    /// Dropped from the list by the publisher; kept here, and shown so.
    pub removed: bool,
    /// Started here, by hand or by auto-download.
    pub downloaded: bool,
    /// Its download was cancelled from the feed since. Still `downloaded`, so
    /// auto-download does not start it again.
    pub cancelled: bool,
}

/// A file another followed feed downloaded, as
/// [`Database::feed_downloaded_elsewhere`] finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElsewhereCopy {
    pub ed2k: String,
    pub folder: String,
    pub title: String,
    pub name: String,
    pub size: i64,
}

/// A head just published, as [`Database::feed_own_published`] records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnPublish {
    pub sequence: i64,
    pub list_ed2k: String,
    pub list_blake3: String,
    pub list_size: i64,
    pub item_count: i64,
    pub title: String,
    pub description: String,
}

/// What taking up a new list changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListUpdate {
    pub added: Vec<FeedItem>,
    pub removed: usize,
}

impl Database {
    fn ensure_feeds_locked(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS feeds_own (
                salt TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                sequence INTEGER NOT NULL DEFAULT 0,
                list_ed2k TEXT NOT NULL DEFAULT '',
                list_blake3 TEXT NOT NULL DEFAULT '',
                list_size INTEGER NOT NULL DEFAULT 0,
                item_count INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                published_at INTEGER NOT NULL DEFAULT 0,
                published_title TEXT NOT NULL DEFAULT '',
                published_description TEXT NOT NULL DEFAULT '',
                changed INTEGER NOT NULL DEFAULT 0,
                pending_sequence INTEGER NOT NULL DEFAULT 0,
                pending_ed2k TEXT NOT NULL DEFAULT '',
                pending_blake3 TEXT NOT NULL DEFAULT '',
                pending_size INTEGER NOT NULL DEFAULT 0,
                pending_item_count INTEGER NOT NULL DEFAULT 0,
                pending_title TEXT NOT NULL DEFAULT '',
                pending_description TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS feeds_own_items (
                salt TEXT NOT NULL,
                position INTEGER NOT NULL,
                ed2k TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                aich TEXT NOT NULL DEFAULT '',
                blake3 TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (salt, ed2k)
            );
            CREATE TABLE IF NOT EXISTS feeds_followed (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                sequence INTEGER NOT NULL DEFAULT 0,
                list_ed2k TEXT NOT NULL DEFAULT '',
                list_blake3 TEXT NOT NULL DEFAULT '',
                list_size INTEGER NOT NULL DEFAULT 0,
                item_count INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'waiting',
                list_sequence INTEGER NOT NULL DEFAULT 0,
                held_ed2k TEXT NOT NULL DEFAULT '',
                held_blake3 TEXT NOT NULL DEFAULT '',
                held_size INTEGER NOT NULL DEFAULT 0,
                unread INTEGER NOT NULL DEFAULT 0,
                followed_at INTEGER NOT NULL,
                checked_at INTEGER NOT NULL DEFAULT 0,
                auto_download INTEGER NOT NULL DEFAULT 0,
                auto_max_item_mib INTEGER NOT NULL DEFAULT 1024,
                auto_max_day_mib INTEGER NOT NULL DEFAULT 4096,
                auto_category TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (publisher, salt)
            );
            CREATE TABLE IF NOT EXISTS feeds_followed_items (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                ed2k TEXT NOT NULL,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                aich TEXT NOT NULL DEFAULT '',
                blake3 TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                first_seen INTEGER NOT NULL,
                is_new INTEGER NOT NULL DEFAULT 1,
                removed INTEGER NOT NULL DEFAULT 0,
                downloaded INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (publisher, salt, ed2k)
            );
            CREATE TABLE IF NOT EXISTS feeds_auto_started (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                at INTEGER NOT NULL,
                bytes INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS feeds_auto_started_feed ON feeds_auto_started (publisher, salt, at);
            CREATE TABLE IF NOT EXISTS feeds_discovered (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                item_count INTEGER NOT NULL DEFAULT 0,
                list_size INTEGER NOT NULL DEFAULT 0,
                sequence INTEGER NOT NULL DEFAULT 0,
                listed_at INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL,
                PRIMARY KEY (publisher, salt)
            );
            -- Deleted feeds of ours whose last listing may still be live: their
            -- withdrawal is sent daily until it lapses.
            CREATE TABLE IF NOT EXISTS feeds_own_withdrawn (
                salt TEXT PRIMARY KEY,
                listing_sent_at INTEGER NOT NULL,
                listing_stamp INTEGER NOT NULL,
                sent_at INTEGER NOT NULL DEFAULT 0
            );
            -- Feeds and publishers the user hid from Discover; an empty salt
            -- hides every feed of the publisher.
            CREATE TABLE IF NOT EXISTS feeds_hidden (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                PRIMARY KEY (publisher, salt)
            );
            -- Per-day counts a development build kept before the rolling window.
            DROP TABLE IF EXISTS feeds_auto_bytes;",
        )?;
        // A table made by a development build before these columns. Each is
        // checked on its own, so one added before a crash is not added twice.
        for (table, column, kind) in [
            ("feeds_own", "published_title", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "published_description", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "changed", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "pending_sequence", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "pending_ed2k", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "pending_blake3", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "pending_size", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "pending_item_count", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "pending_title", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "pending_description", "TEXT NOT NULL DEFAULT ''"),
            ("feeds_own", "listed", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "listing_sent_at", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "listing_stamp", "INTEGER NOT NULL DEFAULT 0"),
            ("feeds_own", "refreshed_at", "INTEGER NOT NULL DEFAULT 0"),
            // The folder in `Feeds` its files finish in; empty until the first.
            ("feeds_followed", "folder", "TEXT NOT NULL DEFAULT ''"),
            // When auto-download was last turned on; 0 if not since this column.
            ("feeds_followed", "auto_since", "INTEGER NOT NULL DEFAULT 0"),
            // When a head was last found.
            ("feeds_followed", "seen_at", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let present: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info(?1) WHERE name = ?2",
                params![table, column],
                |row| row.get(0),
            )?;
            if !present {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {kind};"))?;
                // Feeds followed before it was kept count as seen now: one
                // already gone says so once it has been missed long enough,
                // not on the first start after the update.
                if column == "seen_at" {
                    conn.execute(
                        "UPDATE feeds_followed SET seen_at = ?1 WHERE list_sequence != 0",
                        params![chrono::Utc::now().timestamp()],
                    )?;
                }
            }
        }
        Ok(())
    }

    // ── Publishing ──────────────────────────────────────────────────────

    pub fn feeds_own(&self) -> anyhow::Result<Vec<OwnFeed>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT salt, title, description, sequence, list_ed2k, list_blake3, list_size, item_count,
                    created_at, published_at, published_title, published_description, changed,
                    pending_sequence, pending_ed2k, pending_blake3, pending_size, pending_item_count,
                    pending_title, pending_description, listed, listing_sent_at, refreshed_at
             FROM feeds_own ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let pending_sequence: i64 = row.get(13)?;
                let pending = if pending_sequence > 0 {
                    Some(OwnPublish {
                        sequence: pending_sequence,
                        list_ed2k: row.get(14)?,
                        list_blake3: row.get(15)?,
                        list_size: row.get(16)?,
                        item_count: row.get(17)?,
                        title: row.get(18)?,
                        description: row.get(19)?,
                    })
                } else {
                    None
                };
                Ok(OwnFeed {
                    salt: row.get(0)?,
                    title: row.get(1)?,
                    description: row.get(2)?,
                    sequence: row.get(3)?,
                    list_ed2k: row.get(4)?,
                    list_blake3: row.get(5)?,
                    list_size: row.get(6)?,
                    item_count: row.get(7)?,
                    created_at: row.get(8)?,
                    published_at: row.get(9)?,
                    published_title: row.get(10)?,
                    published_description: row.get(11)?,
                    changed: row.get::<_, i64>(12)? != 0,
                    pending,
                    listed: row.get::<_, i64>(20)? != 0,
                    listing_sent_at: row.get(21)?,
                    refreshed_at: row.get(22)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn feed_own(&self, salt: &str) -> anyhow::Result<Option<OwnFeed>> {
        Ok(self.feeds_own()?.into_iter().find(|feed| feed.salt == salt))
    }

    /// Start a feed. `false` when the identity already has as many as it may.
    pub fn feed_own_create(
        &self,
        salt: &str,
        title: &str,
        description: &str,
        listed: bool,
        now: i64,
        max: usize,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM feeds_own", [], |row| row.get(0))?;
        if count as usize >= max {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO feeds_own (salt, title, description, created_at, listed) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![salt, title, description, now, listed],
        )?;
        Ok(true)
    }

    pub fn feed_own_set_details(&self, salt: &str, title: &str, description: &str) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE feeds_own SET title = ?2, description = ?3,
                    changed = changed OR title != ?2 OR description != ?3
             WHERE salt = ?1",
            params![salt, title, description],
        )? > 0)
    }

    /// A feed's items, in the publisher's order.
    pub fn feed_own_items(&self, salt: &str) -> anyhow::Result<Vec<FeedItem>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Self::feed_own_items_locked(&conn, salt)
    }

    fn feed_own_items_locked(conn: &Connection, salt: &str) -> anyhow::Result<Vec<FeedItem>> {
        let mut stmt = conn.prepare(
            "SELECT ed2k, name, size, aich, blake3, note FROM feeds_own_items
             WHERE salt = ?1 ORDER BY position",
        )?;
        let rows = stmt
            .query_map(params![salt], |row| {
                Ok(FeedItem {
                    ed2k: row.get(0)?,
                    name: row.get(1)?,
                    size: row.get(2)?,
                    aich: row.get(3)?,
                    blake3: row.get(4)?,
                    note: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Replace a feed's items with `items`, in that order. `false` when
    /// there is no such feed. The feed counts as changed only when the items
    /// differ from those held, in order or in any field: saving the same
    /// list again leaves an up-to-date feed up to date.
    pub fn feed_own_set_items(&self, salt: &str, items: &[FeedItem]) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let found: bool =
            tx.query_row("SELECT COUNT(*) > 0 FROM feeds_own WHERE salt = ?1", params![salt], |row| row.get(0))?;
        if !found {
            return Ok(false);
        }
        if Self::feed_own_items_locked(&tx, salt)? == items {
            return Ok(true);
        }
        tx.execute("UPDATE feeds_own SET changed = 1 WHERE salt = ?1", params![salt])?;
        tx.execute("DELETE FROM feeds_own_items WHERE salt = ?1", params![salt])?;
        {
            let mut insert = tx.prepare(
                "INSERT OR IGNORE INTO feeds_own_items (salt, position, ed2k, name, size, aich, blake3, note)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for (position, item) in items.iter().enumerate() {
                insert.execute(params![
                    salt,
                    position as i64,
                    item.ed2k,
                    item.name,
                    item.size,
                    item.aich,
                    item.blake3,
                    item.note
                ])?;
            }
        }
        tx.commit()?;
        Ok(true)
    }

    /// Record a head published for `salt`: its list, and the title and
    /// description it carried, in place of any pending head. `items` are
    /// those its list was made from, compared with the items held now so an
    /// edit saved while the head was out still counts as unpublished; `None`
    /// when they are not known, and the feed counts as changed. `false`,
    /// changing nothing, when a later sequence is recorded already.
    pub fn feed_own_published(
        &self,
        salt: &str,
        published: &OwnPublish,
        items: Option<&[FeedItem]>,
        now: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let items_changed = match items {
            Some(items) => Self::feed_own_items_locked(&tx, salt)? != items,
            None => true,
        };
        let recorded = tx.execute(
            "UPDATE feeds_own SET sequence = ?2, list_ed2k = ?3, list_blake3 = ?4, list_size = ?5,
                    item_count = ?6, published_at = ?7, published_title = ?8, published_description = ?9,
                    changed = (title != ?8 OR description != ?9 OR ?10),
                    pending_sequence = 0, pending_ed2k = '', pending_blake3 = '', pending_size = 0,
                    pending_item_count = 0, pending_title = '', pending_description = ''
             WHERE salt = ?1 AND sequence < ?2",
            params![
                salt,
                published.sequence,
                published.list_ed2k,
                published.list_blake3,
                published.list_size,
                published.item_count,
                now,
                published.title,
                published.description,
                items_changed,
            ],
        )? > 0;
        tx.commit()?;
        Ok(recorded)
    }

    /// Keep `pending` as `salt`'s pending head, in place of any before it,
    /// or with `None` forget the one kept. `false`, changing nothing, when
    /// `pending` is no newer than the head published.
    pub fn feed_own_set_pending(&self, salt: &str, pending: Option<&OwnPublish>) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let changed = match pending {
            Some(pending) => conn.execute(
                "UPDATE feeds_own SET pending_sequence = ?2, pending_ed2k = ?3, pending_blake3 = ?4,
                        pending_size = ?5, pending_item_count = ?6, pending_title = ?7, pending_description = ?8
                 WHERE salt = ?1 AND sequence < ?2",
                params![
                    salt,
                    pending.sequence,
                    pending.list_ed2k,
                    pending.list_blake3,
                    pending.list_size,
                    pending.item_count,
                    pending.title,
                    pending.description,
                ],
            )?,
            None => conn.execute(
                "UPDATE feeds_own SET pending_sequence = 0, pending_ed2k = '', pending_blake3 = '', pending_size = 0,
                        pending_item_count = 0, pending_title = '', pending_description = ''
                 WHERE salt = ?1",
                params![salt],
            )?,
        };
        Ok(changed > 0)
    }

    /// Record that head `sequence` of `salt` was signed and sent again. When
    /// the user last published stays as it was.
    pub fn feed_own_republished(&self, salt: &str, sequence: i64, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_own SET refreshed_at = ?3 WHERE salt = ?1 AND sequence = ?2",
            params![salt, sequence, now],
        )?;
        Ok(())
    }

    /// The list the last head names is gone and its items no longer make
    /// it: the feed needs publishing again.
    pub fn feed_own_mark_changed(&self, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute("UPDATE feeds_own SET changed = 1 WHERE salt = ?1", params![salt])?;
        Ok(())
    }

    /// Delete a feed of ours. One whose last listing, sent at most
    /// `listing_ttl` seconds before `now`, may still be live is kept as a
    /// withdrawal to send (see [`Self::feed_withdrawals_due`]).
    pub fn feed_own_delete(&self, salt: &str, now: i64, listing_ttl: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR REPLACE INTO feeds_own_withdrawn (salt, listing_sent_at, listing_stamp, sent_at)
             SELECT salt, listing_sent_at, listing_stamp, 0 FROM feeds_own
             WHERE salt = ?1 AND listing_sent_at > 0 AND listing_sent_at >= ?2",
            params![salt, now - listing_ttl],
        )?;
        tx.execute("DELETE FROM feeds_own_items WHERE salt = ?1", params![salt])?;
        tx.execute("DELETE FROM feeds_own WHERE salt = ?1", params![salt])?;
        tx.commit()?;
        Ok(())
    }

    /// List a feed of ours in the public index, or take it out. `false` when
    /// there is no such feed.
    pub fn feed_own_set_listed(&self, salt: &str, listed: bool) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute("UPDATE feeds_own SET listed = ?2 WHERE salt = ?1", params![salt, listed])? > 0)
    }

    /// What to send of feed `salt` in the public index at `now`, stamped and
    /// recorded as sent in one step, so a listing and a withdrawal decided
    /// apart can never be stamped out of order: its listing while it is
    /// listed and `published`, or its withdrawal while one it was listed
    /// under, sent at most `listing_ttl` seconds before, may be live.
    /// `None` when there is nothing to send.
    pub fn feed_own_take_listing(
        &self,
        salt: &str,
        published: bool,
        now: i64,
        listing_ttl: i64,
    ) -> anyhow::Result<Option<DueListing>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let row: Option<(bool, i64, i64)> = conn
            .query_row(
                "SELECT listed, listing_sent_at, listing_stamp FROM feeds_own WHERE salt = ?1",
                params![salt],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((listed, sent_at, last_stamp)) = row else {
            return Ok(None);
        };
        let withdrawn = match (listed, published) {
            (true, true) => false,
            (false, _) if sent_at > 0 && now - sent_at <= listing_ttl => true,
            _ => return Ok(None),
        };
        let stamp = now.max(last_stamp.saturating_add(1));
        conn.execute(
            "UPDATE feeds_own SET listing_stamp = ?2,
                    listing_sent_at = CASE WHEN ?3 THEN listing_sent_at ELSE ?2 END
             WHERE salt = ?1",
            params![salt, stamp, withdrawn],
        )?;
        Ok(Some(DueListing { salt: salt.to_string(), withdrawn, stamp }))
    }

    /// The withdrawals of deleted feeds due at `now`, stamped and recorded as
    /// sent: each is sent at once, then every `interval` seconds, until the
    /// listing it displaces has lapsed, `listing_ttl` after it was sent.
    pub fn feed_withdrawals_due(&self, now: i64, interval: i64, listing_ttl: i64) -> anyhow::Result<Vec<DueListing>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM feeds_own_withdrawn WHERE listing_sent_at < ?1", params![now - listing_ttl])?;
        let due: Vec<(String, i64)> = {
            let mut stmt = tx.prepare(
                "SELECT salt, listing_stamp FROM feeds_own_withdrawn WHERE sent_at = 0 OR sent_at <= ?1",
            )?;
            let rows = stmt
                .query_map(params![now - interval], |row| Ok((row.get(0)?, row.get(1)?)))?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut out = Vec::with_capacity(due.len());
        for (salt, last_stamp) in due {
            let stamp = now.max(last_stamp.saturating_add(1));
            tx.execute(
                "UPDATE feeds_own_withdrawn SET listing_stamp = ?2, sent_at = ?3 WHERE salt = ?1",
                params![salt, stamp, now],
            )?;
            out.push(DueListing { salt, withdrawn: true, stamp });
        }
        tx.commit()?;
        Ok(out)
    }

    // ── Following ───────────────────────────────────────────────────────

    /// Follow a feed, with auto-download off and its default caps. `false`
    /// when it is followed already. The caps are written out because a
    /// table made by a development build has column defaults of 0.
    pub fn feed_follow(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "INSERT OR IGNORE INTO feeds_followed (publisher, salt, followed_at, auto_max_item_mib, auto_max_day_mib)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![publisher, salt, now, FEED_AUTO_DEFAULT_ITEM_MIB, FEED_AUTO_DEFAULT_DAY_MIB],
        )? > 0)
    }

    pub fn feeds_followed(&self) -> anyhow::Result<Vec<FollowedFeed>> {
        self.feeds_followed_where(None)
    }

    pub fn feed_followed(&self, publisher: &str, salt: &str) -> anyhow::Result<Option<FollowedFeed>> {
        Ok(self.feeds_followed_where(Some((publisher, salt)))?.into_iter().next())
    }

    fn feeds_followed_where(&self, key: Option<(&str, &str)>) -> anyhow::Result<Vec<FollowedFeed>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let select = "SELECT publisher, salt, title, description, sequence, list_ed2k, list_blake3, list_size,
                    item_count, state, list_sequence, unread, followed_at, checked_at, auto_download,
                    auto_max_item_mib, auto_max_day_mib, auto_category, held_ed2k, held_blake3, held_size, folder,
                    auto_since, seen_at
             FROM feeds_followed";
        let map = |row: &rusqlite::Row<'_>| {
            Ok(FollowedFeed {
                publisher: row.get(0)?,
                salt: row.get(1)?,
                title: row.get(2)?,
                description: row.get(3)?,
                sequence: row.get(4)?,
                list_ed2k: row.get(5)?,
                list_blake3: row.get(6)?,
                list_size: row.get(7)?,
                item_count: row.get(8)?,
                state: row.get(9)?,
                list_sequence: row.get(10)?,
                unread: row.get(11)?,
                followed_at: row.get(12)?,
                checked_at: row.get(13)?,
                auto_download: row.get::<_, i64>(14)? != 0,
                auto_max_item_mib: row.get(15)?,
                auto_max_day_mib: row.get(16)?,
                auto_category: row.get(17)?,
                held_ed2k: row.get(18)?,
                held_blake3: row.get(19)?,
                held_size: row.get(20)?,
                folder: row.get(21)?,
                auto_since: row.get(22)?,
                seen_at: row.get(23)?,
            })
        };
        let rows = match key {
            Some((publisher, salt)) => {
                let mut stmt = conn.prepare(&format!("{select} WHERE publisher = ?1 AND salt = ?2"))?;
                let rows = stmt.query_map(params![publisher, salt], map)?.collect::<Result<Vec<_>, _>>()?;
                rows
            }
            None => {
                let mut stmt = conn.prepare(&format!("{select} ORDER BY followed_at"))?;
                let rows = stmt.query_map([], map)?.collect::<Result<Vec<_>, _>>()?;
                rows
            }
        };
        Ok(rows)
    }

    /// Take up a head newer than the one held. Returns whether it was
    /// newer: an older or equal sequence changes nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn feed_take_head(
        &self,
        publisher: &str,
        salt: &str,
        sequence: i64,
        title: &str,
        description: &str,
        list_ed2k: &str,
        list_blake3: &str,
        list_size: i64,
        item_count: i64,
        now: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE feeds_followed SET sequence = ?3, title = ?4, description = ?5, list_ed2k = ?6,
                    list_blake3 = ?7, list_size = ?8, item_count = ?9, checked_at = ?10,
                    state = CASE WHEN list_sequence = 0 THEN 'waiting' ELSE 'fetching' END
             WHERE publisher = ?1 AND salt = ?2 AND sequence < ?3",
            params![publisher, salt, sequence, title, description, list_ed2k, list_blake3, list_size, item_count, now],
        )? > 0)
    }

    /// Note that a head of the feed was found, newer or not.
    pub fn feed_seen(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed SET seen_at = MAX(seen_at, ?3) WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, now],
        )?;
        Ok(())
    }

    /// Note a look for the head that found nothing newer.
    pub fn feed_checked(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed SET checked_at = ?3 WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, now],
        )?;
        Ok(())
    }

    /// The list held is gone from disk: fetch the current one again. Its
    /// items stay, so what the new one adds is still news.
    pub fn feed_lost_held(&self, publisher: &str, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed SET list_sequence = -1, held_ed2k = '', held_blake3 = '', held_size = 0,
                    state = 'fetching'
             WHERE publisher = ?1 AND salt = ?2 AND list_sequence > 0",
            params![publisher, salt],
        )?;
        Ok(())
    }

    /// Take a broken list as owed again, for the user to have it fetched once
    /// more. The sequence whose list was broken, or `None` if none was.
    pub fn feed_clear_broken(&self, publisher: &str, salt: &str) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let sequence: Option<i64> = conn
            .query_row(
                "SELECT sequence FROM feeds_followed WHERE publisher = ?1 AND salt = ?2 AND state = 'broken'",
                params![publisher, salt],
                |row| row.get(0),
            )
            .optional()?;
        if sequence.is_some() {
            conn.execute(
                "UPDATE feeds_followed SET state = CASE WHEN list_sequence = 0 THEN 'waiting' ELSE 'fetching' END
                 WHERE publisher = ?1 AND salt = ?2 AND state = 'broken'",
                params![publisher, salt],
            )?;
        }
        Ok(sequence)
    }

    /// The list for `sequence` did not match its head, or did not parse.
    pub fn feed_mark_broken(&self, publisher: &str, salt: &str, sequence: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed SET state = 'broken' WHERE publisher = ?1 AND salt = ?2 AND sequence = ?3",
            params![publisher, salt, sequence],
        )?;
        Ok(())
    }

    /// Take up the list of head `sequence`: items new to this side are added
    /// as new, items gone from it are marked removed (and kept), and the
    /// feed counts what is unread. Nothing when a newer head has been taken
    /// up meanwhile.
    pub fn feed_take_list(
        &self,
        publisher: &str,
        salt: &str,
        sequence: i64,
        items: &[FeedItem],
        now: i64,
    ) -> anyhow::Result<Option<ListUpdate>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let current: Option<i64> = tx
            .query_row(
                "SELECT sequence FROM feeds_followed WHERE publisher = ?1 AND salt = ?2",
                params![publisher, salt],
                |row| row.get(0),
            )
            .optional()?;
        if current != Some(sequence) {
            return Ok(None);
        }
        // The first list of a feed just followed: nothing in it is news.
        let first: bool = tx.query_row(
            "SELECT list_sequence = 0 FROM feeds_followed WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt],
            |row| row.get(0),
        )?;
        // Auto-download turned on before it came takes none of it either.
        if first {
            tx.execute(
                "UPDATE feeds_followed SET auto_since = MAX(auto_since, ?3)
                 WHERE publisher = ?1 AND salt = ?2 AND auto_since > 0",
                params![publisher, salt, now.saturating_add(1)],
            )?;
        }
        // Each item held, and whether the publisher had removed it.
        let held: std::collections::HashMap<String, bool> = {
            let mut stmt =
                tx.prepare("SELECT ed2k, removed FROM feeds_followed_items WHERE publisher = ?1 AND salt = ?2")?;
            let rows = stmt
                .query_map(params![publisher, salt], |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)))?
                .collect::<Result<_, _>>()?;
            rows
        };
        let mut update = ListUpdate::default();
        let listed: std::collections::HashSet<&str> = items.iter().map(|item| item.ed2k.as_str()).collect();
        for item in items {
            if let Some(&was_removed) = held.get(&item.ed2k) {
                // Listed again after a removal: news again.
                let back = was_removed && !first;
                tx.execute(
                    "UPDATE feeds_followed_items SET name = ?4, size = ?5, aich = ?6, blake3 = ?7, note = ?8,
                            removed = 0, is_new = is_new OR ?9, first_seen = CASE WHEN ?9 THEN ?10 ELSE first_seen END
                     WHERE publisher = ?1 AND salt = ?2 AND ed2k = ?3",
                    params![publisher, salt, item.ed2k, item.name, item.size, item.aich, item.blake3, item.note, back, now],
                )?;
                if back {
                    update.added.push(item.clone());
                }
            } else {
                tx.execute(
                    "INSERT INTO feeds_followed_items
                        (publisher, salt, ed2k, name, size, aich, blake3, note, first_seen, is_new)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                    params![
                        publisher,
                        salt,
                        item.ed2k,
                        item.name,
                        item.size,
                        item.aich,
                        item.blake3,
                        item.note,
                        now,
                        !first
                    ],
                )?;
                if !first {
                    update.added.push(item.clone());
                }
            }
        }
        for gone in held.keys().filter(|ed2k| !listed.contains(ed2k.as_str())) {
            update.removed += tx.execute(
                "UPDATE feeds_followed_items SET removed = 1, is_new = 0
                 WHERE publisher = ?1 AND salt = ?2 AND ed2k = ?3 AND removed = 0",
                params![publisher, salt, gone],
            )?;
        }
        // Removed items are kept to show, but no more than a list's worth: a
        // publisher replacing its list on every publish would grow this
        // without end.
        tx.execute(
            "DELETE FROM feeds_followed_items
             WHERE publisher = ?1 AND salt = ?2 AND removed = 1 AND rowid NOT IN (
                 SELECT rowid FROM feeds_followed_items
                 WHERE publisher = ?1 AND salt = ?2 AND removed = 1
                 ORDER BY first_seen DESC, rowid DESC LIMIT ?3)",
            params![publisher, salt, REMOVED_ITEMS_KEPT],
        )?;
        tx.execute(
            "UPDATE feeds_followed SET state = 'ok', list_sequence = ?3,
                    held_ed2k = list_ed2k, held_blake3 = list_blake3, held_size = list_size,
                    unread = (SELECT COUNT(*) FROM feeds_followed_items
                              WHERE publisher = ?1 AND salt = ?2 AND is_new = 1)
             WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, sequence],
        )?;
        tx.commit()?;
        Ok(Some(update))
    }

    /// A followed feed's items: newest first, removed ones last.
    pub fn feed_followed_items(&self, publisher: &str, salt: &str) -> anyhow::Result<Vec<FollowedItem>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let mut stmt = conn.prepare(
            // Newest first, and each list's new files in the order the
            // publisher put them.
            "SELECT ed2k, name, size, aich, blake3, note, first_seen, is_new, removed, downloaded
             FROM feeds_followed_items WHERE publisher = ?1 AND salt = ?2
             ORDER BY removed, first_seen DESC, rowid ASC",
        )?;
        let rows = stmt
            .query_map(params![publisher, salt], |row| {
                Ok(FollowedItem {
                    item: FeedItem {
                        ed2k: row.get(0)?,
                        name: row.get(1)?,
                        size: row.get(2)?,
                        aich: row.get(3)?,
                        blake3: row.get(4)?,
                        note: row.get(5)?,
                    },
                    first_seen: row.get(6)?,
                    is_new: row.get::<_, i64>(7)? != 0,
                    removed: row.get::<_, i64>(8)? != 0,
                    downloaded: row.get::<_, i64>(9)? != 0,
                    cancelled: row.get::<_, i64>(9)? == DOWNLOAD_CANCELLED,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn feed_mark_read(&self, publisher: &str, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "UPDATE feeds_followed_items SET is_new = 0 WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt],
        )?;
        tx.execute(
            "UPDATE feeds_followed SET unread = 0 WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn feed_mark_downloaded(&self, publisher: &str, salt: &str, ed2k: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed_items SET downloaded = 1
             WHERE publisher = ?1 AND salt = ?2 AND ed2k = ?3",
            params![publisher, salt, ed2k],
        )?;
        Ok(())
    }

    /// What other followed feeds downloaded, to find copies a feed already
    /// has elsewhere: each file's eD2K hash, the folder in `Feeds` it went to,
    /// that feed's title, and the file's name and size there.
    pub fn feed_downloaded_elsewhere(&self, publisher: &str, salt: &str) -> anyhow::Result<Vec<ElsewhereCopy>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let mut stmt = conn.prepare(
            "SELECT i.ed2k, f.folder, f.title, i.name, i.size
             FROM feeds_followed_items i
             JOIN feeds_followed f ON f.publisher = i.publisher AND f.salt = i.salt
             WHERE i.downloaded = 1 AND f.folder != '' AND NOT (i.publisher = ?1 AND i.salt = ?2)",
        )?;
        let rows = stmt
            .query_map(params![publisher, salt], |row| {
                Ok(ElsewhereCopy {
                    ed2k: row.get(0)?,
                    folder: row.get(1)?,
                    title: row.get(2)?,
                    name: row.get(3)?,
                    size: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Record that the user cancelled an item's download from the feed.
    pub fn feed_mark_cancelled(&self, publisher: &str, salt: &str, ed2k: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed_items SET downloaded = ?4
             WHERE publisher = ?1 AND salt = ?2 AND ed2k = ?3",
            params![publisher, salt, ed2k, DOWNLOAD_CANCELLED],
        )?;
        Ok(())
    }

    /// Set a followed feed's auto-download. Turned on from off at `now`, it
    /// takes the files first seen from then.
    #[allow(clippy::too_many_arguments)]
    pub fn feed_set_auto_download(
        &self,
        publisher: &str,
        salt: &str,
        enabled: bool,
        max_item_mib: i64,
        max_day_mib: i64,
        category: &str,
        now: i64,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE feeds_followed SET
                    auto_since = CASE WHEN ?3 AND auto_download = 0 THEN ?7 ELSE auto_since END,
                    auto_download = ?3, auto_max_item_mib = ?4, auto_max_day_mib = ?5, auto_category = ?6
             WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, enabled, max_item_mib, max_day_mib, category, now],
        )? > 0)
    }

    /// Start a feed's auto-download window at `now` when it has none: one
    /// turned on before the window was kept takes only what comes from now.
    pub fn feed_start_auto_since(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_followed SET auto_since = ?3 WHERE publisher = ?1 AND salt = ?2 AND auto_since = 0",
            params![publisher, salt, now],
        )?;
        Ok(())
    }

    /// Bytes auto-download has started for a feed in the
    /// [`FEED_AUTO_WINDOW_SECS`] up to `now`.
    pub fn feed_auto_bytes(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<i64> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.query_row(
            "SELECT COALESCE(SUM(bytes), 0) FROM feeds_auto_started
             WHERE publisher = ?1 AND salt = ?2 AND at > ?3",
            params![publisher, salt, now - FEED_AUTO_WINDOW_SECS],
            |row| row.get(0),
        )?)
    }

    /// Count `bytes` auto-download started for a feed at `now`. Entries out
    /// of every feed's window go, so the log holds a day at most; so do
    /// entries a day ahead of `now`, left by a clock set back.
    pub fn feed_add_auto_bytes(&self, publisher: &str, salt: &str, now: i64, bytes: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO feeds_auto_started (publisher, salt, at, bytes) VALUES (?1, ?2, ?3, ?4)",
            params![publisher, salt, now, bytes],
        )?;
        tx.execute(
            "DELETE FROM feeds_auto_started WHERE at <= ?1 OR at > ?2",
            params![now - FEED_AUTO_WINDOW_SECS, now + FEED_AUTO_WINDOW_SECS],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Stop following a feed and forget its items. Files downloaded from it
    /// stay where they are.
    pub fn feed_unfollow(&self, publisher: &str, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        for table in ["feeds_followed_items", "feeds_auto_started", "feeds_followed"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE publisher = ?1 AND salt = ?2"),
                params![publisher, salt],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// The folder in `Feeds` the followed feed's files finish in: the one it
    /// was given by its first download, or, for that first, one named after
    /// `title` and unlike every other feed's. `None` when it is not followed.
    pub fn feed_followed_folder(&self, publisher: &str, salt: &str, title: &str) -> anyhow::Result<Option<String>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let held: Option<String> = tx
            .query_row(
                "SELECT folder FROM feeds_followed WHERE publisher = ?1 AND salt = ?2",
                params![publisher, salt],
                |row| row.get(0),
            )
            .optional()?;
        let Some(held) = held else {
            return Ok(None);
        };
        if !held.is_empty() {
            return Ok(Some(held));
        }
        let taken: Vec<String> = {
            let mut stmt = tx.prepare("SELECT folder FROM feeds_followed WHERE folder != ''")?;
            let rows = stmt.query_map([], |row| row.get(0))?.collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let folder = crate::sharing::feed_downloads::unique_folder_name(title, salt, &taken);
        tx.execute(
            "UPDATE feeds_followed SET folder = ?3 WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, folder],
        )?;
        tx.commit()?;
        Ok(Some(folder))
    }

    // ── Discover ────────────────────────────────────────────────────────

    /// The feeds the last Discover walks found, newest publish first,
    /// leaving out any found more than `max_age` seconds before `now`.
    pub fn feeds_discovered(&self, now: i64, max_age: i64) -> anyhow::Result<Vec<DiscoveredFeed>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute("DELETE FROM feeds_discovered WHERE listed_at < ?1", params![now - max_age])?;
        let mut stmt = conn.prepare(
            "SELECT publisher, salt, title, description, item_count, list_size, sequence, listed_at, first_seen
             FROM feeds_discovered ORDER BY sequence DESC",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok(DiscoveredFeed {
                    publisher: row.get(0)?,
                    salt: row.get(1)?,
                    title: row.get(2)?,
                    description: row.get(3)?,
                    item_count: row.get(4)?,
                    list_size: row.get(5)?,
                    sequence: row.get(6)?,
                    listed_at: row.get(7)?,
                    first_seen: row.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Record what a Discover walk found, and forget each feed of `forget`
    /// listed no later than the time given with it: one found withdrawn, as
    /// of its withdrawal, or one whose listing lapsed, as of any time. A feed
    /// already known keeps when it was first found, and is replaced only by
    /// a listing signed later. Returns each written feed's first-seen time,
    /// by `(publisher, salt)`.
    pub fn feeds_discovered_put(
        &self,
        found: &[DiscoveredFeed],
        forget: &[(String, String, i64)],
        now: i64,
    ) -> anyhow::Result<std::collections::HashMap<(String, String), i64>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let mut first_seen = std::collections::HashMap::new();
        {
            let mut upsert = tx.prepare(
                "INSERT INTO feeds_discovered
                    (publisher, salt, title, description, item_count, list_size, sequence, listed_at, first_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(publisher, salt) DO UPDATE SET
                    title = excluded.title, description = excluded.description,
                    item_count = excluded.item_count, list_size = excluded.list_size,
                    sequence = excluded.sequence, listed_at = excluded.listed_at
                 WHERE excluded.listed_at > feeds_discovered.listed_at",
            )?;
            let mut seen = tx.prepare("SELECT first_seen FROM feeds_discovered WHERE publisher = ?1 AND salt = ?2")?;
            for feed in found {
                upsert.execute(params![
                    feed.publisher,
                    feed.salt,
                    feed.title,
                    feed.description,
                    feed.item_count,
                    feed.list_size,
                    feed.sequence,
                    feed.listed_at,
                    now,
                ])?;
                let at: i64 = seen.query_row(params![feed.publisher, feed.salt], |row| row.get(0))?;
                first_seen.insert((feed.publisher.clone(), feed.salt.clone()), at);
            }
            let mut delete = tx.prepare(
                "DELETE FROM feeds_discovered WHERE publisher = ?1 AND salt = ?2 AND listed_at <= ?3",
            )?;
            for (publisher, salt, at) in forget {
                delete.execute(params![publisher, salt, at])?;
            }
        }
        tx.commit()?;
        Ok(first_seen)
    }

    /// The feeds hidden from Discover, as `(publisher, salt)`; an empty salt
    /// hides the publisher.
    pub fn feeds_hidden(&self) -> anyhow::Result<Vec<(String, String)>> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let mut stmt = conn.prepare("SELECT publisher, salt FROM feeds_hidden")?;
        let rows = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Hide a feed from Discover, or with an empty `salt` every feed of its
    /// publisher; with `hidden` false, show it again.
    pub fn feed_set_hidden(&self, publisher: &str, salt: &str, hidden: bool) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        if hidden {
            conn.execute(
                "INSERT OR IGNORE INTO feeds_hidden (publisher, salt) VALUES (?1, ?2)",
                params![publisher, salt],
            )?;
        } else {
            conn.execute(
                "DELETE FROM feeds_hidden WHERE publisher = ?1 AND salt = ?2",
                params![publisher, salt],
            )?;
        }
        Ok(())
    }

    /// Show every hidden feed and publisher in Discover again.
    pub fn feeds_hidden_clear(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute("DELETE FROM feeds_hidden", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(tag: &str) -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("ember-feeds-{tag}-{}-{}.db", std::process::id(), rand::random::<u64>()));
        let _ = std::fs::remove_file(&path);
        (Database::open_at(&path).expect("open db"), path)
    }

    fn drop_db(db: Database, path: std::path::PathBuf) {
        drop(db);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    fn item(ed2k: &str, name: &str) -> FeedItem {
        FeedItem {
            ed2k: ed2k.into(),
            name: name.into(),
            size: 10,
            aich: String::new(),
            blake3: "bb".repeat(32),
            note: String::new(),
        }
    }

    const PUB: &str = "pp";
    const SALT: &str = "ss";

    fn take_head(db: &Database, sequence: i64) -> bool {
        db.feed_take_head(PUB, SALT, sequence, "T", "", "l", "b", 5, 1, 100).unwrap()
    }

    #[test]
    fn new_and_removed_items_are_worked_out_across_lists() {
        let (db, path) = db("diff");
        assert!(db.feed_follow(PUB, SALT, 1).unwrap());
        assert!(!db.feed_follow(PUB, SALT, 2).unwrap(), "followed once");

        assert!(take_head(&db, 10));
        let first = db.feed_take_list(PUB, SALT, 10, &[item("a", "A"), item("b", "B")], 100).unwrap().unwrap();
        assert_eq!(first, ListUpdate::default(), "a first list is not news");
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().unread, 0);

        assert!(take_head(&db, 20));
        let second = db.feed_take_list(PUB, SALT, 20, &[item("b", "B2"), item("c", "C")], 200).unwrap().unwrap();
        assert_eq!(second.added.iter().map(|i| i.ed2k.as_str()).collect::<Vec<_>>(), vec!["c"]);
        assert_eq!(second.removed, 1);
        let feed = db.feed_followed(PUB, SALT).unwrap().unwrap();
        assert_eq!((feed.state.as_str(), feed.list_sequence, feed.unread), ("ok", 20, 1));
        let items = db.feed_followed_items(PUB, SALT).unwrap();
        let names: Vec<(&str, bool, bool)> =
            items.iter().map(|i| (i.item.name.as_str(), i.is_new, i.removed)).collect();
        assert_eq!(names, vec![("C", true, false), ("B2", false, false), ("A", false, true)]);

        db.feed_mark_read(PUB, SALT).unwrap();
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().unread, 0);
        drop_db(db, path);
    }

    #[test]
    fn an_older_head_or_a_stale_list_changes_nothing() {
        let (db, path) = db("order");
        db.feed_follow(PUB, SALT, 1).unwrap();
        assert!(take_head(&db, 20));
        assert!(!take_head(&db, 20), "the same sequence again");
        assert!(!take_head(&db, 15), "an older one");
        assert!(db.feed_take_list(PUB, SALT, 15, &[item("a", "A")], 100).unwrap().is_none(), "a list for another head");
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().state, "waiting");
        db.feed_mark_broken(PUB, SALT, 20).unwrap();
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().state, "broken");
        assert_eq!(db.feed_clear_broken(PUB, SALT).unwrap(), Some(20), "Retry takes it as owed again");
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().state, "waiting");
        assert_eq!(db.feed_clear_broken(PUB, SALT).unwrap(), None, "nothing broken now");
        drop_db(db, path);
    }

    #[test]
    fn a_file_another_feed_downloaded_is_found_for_this_one() {
        let (db, path) = db("elsewhere");
        for salt in [SALT, "other"] {
            db.feed_follow(PUB, salt, 1).unwrap();
            db.feed_take_head(PUB, salt, 20, "T", "", "l", "b", 5, 1, 100).unwrap();
            db.feed_take_list(PUB, salt, 20, &[item("a", "A")], 100).unwrap().unwrap();
        }
        assert!(db.feed_downloaded_elsewhere(PUB, SALT).unwrap().is_empty(), "nothing downloaded yet");
        db.feed_mark_downloaded(PUB, "other", "a").unwrap();
        assert!(db.feed_downloaded_elsewhere(PUB, SALT).unwrap().is_empty(), "no folder before the first");
        let folder = db.feed_followed_folder(PUB, "other", "Other").unwrap().unwrap();
        let found = db.feed_downloaded_elsewhere(PUB, SALT).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].ed2k.as_str(), found[0].folder.as_str(), found[0].name.as_str()), ("a", folder.as_str(), "A"));
        assert!(db.feed_downloaded_elsewhere(PUB, "other").unwrap().is_empty(), "not its own");
        db.feed_mark_cancelled(PUB, "other", "a").unwrap();
        assert!(db.feed_downloaded_elsewhere(PUB, SALT).unwrap().is_empty(), "cancelled there");
        drop_db(db, path);
    }

    #[test]
    fn a_head_found_again_counts_as_seen() {
        let (db, path) = db("seen");
        db.feed_follow(PUB, SALT, 1).unwrap();
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().seen_at, 0);
        db.feed_seen(PUB, SALT, 500).unwrap();
        db.feed_seen(PUB, SALT, 400).unwrap();
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().seen_at, 500, "never moved back");
        drop_db(db, path);
    }

    #[test]
    fn a_cancelled_download_stays_asked_for() {
        let (db, path) = db("cancelled");
        db.feed_follow(PUB, SALT, 1).unwrap();
        assert!(take_head(&db, 20));
        db.feed_take_list(PUB, SALT, 20, &[item("a", "A")], 100).unwrap().unwrap();
        let read = |db: &Database| db.feed_followed_items(PUB, SALT).unwrap().remove(0);
        db.feed_mark_downloaded(PUB, SALT, "a").unwrap();
        assert!(read(&db).downloaded && !read(&db).cancelled);
        db.feed_mark_cancelled(PUB, SALT, "a").unwrap();
        assert!(read(&db).downloaded && read(&db).cancelled, "auto-download must not take it again");
        db.feed_mark_downloaded(PUB, SALT, "a").unwrap();
        assert!(!read(&db).cancelled, "downloading it again clears it");
        drop_db(db, path);
    }

    #[test]
    fn own_feeds_are_capped_and_keep_their_order() {
        let (db, path) = db("own");
        assert!(db.feed_own_create("s1", "One", "", false, 1, 2).unwrap());
        assert!(db.feed_own_create("s2", "Two", "", false, 2, 2).unwrap());
        assert!(!db.feed_own_create("s3", "Three", "", false, 3, 2).unwrap(), "past the cap");
        db.feed_own_set_items("s1", &[item("b", "B"), item("a", "A")]).unwrap();
        let names: Vec<String> = db.feed_own_items("s1").unwrap().into_iter().map(|i| i.name).collect();
        assert_eq!(names, vec!["B", "A"]);
        assert!(!db.feed_own_set_items("nope", &[item("a", "A")]).unwrap(), "no such feed");
        db.feed_own_delete("s1", 10, 100).unwrap();
        assert!(db.feed_own("s1").unwrap().is_none());
        assert!(db.feed_own_items("s1").unwrap().is_empty());
        drop_db(db, path);
    }

    const TTL: i64 = 1000;

    fn take(db: &Database, published: bool, now: i64) -> Option<(bool, i64)> {
        db.feed_own_take_listing("s", published, now, TTL).unwrap().map(|due| (due.withdrawn, due.stamp))
    }

    #[test]
    fn a_feed_never_listed_sends_no_withdrawal() {
        let (db, path) = db("never-listed");
        db.feed_own_create("s", "One", "", true, 1, 8).unwrap();
        assert!(db.feed_own("s").unwrap().unwrap().listed);
        assert_eq!(take(&db, false, 10), None, "not published, so not listed yet");
        assert!(db.feed_own_set_listed("s", false).unwrap());
        assert_eq!(take(&db, true, 20), None, "no listing named it, so none to withdraw");
        assert!(!db.feed_own_set_listed("nope", true).unwrap(), "no such feed");
        drop_db(db, path);
    }

    #[test]
    fn a_listed_feed_is_withdrawn_until_its_listing_lapses() {
        let (db, path) = db("withdrawn");
        db.feed_own_create("s", "One", "", true, 1, 8).unwrap();
        assert_eq!(take(&db, true, 100), Some((false, 100)));
        assert_eq!(take(&db, true, 100), Some((false, 101)), "the same second again goes a second on");
        assert_eq!(db.feed_own("s").unwrap().unwrap().listing_sent_at, 101);
        db.feed_own_set_listed("s", false).unwrap();
        assert_eq!(take(&db, true, 50), Some((true, 102)), "past the last, whatever the clock says");
        assert_eq!(db.feed_own("s").unwrap().unwrap().listing_sent_at, 101, "a withdrawal is not a listing");
        assert_eq!(take(&db, true, 101 + TTL), Some((true, 101 + TTL)));
        assert_eq!(take(&db, true, 102 + TTL), None, "the listing it displaces has lapsed");
        drop_db(db, path);
    }

    #[test]
    fn a_deleted_feed_is_withdrawn_daily_until_its_listing_lapses() {
        let (db, path) = db("tombstone");
        db.feed_own_create("s", "One", "", true, 1, 8).unwrap();
        db.feed_own_create("t", "Two", "", false, 1, 8).unwrap();
        assert_eq!(take(&db, true, 100), Some((false, 100)));
        db.feed_own_delete("s", 200, TTL).unwrap();
        db.feed_own_delete("t", 200, TTL).unwrap();
        let due = db.feed_withdrawals_due(200, 50, TTL).unwrap();
        assert_eq!(due, vec![DueListing { salt: "s".into(), withdrawn: true, stamp: 200 }], "only the one listed");
        assert!(db.feed_withdrawals_due(240, 50, TTL).unwrap().is_empty(), "not due again yet");
        assert_eq!(db.feed_withdrawals_due(250, 50, TTL).unwrap().len(), 1);
        assert!(db.feed_withdrawals_due(101 + TTL, 50, TTL).unwrap().is_empty(), "lapsed, and forgotten");
        assert!(db.feed_withdrawals_due(2000 + TTL, 0, TTL).unwrap().is_empty());
        drop_db(db, path);
    }

    fn discovered(salt: &str, listed_at: i64, title: &str) -> DiscoveredFeed {
        DiscoveredFeed {
            publisher: PUB.into(),
            salt: salt.into(),
            title: title.into(),
            description: String::new(),
            item_count: 1,
            list_size: 10,
            sequence: listed_at * 1000,
            listed_at,
            first_seen: 0,
        }
    }

    #[test]
    fn discovered_feeds_keep_when_first_found_and_the_newest_listing() {
        let (db, path) = db("discovered");
        let seen = db.feeds_discovered_put(&[discovered("a", 100, "A"), discovered("b", 100, "B")], &[], 1000).unwrap();
        assert_eq!(seen[&(PUB.to_string(), "a".to_string())], 1000);
        let seen = db.feeds_discovered_put(&[discovered("a", 200, "A2"), discovered("b", 50, "Older")], &[], 2000).unwrap();
        assert_eq!(seen[&(PUB.to_string(), "a".to_string())], 1000, "first found at 1000");
        let feeds = db.feeds_discovered(2000, 10_000).unwrap();
        let title = |salt: &str| feeds.iter().find(|f| f.salt == salt).map(|f| f.title.clone());
        assert_eq!(title("a").as_deref(), Some("A2"));
        assert_eq!(title("b").as_deref(), Some("B"), "an older listing does not replace a newer");

        db.feeds_discovered_put(&[], &[(PUB.into(), "a".into(), 150), (PUB.into(), "b".into(), 150)], 3000).unwrap();
        let feeds = db.feeds_discovered(3000, 10_000).unwrap();
        assert_eq!(feeds.iter().map(|f| f.salt.as_str()).collect::<Vec<_>>(), vec!["a"], "listed again after it was withdrawn");
        assert!(db.feeds_discovered(200 + 10_001, 10_000).unwrap().is_empty(), "lapsed with its listing");
        drop_db(db, path);
    }

    #[test]
    fn a_feed_keeps_the_folder_its_first_download_gave_it() {
        let (db, path) = db("folder");
        assert_eq!(db.feed_followed_folder(PUB, SALT, "Mixes").unwrap(), None, "not followed");
        db.feed_follow(PUB, SALT, 1).unwrap();
        db.feed_follow(PUB, "other-salt", 1).unwrap();
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().folder, "");
        assert_eq!(db.feed_followed_folder(PUB, SALT, "Mixes").unwrap().as_deref(), Some("Mixes"));
        assert_eq!(db.feed_followed_folder(PUB, SALT, "Renamed").unwrap().as_deref(), Some("Mixes"), "kept");
        assert_eq!(
            db.feed_followed_folder(PUB, "other-salt", "mixes").unwrap().as_deref(),
            Some("mixes (other-sa)"),
            "another feed of that name"
        );
        assert_eq!(db.feed_followed(PUB, SALT).unwrap().unwrap().folder, "Mixes");
        drop_db(db, path);
    }

    #[test]
    fn auto_download_takes_files_from_when_it_was_last_turned_on() {
        let (db, path) = db("auto-since");
        db.feed_follow(PUB, SALT, 1).unwrap();
        let since = |salt: &str| db.feed_followed(PUB, salt).unwrap().unwrap().auto_since;
        assert_eq!(since(SALT), 0);
        assert!(db.feed_set_auto_download(PUB, SALT, true, 0, 0, "", 100).unwrap());
        assert_eq!(since(SALT), 100);
        db.feed_set_auto_download(PUB, SALT, true, 50, 0, "", 200).unwrap();
        assert_eq!(since(SALT), 100, "a cap changed while on");
        db.feed_set_auto_download(PUB, SALT, false, 50, 0, "", 300).unwrap();
        assert_eq!(since(SALT), 100);
        db.feed_set_auto_download(PUB, SALT, true, 50, 0, "", 400).unwrap();
        assert_eq!(since(SALT), 400, "turned on again");
        assert!(!db.feed_set_auto_download(PUB, "nope", true, 0, 0, "", 500).unwrap(), "not followed");

        db.feed_follow(PUB, "older", 1).unwrap();
        db.feed_start_auto_since(PUB, "older", 50).unwrap();
        db.feed_start_auto_since(PUB, "older", 60).unwrap();
        assert_eq!(since("older"), 50, "started once");
        db.feed_start_auto_since(PUB, SALT, 900).unwrap();
        assert_eq!(since(SALT), 400, "one already started is kept");

        assert!(take_head(&db, 10));
        db.feed_take_list(PUB, SALT, 10, &[item("a", "A")], 500).unwrap().unwrap();
        assert_eq!(since(SALT), 501, "turned on before the first list came, which brings nothing to take");
        let first_seen = db.feed_followed_items(PUB, SALT).unwrap()[0].first_seen;
        assert!(first_seen < since(SALT));
        assert!(take_head(&db, 20));
        db.feed_take_list(PUB, SALT, 20, &[item("a", "A"), item("b", "B")], 600).unwrap().unwrap();
        assert_eq!(since(SALT), 501, "a later list leaves it");
        let new = db.feed_followed_items(PUB, SALT).unwrap().into_iter().find(|i| i.item.ed2k == "b").unwrap();
        assert!(new.first_seen >= since(SALT), "what it adds is taken");

        db.feed_follow(PUB, "off", 1).unwrap();
        db.feed_take_head(PUB, "off", 10, "T", "", "l", "b", 5, 1, 100).unwrap();
        db.feed_take_list(PUB, "off", 10, &[item("a", "A")], 700).unwrap().unwrap();
        assert_eq!(since("off"), 0, "never turned on stays so");
        drop_db(db, path);
    }

    #[test]
    fn feeds_and_publishers_are_hidden_and_shown_again() {
        let (db, path) = db("hidden");
        db.feed_set_hidden(PUB, "a", true).unwrap();
        db.feed_set_hidden(PUB, "", true).unwrap();
        db.feed_set_hidden(PUB, "", true).unwrap();
        assert_eq!(db.feeds_hidden().unwrap().len(), 2);
        db.feed_set_hidden(PUB, "a", false).unwrap();
        assert_eq!(db.feeds_hidden().unwrap(), vec![(PUB.to_string(), String::new())]);
        db.feeds_hidden_clear().unwrap();
        assert!(db.feeds_hidden().unwrap().is_empty());
        drop_db(db, path);
    }

    fn publish(sequence: i64, title: &str) -> OwnPublish {
        OwnPublish {
            sequence,
            list_ed2k: "e".into(),
            list_blake3: "b".into(),
            list_size: 5,
            item_count: 1,
            title: title.into(),
            description: String::new(),
        }
    }

    #[test]
    fn a_publish_never_goes_back_and_an_edit_waits_for_the_next() {
        let (db, path) = db("publish");
        db.feed_own_create("s", "One", "", false, 1, 8).unwrap();
        assert!(db.feed_own_published("s", &publish(20, "One"), Some(&[]), 5).unwrap());
        assert!(!db.feed_own_published("s", &publish(10, "One"), Some(&[]), 6).unwrap(), "an older publish finishing late");
        let feed = db.feed_own("s").unwrap().unwrap();
        assert_eq!((feed.sequence, feed.published_at, feed.changed), (20, 5, false));

        db.feed_own_set_details("s", "Two", "").unwrap();
        let feed = db.feed_own("s").unwrap().unwrap();
        assert!(feed.changed);
        assert_eq!(feed.published_title, "One", "the republish keeps what was published");

        db.feed_own_republished("s", 20, 9).unwrap();
        let feed = db.feed_own("s").unwrap().unwrap();
        assert_eq!((feed.published_at, feed.refreshed_at), (5, 9), "a republish is not the user's publish");
        assert!(db.feed_own_published("s", &publish(30, "Two"), Some(&[]), 10).unwrap());
        assert!(!db.feed_own("s").unwrap().unwrap().changed);
        drop_db(db, path);
    }

    #[test]
    fn items_saved_while_a_head_was_out_stay_unpublished() {
        let (db, path) = db("midpublish");
        db.feed_own_create("s", "One", "", false, 1, 8).unwrap();
        let sent = vec![item("a", "A")];
        db.feed_own_set_items("s", &sent).unwrap();
        db.feed_own_set_items("s", &[item("a", "A"), item("b", "B")]).unwrap();
        assert!(db.feed_own_published("s", &publish(20, "One"), Some(&sent), 5).unwrap());
        assert!(db.feed_own("s").unwrap().unwrap().changed, "saved after the list was made");
        assert!(db.feed_own_published("s", &publish(30, "One"), None, 6).unwrap());
        assert!(db.feed_own("s").unwrap().unwrap().changed, "items not known");
        drop_db(db, path);
    }

    #[test]
    fn a_pending_head_is_kept_until_a_head_is_recorded() {
        let (db, path) = db("pending");
        db.feed_own_create("s", "One", "", false, 1, 8).unwrap();
        assert!(db.feed_own_published("s", &publish(20, "One"), Some(&[]), 5).unwrap());
        assert!(!db.feed_own_set_pending("s", Some(&publish(20, "One"))).unwrap(), "no newer than the head");
        assert!(db.feed_own("s").unwrap().unwrap().pending.is_none());

        let pending = OwnPublish { list_ed2k: "f".into(), ..publish(25, "One") };
        assert!(db.feed_own_set_pending("s", Some(&pending)).unwrap());
        let feed = db.feed_own("s").unwrap().unwrap();
        assert_eq!((feed.sequence, feed.pending), (20, Some(pending.clone())));
        let replaced = publish(27, "One");
        db.feed_own_set_pending("s", Some(&replaced)).unwrap();
        assert_eq!(db.feed_own("s").unwrap().unwrap().pending, Some(replaced.clone()), "one per feed");

        assert!(db.feed_own_published("s", &replaced, Some(&[]), 6).unwrap());
        let feed = db.feed_own("s").unwrap().unwrap();
        assert_eq!((feed.sequence, feed.pending), (27, None));

        db.feed_own_set_pending("s", Some(&publish(30, "One"))).unwrap();
        assert!(db.feed_own_set_pending("s", None).unwrap());
        assert!(db.feed_own("s").unwrap().unwrap().pending.is_none());
        drop_db(db, path);
    }

    #[test]
    fn saving_the_same_items_again_leaves_a_published_feed_up_to_date() {
        let (db, path) = db("unchanged");
        db.feed_own_create("s", "One", "", false, 1, 8).unwrap();
        let items = vec![item("a", "A"), item("b", "B")];
        db.feed_own_set_items("s", &items).unwrap();
        assert!(db.feed_own_published("s", &publish(20, "One"), Some(&items), 5).unwrap());
        assert!(!db.feed_own("s").unwrap().unwrap().changed);

        assert!(db.feed_own_set_items("s", &items).unwrap());
        assert!(!db.feed_own("s").unwrap().unwrap().changed, "the same items");

        let reordered = vec![item("b", "B"), item("a", "A")];
        db.feed_own_set_items("s", &reordered).unwrap();
        assert!(db.feed_own("s").unwrap().unwrap().changed, "another order");

        assert!(db.feed_own_published("s", &publish(30, "One"), Some(&reordered), 6).unwrap());
        let noted = vec![FeedItem { note: "listen".into(), ..item("b", "B") }, item("a", "A")];
        db.feed_own_set_items("s", &noted).unwrap();
        assert!(db.feed_own("s").unwrap().unwrap().changed, "a note");

        assert!(db.feed_own_published("s", &publish(40, "One"), Some(&noted), 7).unwrap());
        db.feed_own_mark_changed("s").unwrap();
        assert!(db.feed_own("s").unwrap().unwrap().changed);
        drop_db(db, path);
    }

    #[test]
    fn an_item_listed_again_is_news_and_removed_items_are_bounded() {
        let (db, path) = db("relist");
        db.feed_follow(PUB, SALT, 1).unwrap();
        take_head(&db, 10);
        db.feed_take_list(PUB, SALT, 10, &[item("a", "A")], 100).unwrap();
        take_head(&db, 20);
        db.feed_take_list(PUB, SALT, 20, &[], 200).unwrap();
        take_head(&db, 30);
        let back = db.feed_take_list(PUB, SALT, 30, &[item("a", "A")], 300).unwrap().unwrap();
        assert_eq!(back.added.len(), 1, "listed again after a removal");
        let items = db.feed_followed_items(PUB, SALT).unwrap();
        assert!(items[0].is_new && !items[0].removed);

        let many: Vec<FeedItem> = (0..REMOVED_ITEMS_KEPT + 5).map(|i| item(&format!("{i:032x}"), "X")).collect();
        take_head(&db, 40);
        db.feed_take_list(PUB, SALT, 40, &many, 400).unwrap();
        take_head(&db, 50);
        db.feed_take_list(PUB, SALT, 50, &[], 500).unwrap();
        let removed = db.feed_followed_items(PUB, SALT).unwrap().iter().filter(|i| i.removed).count();
        assert_eq!(removed as i64, REMOVED_ITEMS_KEPT);
        drop_db(db, path);
    }

    #[test]
    fn a_new_follow_has_the_default_caps_and_a_cap_of_0_is_kept() {
        let (db, path) = db("caps");
        db.feed_follow(PUB, SALT, 1).unwrap();
        let feed = db.feed_followed(PUB, SALT).unwrap().unwrap();
        assert!(!feed.auto_download);
        assert_eq!(
            (feed.auto_max_item_mib, feed.auto_max_day_mib),
            (FEED_AUTO_DEFAULT_ITEM_MIB, FEED_AUTO_DEFAULT_DAY_MIB)
        );

        db.conn.lock().execute("INSERT INTO feeds_followed (publisher, salt, followed_at) VALUES ('q', 's', 1)", []).unwrap();
        let bare = db.feed_followed("q", "s").unwrap().unwrap();
        assert_eq!(
            (bare.auto_max_item_mib, bare.auto_max_day_mib),
            (FEED_AUTO_DEFAULT_ITEM_MIB, FEED_AUTO_DEFAULT_DAY_MIB),
            "the column defaults"
        );

        db.feed_set_auto_download(PUB, SALT, true, 0, 0, "", 1).unwrap();
        let feed = db.feed_followed(PUB, SALT).unwrap().unwrap();
        assert_eq!((feed.auto_download, feed.auto_max_item_mib, feed.auto_max_day_mib), (true, 0, 0));
        drop_db(db, path);
    }

    #[test]
    fn auto_download_counts_bytes_over_the_last_day_and_unfollow_forgets_everything() {
        let (db, path) = db("auto");
        db.feed_follow(PUB, SALT, 1).unwrap();
        // Late on one UTC day, then early the next: one window, not two.
        let evening = 86_400 * 100 + 23 * 3600;
        db.feed_add_auto_bytes(PUB, SALT, evening, 5).unwrap();
        db.feed_add_auto_bytes(PUB, SALT, evening + 2 * 3600, 7).unwrap();
        assert_eq!(db.feed_auto_bytes(PUB, SALT, evening + 2 * 3600).unwrap(), 12);
        db.feed_add_auto_bytes("other", SALT, evening, 100).unwrap();
        assert_eq!(db.feed_auto_bytes(PUB, SALT, evening + 2 * 3600).unwrap(), 12, "per feed");
        assert_eq!(db.feed_auto_bytes(PUB, SALT, evening + FEED_AUTO_WINDOW_SECS).unwrap(), 7, "the first has aged out");
        db.feed_add_auto_bytes(PUB, SALT, evening + 3 * FEED_AUTO_WINDOW_SECS, 1).unwrap();
        let rows: i64 = db.conn.lock().query_row("SELECT COUNT(*) FROM feeds_auto_started", [], |row| row.get(0)).unwrap();
        assert_eq!(rows, 1, "the log keeps a day at most");
        db.feed_unfollow(PUB, SALT).unwrap();
        assert!(db.feed_followed(PUB, SALT).unwrap().is_none());
        drop_db(db, path);
    }
}
