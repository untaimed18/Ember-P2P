//! Feeds: the ones this identity publishes, with their items, and the ones it
//! follows, with the items of the list it holds. See `network::ember::feed`.
//!
//! Everything here is public by design — a feed is published under its
//! publisher's identity, and its list is served to anyone — so none of it is
//! sealed with the chat key.

use super::*;

/// Items a publisher removed that a follower keeps showing, per feed.
const REMOVED_ITEMS_KEPT: i64 = 2_000;

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
    pub published_at: i64,
    /// The title and description the last head carried, which the daily
    /// republish signs again: an edit not yet published stays unpublished.
    #[serde(skip)]
    pub published_title: String,
    #[serde(skip)]
    pub published_description: String,
    /// Details or items edited since the last publish.
    pub changed: bool,
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
    /// Per item, in MiB; 0 for no cap.
    pub auto_max_item_mib: i64,
    /// Per day, in MiB; 0 for no cap.
    pub auto_max_day_mib: i64,
    pub auto_category: String,
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
                changed INTEGER NOT NULL DEFAULT 0
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
                auto_max_item_mib INTEGER NOT NULL DEFAULT 0,
                auto_max_day_mib INTEGER NOT NULL DEFAULT 0,
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
            CREATE TABLE IF NOT EXISTS feeds_auto_bytes (
                publisher TEXT NOT NULL,
                salt TEXT NOT NULL,
                day INTEGER NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (publisher, salt, day)
            );",
        )?;
        // A table made by a development build before these columns. Each is
        // checked on its own, so one added before a crash is not added twice.
        for (column, kind) in [
            ("published_title", "TEXT NOT NULL DEFAULT ''"),
            ("published_description", "TEXT NOT NULL DEFAULT ''"),
            ("changed", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let present: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('feeds_own') WHERE name = ?1",
                params![column],
                |row| row.get(0),
            )?;
            if !present {
                conn.execute_batch(&format!("ALTER TABLE feeds_own ADD COLUMN {column} {kind};"))?;
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
                    created_at, published_at, published_title, published_description, changed
             FROM feeds_own ORDER BY created_at",
        )?;
        let rows = stmt
            .query_map([], |row| {
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
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub fn feed_own(&self, salt: &str) -> anyhow::Result<Option<OwnFeed>> {
        Ok(self.feeds_own()?.into_iter().find(|feed| feed.salt == salt))
    }

    /// Start a feed. `false` when the identity already has as many as it may.
    pub fn feed_own_create(&self, salt: &str, title: &str, description: &str, now: i64, max: usize) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM feeds_own", [], |row| row.get(0))?;
        if count as usize >= max {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO feeds_own (salt, title, description, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![salt, title, description, now],
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
    /// there is no such feed.
    pub fn feed_own_set_items(&self, salt: &str, items: &[FeedItem]) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        if tx.execute("UPDATE feeds_own SET changed = 1 WHERE salt = ?1", params![salt])? == 0 {
            return Ok(false);
        }
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
    /// description it carried. `false`, changing nothing, when a later
    /// sequence is recorded already.
    pub fn feed_own_published(&self, salt: &str, published: &OwnPublish, now: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE feeds_own SET sequence = ?2, list_ed2k = ?3, list_blake3 = ?4, list_size = ?5,
                    item_count = ?6, published_at = ?7, published_title = ?8, published_description = ?9,
                    changed = (title != ?8 OR description != ?9)
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
            ],
        )? > 0)
    }

    /// Record that head `sequence` of `salt` was signed and sent again.
    pub fn feed_own_republished(&self, salt: &str, sequence: i64, now: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        conn.execute(
            "UPDATE feeds_own SET published_at = ?3 WHERE salt = ?1 AND sequence = ?2",
            params![salt, sequence, now],
        )?;
        Ok(())
    }

    pub fn feed_own_delete(&self, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("DELETE FROM feeds_own_items WHERE salt = ?1", params![salt])?;
        tx.execute("DELETE FROM feeds_own WHERE salt = ?1", params![salt])?;
        tx.commit()?;
        Ok(())
    }

    // ── Following ───────────────────────────────────────────────────────

    /// Follow a feed. `false` when it is followed already.
    pub fn feed_follow(&self, publisher: &str, salt: &str, now: i64) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "INSERT OR IGNORE INTO feeds_followed (publisher, salt, followed_at) VALUES (?1, ?2, ?3)",
            params![publisher, salt, now],
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
                    auto_max_item_mib, auto_max_day_mib, auto_category, held_ed2k, held_blake3, held_size
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
            "SELECT ed2k, name, size, aich, blake3, note, first_seen, is_new, removed, downloaded
             FROM feeds_followed_items WHERE publisher = ?1 AND salt = ?2
             ORDER BY removed, first_seen DESC, rowid DESC",
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

    #[allow(clippy::too_many_arguments)]
    pub fn feed_set_auto_download(
        &self,
        publisher: &str,
        salt: &str,
        enabled: bool,
        max_item_mib: i64,
        max_day_mib: i64,
        category: &str,
    ) -> anyhow::Result<bool> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn.execute(
            "UPDATE feeds_followed SET auto_download = ?3, auto_max_item_mib = ?4, auto_max_day_mib = ?5,
                    auto_category = ?6
             WHERE publisher = ?1 AND salt = ?2",
            params![publisher, salt, enabled, max_item_mib, max_day_mib, category],
        )? > 0)
    }

    /// Bytes auto-download has started for a feed on `day` (days since the
    /// epoch, UTC).
    pub fn feed_auto_bytes(&self, publisher: &str, salt: &str, day: i64) -> anyhow::Result<i64> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        Ok(conn
            .query_row(
                "SELECT bytes FROM feeds_auto_bytes WHERE publisher = ?1 AND salt = ?2 AND day = ?3",
                params![publisher, salt, day],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0))
    }

    pub fn feed_add_auto_bytes(&self, publisher: &str, salt: &str, day: i64, bytes: i64) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO feeds_auto_bytes (publisher, salt, day, bytes) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(publisher, salt, day) DO UPDATE SET bytes = bytes + excluded.bytes",
            params![publisher, salt, day, bytes],
        )?;
        // Only today's and yesterday's counts are ever read.
        tx.execute("DELETE FROM feeds_auto_bytes WHERE day < ?1", params![day - 1])?;
        tx.commit()?;
        Ok(())
    }

    /// Stop following a feed and forget its items. Files downloaded from it
    /// stay where they are.
    pub fn feed_unfollow(&self, publisher: &str, salt: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_feeds_locked(&conn)?;
        let tx = conn.unchecked_transaction()?;
        for table in ["feeds_followed_items", "feeds_auto_bytes", "feeds_followed"] {
            tx.execute(
                &format!("DELETE FROM {table} WHERE publisher = ?1 AND salt = ?2"),
                params![publisher, salt],
            )?;
        }
        tx.commit()?;
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
        drop_db(db, path);
    }

    #[test]
    fn own_feeds_are_capped_and_keep_their_order() {
        let (db, path) = db("own");
        assert!(db.feed_own_create("s1", "One", "", 1, 2).unwrap());
        assert!(db.feed_own_create("s2", "Two", "", 2, 2).unwrap());
        assert!(!db.feed_own_create("s3", "Three", "", 3, 2).unwrap(), "past the cap");
        db.feed_own_set_items("s1", &[item("b", "B"), item("a", "A")]).unwrap();
        let names: Vec<String> = db.feed_own_items("s1").unwrap().into_iter().map(|i| i.name).collect();
        assert_eq!(names, vec!["B", "A"]);
        assert!(!db.feed_own_set_items("nope", &[item("a", "A")]).unwrap(), "no such feed");
        db.feed_own_delete("s1").unwrap();
        assert!(db.feed_own("s1").unwrap().is_none());
        assert!(db.feed_own_items("s1").unwrap().is_empty());
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
        db.feed_own_create("s", "One", "", 1, 8).unwrap();
        assert!(db.feed_own_published("s", &publish(20, "One"), 5).unwrap());
        assert!(!db.feed_own_published("s", &publish(10, "One"), 6).unwrap(), "an older publish finishing late");
        let feed = db.feed_own("s").unwrap().unwrap();
        assert_eq!((feed.sequence, feed.published_at, feed.changed), (20, 5, false));

        db.feed_own_set_details("s", "Two", "").unwrap();
        let feed = db.feed_own("s").unwrap().unwrap();
        assert!(feed.changed);
        assert_eq!(feed.published_title, "One", "the republish keeps what was published");

        db.feed_own_republished("s", 20, 9).unwrap();
        assert_eq!(db.feed_own("s").unwrap().unwrap().published_at, 9);
        assert!(db.feed_own_published("s", &publish(30, "Two"), 10).unwrap());
        assert!(!db.feed_own("s").unwrap().unwrap().changed);
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
    fn auto_download_counts_bytes_per_day_and_unfollow_forgets_everything() {
        let (db, path) = db("auto");
        db.feed_follow(PUB, SALT, 1).unwrap();
        db.feed_add_auto_bytes(PUB, SALT, 100, 5).unwrap();
        db.feed_add_auto_bytes(PUB, SALT, 100, 7).unwrap();
        assert_eq!(db.feed_auto_bytes(PUB, SALT, 100).unwrap(), 12);
        db.feed_add_auto_bytes(PUB, SALT, 103, 1).unwrap();
        assert_eq!(db.feed_auto_bytes(PUB, SALT, 100).unwrap(), 0, "old days are dropped");
        db.feed_unfollow(PUB, SALT).unwrap();
        assert!(db.feed_followed(PUB, SALT).unwrap().is_none());
        drop_db(db, path);
    }
}
