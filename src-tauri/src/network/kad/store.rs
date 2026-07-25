use std::collections::HashMap;
use std::mem::size_of;

use tracing::debug;

use super::messages::{PublishEntry, SearchResultEntry};
use super::types::*;

const MAX_ENTRIES_PER_KEY: usize = 1000;
const MAX_TOTAL_ENTRIES: usize = 50_000;
const MAX_TOTAL_RETAINED_BYTES: usize = 64 * 1024 * 1024;
const MAX_RETAINED_BYTES_PER_KEY: usize = 4 * 1024 * 1024;
const MAX_RETAINED_BYTES_PER_PUBLISHER_PER_KEY: usize = 2 * 1024 * 1024;
const MAX_RETAINED_BYTES_PER_ENTRY: usize = 64 * 1024;
const MAX_STORED_TAGS: usize = 64;
const MAX_STORED_TAG_NAME_BYTES: usize = 256;
const MAX_STORED_STRING_BYTES: usize = 8 * 1024;
const MAX_STORED_FILENAME_BYTES: usize = 4 * 1024;
const MAX_STORED_BLOB_BYTES: usize = 8 * 1024;
// eMule caps one keyword-publish batch at 150 files. Mirroring that as the
// maximum contribution from one verified KAD identity prevents one publisher
// monopolising an entire 1000-entry keyword bucket while accepting a complete
// standards-sized publish from an ordinary peer.
const MAX_KEYWORD_ENTRIES_PER_SENDER: usize = 150;
/// How long a keyword entry we're storing *for another node* survives
/// before we evict it. `publish::keyword_republish_interval` assumes
/// every other KAD node enforces this same TTL against entries *we*
/// publish, and caps its load-based backoff so we always renew before
/// theirs would expire — keep the two in sync if this changes.
pub(super) const KEYWORD_TTL_SECS: i64 = 86_400; // 24 hours
const SOURCE_TTL_SECS: i64 = 18_000; // 5 hours
const NOTES_TTL_SECS: i64 = 86_400; // 24 hours
const MAX_NOTES_PER_FILE: usize = 150;

#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub id: KadId,
    pub tags: Vec<KadTag>,
    pub stored_at: i64,
    pub ttl_secs: i64,
    /// The KAD ID of the node that published this entry (used for dedup).
    pub source_id: KadId,
    retained_bytes: usize,
}

impl StoredEntry {
    pub fn is_expired(&self, now: i64) -> bool {
        now.saturating_sub(self.stored_at) >= self.ttl_secs
    }
}

/// Normalize spare capacities before retention, then account for every byte
/// retained by the entry. Capacities (not lengths) make counter updates exact;
/// the conservative inline `size_of` component also includes allocator-backed
/// field headers and the accounting field itself.
fn normalize_and_size_tags(mut tags: Vec<KadTag>) -> Option<(Vec<KadTag>, usize)> {
    if tags.len() > MAX_STORED_TAGS {
        return None;
    }
    for tag in &mut tags {
        match &mut tag.name {
            TagName::Id(_) => {}
            TagName::Str(name) => {
                if name.len() > MAX_STORED_TAG_NAME_BYTES {
                    return None;
                }
                name.shrink_to_fit();
            }
        }
        match &mut tag.value {
            TagValue::String(value) => {
                let limit = if matches!(tag.name, TagName::Id(TAG_FILENAME)) {
                    MAX_STORED_FILENAME_BYTES
                } else {
                    MAX_STORED_STRING_BYTES
                };
                if value.len() > limit {
                    return None;
                }
                value.shrink_to_fit();
            }
            TagValue::Blob(value) | TagValue::Bsob(value) => {
                if value.len() > MAX_STORED_BLOB_BYTES {
                    return None;
                }
                value.shrink_to_fit();
            }
            _ => {}
        }
    }
    tags.shrink_to_fit();

    let mut bytes =
        size_of::<StoredEntry>().checked_add(tags.capacity().checked_mul(size_of::<KadTag>())?)?;
    for tag in &tags {
        if let TagName::Str(name) = &tag.name {
            bytes = bytes.checked_add(name.capacity())?;
        }
        match &tag.value {
            TagValue::String(value) => bytes = bytes.checked_add(value.capacity())?,
            TagValue::Blob(value) | TagValue::Bsob(value) => {
                bytes = bytes.checked_add(value.capacity())?
            }
            _ => {}
        }
    }
    (bytes <= MAX_RETAINED_BYTES_PER_ENTRY).then_some((tags, bytes))
}

fn retained_bytes(entries: &[StoredEntry]) -> usize {
    entries.iter().map(|entry| entry.retained_bytes).sum()
}

/// eMule `CIndexed::AddKeyword` minimum-content gate for a single
/// `PublishKeyReq` entry: non-empty `TAG_FILENAME`, non-zero `TAG_FILESIZE`,
/// and at least one tag present.
fn keyword_entry_has_min_content(tags: &[KadTag]) -> bool {
    if tags.is_empty() {
        return false;
    }
    let has_filename = tags.iter().any(|t| {
        matches!(&t.name, TagName::Id(TAG_FILENAME))
            && matches!(&t.value, TagValue::String(s) if !s.is_empty())
    });
    let has_filesize = tags.iter().any(|t| {
        matches!(&t.name, TagName::Id(TAG_FILESIZE)) && t.as_uint().map_or(false, |v| v > 0)
    });
    has_filename && has_filesize
}

pub struct DhtStore {
    keyword_entries: HashMap<KadId, Vec<StoredEntry>>,
    source_entries: HashMap<KadId, Vec<StoredEntry>>,
    notes_entries: HashMap<KadId, Vec<StoredEntry>>,
    total_count: usize,
    total_retained_bytes: usize,
    local_id: KadId,
}

impl DhtStore {
    pub fn new() -> Self {
        DhtStore {
            keyword_entries: HashMap::new(),
            source_entries: HashMap::new(),
            notes_entries: HashMap::new(),
            total_count: 0,
            total_retained_bytes: 0,
            local_id: KadId::zero(),
        }
    }

    pub fn set_local_id(&mut self, id: KadId) {
        self.local_id = id;
    }

    /// Check if the target is within our tolerance zone for accepting publishes.
    ///
    /// Matches eMule `Process_KADEMLIA2_PUBLISH_*`: accept when
    /// `distance.chunk(0) <= SEARCHTOLERANCE` **or** the publisher is on a LAN
    /// IP (`IsLANIP`). The LAN bypass is required for local/test topologies
    /// where peers sit outside the XOR zone but are trusted by address class.
    pub fn is_within_tolerance_for(
        &self,
        target: &KadId,
        publisher_ip: Option<std::net::Ipv4Addr>,
    ) -> bool {
        let distance = self.local_id.xor_distance(target);
        if distance.chunk(0) <= SEARCH_TOLERANCE {
            return true;
        }
        publisher_ip.is_some_and(super::ip_filter::is_lan_ip)
    }

    pub fn store_keyword_entries(
        &mut self,
        target: &KadId,
        entries: Vec<PublishEntry>,
        sender_id: &KadId,
    ) -> u8 {
        let bucket = self.keyword_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        let bytes_before = retained_bytes(bucket);
        bucket.retain(|e| !e.is_expired(now));
        self.total_count = self.total_count.saturating_sub(len_before - bucket.len());
        self.total_retained_bytes = self
            .total_retained_bytes
            .saturating_sub(bytes_before.saturating_sub(retained_bytes(bucket)));
        let mut sender_entry_count = bucket
            .iter()
            .filter(|entry| entry.source_id == *sender_id)
            .count();

        for entry in entries {
            // eMule `CIndexed::AddKeyword` rejects a keyword entry outright
            // when it has no filename, no size, or no tags at all:
            // `if (!pEntry->m_uSize || pEntry->GetCommonFileName().IsEmpty()
            //     || !pEntry->GetTagCount() || ...) return false;`
            // Without this gate a publisher (malicious or buggy) could store
            // an entry carrying neither a name nor a size, which we would
            // then hand back to real searchers via `search_keywords` as an
            // unusable result. Mirrors the same minimum-content gate already
            // applied to source (`has_source_type`/`has_tcp_port`) and notes
            // (`has_comment`/`has_rating`) publishes below.
            if !keyword_entry_has_min_content(&entry.tags) {
                continue;
            }
            let Some((tags, entry_bytes)) = normalize_and_size_tags(entry.tags) else {
                continue;
            };
            let key_bytes = retained_bytes(bucket);
            let publisher_bytes: usize = bucket
                .iter()
                .filter(|stored| stored.source_id == *sender_id)
                .map(|stored| stored.retained_bytes)
                .sum();
            if let Some(pos) = bucket
                .iter()
                .position(|e| e.id == entry.id && e.source_id == *sender_id)
            {
                let old_bytes = bucket[pos].retained_bytes;
                if key_bytes
                    .saturating_sub(old_bytes)
                    .saturating_add(entry_bytes)
                    > MAX_RETAINED_BYTES_PER_KEY
                    || publisher_bytes
                        .saturating_sub(old_bytes)
                        .saturating_add(entry_bytes)
                        > MAX_RETAINED_BYTES_PER_PUBLISHER_PER_KEY
                    || self
                        .total_retained_bytes
                        .saturating_sub(old_bytes)
                        .saturating_add(entry_bytes)
                        > MAX_TOTAL_RETAINED_BYTES
                {
                    continue;
                }
                bucket[pos].tags = tags;
                bucket[pos].stored_at = now;
                bucket[pos].retained_bytes = entry_bytes;
                self.total_retained_bytes = self
                    .total_retained_bytes
                    .saturating_sub(old_bytes)
                    .saturating_add(entry_bytes);
            } else {
                // Skip *this* new entry when full, but keep scanning the rest
                // of the batch: later entries may be updates to existing records
                // (the branch above) which cost no capacity and must still
                // refresh `stored_at`, otherwise an active republish that
                // happens to include one over-cap new entry would let its other
                // (already-stored) entries expire.
                if sender_entry_count >= MAX_KEYWORD_ENTRIES_PER_SENDER {
                    continue;
                }
                if self.total_count >= MAX_TOTAL_ENTRIES {
                    continue;
                }
                if bucket.len() >= MAX_ENTRIES_PER_KEY {
                    continue;
                }
                if key_bytes.saturating_add(entry_bytes) > MAX_RETAINED_BYTES_PER_KEY
                    || publisher_bytes.saturating_add(entry_bytes)
                        > MAX_RETAINED_BYTES_PER_PUBLISHER_PER_KEY
                    || self.total_retained_bytes.saturating_add(entry_bytes)
                        > MAX_TOTAL_RETAINED_BYTES
                {
                    continue;
                }
                bucket.push(StoredEntry {
                    id: entry.id,
                    tags,
                    stored_at: now,
                    ttl_secs: KEYWORD_TTL_SECS,
                    source_id: *sender_id,
                    retained_bytes: entry_bytes,
                });
                self.total_count += 1;
                self.total_retained_bytes += entry_bytes;
                sender_entry_count += 1;
            }
        }

        // `entry(*target).or_default()` above unconditionally inserts a
        // `target -> Vec::new()` key, even for a request with an empty
        // `entries` list (a wire-valid `count = 0` publish) or one where
        // every candidate was rejected by the caps above. Without this,
        // an attacker can grow `keyword_entries`'s key count without
        // bound — entirely independent of `MAX_TOTAL_ENTRIES`, which only
        // bounds stored *entries*, not distinct HashMap keys — by sending
        // trivial ~20-byte publish requests each addressed to a fresh
        // `target` within our tolerance zone (our `local_id` isn't
        // secret, and KAD's UDP transport has no handshake to rate-limit
        // via source IP once an attacker spoofs a fresh one per packet).
        if bucket.is_empty() {
            self.keyword_entries.remove(target);
        }

        self.compute_load()
    }

    pub fn store_source_entry(
        &mut self,
        target: &KadId,
        sender_id: KadId,
        mut tags: Vec<KadTag>,
        sender_ip: std::net::Ipv4Addr,
        sender_port: u16,
    ) -> u8 {
        // eMule `Process_KADEMLIA2_PUBLISH_SOURCE_REQ` + `CIndexed::AddSources`
        // only index a source once it forms a usable record: it must carry a
        // `TAG_SOURCETYPE` (which sets eMule's `m_bSource`) and a non-zero TCP
        // port (`TAG_SOURCEPORT`, eMule's `m_uTCPPort`). Records missing either
        // are dropped by eMule, so storing them here would let us serve
        // unconnectable / malformed sources back to eMule peers. We reject the
        // same cases (returning the current bucket load without indexing). The
        // UDP port may still fall back to the packet's source port below,
        // mirroring eMule initialising `m_uUDPPort = uUDPPort` before reading
        // the optional `TAG_SOURCEUPORT`.
        let has_source_type = tags
            .iter()
            .any(|t| matches!(&t.name, TagName::Id(TAG_SOURCETYPE)));
        let has_tcp_port = tags.iter().any(|t| {
            matches!(&t.name, TagName::Id(TAG_SOURCEPORT)) && t.as_uint().map_or(false, |p| p > 0)
        });
        if !has_source_type || !has_tcp_port {
            return self.compute_load();
        }

        let bucket = self.source_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        let bytes_before = retained_bytes(bucket);
        bucket.retain(|e| !e.is_expired(now));
        let removed = len_before - bucket.len();
        self.total_count = self.total_count.saturating_sub(removed);
        self.total_retained_bytes = self
            .total_retained_bytes
            .saturating_sub(bytes_before.saturating_sub(retained_bytes(bucket)));
        let existing_pos = bucket.iter().position(|entry| entry.id == sender_id);

        if existing_pos.is_none()
            && (self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_ENTRIES_PER_KEY)
        {
            // Don't leave behind an empty `target -> Vec::new()` key for a
            // brand-new target that got rejected outright by the global/
            // per-key cap — see the matching comment in
            // `store_keyword_entries` for why this otherwise allows
            // unbounded HashMap key growth that bypasses both caps (the
            // minimum-field gate above makes this path slightly more
            // expensive to abuse than the keyword one, but still cheap:
            // just two tags per packet).
            if bucket.is_empty() {
                self.source_entries.remove(target);
            }
            return self.compute_load();
        }

        const MAX_SOURCES_PER_IP: usize = 3;
        let ip_u32 = u32::from_be_bytes(sender_ip.octets());
        let ip_count = bucket
            .iter()
            .filter(|entry| entry.id != sender_id)
            .filter(|e| {
                e.tags.iter().any(|t| {
                    matches!(&t.name, TagName::Id(TAG_SOURCEIP))
                        && matches!(&t.value, TagValue::Uint32(v) if *v == ip_u32)
                })
            })
            .count();
        if ip_count >= MAX_SOURCES_PER_IP {
            return self.compute_load();
        }

        // Always override source IP with the actual packet sender IP to prevent spoofing.
        // A publisher can specify a port (for TCP connections) but the IP must be verified.
        let ip_u32 = u32::from_be_bytes(sender_ip.octets());
        tags.retain(|t| !matches!(&t.name, TagName::Id(TAG_SOURCEIP)));
        tags.push(KadTag {
            name: TagName::Id(TAG_SOURCEIP),
            value: TagValue::Uint32(ip_u32),
        });
        // A valid, non-zero TCP `TAG_SOURCEPORT` is guaranteed by the
        // validation at the top of this function, so we never fabricate one
        // from the UDP source port (which is not a TCP listen port and would
        // produce an unconnectable source).
        //
        // eMule `Process_KADEMLIA2_PUBLISH_SOURCE_REQ` only accepts an
        // incoming `TAG_SOURCEUPORT` when it parses as a *non-zero* int
        // (`pTag->IsInt() && (uint16)pTag->GetInt() > 0`); a present-but-zero
        // tag is discarded and `m_uUDPPort` keeps its default of the packet's
        // real source port. Checking presence alone (as opposed to a
        // non-zero value) would let a publisher plant an unusable `0` UDP
        // port that we'd then serve back to real searchers.
        let has_valid_uport = tags.iter().any(|t| {
            matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)) && t.as_uint().is_some_and(|p| p > 0)
        });
        if !has_valid_uport {
            tags.retain(|t| !matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)));
            tags.push(KadTag {
                name: TagName::Id(TAG_SOURCEUPORT),
                value: TagValue::Uint16(sender_port),
            });
        }

        let Some((tags, entry_bytes)) = normalize_and_size_tags(tags) else {
            if bucket.is_empty() {
                self.source_entries.remove(target);
            }
            return self.compute_load();
        };
        let old_bytes = existing_pos
            .map(|pos| bucket[pos].retained_bytes)
            .unwrap_or(0);
        if retained_bytes(bucket)
            .saturating_sub(old_bytes)
            .saturating_add(entry_bytes)
            > MAX_RETAINED_BYTES_PER_KEY
            || self
                .total_retained_bytes
                .saturating_sub(old_bytes)
                .saturating_add(entry_bytes)
                > MAX_TOTAL_RETAINED_BYTES
        {
            if bucket.is_empty() {
                self.source_entries.remove(target);
            }
            return self.compute_load();
        }
        let stored = StoredEntry {
            id: sender_id,
            tags,
            stored_at: now,
            ttl_secs: SOURCE_TTL_SECS,
            source_id: sender_id,
            retained_bytes: entry_bytes,
        };
        if let Some(pos) = existing_pos {
            bucket[pos] = stored;
        } else {
            bucket.push(stored);
            self.total_count += 1;
        }
        self.total_retained_bytes = self
            .total_retained_bytes
            .saturating_sub(old_bytes)
            .saturating_add(entry_bytes);

        self.compute_load()
    }

    #[cfg(test)]
    pub fn search_keywords(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.search_keywords_page(target, 0, usize::MAX, |_, _| true)
    }

    #[cfg(test)]
    pub fn search_sources(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.search_sources_page(target, 0, usize::MAX, |_, _| true)
    }

    fn search_page<F>(
        entries: Option<&Vec<StoredEntry>>,
        start: usize,
        limit: usize,
        mut predicate: F,
    ) -> Vec<SearchResultEntry>
    where
        F: FnMut(&KadId, &[KadTag]) -> bool,
    {
        let now = chrono::Utc::now().timestamp();
        entries
            .into_iter()
            .flatten()
            .filter(|entry| !entry.is_expired(now))
            .filter(|entry| predicate(&entry.id, &entry.tags))
            .skip(start)
            .take(limit)
            .map(|entry| SearchResultEntry {
                id: entry.id,
                tags: entry.tags.clone(),
            })
            .collect()
    }

    pub fn search_keywords_page<F>(
        &self,
        target: &KadId,
        start: usize,
        limit: usize,
        predicate: F,
    ) -> Vec<SearchResultEntry>
    where
        F: FnMut(&KadId, &[KadTag]) -> bool,
    {
        Self::search_page(self.keyword_entries.get(target), start, limit, predicate)
    }

    pub fn search_sources_page<F>(
        &self,
        target: &KadId,
        start: usize,
        limit: usize,
        predicate: F,
    ) -> Vec<SearchResultEntry>
    where
        F: FnMut(&KadId, &[KadTag]) -> bool,
    {
        Self::search_page(self.source_entries.get(target), start, limit, predicate)
    }

    pub fn store_notes_entry(&mut self, target: &KadId, sender_id: KadId, tags: Vec<KadTag>) -> u8 {
        // Mirror `store_source_entry`'s minimum-field gate: a note with
        // neither a non-empty comment (TAG_DESCRIPTION) nor a non-zero
        // rating (TAG_FILERATING) carries nothing worth serving back to
        // other peers via `search_notes`. Without this, an empty/no-op
        // PublishNotesReq still consumed a `MAX_NOTES_PER_FILE` slot and
        // could itself be searched-and-returned as a blank note.
        let has_comment = tags.iter().any(|t| {
            matches!(&t.name, TagName::Id(TAG_DESCRIPTION))
                && matches!(&t.value, TagValue::String(s) if !s.is_empty())
        });
        let has_rating = tags.iter().any(|t| {
            matches!(&t.name, TagName::Id(TAG_FILERATING))
                && matches!(&t.value, TagValue::Uint8(r) if *r > 0)
        });
        if !has_comment && !has_rating {
            return self.compute_load();
        }

        let bucket = self.notes_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        let bytes_before = retained_bytes(bucket);
        bucket.retain(|e| !e.is_expired(now));
        let removed = len_before - bucket.len();
        self.total_count = self.total_count.saturating_sub(removed);
        self.total_retained_bytes = self
            .total_retained_bytes
            .saturating_sub(bytes_before.saturating_sub(retained_bytes(bucket)));
        let existing_pos = bucket.iter().position(|entry| entry.id == sender_id);

        if existing_pos.is_none()
            && (self.total_count >= MAX_TOTAL_ENTRIES || bucket.len() >= MAX_NOTES_PER_FILE)
        {
            // See the matching comment in `store_keyword_entries`/
            // `store_source_entry`: don't leave an empty bucket key behind
            // for a brand-new target rejected by the cap.
            if bucket.is_empty() {
                self.notes_entries.remove(target);
            }
            return self.compute_load();
        }

        let Some((tags, entry_bytes)) = normalize_and_size_tags(tags) else {
            if bucket.is_empty() {
                self.notes_entries.remove(target);
            }
            return self.compute_load();
        };
        let old_bytes = existing_pos
            .map(|pos| bucket[pos].retained_bytes)
            .unwrap_or(0);
        if retained_bytes(bucket)
            .saturating_sub(old_bytes)
            .saturating_add(entry_bytes)
            > MAX_RETAINED_BYTES_PER_KEY
            || self
                .total_retained_bytes
                .saturating_sub(old_bytes)
                .saturating_add(entry_bytes)
                > MAX_TOTAL_RETAINED_BYTES
        {
            if bucket.is_empty() {
                self.notes_entries.remove(target);
            }
            return self.compute_load();
        }
        let stored = StoredEntry {
            id: sender_id,
            tags,
            stored_at: now,
            ttl_secs: NOTES_TTL_SECS,
            source_id: sender_id,
            retained_bytes: entry_bytes,
        };
        if let Some(pos) = existing_pos {
            bucket[pos] = stored;
        } else {
            bucket.push(stored);
            self.total_count += 1;
        }
        self.total_retained_bytes = self
            .total_retained_bytes
            .saturating_sub(old_bytes)
            .saturating_add(entry_bytes);

        self.compute_load()
    }

    #[cfg(test)]
    pub fn search_notes(&self, target: &KadId) -> Vec<SearchResultEntry> {
        self.search_notes_page(target, 0, usize::MAX, |_, _| true)
    }

    pub fn search_notes_page<F>(
        &self,
        target: &KadId,
        start: usize,
        limit: usize,
        predicate: F,
    ) -> Vec<SearchResultEntry>
    where
        F: FnMut(&KadId, &[KadTag]) -> bool,
    {
        Self::search_page(self.notes_entries.get(target), start, limit, predicate)
    }

    pub fn cleanup_expired(&mut self) {
        let now = chrono::Utc::now().timestamp();
        let count_before = self.total_count;
        let bytes_before = self.total_retained_bytes;

        for entries in self.keyword_entries.values_mut() {
            entries.retain(|e| !e.is_expired(now));
        }
        self.keyword_entries.retain(|_, v| !v.is_empty());

        for entries in self.source_entries.values_mut() {
            entries.retain(|e| !e.is_expired(now));
        }
        self.source_entries.retain(|_, v| !v.is_empty());

        for entries in self.notes_entries.values_mut() {
            entries.retain(|e| !e.is_expired(now));
        }
        self.notes_entries.retain(|_, v| !v.is_empty());

        self.total_count = self
            .keyword_entries
            .values()
            .chain(self.source_entries.values())
            .chain(self.notes_entries.values())
            .map(Vec::len)
            .sum();
        self.total_retained_bytes = self
            .keyword_entries
            .values()
            .chain(self.source_entries.values())
            .chain(self.notes_entries.values())
            .map(|entries| retained_bytes(entries))
            .sum();
        let removed = count_before.saturating_sub(self.total_count);
        if removed > 0 {
            debug!(
                "DHT store cleanup: removed {removed} expired entries ({} retained bytes)",
                bytes_before.saturating_sub(self.total_retained_bytes)
            );
        }
    }

    /// Returns a 0-100 load percentage suitable for the KADEMLIA2_PUBLISH_RES
    /// `byLoad` field. K16: eMule 0.50a's `CIndexed::SendPublishResponse`
    /// computes this as `(m_uTotalIndexLoad * 100) / m_uMaxIndexLoad`,
    /// i.e. a straight percentage capped at 100 — which is what this does.
    /// Peers that treat load ≥ 100 as "skip this node for now" work
    /// correctly against us because we never emit values above 100 here;
    /// our receive-side handlers also treat `load >= 100` as an
    /// informational bucket-full signal (see PublishRes handling).
    fn compute_load(&self) -> u8 {
        let ratio = (self.total_count as f64 / MAX_TOTAL_ENTRIES as f64)
            .max(self.total_retained_bytes as f64 / MAX_TOTAL_RETAINED_BYTES as f64);
        (ratio * 100.0).min(100.0) as u8
    }
}

#[cfg(test)]
mod keyword_store_tests {
    use super::*;

    fn entry(index: u16) -> PublishEntry {
        let mut id = [0u8; 16];
        id[..2].copy_from_slice(&index.to_le_bytes());
        PublishEntry {
            id: KadId(id),
            // Minimum viable content (filename + non-zero size) so these
            // synthetic entries pass `keyword_entry_has_min_content` and the
            // per-sender-cap tests below exercise the cap logic itself,
            // rather than being masked by the content gate.
            tags: vec![
                KadTag {
                    name: TagName::Id(TAG_FILENAME),
                    value: TagValue::String(format!("file-{index}.bin")),
                },
                KadTag {
                    name: TagName::Id(TAG_FILESIZE),
                    value: TagValue::Uint64(1024),
                },
            ],
        }
    }

    #[test]
    fn one_sender_cannot_monopolize_a_keyword_bucket() {
        let mut store = DhtStore::new();
        let target = KadId([0x11; 16]);
        let first_sender = KadId([0x22; 16]);
        let second_sender = KadId([0x33; 16]);

        let oversized_batch = (0..(MAX_KEYWORD_ENTRIES_PER_SENDER as u16 + 25))
            .map(entry)
            .collect();
        store.store_keyword_entries(&target, oversized_batch, &first_sender);
        store.store_keyword_entries(&target, vec![entry(500)], &second_sender);

        let bucket = store.keyword_entries.get(&target).unwrap();
        assert_eq!(
            bucket
                .iter()
                .filter(|stored| stored.source_id == first_sender)
                .count(),
            MAX_KEYWORD_ENTRIES_PER_SENDER
        );
        assert!(bucket
            .iter()
            .any(|stored| stored.source_id == second_sender));
    }

    /// eMule `CIndexed::AddKeyword` rejects an entry with no filename, no
    /// size, or no tags at all. Without an equivalent gate here, a
    /// malformed/malicious `PublishKeyReq` entry would be stored and later
    /// served back to real searchers via `search_keywords`.
    #[test]
    fn rejects_keyword_entry_with_no_tags() {
        let mut store = DhtStore::new();
        let target = KadId([0x55; 16]);
        let sender = KadId([0x66; 16]);
        store.store_keyword_entries(
            &target,
            vec![PublishEntry {
                id: KadId([0x77; 16]),
                tags: Vec::new(),
            }],
            &sender,
        );
        assert!(
            store.search_keywords(&target).is_empty(),
            "an entry with no tags at all must not be indexed"
        );
    }

    #[test]
    fn rejects_keyword_entry_missing_filename() {
        let mut store = DhtStore::new();
        let target = KadId([0x55; 16]);
        let sender = KadId([0x66; 16]);
        store.store_keyword_entries(
            &target,
            vec![PublishEntry {
                id: KadId([0x77; 16]),
                tags: vec![KadTag {
                    name: TagName::Id(TAG_FILESIZE),
                    value: TagValue::Uint64(1024),
                }],
            }],
            &sender,
        );
        assert!(
            store.search_keywords(&target).is_empty(),
            "an entry with no filename must not be indexed"
        );
    }

    #[test]
    fn rejects_keyword_entry_with_zero_filesize() {
        let mut store = DhtStore::new();
        let target = KadId([0x55; 16]);
        let sender = KadId([0x66; 16]);
        store.store_keyword_entries(
            &target,
            vec![PublishEntry {
                id: KadId([0x77; 16]),
                tags: vec![
                    KadTag {
                        name: TagName::Id(TAG_FILENAME),
                        value: TagValue::String("file.bin".to_string()),
                    },
                    KadTag {
                        name: TagName::Id(TAG_FILESIZE),
                        value: TagValue::Uint64(0),
                    },
                ],
            }],
            &sender,
        );
        assert!(
            store.search_keywords(&target).is_empty(),
            "an entry with a zero-byte size must not be indexed"
        );
    }

    #[test]
    fn accepts_keyword_entry_with_filename_and_size() {
        let mut store = DhtStore::new();
        let target = KadId([0x55; 16]);
        let sender = KadId([0x66; 16]);
        store.store_keyword_entries(&target, vec![entry(1)], &sender);
        assert_eq!(store.search_keywords(&target).len(), 1);
    }

    #[test]
    fn retained_byte_counter_tracks_replace_and_expiry_exactly() {
        let mut store = DhtStore::new();
        let target = KadId([0x70; 16]);
        let sender = KadId([0x71; 16]);
        store.store_keyword_entries(&target, vec![entry(1)], &sender);
        let first = store.keyword_entries[&target][0].retained_bytes;
        assert_eq!(store.total_retained_bytes, first);

        let mut replacement = entry(1);
        replacement.tags.push(KadTag {
            name: TagName::Str("format".to_string()),
            value: TagValue::String("application/octet-stream".repeat(20)),
        });
        store.store_keyword_entries(&target, vec![replacement], &sender);
        let second = store.keyword_entries[&target][0].retained_bytes;
        assert!(second > first);
        assert_eq!(store.total_retained_bytes, second);

        store.keyword_entries.get_mut(&target).unwrap()[0].stored_at = 0;
        store.cleanup_expired();
        assert_eq!(store.total_count, 0);
        assert_eq!(store.total_retained_bytes, 0);
    }

    #[test]
    fn rejects_oversized_stored_fields_without_leaving_bucket() {
        let mut store = DhtStore::new();
        let target = KadId([0x72; 16]);
        let sender = KadId([0x73; 16]);
        let mut oversized = entry(1);
        oversized.tags[0].value = TagValue::String("x".repeat(MAX_STORED_FILENAME_BYTES + 1));
        store.store_keyword_entries(&target, vec![oversized], &sender);
        assert!(!store.keyword_entries.contains_key(&target));
        assert_eq!(store.total_retained_bytes, 0);
    }

    #[test]
    fn keyword_publish_and_search_keep_emule_batch_and_page_sizes() {
        let mut store = DhtStore::new();
        let target = KadId([0x74; 16]);
        store.store_keyword_entries(&target, (0..150).map(entry).collect(), &KadId([0x75; 16]));
        store.store_keyword_entries(&target, (150..300).map(entry).collect(), &KadId([0x76; 16]));
        assert_eq!(
            store.keyword_entries[&target]
                .iter()
                .filter(|entry| entry.source_id == KadId([0x75; 16]))
                .count(),
            150
        );
        let page = store.search_keywords_page(&target, 25, 200, |_, _| true);
        assert_eq!(page.len(), 200);
    }
}

#[cfg(test)]
mod tolerance_tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn within_tolerance_accepts_lan_publisher_outside_xor_zone() {
        let mut store = DhtStore::new();
        // Local id far from target so chunk(0) exceeds SEARCH_TOLERANCE.
        store.set_local_id(KadId([0xFF; 16]));
        let target = KadId([0x00; 16]);
        assert!(
            !store.is_within_tolerance_for(&target, None),
            "target must be outside XOR tolerance for this setup"
        );
        assert!(
            store.is_within_tolerance_for(&target, Some(Ipv4Addr::new(192, 168, 1, 10))),
            "LAN publisher must bypass tolerance like eMule IsLANIP"
        );
        assert!(
            !store.is_within_tolerance_for(&target, Some(Ipv4Addr::new(8, 8, 8, 8))),
            "public IP outside zone must still be rejected"
        );
    }
}

#[cfg(test)]
mod source_store_tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn id_tag(id: u8, value: TagValue) -> KadTag {
        KadTag {
            name: TagName::Id(id),
            value,
        }
    }

    fn target() -> KadId {
        KadId([0x11; 16])
    }

    fn sender() -> KadId {
        KadId([0x22; 16])
    }

    #[test]
    fn rejects_source_publish_without_source_type() {
        let mut store = DhtStore::new();
        let tags = vec![
            id_tag(TAG_SOURCEPORT, TagValue::Uint16(4662)),
            id_tag(TAG_FILESIZE, TagValue::Uint64(1000)),
        ];
        store.store_source_entry(&target(), sender(), tags, Ipv4Addr::new(1, 2, 3, 4), 5000);
        assert!(
            store.search_sources(&target()).is_empty(),
            "a source publish without TAG_SOURCETYPE must not be indexed"
        );
    }

    #[test]
    fn rejects_source_publish_without_tcp_port() {
        let mut store = DhtStore::new();
        let tags = vec![
            id_tag(TAG_SOURCETYPE, TagValue::Uint8(1)),
            id_tag(TAG_FILESIZE, TagValue::Uint64(1000)),
        ];
        store.store_source_entry(&target(), sender(), tags, Ipv4Addr::new(1, 2, 3, 4), 5000);
        assert!(
            store.search_sources(&target()).is_empty(),
            "a source publish without TAG_SOURCEPORT must not be indexed"
        );
    }

    #[test]
    fn rejects_source_publish_with_zero_tcp_port() {
        let mut store = DhtStore::new();
        let tags = vec![
            id_tag(TAG_SOURCETYPE, TagValue::Uint8(1)),
            id_tag(TAG_SOURCEPORT, TagValue::Uint16(0)),
        ];
        store.store_source_entry(&target(), sender(), tags, Ipv4Addr::new(1, 2, 3, 4), 5000);
        assert!(
            store.search_sources(&target()).is_empty(),
            "a zero TAG_SOURCEPORT must be treated as missing and rejected"
        );
    }

    #[test]
    fn stores_valid_source_without_fabricating_tcp_port_from_udp() {
        let mut store = DhtStore::new();
        let tags = vec![
            id_tag(TAG_SOURCETYPE, TagValue::Uint8(1)),
            id_tag(TAG_SOURCEPORT, TagValue::Uint16(4662)),
            id_tag(TAG_FILESIZE, TagValue::Uint64(1000)),
        ];
        // No TAG_SOURCEUPORT -> UDP port falls back to the packet source port
        // (5000), matching eMule. The TCP port must stay the published 4662
        // and must never be fabricated from the UDP port.
        store.store_source_entry(&target(), sender(), tags, Ipv4Addr::new(1, 2, 3, 4), 5000);
        let results = store.search_sources(&target());
        assert_eq!(results.len(), 1, "valid source must be indexed");
        let entry = &results[0];
        let tcp = entry
            .tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Id(TAG_SOURCEPORT)))
            .and_then(|t| t.as_uint());
        let udp = entry
            .tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)))
            .and_then(|t| t.as_uint());
        assert_eq!(tcp, Some(4662), "published TCP port must be preserved");
        assert_eq!(udp, Some(5000), "UDP port falls back to the packet source");
    }

    /// eMule `Process_KADEMLIA2_PUBLISH_SOURCE_REQ` only honors an incoming
    /// `TAG_SOURCEUPORT` when it parses as non-zero
    /// (`pTag->IsInt() && (uint16)pTag->GetInt() > 0`); a present-but-zero
    /// tag is discarded and the packet's real source port is used instead.
    /// Checking mere presence (rather than a non-zero value) would let a
    /// publisher plant an unusable `0` UDP port that we'd then serve back
    /// to real searchers.
    #[test]
    fn zero_source_uport_tag_is_replaced_with_packet_source_port() {
        let mut store = DhtStore::new();
        let tags = vec![
            id_tag(TAG_SOURCETYPE, TagValue::Uint8(1)),
            id_tag(TAG_SOURCEPORT, TagValue::Uint16(4662)),
            id_tag(TAG_SOURCEUPORT, TagValue::Uint16(0)),
        ];
        store.store_source_entry(&target(), sender(), tags, Ipv4Addr::new(1, 2, 3, 4), 5000);
        let results = store.search_sources(&target());
        assert_eq!(results.len(), 1, "valid source must still be indexed");
        let udp = results[0]
            .tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Id(TAG_SOURCEUPORT)))
            .and_then(|t| t.as_uint());
        assert_eq!(
            udp,
            Some(5000),
            "an explicit zero UDP port tag must be replaced with the packet's real source port"
        );
    }
}

#[cfg(test)]
mod notes_store_tests {
    use super::*;

    fn id_tag(id: u8, value: TagValue) -> KadTag {
        KadTag {
            name: TagName::Id(id),
            value,
        }
    }

    fn target() -> KadId {
        KadId([0x33; 16])
    }

    fn sender() -> KadId {
        KadId([0x44; 16])
    }

    #[test]
    fn rejects_empty_note_with_no_comment_or_rating() {
        let mut store = DhtStore::new();
        let tags = vec![id_tag(TAG_FILERATING, TagValue::Uint8(0))];
        store.store_notes_entry(&target(), sender(), tags);
        assert!(
            store.search_notes(&target()).is_empty(),
            "a note with no comment and a zero rating must not be indexed"
        );
    }

    #[test]
    fn rejects_note_with_empty_comment_string() {
        let mut store = DhtStore::new();
        let tags = vec![id_tag(TAG_DESCRIPTION, TagValue::String(String::new()))];
        store.store_notes_entry(&target(), sender(), tags);
        assert!(
            store.search_notes(&target()).is_empty(),
            "an empty-string comment must not be treated as meaningful content"
        );
    }

    #[test]
    fn accepts_note_with_nonempty_comment() {
        let mut store = DhtStore::new();
        let tags = vec![id_tag(
            TAG_DESCRIPTION,
            TagValue::String("great file".to_string()),
        )];
        store.store_notes_entry(&target(), sender(), tags);
        assert_eq!(store.search_notes(&target()).len(), 1);
    }

    #[test]
    fn accepts_note_with_nonzero_rating() {
        let mut store = DhtStore::new();
        let tags = vec![id_tag(TAG_FILERATING, TagValue::Uint8(5))];
        store.store_notes_entry(&target(), sender(), tags);
        assert_eq!(store.search_notes(&target()).len(), 1);
    }
}
