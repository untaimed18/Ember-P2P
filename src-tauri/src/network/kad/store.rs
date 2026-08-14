use std::collections::HashMap;
use std::mem::size_of;

use tracing::debug;

use super::messages::{PublishEntry, SearchResultEntry};
use super::types::*;

const MAX_ENTRIES_PER_KEY: usize = 1000;
const MAX_TOTAL_ENTRIES: usize = 50_000;
const MAX_TOTAL_RETAINED_BYTES: usize = 64 * 1024 * 1024;
/// Shares of [`MAX_TOTAL_RETAINED_BYTES`] reserved from the record types that
/// carry no per-publisher byte budget and are never evicted.
///
/// All three types draw on one byte cap, but only keyword records are charged to
/// a publisher (`keyword_publisher_usage`) and only keyword records can be shed
/// (`evict_keyword_bytes`). So whichever of the other two reached the cap first
/// locked the whole store: every later publish of any type was refused, for the
/// five hours a source record lives or the day a note does. Fencing them leaves
/// keyword publishing at least a quarter of the cap, inside which its own
/// budgets and eviction still apply.
const MAX_SOURCE_RETAINED_BYTES: usize = MAX_TOTAL_RETAINED_BYTES / 2;
/// Share of [`MAX_TOTAL_ENTRIES`] that source records may occupy.
///
/// The byte share above fences the dimension that does not bind. A source entry
/// is a handful of small tags, so 50,000 of them is roughly 17 MB: the shared
/// *count* cap is reached with the source byte share still half empty, and at
/// that point every keyword and notes publish is refused. Eviction cannot save
/// them either, because `evict_keyword_bytes` only sheds keyword entries and
/// source records are never evicted at all — so the store-wide lockout the byte
/// share was added to prevent stayed reachable through the count instead, for
/// the five hours a source record lives.
const MAX_SOURCE_TOTAL_ENTRIES: usize = MAX_TOTAL_ENTRIES / 2;
const MAX_NOTES_RETAINED_BYTES: usize = MAX_TOTAL_RETAINED_BYTES / 8;
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
/// Global budget for one publisher *across every keyword target*.
///
/// Every other keyword cap is per key, so nothing bounded what a single
/// publisher consumed in total. `is_within_tolerance_for` only checks XOR
/// distance to a target the publisher picks, and our `local_id` isn't
/// secret, so in-tolerance targets are trivial to mint: 16 of them at the
/// 2 MiB per-publisher-per-key allowance exhausted the whole 64 MiB store,
/// after which we refused every keyword, source and notes publish from
/// honest peers for the full 24-hour `KEYWORD_TTL_SECS` while still
/// advertising ourselves as a storage node. These mirror what the source
/// path already does per IP with `MAX_SOURCES_PER_IP`.
const MAX_KEYWORD_ENTRIES_PER_PUBLISHER: usize = 2_000;
const MAX_KEYWORD_BYTES_PER_PUBLISHER: usize = 4 * 1024 * 1024;
/// How many of a publisher's targets one eviction pass inspects. `targets`
/// is a hint that can name buckets the publisher no longer occupies, and
/// walking the whole keyword index on a packet path is the same O(n)-per-
/// datagram shape the flood-protection tables were fixed for.
const KEYWORD_EVICTION_TARGET_PROBES: usize = 4;
/// Entries one `PublishKeyReq` may shed in total. Budgeted per packet, not
/// per entry: a packet carries up to 300 entries, so a per-entry budget
/// would put the eviction scan itself back on the amplification menu.
const MAX_KEYWORD_EVICTIONS_PER_PUBLISH: usize = 8;
/// How long a keyword entry we're storing *for another node* survives
/// before we evict it. `publish::keyword_republish_interval` assumes
/// every other KAD node enforces this same TTL against entries *we*
/// publish, and caps its load-based backoff so we always renew before
/// theirs would expire — keep the two in sync if this changes.
pub(super) const KEYWORD_TTL_SECS: i64 = 86_400; // 24 hours
const SOURCE_TTL_SECS: i64 = 18_000; // 5 hours
const NOTES_TTL_SECS: i64 = 86_400; // 24 hours
const MAX_NOTES_PER_FILE: usize = 150;
/// Share of `MAX_TOTAL_ENTRIES` that stored notes may occupy.
///
/// Notes are the least load-bearing record type — losing one costs a comment or
/// a rating, where losing a source record costs a download and losing a keyword
/// record costs a search hit. Ring-fencing them means an unbudgeted notes flood
/// cannot deny the two that matter. See `store_notes_entry`.
const MAX_NOTES_TOTAL_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
pub struct StoredEntry {
    pub id: KadId,
    pub tags: Vec<KadTag>,
    pub stored_at: i64,
    pub ttl_secs: i64,
    /// The KAD ID of the node that published this entry (used for dedup).
    pub source_id: KadId,
    /// Source address of the packet that stored this keyword entry, i.e. the
    /// `keyword_publisher_usage` record its bytes are charged to. Source and
    /// notes entries take no part in that index and leave this `None`.
    publisher_ip: Option<std::net::Ipv4Addr>,
    retained_bytes: usize,
}

impl StoredEntry {
    pub fn is_expired(&self, now: i64) -> bool {
        now.saturating_sub(self.stored_at) >= self.ttl_secs
    }

    /// The `keyword_publisher_usage` record this entry's bytes are charged
    /// to. Every add, remove and rebuild has to agree on this or the global
    /// budget silently drifts, so derive it in one place from the entry
    /// itself rather than from whatever the current packet claims.
    fn keyword_budget_key(&self) -> PublisherKey {
        keyword_budget_key(&self.source_id, self.publisher_ip)
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

/// Who the *global* per-publisher keyword budget is charged to.
///
/// Not the `(ip, port)`-derived publisher id the per-key caps use: for any
/// peer not in our routing table that id is `md5(ip || port)`
/// (`resolve_keyword_publisher_id`), so rotating the UDP source port mints
/// unlimited distinct publisher identities from a single address — roughly
/// 25 ports is enough to place 50,000 entries and reach `MAX_TOTAL_ENTRIES`,
/// which is precisely the store-wide lockout the budget was added to prevent.
/// The source address can't be rotated without also giving up delivery, so
/// the global budget is charged to that, matching what the source path
/// already does with `MAX_SOURCES_PER_IP`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum PublisherKey {
    Ip(std::net::Ipv4Addr),
    /// Fallback when the caller has no source address. Reachable from tests
    /// only: the KAD socket is bound `AF_INET`, so the publish handler's
    /// `from_ip_v4` always yields an address. Even if an IPv6 source could
    /// arrive it would not be a bypass — `resolve_keyword_publisher_id`
    /// gives every non-IPv4 sender `KadId::zero()`, so they would all share
    /// one budget, which is stricter than a per-address one.
    Id(KadId),
}

fn keyword_budget_key(sender_id: &KadId, sender_ip: Option<std::net::Ipv4Addr>) -> PublisherKey {
    match sender_ip {
        Some(ip) => PublisherKey::Ip(ip),
        None => PublisherKey::Id(*sender_id),
    }
}

/// What one publisher is holding in the keyword index in total, so the
/// global per-publisher budget can be enforced without walking every bucket.
#[derive(Debug, Default)]
struct PublisherUsage {
    entries: usize,
    bytes: usize,
    /// Per-target entry counts for this publisher. Keeping counts rather than
    /// a plain set lets removals retire a target as soon as its final entry
    /// leaves, so eviction never wastes its bounded probe budget on a long
    /// prefix of expired names.
    targets: HashMap<KadId, usize>,
}

/// Fold a stored keyword entry into its publisher's global usage.
/// `freed_bytes` is the size of the entry it replaced, if any.
fn publisher_usage_add(
    usage: &mut HashMap<PublisherKey, PublisherUsage>,
    heaviest: &mut Option<PublisherKey>,
    publisher: &PublisherKey,
    target: &KadId,
    added_entries: usize,
    bytes: usize,
    freed_bytes: usize,
) {
    let record = usage.entry(*publisher).or_default();
    record.entries = record.entries.saturating_add(added_entries);
    record.bytes = record
        .bytes
        .saturating_sub(freed_bytes)
        .saturating_add(bytes);
    if added_entries > 0 {
        *record.targets.entry(*target).or_insert(0) += added_entries;
    } else {
        // An in-place refresh normally finds an existing count. Preserve a
        // minimally useful hint if a prior interrupted migration left the
        // derived index incomplete; the periodic rebuild will make it exact.
        record.targets.entry(*target).or_insert(1);
    }
    let record_bytes = record.bytes;

    // Cheap running "who is holding the most" hint. It can go stale when the
    // named publisher shrinks, but it always names a publisher that was the
    // heaviest at some point, and `cleanup_expired` recomputes it exactly —
    // that's enough to aim eviction while keeping this O(1) on the packet path.
    let heaviest_bytes = heaviest
        .as_ref()
        .and_then(|id| usage.get(id))
        .map_or(0, |record| record.bytes);
    if record_bytes > heaviest_bytes {
        *heaviest = Some(*publisher);
    }
}

/// Fold one removed keyword entry out of its publisher's global usage.
fn publisher_usage_remove(
    usage: &mut HashMap<PublisherKey, PublisherUsage>,
    heaviest: &mut Option<PublisherKey>,
    publisher: &PublisherKey,
    target: &KadId,
    bytes: usize,
) {
    let Some(record) = usage.get_mut(publisher) else {
        return;
    };
    record.entries = record.entries.saturating_sub(1);
    record.bytes = record.bytes.saturating_sub(bytes);
    if let Some(target_entries) = record.targets.get_mut(target) {
        *target_entries = target_entries.saturating_sub(1);
        if *target_entries == 0 {
            record.targets.remove(target);
        }
    }
    let drained = record.entries == 0;
    if drained {
        usage.remove(publisher);
        if heaviest.as_ref() == Some(publisher) {
            *heaviest = None;
        }
    }
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
    /// Keyword usage per publisher, summed across every target.
    keyword_publisher_usage: HashMap<PublisherKey, PublisherUsage>,
    /// Running hint at the publisher holding the most keyword bytes; the
    /// eviction target when the global byte cap is reached.
    heaviest_keyword_publisher: Option<PublisherKey>,
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
            keyword_publisher_usage: HashMap::new(),
            heaviest_keyword_publisher: None,
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

    /// `sender_ip` is the address the publish packet arrived from; the
    /// global per-publisher budget is charged to it (see `PublisherKey`).
    /// `None` means the caller has no address to charge — tests only, the
    /// publish handler always has one.
    pub fn store_keyword_entries(
        &mut self,
        target: &KadId,
        entries: Vec<PublishEntry>,
        sender_id: &KadId,
        sender_ip: Option<std::net::Ipv4Addr>,
    ) -> u8 {
        let now = chrono::Utc::now().timestamp();
        let budget_key = keyword_budget_key(sender_id, sender_ip);

        // Scoped so the bucket borrow ends before the global-budget
        // bookkeeping below, which needs `&mut self`.
        let mut expired: Vec<(PublisherKey, usize)> = Vec::new();
        {
            let bucket = self.keyword_entries.entry(*target).or_default();
            let len_before = bucket.len();
            let bytes_before = retained_bytes(bucket);
            bucket.retain(|e| {
                if e.is_expired(now) {
                    expired.push((e.keyword_budget_key(), e.retained_bytes));
                    false
                } else {
                    true
                }
            });
            self.total_count = self.total_count.saturating_sub(len_before - bucket.len());
            self.total_retained_bytes = self
                .total_retained_bytes
                .saturating_sub(bytes_before.saturating_sub(retained_bytes(bucket)));
        }
        for (publisher, bytes) in expired {
            publisher_usage_remove(
                &mut self.keyword_publisher_usage,
                &mut self.heaviest_keyword_publisher,
                &publisher,
                target,
                bytes,
            );
        }
        let mut sender_entry_count = self.keyword_entries.get(target).map_or(0, |bucket| {
            bucket
                .iter()
                .filter(|entry| entry.source_id == *sender_id)
                .count()
        });
        let mut eviction_budget = MAX_KEYWORD_EVICTIONS_PER_PUBLISH;

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

            // Shed the heaviest publisher's bulk rather than refusing every
            // publish once the store is full — see `evict_keyword_bytes`.
            // Done before the bucket is borrowed, and deliberately only when
            // a *global* cap is the blocker: the per-key and per-publisher
            // caps below are this publisher's own allowance and must not be
            // bought with somebody else's entries.
            //
            // Both global caps have to be gates here. `MAX_TOTAL_ENTRIES` is
            // shared across keyword, source and notes, and real entries run
            // 100-200 bytes, so the count cap binds at roughly 5-10 MB of the
            // 64 MiB byte cap: gating on bytes alone meant eviction never ran
            // at all and the full-store lockout it exists to prevent stayed
            // reachable for the whole `KEYWORD_TTL_SECS`.
            // Price the arriving publisher's *own* allowance first. Eviction
            // spends somebody else's entries, and the caps below belong to this
            // publisher, so an entry its own allowance refuses must cost nobody
            // anything. Checking them only after the eviction ran let a peer with
            // a deliberately small footprint shed up to
            // `MAX_KEYWORD_EVICTIONS_PER_PUBLISH` of the heaviest *other*
            // publisher's records per packet and then have its entry dropped by
            // the `continue`s further down — free, repeatable deletion of honest
            // records, against publishers that only republish every 20 hours.
            // Replacements are priced here too. Exempting them left the same
            // hole from the other side: a publisher republishing one entry near
            // `MAX_RETAINED_BYTES_PER_ENTRY` evicted for the byte delta and was
            // then refused by its own caps below, so the eviction bought nothing
            // and was never refunded.
            //
            // Every value read here predates the eviction, and eviction only ever
            // *removes* entries, so each is an upper bound on the post-eviction
            // state: whatever passes here still passes afterwards. That is what
            // lets both branches below re-check only the global caps — the ones
            // eviction exists to relieve — leaving a publisher's own allowance
            // decided in exactly one place.
            let replaced = self.keyword_entries.get(target).and_then(|bucket| {
                bucket
                    .iter()
                    .find(|e| e.id == entry.id && e.source_id == *sender_id)
                    .map(|e| (e.retained_bytes, e.keyword_budget_key()))
            });
            let is_replacement = replaced.is_some();
            {
                let existing = self.keyword_entries.get(target);
                let bucket_len = existing.map_or(0, |bucket| bucket.len());
                let key_bytes_now = existing.map_or(0, |bucket| retained_bytes(bucket));
                let publisher_bytes_now: usize = existing.map_or(0, |bucket| {
                    bucket
                        .iter()
                        .filter(|stored| stored.source_id == *sender_id)
                        .map(|stored| stored.retained_bytes)
                        .sum()
                });
                let usage = self.keyword_publisher_usage.get(&budget_key);
                let publisher_entries_now = usage.map_or(0, |usage| usage.entries);
                let publisher_total_bytes_now = usage.map_or(0, |usage| usage.bytes);
                // A replacement frees the bytes it already holds. It only keeps
                // its publisher-level credit while it stays on the same budget
                // key: a routing-table contact keeps its KAD id across an address
                // change, so an entry can be charged to a different key than the
                // packet arrives on, and it is landing on the new key for the
                // first time.
                let (old_bytes, same_budget_key) = match replaced {
                    Some((bytes, old_key)) => (bytes, old_key == budget_key),
                    None => (0, false),
                };
                let publisher_credit = if same_budget_key { old_bytes } else { 0 };
                if (!is_replacement
                    && (sender_entry_count >= MAX_KEYWORD_ENTRIES_PER_SENDER
                        || bucket_len >= MAX_ENTRIES_PER_KEY))
                    || ((!is_replacement || !same_budget_key)
                        && publisher_entries_now >= MAX_KEYWORD_ENTRIES_PER_PUBLISHER)
                    || key_bytes_now
                        .saturating_sub(old_bytes)
                        .saturating_add(entry_bytes)
                        > MAX_RETAINED_BYTES_PER_KEY
                    || publisher_bytes_now
                        .saturating_sub(old_bytes)
                        .saturating_add(entry_bytes)
                        > MAX_RETAINED_BYTES_PER_PUBLISHER_PER_KEY
                    || publisher_total_bytes_now
                        .saturating_sub(publisher_credit)
                        .saturating_add(entry_bytes)
                        > MAX_KEYWORD_BYTES_PER_PUBLISHER
                {
                    continue;
                }
            }

            let over_total_bytes =
                self.total_retained_bytes.saturating_add(entry_bytes) > MAX_TOTAL_RETAINED_BYTES;
            let over_total_count = self.total_count >= MAX_TOTAL_ENTRIES;
            if over_total_bytes || over_total_count {
                // A refresh of an entry we already hold costs no slot and only
                // the byte difference, so price it before deciding to evict.
                let replaced_bytes = replaced.map_or(0, |(bytes, _)| bytes);
                let needs_bytes = self
                    .total_retained_bytes
                    .saturating_sub(replaced_bytes)
                    .saturating_add(entry_bytes)
                    > MAX_TOTAL_RETAINED_BYTES;
                let needs_slot = over_total_count && !is_replacement;
                if (needs_bytes || needs_slot)
                    && self.evict_keyword_bytes(
                        entry_bytes.saturating_sub(replaced_bytes),
                        &mut eviction_budget,
                    )
                {
                    // Eviction may have taken entries this sender holds under
                    // this very target, so refresh the per-key tally.
                    sender_entry_count = self.keyword_entries.get(target).map_or(0, |bucket| {
                        bucket
                            .iter()
                            .filter(|stored| stored.source_id == *sender_id)
                            .count()
                    });
                }
            }

            let bucket = self.keyword_entries.entry(*target).or_default();
            if let Some(pos) = bucket
                .iter()
                .position(|e| e.id == entry.id && e.source_id == *sender_id)
            {
                let old_bytes = bucket[pos].retained_bytes;
                let old_key = bucket[pos].keyword_budget_key();
                let same_budget_key = old_key == budget_key;
                // Only the global cap is re-checked. This publisher's own
                // allowance — per key, per publisher-per-key, and per publisher,
                // including the credit an entry keeps only while it stays on the
                // same budget key — was priced above, before any eviction, and
                // eviction can only have moved those numbers down.
                if self
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
                bucket[pos].publisher_ip = sender_ip;
                self.total_retained_bytes = self
                    .total_retained_bytes
                    .saturating_sub(old_bytes)
                    .saturating_add(entry_bytes);
                if same_budget_key {
                    publisher_usage_add(
                        &mut self.keyword_publisher_usage,
                        &mut self.heaviest_keyword_publisher,
                        &budget_key,
                        target,
                        0,
                        entry_bytes,
                        old_bytes,
                    );
                } else {
                    // Netting the delta against the new key alone would
                    // leave the old key holding bytes and an entry count no
                    // stored entry points at, and the new key short by the
                    // same amount, until `cleanup_expired` rebuilt the index
                    // 300 seconds later — the short side is budget the
                    // publisher gets for free. Move the entry across.
                    publisher_usage_remove(
                        &mut self.keyword_publisher_usage,
                        &mut self.heaviest_keyword_publisher,
                        &old_key,
                        target,
                        old_bytes,
                    );
                    publisher_usage_add(
                        &mut self.keyword_publisher_usage,
                        &mut self.heaviest_keyword_publisher,
                        &budget_key,
                        target,
                        1,
                        entry_bytes,
                        0,
                    );
                }
            } else {
                // Skip *this* new entry when full, but keep scanning the rest
                // of the batch: later entries may be updates to existing records
                // (the branch above) which cost no capacity and must still
                // refresh `stored_at`, otherwise an active republish that
                // happens to include one over-cap new entry would let its other
                // (already-stored) entries expire.
                // As in the replacement branch, only the global caps are re-checked
                // here: everything this publisher is individually allowed was
                // priced before the eviction above.
                if self.total_count >= MAX_TOTAL_ENTRIES
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
                    publisher_ip: sender_ip,
                    retained_bytes: entry_bytes,
                });
                self.total_count += 1;
                self.total_retained_bytes += entry_bytes;
                sender_entry_count += 1;
                publisher_usage_add(
                    &mut self.keyword_publisher_usage,
                    &mut self.heaviest_keyword_publisher,
                    &budget_key,
                    target,
                    1,
                    entry_bytes,
                    0,
                );
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
        if self
            .keyword_entries
            .get(target)
            .is_some_and(|bucket| bucket.is_empty())
        {
            self.keyword_entries.remove(target);
        }

        self.compute_load()
    }

    /// Free keyword bytes by shedding the publisher currently holding the
    /// most, largest entry first (ties broken by the oldest `stored_at`, i.e.
    /// least recently refreshed). Returns whether anything was evicted.
    ///
    /// Called only when `MAX_TOTAL_RETAINED_BYTES` or `MAX_TOTAL_ENTRIES`
    /// would otherwise refuse a publish. Refusing outright is what let one
    /// publisher spreading 4 MiB across 16 self-chosen in-tolerance targets
    /// shut the keyword index down for honest peers for a full
    /// `KEYWORD_TTL_SECS`. Aiming at the heaviest
    /// publisher means the pressure lands on whoever is actually consuming
    /// the store, including the arriving publisher when that is them.
    fn evict_keyword_bytes(&mut self, needed: usize, budget: &mut usize) -> bool {
        let mut freed = 0usize;
        while freed < needed && *budget > 0 {
            let publisher = match self.heaviest_keyword_publisher {
                Some(publisher) => publisher,
                // The hint is cleared once its publisher is drained, and
                // `publisher_usage_add` only ever ratchets it upward, so
                // stopping here left eviction dead until the next
                // `cleanup_expired` recomputed it — a 300-second timer, during
                // which the store stayed full and refused everyone. Re-aim
                // exactly instead. This costs one pass over
                // `keyword_publisher_usage` per *drained publisher*, which
                // `MAX_KEYWORD_EVICTIONS_PER_PUBLISH` already bounds per
                // packet; it is not a per-packet cost.
                None => match self.recompute_heaviest_keyword_publisher() {
                    Some(publisher) => publisher,
                    None => break,
                },
            };
            let Some(bytes) = self.evict_one_keyword_entry(&publisher) else {
                break;
            };
            *budget -= 1;
            freed = freed.saturating_add(bytes);
        }
        freed > 0
    }

    /// Point `heaviest_keyword_publisher` at whoever actually holds the most
    /// keyword bytes right now, and return it.
    fn recompute_heaviest_keyword_publisher(&mut self) -> Option<PublisherKey> {
        self.heaviest_keyword_publisher = self
            .keyword_publisher_usage
            .iter()
            .max_by_key(|(_, record)| record.bytes)
            .map(|(publisher, _)| *publisher);
        self.heaviest_keyword_publisher
    }

    /// Drop `publisher`'s largest keyword entry among a bounded sample of the
    /// targets it holds. Returns the bytes reclaimed.
    fn evict_one_keyword_entry(&mut self, publisher: &PublisherKey) -> Option<usize> {
        let candidates: Vec<KadId> = self
            .keyword_publisher_usage
            .get(publisher)?
            .targets
            .keys()
            .take(KEYWORD_EVICTION_TARGET_PROBES)
            .copied()
            .collect();

        let mut stale: Vec<KadId> = Vec::new();
        // (target, index, bytes)
        let mut victim: Option<(KadId, usize, usize)> = None;
        for candidate in candidates {
            let best = self.keyword_entries.get(&candidate).and_then(|bucket| {
                bucket
                    .iter()
                    .enumerate()
                    .filter(|(_, stored)| stored.keyword_budget_key() == *publisher)
                    .max_by_key(|(_, stored)| (stored.retained_bytes, -stored.stored_at))
                    .map(|(index, stored)| (index, stored.retained_bytes))
            });
            match best {
                Some((index, bytes)) => {
                    if victim.map_or(true, |(_, _, best_bytes)| bytes > best_bytes) {
                        victim = Some((candidate, index, bytes));
                    }
                }
                // The publisher no longer occupies this target.
                None => stale.push(candidate),
            }
        }
        if let Some(record) = self.keyword_publisher_usage.get_mut(publisher) {
            for candidate in stale {
                record.targets.remove(&candidate);
            }
        }

        let (target, index, bytes) = victim?;
        let bucket = self.keyword_entries.get_mut(&target)?;
        bucket.remove(index);
        let emptied = bucket.is_empty();
        if emptied {
            self.keyword_entries.remove(&target);
        }
        self.total_count = self.total_count.saturating_sub(1);
        self.total_retained_bytes = self.total_retained_bytes.saturating_sub(bytes);
        publisher_usage_remove(
            &mut self.keyword_publisher_usage,
            &mut self.heaviest_keyword_publisher,
            publisher,
            &target,
            bytes,
        );
        Some(bytes)
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

        // `MAX_SOURCES_PER_IP` bounds one bucket, and the number of buckets is
        // not bounded — an in-tolerance target is free to pick — so it is not a
        // global per-publisher budget. Source records are never evicted and live
        // for five hours, so without a share of the byte cap one address could
        // take all of it and deny every keyword and notes publish too. Summed on
        // demand for the same reason the notes share is.
        let source_bytes_all: usize = self
            .source_entries
            .values()
            .map(|bucket| retained_bytes(bucket))
            .sum();
        let source_count_all: usize = self.source_entries.values().map(Vec::len).sum();

        let bucket = self.source_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        let bytes_before = retained_bytes(bucket);
        bucket.retain(|e| !e.is_expired(now));
        let removed = len_before - bucket.len();
        let pruned_bytes = bytes_before.saturating_sub(retained_bytes(bucket));
        let source_bytes_now = source_bytes_all.saturating_sub(pruned_bytes);
        let source_count_now = source_count_all.saturating_sub(removed);
        self.total_count = self.total_count.saturating_sub(removed);
        self.total_retained_bytes = self.total_retained_bytes.saturating_sub(pruned_bytes);
        let existing_pos = bucket.iter().position(|entry| entry.id == sender_id);

        if existing_pos.is_none()
            && (self.total_count >= MAX_TOTAL_ENTRIES
                || source_count_now >= MAX_SOURCE_TOTAL_ENTRIES
                || bucket.len() >= MAX_ENTRIES_PER_KEY)
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
            || source_bytes_now
                .saturating_sub(old_bytes)
                .saturating_add(entry_bytes)
                > MAX_SOURCE_RETAINED_BYTES
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
            publisher_ip: None,
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

        // Notes get their own share of the store rather than competing for the
        // shared entry cap.
        //
        // `sender_id` is a wire field and `target` only has to fall inside our
        // search tolerance, so one peer can mint a fresh entry *and* a fresh
        // bucket per packet; the per-target `MAX_NOTES_PER_FILE` bounds neither.
        // Unlike keywords (`keyword_publisher_usage`) and sources
        // (`MAX_SOURCES_PER_IP`), notes have no publisher accounting to charge,
        // and a note entry carries no publisher tag to count one from. Until it
        // does, this at least keeps the damage inside the notes budget: filling
        // it denies further notes, where filling the shared cap used to refuse
        // every new source record and start evicting honest keyword entries.
        //
        // Summed on demand rather than tracked: it is a few thousand `Vec::len`
        // reads on a path a peer can only reach 8–16 times per 15s, which is far
        // cheaper than keeping another counter correct across expiry, eviction
        // and overwrite.
        let notes_total: usize = self.notes_entries.values().map(Vec::len).sum();
        // `MAX_NOTES_TOTAL_ENTRIES` fences the entry *count* only, which is the
        // wrong dimension when the binding limit is bytes: a note may carry up
        // to `MAX_RETAINED_BYTES_PER_ENTRY`, so a few hundred fat notes reach
        // the shared byte cap while the count fence is still an order of
        // magnitude away. Notes are never evicted and live for a day, so that
        // refused every new source record and left keyword eviction with only
        // keyword bytes to shed — the store-wide lockout this share prevents.
        let notes_bytes_all: usize = self
            .notes_entries
            .values()
            .map(|bucket| retained_bytes(bucket))
            .sum();

        let bucket = self.notes_entries.entry(*target).or_default();
        let now = chrono::Utc::now().timestamp();

        let len_before = bucket.len();
        let bytes_before = retained_bytes(bucket);
        bucket.retain(|e| !e.is_expired(now));
        let removed = len_before - bucket.len();
        let pruned_bytes = bytes_before.saturating_sub(retained_bytes(bucket));
        let notes_bytes_now = notes_bytes_all.saturating_sub(pruned_bytes);
        self.total_count = self.total_count.saturating_sub(removed);
        self.total_retained_bytes = self.total_retained_bytes.saturating_sub(pruned_bytes);
        let existing_pos = bucket.iter().position(|entry| entry.id == sender_id);

        if existing_pos.is_none()
            && (self.total_count >= MAX_TOTAL_ENTRIES
                || notes_total.saturating_sub(removed) >= MAX_NOTES_TOTAL_ENTRIES
                || bucket.len() >= MAX_NOTES_PER_FILE)
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
            || notes_bytes_now
                .saturating_sub(old_bytes)
                .saturating_add(entry_bytes)
                > MAX_NOTES_RETAINED_BYTES
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
            publisher_ip: None,
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

        // Rebuild the per-publisher index from scratch: the incremental
        // updates on the publish path keep the counts exact, but this also
        // drops stale `targets` hints and re-establishes the heaviest-holder
        // hint that `evict_one_keyword_entry` aims with.
        self.keyword_publisher_usage.clear();
        for (target, entries) in &self.keyword_entries {
            for entry in entries {
                let record = self
                    .keyword_publisher_usage
                    .entry(entry.keyword_budget_key())
                    .or_default();
                record.entries += 1;
                record.bytes = record.bytes.saturating_add(entry.retained_bytes);
                *record.targets.entry(*target).or_insert(0) += 1;
            }
        }
        self.heaviest_keyword_publisher = self
            .keyword_publisher_usage
            .iter()
            .max_by_key(|(_, record)| record.bytes)
            .map(|(publisher, _)| *publisher);

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
    use std::net::Ipv4Addr;

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
        store.store_keyword_entries(&target, oversized_batch, &first_sender, None);
        store.store_keyword_entries(&target, vec![entry(500)], &second_sender, None);

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

    fn sized_entry(index: u16, filler: usize) -> PublishEntry {
        let mut entry = entry(index);
        entry.tags.push(KadTag {
            name: TagName::Str("filler".to_string()),
            value: TagValue::String("f".repeat(filler)),
        });
        entry
    }

    fn numbered_target(index: u16) -> KadId {
        let mut target = [0u8; 16];
        target[..2].copy_from_slice(&index.to_le_bytes());
        KadId(target)
    }

    /// Every other keyword cap is per key, so a publisher could spread its
    /// load over self-chosen in-tolerance targets and consume the whole
    /// store. The global per-publisher budget is what bounds that.
    #[test]
    fn one_publisher_cannot_spread_across_keys_to_exhaust_the_store() {
        let mut store = DhtStore::new();
        let publisher = KadId([0x81; 16]);
        let keys = MAX_KEYWORD_ENTRIES_PER_PUBLISHER / MAX_KEYWORD_ENTRIES_PER_SENDER + 3;
        for key in 0..keys {
            let batch = (0..MAX_KEYWORD_ENTRIES_PER_SENDER as u16)
                .map(entry)
                .collect();
            store.store_keyword_entries(&numbered_target(key as u16), batch, &publisher, None);
        }
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Id(publisher)].entries,
            MAX_KEYWORD_ENTRIES_PER_PUBLISHER,
            "the per-key caps must not add up to an unbounded global footprint"
        );

        // An honest publisher must still get in.
        let honest = KadId([0x82; 16]);
        let honest_target = KadId([0x99; 16]);
        store.store_keyword_entries(&honest_target, vec![entry(1)], &honest, None);
        assert_eq!(store.search_keywords(&honest_target).len(), 1);
    }

    /// Eviction spends another publisher's records, so it must not run for an
    /// entry this publisher's own allowance is going to refuse anyway. Both paths
    /// used to evict first and refuse afterwards, and an eviction is never
    /// refunded — free, repeatable deletion of honest records, aimed at whoever
    /// happens to be heaviest.
    #[test]
    fn a_publish_refused_by_its_own_allowance_evicts_nothing() {
        let mut store = DhtStore::new();
        let target = numbered_target(1);
        let greedy = KadId([0x92; 16]);

        // The greedy publisher's own entry, stored while the key still has room.
        let small = sized_entry(900, 100);
        store.store_keyword_entries(&target, vec![small.clone()], &greedy, None);

        // Fill this key to its byte cap with other publishers. That does two
        // things: growth under the key is now refused, and the heaviest publisher
        // — the one `evict_keyword_bytes` takes from — is somebody other than the
        // greedy one, without which this test would pass no matter what.
        for publisher in 0..6u8 {
            let filler = KadId([0xA0 + publisher; 16]);
            let batch: Vec<PublishEntry> = (0..MAX_KEYWORD_ENTRIES_PER_SENDER as u16)
                .map(|index| sized_entry(index, 8000))
                .collect();
            store.store_keyword_entries(&target, batch, &filler, None);
        }
        let heaviest = store
            .heaviest_keyword_publisher
            .expect("some publisher is heaviest");
        assert_ne!(
            heaviest,
            PublisherKey::Id(greedy),
            "eviction must be aimed at another publisher for this to prove anything"
        );

        // Park the store against the global byte cap so a publish has to evict to
        // make room, then offer a replacement the per-key byte cap refuses.
        store.total_retained_bytes = MAX_TOTAL_RETAINED_BYTES;
        let before: Vec<(KadId, KadId)> = store.keyword_entries[&target]
            .iter()
            .map(|stored| (stored.id, stored.source_id))
            .collect();

        store.store_keyword_entries(&target, vec![sized_entry(900, 8000)], &greedy, None);

        assert_eq!(
            store.keyword_entries[&target]
                .iter()
                .map(|stored| (stored.id, stored.source_id))
                .collect::<Vec<_>>(),
            before,
            "a refused publish must not have shed anybody's records"
        );
        let stored_small = store.keyword_entries[&target]
            .iter()
            .find(|stored| stored.id == small.id && stored.source_id == greedy)
            .expect("the original small entry survives");
        assert!(
            stored_small.retained_bytes < 8000,
            "and the refused replacement must not have been applied either"
        );
    }

    /// When the global byte cap blocks a publish we shed the heaviest
    /// publisher's largest entry rather than refusing everyone — otherwise
    /// whoever fills the store first locks it for a full `KEYWORD_TTL_SECS`.
    #[test]
    fn eviction_sheds_the_heaviest_publishers_largest_entry() {
        let mut store = DhtStore::new();
        let heavy = KadId([0x91; 16]);
        let light = KadId([0x92; 16]);
        let heavy_target = numbered_target(1);
        let light_target = numbered_target(2);

        store.store_keyword_entries(
            &heavy_target,
            vec![sized_entry(1, 1024), sized_entry(2, 8000)],
            &heavy,
            None,
        );
        store.store_keyword_entries(&light_target, vec![sized_entry(3, 512)], &light, None);
        assert_eq!(
            store.heaviest_keyword_publisher,
            Some(PublisherKey::Id(heavy))
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Id(heavy)].targets[&heavy_target],
            2,
            "per-target accounting must retain every entry under this key"
        );

        let bytes_before = store.total_retained_bytes;
        let mut budget = MAX_KEYWORD_EVICTIONS_PER_PUBLISH;
        assert!(store.evict_keyword_bytes(1, &mut budget));

        assert_eq!(
            store.search_keywords(&light_target).len(),
            1,
            "the light publisher must not pay for the heavy one's footprint"
        );
        let remaining = store.search_keywords(&heavy_target);
        assert_eq!(remaining.len(), 1);
        assert_eq!(
            remaining[0].id,
            entry(1).id,
            "the largest entry must be the one shed"
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Id(heavy)].targets[&heavy_target],
            1,
            "eviction must retire exactly one per-target usage count"
        );
        assert!(store.total_retained_bytes < bytes_before);
        assert_eq!(
            store.total_retained_bytes,
            store
                .keyword_publisher_usage
                .values()
                .map(|usage| usage.bytes)
                .sum::<usize>(),
            "eviction must keep the global and per-publisher counters in step"
        );
    }

    /// Draining the hinted publisher used to end the eviction pass, and
    /// because the hint only ratchets upward it stayed pinned to whoever was
    /// heaviest first — so the first publish needing space wiped an arbitrary
    /// early publisher and eviction then sat dead until the next
    /// `cleanup_expired` 300 seconds later.
    #[test]
    fn eviction_moves_to_the_next_heaviest_once_a_publisher_drains() {
        let mut store = DhtStore::new();
        let first = KadId([0xB1; 16]);
        let second = KadId([0xB2; 16]);
        let first_target = numbered_target(1);
        let second_target = numbered_target(2);

        store.store_keyword_entries(&first_target, vec![sized_entry(1, 4000)], &first, None);
        store.store_keyword_entries(
            &second_target,
            vec![sized_entry(2, 1000), sized_entry(3, 1000)],
            &second,
            None,
        );
        assert_eq!(
            store.heaviest_keyword_publisher,
            Some(PublisherKey::Id(first))
        );

        // One byte more than the hinted publisher holds, so draining it is
        // not enough and the pass has to find the next heaviest.
        let needed = store.keyword_publisher_usage[&PublisherKey::Id(first)].bytes + 1;
        let mut budget = MAX_KEYWORD_EVICTIONS_PER_PUBLISH;
        assert!(store.evict_keyword_bytes(needed, &mut budget));

        assert!(
            !store
                .keyword_publisher_usage
                .contains_key(&PublisherKey::Id(first)),
            "the hinted publisher must be drained first"
        );
        assert_eq!(
            store.search_keywords(&second_target).len(),
            1,
            "eviction must carry on into the next heaviest publisher \
             instead of stopping when the hint is cleared"
        );
    }

    /// `MAX_TOTAL_ENTRIES` is shared across keyword, source and notes, and
    /// realistic 100-200 byte entries reach it at roughly 5-10 MB — a
    /// fraction of the 64 MiB byte cap. Gating eviction on bytes alone meant
    /// it never ran, leaving the full-store lockout it exists to prevent
    /// reachable for a whole `KEYWORD_TTL_SECS`.
    #[test]
    fn eviction_runs_when_the_shared_entry_count_cap_is_reached() {
        let mut store = DhtStore::new();
        let hog = KadId([0xC1; 16]);
        let honest = KadId([0xC2; 16]);
        let hog_target = numbered_target(1);
        let honest_target = numbered_target(2);

        store.store_keyword_entries(
            &hog_target,
            vec![sized_entry(1, 2048), sized_entry(2, 2048)],
            &hog,
            None,
        );
        // Reaching 50,000 entries for real needs ~25 publishers at their full
        // per-publisher allowance; pin the counter so the test exercises the
        // gate rather than the fill.
        store.total_count = MAX_TOTAL_ENTRIES;

        store.store_keyword_entries(&honest_target, vec![entry(3)], &honest, None);
        assert_eq!(
            store.search_keywords(&honest_target).len(),
            1,
            "a full entry table must shed the heaviest publisher, not refuse everyone"
        );
        assert_eq!(
            store.search_keywords(&hog_target).len(),
            1,
            "exactly one of the heaviest publisher's entries pays for the slot"
        );
    }

    /// Eviction spends another publisher's entries, so it must not run for an
    /// entry the arriving publisher's *own* allowance is going to refuse. Checking
    /// those caps only afterwards let a peer with a small footprint delete honest
    /// records for free, once per entry, indefinitely.
    #[test]
    fn a_publisher_over_its_own_cap_evicts_nobody() {
        let mut store = DhtStore::new();
        let honest = KadId([0xD1; 16]);
        let attacker = KadId([0xD2; 16]);
        let honest_target = numbered_target(1);
        let attacker_target = numbered_target(2);

        // An honest publisher with bulk worth evicting.
        store.store_keyword_entries(
            &honest_target,
            vec![sized_entry(1, 2048), sized_entry(2, 2048)],
            &honest,
            None,
        );
        let honest_before = store.search_keywords(&honest_target).len();
        assert_eq!(honest_before, 2);

        // Saturate the attacker's own per-key bucket so any further new entry of
        // its own is refused, then force the global entry cap so eviction would
        // otherwise be considered.
        for index in 0..MAX_ENTRIES_PER_KEY {
            store
                .keyword_entries
                .entry(attacker_target)
                .or_default()
                .push(StoredEntry {
                    id: KadId([(index % 251) as u8; 16]),
                    tags: Vec::new(),
                    stored_at: chrono::Utc::now().timestamp(),
                    ttl_secs: KEYWORD_TTL_SECS,
                    source_id: attacker,
                    publisher_ip: Some(std::net::Ipv4Addr::new(10, 0, 0, 9)),
                    retained_bytes: 1,
                });
        }
        store.total_count = MAX_TOTAL_ENTRIES;

        store.store_keyword_entries(&attacker_target, vec![entry(9)], &attacker, None);

        assert_eq!(
            store.search_keywords(&honest_target).len(),
            honest_before,
            "an entry refused by its own publisher's caps must not cost another \
             publisher a record"
        );
    }

    #[test]
    fn publisher_usage_tracks_replace_and_expiry_exactly() {
        let mut store = DhtStore::new();
        let publisher = KadId([0xA1; 16]);
        let target = KadId([0xA2; 16]);

        store.store_keyword_entries(&target, vec![entry(1), entry(2)], &publisher, None);
        let key = PublisherKey::Id(publisher);
        assert_eq!(store.keyword_publisher_usage[&key].entries, 2);
        assert_eq!(
            store.keyword_publisher_usage[&key].bytes,
            store.total_retained_bytes
        );

        // Re-publishing an id we already hold replaces it rather than adding.
        store.store_keyword_entries(&target, vec![sized_entry(1, 256)], &publisher, None);
        assert_eq!(store.keyword_publisher_usage[&key].entries, 2);
        assert_eq!(
            store.keyword_publisher_usage[&key].bytes,
            store.total_retained_bytes
        );

        for stored in store.keyword_entries.get_mut(&target).unwrap() {
            stored.stored_at = 0;
        }
        store.cleanup_expired();
        assert!(store.keyword_publisher_usage.is_empty());
        assert_eq!(store.heaviest_keyword_publisher, None);
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
            None,
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
            None,
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
            None,
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
        store.store_keyword_entries(&target, vec![entry(1)], &sender, None);
        assert_eq!(store.search_keywords(&target).len(), 1);
    }

    #[test]
    fn retained_byte_counter_tracks_replace_and_expiry_exactly() {
        let mut store = DhtStore::new();
        let target = KadId([0x70; 16]);
        let sender = KadId([0x71; 16]);
        store.store_keyword_entries(&target, vec![entry(1)], &sender, None);
        let first = store.keyword_entries[&target][0].retained_bytes;
        assert_eq!(store.total_retained_bytes, first);

        let mut replacement = entry(1);
        replacement.tags.push(KadTag {
            name: TagName::Str("format".to_string()),
            value: TagValue::String("application/octet-stream".repeat(20)),
        });
        store.store_keyword_entries(&target, vec![replacement], &sender, None);
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
        store.store_keyword_entries(&target, vec![oversized], &sender, None);
        assert!(!store.keyword_entries.contains_key(&target));
        assert_eq!(store.total_retained_bytes, 0);
    }

    #[test]
    fn keyword_publish_and_search_keep_emule_batch_and_page_sizes() {
        let mut store = DhtStore::new();
        let target = KadId([0x74; 16]);
        store.store_keyword_entries(
            &target,
            (0..150).map(entry).collect(),
            &KadId([0x75; 16]),
            None,
        );
        store.store_keyword_entries(
            &target,
            (150..300).map(entry).collect(),
            &KadId([0x76; 16]),
            None,
        );
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

    /// Stand-in for `resolve_keyword_publisher_id`'s `md5(ip || port)`: a
    /// peer outside our routing table gets a different publisher id for
    /// every UDP source port it sends from.
    fn rotated_sender(port_index: u16) -> KadId {
        let mut id = [0xE0u8; 16];
        id[..2].copy_from_slice(&port_index.to_le_bytes());
        KadId(id)
    }

    /// Recompute the per-publisher index from the entries actually stored
    /// and compare. Drift is silent and one-sided in the attacker's favour:
    /// an under-count is budget nobody is charged for.
    fn assert_usage_matches_entries(store: &DhtStore) {
        let mut expected: HashMap<PublisherKey, (usize, usize)> = HashMap::new();
        for entries in store.keyword_entries.values() {
            for stored in entries {
                let slot = expected.entry(stored.keyword_budget_key()).or_default();
                slot.0 += 1;
                slot.1 += stored.retained_bytes;
            }
        }
        assert_eq!(
            store.keyword_publisher_usage.len(),
            expected.len(),
            "publisher index holds records no stored entry accounts for"
        );
        for (key, (entries, bytes)) in expected {
            let record = &store.keyword_publisher_usage[&key];
            assert_eq!(record.entries, entries, "entry count drifted for {key:?}");
            assert_eq!(record.bytes, bytes, "byte count drifted for {key:?}");
        }
    }

    /// The global budget used to be keyed on the `(ip, port)`-derived
    /// publisher id, so rotating the UDP source port minted a fresh budget
    /// per port: ~25 ports placed 50,000 entries and reached
    /// `MAX_TOTAL_ENTRIES` from one address, which is the store-wide lockout
    /// the budget exists to prevent.
    #[test]
    fn port_rotation_from_one_ip_cannot_exceed_the_publisher_budget() {
        let mut store = DhtStore::new();
        let attacker_ip = Ipv4Addr::new(203, 0, 113, 7);
        let ports = MAX_KEYWORD_ENTRIES_PER_PUBLISHER / MAX_KEYWORD_ENTRIES_PER_SENDER + 5;

        for port_index in 0..ports {
            let batch = (0..MAX_KEYWORD_ENTRIES_PER_SENDER as u16)
                .map(entry)
                .collect();
            store.store_keyword_entries(
                &numbered_target(port_index as u16),
                batch,
                &rotated_sender(port_index as u16),
                Some(attacker_ip),
            );
        }

        assert_eq!(
            store.keyword_publisher_usage.len(),
            1,
            "every rotated port must land on the one address's budget"
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Ip(attacker_ip)].entries,
            MAX_KEYWORD_ENTRIES_PER_PUBLISHER,
            "rotating the source port must not mint extra budget"
        );
        assert_usage_matches_entries(&store);

        // And the lockout the budget exists to prevent must not have happened.
        let honest_target = KadId([0x99; 16]);
        store.store_keyword_entries(
            &honest_target,
            vec![entry(1)],
            &KadId([0x9A; 16]),
            Some(Ipv4Addr::new(198, 51, 100, 4)),
        );
        assert_eq!(store.search_keywords(&honest_target).len(), 1);
    }

    #[test]
    fn separate_ips_keep_separate_publisher_budgets() {
        let mut store = DhtStore::new();
        let first_ip = Ipv4Addr::new(203, 0, 113, 7);
        let second_ip = Ipv4Addr::new(198, 51, 100, 4);
        let keys = MAX_KEYWORD_ENTRIES_PER_PUBLISHER / MAX_KEYWORD_ENTRIES_PER_SENDER + 2;

        for (index, ip) in [first_ip, second_ip].into_iter().enumerate() {
            for key in 0..keys {
                let batch = (0..MAX_KEYWORD_ENTRIES_PER_SENDER as u16)
                    .map(entry)
                    .collect();
                store.store_keyword_entries(
                    &numbered_target((index * keys + key) as u16),
                    batch,
                    &rotated_sender(index as u16),
                    Some(ip),
                );
            }
        }

        for ip in [first_ip, second_ip] {
            assert_eq!(
                store.keyword_publisher_usage[&PublisherKey::Ip(ip)].entries,
                MAX_KEYWORD_ENTRIES_PER_PUBLISHER,
                "one address exhausting its budget must not spend another's"
            );
        }
        assert_usage_matches_entries(&store);
    }

    #[test]
    fn ip_keyed_accounting_stays_exact_across_store_replace_evict_and_expire() {
        let mut store = DhtStore::new();
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let other_ip = Ipv4Addr::new(198, 51, 100, 4);
        let first_target = numbered_target(1);
        let second_target = numbered_target(2);

        // Two source ports from one address, so the two publishes share a
        // budget record but not a per-key sender id.
        store.store_keyword_entries(
            &first_target,
            vec![sized_entry(1, 1024), sized_entry(2, 4096)],
            &rotated_sender(1),
            Some(ip),
        );
        store.store_keyword_entries(
            &second_target,
            vec![sized_entry(3, 512)],
            &rotated_sender(2),
            Some(ip),
        );
        store.store_keyword_entries(
            &second_target,
            vec![sized_entry(4, 2048)],
            &rotated_sender(3),
            Some(other_ip),
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Ip(ip)].entries,
            3
        );
        assert_usage_matches_entries(&store);

        // Replace: same id and sender, more bytes.
        store.store_keyword_entries(
            &first_target,
            vec![sized_entry(1, 8192)],
            &rotated_sender(1),
            Some(ip),
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Ip(ip)].entries,
            3,
            "a replacement must not add a slot"
        );
        assert_usage_matches_entries(&store);

        let mut budget = MAX_KEYWORD_EVICTIONS_PER_PUBLISH;
        assert!(store.evict_keyword_bytes(1, &mut budget));
        assert_usage_matches_entries(&store);

        for entries in store.keyword_entries.values_mut() {
            for stored in entries {
                stored.stored_at = 0;
            }
        }
        store.cleanup_expired();
        assert!(store.keyword_publisher_usage.is_empty());
        assert_eq!(store.heaviest_keyword_publisher, None);
    }

    /// A routing-table contact keeps its KAD id across an address change, so
    /// a replacement can arrive on a different budget key than the entry it
    /// replaces. Netting the byte delta against the new key alone would
    /// strand bytes on the old one and short the new one — free budget.
    #[test]
    fn replacing_from_a_new_address_moves_the_entry_between_budgets() {
        let mut store = DhtStore::new();
        let contact = KadId([0xD1; 16]);
        let old_ip = Ipv4Addr::new(203, 0, 113, 7);
        let new_ip = Ipv4Addr::new(198, 51, 100, 4);
        let target = numbered_target(1);

        store.store_keyword_entries(&target, vec![sized_entry(1, 1024)], &contact, Some(old_ip));
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Ip(old_ip)].entries,
            1
        );

        store.store_keyword_entries(&target, vec![sized_entry(1, 4096)], &contact, Some(new_ip));
        assert_eq!(
            store.keyword_entries[&target].len(),
            1,
            "the address change must replace the entry, not duplicate it"
        );
        assert!(
            !store
                .keyword_publisher_usage
                .contains_key(&PublisherKey::Ip(old_ip)),
            "the old address must stop being charged for an entry it no longer holds"
        );
        assert_eq!(
            store.keyword_publisher_usage[&PublisherKey::Ip(new_ip)].entries,
            1
        );
        assert_usage_matches_entries(&store);
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
