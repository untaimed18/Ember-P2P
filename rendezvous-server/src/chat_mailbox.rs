//! Sealed store-and-forward for friend chat.
//!
//! A friend who is offline cannot be handed a message directly, so the sender
//! leaves it here and the recipient collects it later. The server is only a
//! shortcut: the sender keeps the message queued until the recipient's own
//! sealed receipt comes back, so an entry lost to a restart or a full box is
//! delivered directly the next time both are online.
//!
//! The server learns as little as the protocol allows:
//!
//! - A box is a 32-byte address only the two friends can derive (a pairwise
//!   X25519 secret, rotated daily). Nothing ties it to an Ember or Friend ID.
//! - Contents are sealed by the clients and padded to one of
//!   [`BLOB_SIZES`], so a length says little about the message.
//! - Knowing the address is the only authority. Entries go when collected,
//!   or after [`ITEM_TTL`] if they never are.
//! - Everything is in memory under hard caps, and nothing about a box is
//!   logged above `debug!`.

use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

use super::{
    client_network, extract_client_ip, rate_key, AppState, RateBucket, MAX_RATE_ENTRIES,
    RATE_WINDOW,
};

/// The only sizes a sealed entry may have. Clients pad to the smallest that
/// fits, so a message's length shows only as one of four buckets.
pub(crate) const BLOB_SIZES: [usize; 4] = [512, 1024, 2048, 4608];
/// How long an uncollected entry is kept: the sender's own queue gives up on
/// a message after the same week.
pub(crate) const ITEM_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Per box. A box is one sender's channel to one recipient for one day, so
/// this is a day's worth of chat between two people, not a quota on anyone.
pub(crate) const MAX_ITEMS_PER_BOX: usize = 64;
pub(crate) const MAX_BYTES_PER_BOX: usize = 256 * 1024;
/// Over every box. Past it, room is made by dropping the oldest entries of
/// the network holding the most, and a deposit from that network itself is
/// refused; the senders still hold their messages and deliver them directly.
pub(crate) const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;
/// Held at once for deposits from one network ([`quota_network`]). Leaving
/// an entry needs no key, so without this one source could fill the store
/// for everyone; with it and the eviction above, a flood from many networks
/// mostly displaces itself.
pub(crate) const MAX_BYTES_PER_NETWORK: usize = 4 * 1024 * 1024;
/// IPv6 prefix a deposit's held bytes are charged to.
const QUOTA_NETWORK_V6_PREFIX: u32 = 48;
/// A recipient asks for every friend's boxes over the last week in one call.
pub(crate) const MAX_BOXES_PER_FETCH: usize = 400;
/// Entries returned per fetch. The client asks again while `more` is set.
pub(crate) const MAX_ITEMS_PER_FETCH: usize = 32;
pub(crate) const MAX_IDS_PER_DELETE: usize = MAX_ITEMS_PER_BOX;

/// Mailbox requests per minute from one address ([`rate_key`]): a deposit per
/// message, plus a fetch and a few deletes every few minutes.
pub(crate) const MAX_MAILBOX_REQUESTS_PER_MINUTE: u64 = 120;
/// Deposits per minute from one network ([`quota_network`]), so one /24 or
/// /48 cannot fill the store by spreading across its addresses.
pub(crate) const MAX_MAILBOX_PUTS_PER_NETWORK_PER_MINUTE: u64 = 600;

pub(crate) type BoxId = [u8; 32];
pub(crate) type ItemId = [u8; 16];

struct Item {
    id: ItemId,
    blob: Vec<u8>,
    expires_at: Instant,
    /// The depositor's network, charged for the entry until it goes. Kept in
    /// memory only, for the quota, and never logged.
    network: IpAddr,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PutError {
    BadSize,
    BoxFull,
    StoreFull,
    NetworkFull,
}

/// The block a deposit's held bytes are charged to: the /24
/// [`client_network`] uses for IPv4, but a /48 for IPv6, the allocation one
/// site is commonly given, so a site cannot claim a share per /64 it holds.
pub(crate) fn quota_network(ip: IpAddr) -> IpAddr {
    match client_network(ip) {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(
            u128::from(v6) & (u128::MAX << (128 - QUOTA_NETWORK_V6_PREFIX)),
        )),
        v4 => v4,
    }
}

#[derive(Default)]
pub(crate) struct ChatMailboxStore {
    boxes: HashMap<BoxId, VecDeque<Item>>,
    total_bytes: usize,
    network_bytes: HashMap<IpAddr, usize>,
    /// Each network's entries in the order they were left, for dropping its
    /// oldest when the store is full. Entries already gone are skipped then,
    /// and cleared out when the network holds nothing, or at the sweep.
    network_order: HashMap<IpAddr, VecDeque<(BoxId, ItemId)>>,
}

impl ChatMailboxStore {
    pub(crate) fn put(
        &mut self,
        mailbox: BoxId,
        id: ItemId,
        blob: Vec<u8>,
        network: IpAddr,
        now: Instant,
    ) -> Result<(), PutError> {
        if !BLOB_SIZES.contains(&blob.len()) {
            return Err(PutError::BadSize);
        }
        let charged = self.network_bytes.get(&network).copied().unwrap_or(0);
        if charged + blob.len() > MAX_BYTES_PER_NETWORK {
            return Err(PutError::NetworkFull);
        }
        if let Some(items) = self.boxes.get(&mailbox) {
            let held: usize = items.iter().map(|item| item.blob.len()).sum();
            if items.len() >= MAX_ITEMS_PER_BOX || held + blob.len() > MAX_BYTES_PER_BOX {
                return Err(PutError::BoxFull);
            }
        }
        if !self.make_room(network, blob.len()) {
            return Err(PutError::StoreFull);
        }
        self.total_bytes += blob.len();
        *self.network_bytes.entry(network).or_insert(0) += blob.len();
        self.network_order
            .entry(network)
            .or_default()
            .push_back((mailbox, id));
        self.boxes.entry(mailbox).or_default().push_back(Item {
            id,
            blob,
            expires_at: now + ITEM_TTL,
            network,
        });
        Ok(())
    }

    /// Room for `needed` more bytes from `depositor`, dropping the oldest
    /// entries of whichever network holds the most. Never on behalf of a
    /// network that would then hold as much as the one it displaces, so
    /// equals cannot evict each other in turn. Decided before anything goes,
    /// so a deposit that is refused costs no one an entry.
    fn make_room(&mut self, depositor: IpAddr, needed: usize) -> bool {
        let over = (self.total_bytes + needed).saturating_sub(MAX_TOTAL_BYTES);
        if over == 0 {
            return true;
        }
        let charged = self.network_bytes.get(&depositor).copied().unwrap_or(0);
        let Some((&victim, &held)) = self.network_bytes.iter().max_by_key(|(_, bytes)| **bytes)
        else {
            return false;
        };
        // What the victim keeps at worst: `over`, plus one entry's overshoot.
        let largest = BLOB_SIZES[BLOB_SIZES.len() - 1];
        if victim == depositor || held <= charged + needed + over + largest {
            return false;
        }
        while self.total_bytes + needed > MAX_TOTAL_BYTES {
            if !self.evict_oldest(victim) {
                return false;
            }
        }
        true
    }

    fn evict_oldest(&mut self, network: IpAddr) -> bool {
        while let Some((mailbox, id)) = self
            .network_order
            .get_mut(&network)
            .and_then(VecDeque::pop_front)
        {
            let Some(items) = self.boxes.get_mut(&mailbox) else {
                continue;
            };
            let Some(item) = items
                .iter()
                .position(|item| item.id == id)
                .and_then(|at| items.remove(at))
            else {
                continue;
            };
            if items.is_empty() {
                self.boxes.remove(&mailbox);
            }
            self.total_bytes -= item.blob.len();
            Self::release(&mut self.network_bytes, &mut self.network_order, &item);
            return true;
        }
        false
    }

    fn release(
        network_bytes: &mut HashMap<IpAddr, usize>,
        network_order: &mut HashMap<IpAddr, VecDeque<(BoxId, ItemId)>>,
        item: &Item,
    ) {
        if let Some(bytes) = network_bytes.get_mut(&item.network) {
            *bytes = bytes.saturating_sub(item.blob.len());
            if *bytes == 0 {
                network_bytes.remove(&item.network);
                network_order.remove(&item.network);
            }
        }
    }

    /// Live entries in `boxes`, oldest first per box, at most `limit`. The
    /// flag says whether any were left out.
    pub(crate) fn fetch(
        &self,
        boxes: &[BoxId],
        now: Instant,
        limit: usize,
    ) -> (Vec<(BoxId, ItemId, Vec<u8>)>, bool) {
        let mut out = Vec::new();
        for mailbox in boxes {
            let Some(items) = self.boxes.get(mailbox) else {
                continue;
            };
            for item in items.iter().filter(|item| item.expires_at > now) {
                if out.len() >= limit {
                    return (out, true);
                }
                out.push((*mailbox, item.id, item.blob.clone()));
            }
        }
        (out, false)
    }

    /// Remove the named entries from one box. How many went.
    pub(crate) fn delete(&mut self, mailbox: &BoxId, ids: &[ItemId]) -> usize {
        let Some(items) = self.boxes.get_mut(mailbox) else {
            return 0;
        };
        let before = items.len();
        let mut freed = 0usize;
        let network_bytes = &mut self.network_bytes;
        let network_order = &mut self.network_order;
        items.retain(|item| {
            let keep = !ids.contains(&item.id);
            if !keep {
                freed += item.blob.len();
                Self::release(network_bytes, network_order, item);
            }
            keep
        });
        let removed = before - items.len();
        if items.is_empty() {
            self.boxes.remove(mailbox);
        }
        self.total_bytes -= freed;
        removed
    }

    pub(crate) fn prune_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        let mut freed = 0usize;
        let network_bytes = &mut self.network_bytes;
        let network_order = &mut self.network_order;
        self.boxes.retain(|_, items| {
            items.retain(|item| {
                let keep = item.expires_at > now;
                if !keep {
                    removed += 1;
                    freed += item.blob.len();
                    Self::release(network_bytes, network_order, item);
                }
                keep
            });
            !items.is_empty()
        });
        self.total_bytes -= freed;
        // Drop the order's record of entries collected since the last sweep.
        let boxes = &self.boxes;
        self.network_order.retain(|_, order| {
            order.retain(|(mailbox, id)| {
                boxes
                    .get(mailbox)
                    .is_some_and(|items| items.iter().any(|item| item.id == *id))
            });
            !order.is_empty()
        });
        removed
    }

    pub(crate) fn item_count(&self) -> usize {
        self.boxes.values().map(VecDeque::len).sum()
    }

    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes
    }
}

fn parse_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = hex::decode(text.trim()).ok()?;
    <[u8; N]>::try_from(bytes).ok()
}

/// One request from `client_ip`. Deposits are also charged to its network.
async fn admit_mailbox_request(state: &AppState, client_ip: IpAddr, deposit: bool) -> bool {
    let now = Instant::now();
    let mut per_address = state.chat_mailbox_rate_limits.write().await;
    if !deposit {
        return per_address.charge(
            rate_key(client_ip),
            MAX_MAILBOX_REQUESTS_PER_MINUTE,
            RATE_WINDOW,
            now,
            MAX_RATE_ENTRIES,
        );
    }
    let mut per_network = state.chat_mailbox_network_rate_limits.write().await;
    admit_deposit(&mut per_address, &mut per_network, client_ip, now)
}

/// Charges both tiers only when both admit, for the reason
/// `admit_channel_create` gives.
fn admit_deposit(
    per_address: &mut RateBucket,
    per_network: &mut RateBucket,
    ip: IpAddr,
    now: Instant,
) -> bool {
    let address_key = rate_key(ip);
    let network_key = quota_network(ip);
    if per_address.exhausted(address_key, MAX_MAILBOX_REQUESTS_PER_MINUTE, RATE_WINDOW, now)
        || per_network.exhausted(
            network_key,
            MAX_MAILBOX_PUTS_PER_NETWORK_PER_MINUTE,
            RATE_WINDOW,
            now,
        )
    {
        return false;
    }
    let address_ok = per_address.charge(
        address_key,
        MAX_MAILBOX_REQUESTS_PER_MINUTE,
        RATE_WINDOW,
        now,
        MAX_RATE_ENTRIES,
    );
    let network_ok = per_network.charge(
        network_key,
        MAX_MAILBOX_PUTS_PER_NETWORK_PER_MINUTE,
        RATE_WINDOW,
        now,
        MAX_RATE_ENTRIES,
    );
    address_ok && network_ok
}

#[derive(Deserialize)]
pub(crate) struct PutRequest {
    #[serde(rename = "box")]
    mailbox: String,
    blob: String,
}

#[derive(Serialize)]
pub(crate) struct PutResponse {
    id: String,
}

pub(crate) async fn chat_mailbox_put(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<PutRequest>,
) -> Result<Json<PutResponse>, StatusCode> {
    let mailbox: BoxId = parse_fixed(&body.mailbox).ok_or(StatusCode::BAD_REQUEST)?;
    let blob = hex::decode(body.blob.trim()).map_err(|_| StatusCode::BAD_REQUEST)?;
    if !BLOB_SIZES.contains(&blob.len()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let client_ip = extract_client_ip(&headers, addr);
    if !admit_mailbox_request(&state, client_ip, true).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    let stored = state.chat_mailbox.write().await.put(
        mailbox,
        id,
        blob,
        quota_network(client_ip),
        Instant::now(),
    );
    match stored {
        Ok(()) => Ok(Json(PutResponse { id: hex::encode(id) })),
        Err(PutError::BadSize) => Err(StatusCode::BAD_REQUEST),
        Err(PutError::BoxFull | PutError::NetworkFull) => Err(StatusCode::INSUFFICIENT_STORAGE),
        Err(PutError::StoreFull) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

#[derive(Deserialize)]
pub(crate) struct FetchRequest {
    boxes: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct FetchedItem {
    #[serde(rename = "box")]
    mailbox: String,
    id: String,
    blob: String,
}

#[derive(Serialize)]
pub(crate) struct FetchResponse {
    items: Vec<FetchedItem>,
    /// More entries are waiting than one answer carries.
    more: bool,
}

pub(crate) async fn chat_mailbox_fetch(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<FetchRequest>,
) -> Result<Json<FetchResponse>, StatusCode> {
    if body.boxes.len() > MAX_BOXES_PER_FETCH {
        return Err(StatusCode::BAD_REQUEST);
    }
    let boxes: Vec<BoxId> = body
        .boxes
        .iter()
        .map(|text| parse_fixed(text))
        .collect::<Option<_>>()
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !admit_mailbox_request(&state, extract_client_ip(&headers, addr), false).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let (items, more) =
        state
            .chat_mailbox
            .read()
            .await
            .fetch(&boxes, Instant::now(), MAX_ITEMS_PER_FETCH);
    Ok(Json(FetchResponse {
        items: items
            .into_iter()
            .map(|(mailbox, id, blob)| FetchedItem {
                mailbox: hex::encode(mailbox),
                id: hex::encode(id),
                blob: hex::encode(blob),
            })
            .collect(),
        more,
    }))
}

#[derive(Deserialize)]
pub(crate) struct DeleteRequest {
    #[serde(rename = "box")]
    mailbox: String,
    ids: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct DeleteResponse {
    deleted: usize,
}

pub(crate) async fn chat_mailbox_delete(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<DeleteRequest>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    if body.ids.len() > MAX_IDS_PER_DELETE {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mailbox: BoxId = parse_fixed(&body.mailbox).ok_or(StatusCode::BAD_REQUEST)?;
    let ids: Vec<ItemId> = body
        .ids
        .iter()
        .map(|text| parse_fixed(text))
        .collect::<Option<_>>()
        .ok_or(StatusCode::BAD_REQUEST)?;
    if !admit_mailbox_request(&state, extract_client_ip(&headers, addr), false).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let deleted = state.chat_mailbox.write().await.delete(&mailbox, &ids);
    Ok(Json(DeleteResponse { deleted }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net() -> IpAddr {
        "8.8.8.0".parse().unwrap()
    }

    fn blob(size: usize, fill: u8) -> Vec<u8> {
        vec![fill; size]
    }

    #[test]
    fn only_bucket_sizes_are_stored() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        for size in BLOB_SIZES {
            assert!(store.put([1; 32], [size as u8; 16], blob(size, 0), net(), now).is_ok());
        }
        for size in [0, 511, 513, 4096, 4609, 8192] {
            assert_eq!(
                store.put([1; 32], [9; 16], blob(size, 0), net(), now),
                Err(PutError::BadSize),
                "{size}"
            );
        }
        assert_eq!(store.item_count(), BLOB_SIZES.len());
    }

    #[test]
    fn a_round_trip_returns_entries_until_they_are_deleted() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        store.put([1; 32], [1; 16], blob(512, 1), net(), now).unwrap();
        store.put([1; 32], [2; 16], blob(1024, 2), net(), now).unwrap();
        store.put([2; 32], [3; 16], blob(512, 3), net(), now).unwrap();

        let (items, more) = store.fetch(&[[1; 32], [9; 32]], now, MAX_ITEMS_PER_FETCH);
        assert!(!more);
        assert_eq!(items.len(), 2, "only the boxes asked for");
        assert_eq!(items[0].1, [1; 16], "oldest first");

        assert_eq!(store.delete(&[1; 32], &[[1; 16], [7; 16]]), 1, "only the named ids");
        let (items, _) = store.fetch(&[[1; 32]], now, MAX_ITEMS_PER_FETCH);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].1, [2; 16]);
        assert_eq!(store.total_bytes(), 1024 + 512);
        assert_eq!(store.delete(&[2; 32], &[[1; 16]]), 0, "an id from another box");
    }

    #[test]
    fn a_full_box_refuses_more_and_the_rest_are_unaffected() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        for i in 0..MAX_ITEMS_PER_BOX {
            store.put([1; 32], [i as u8; 16], blob(512, 0), net(), now).unwrap();
        }
        assert_eq!(
            store.put([1; 32], [200; 16], blob(512, 0), net(), now),
            Err(PutError::BoxFull)
        );
        assert!(store.put([2; 32], [1; 16], blob(512, 0), net(), now).is_ok());

        let mut bytes = ChatMailboxStore::default();
        let fits = MAX_BYTES_PER_BOX / 4608;
        for i in 0..fits {
            bytes.put([3; 32], [i as u8; 16], blob(4608, 0), net(), now).unwrap();
        }
        assert_eq!(
            bytes.put([3; 32], [99; 16], blob(4608, 0), net(), now),
            Err(PutError::BoxFull),
            "the byte cap binds before the item cap for large entries"
        );
    }

    #[test]
    fn the_store_refuses_entries_past_its_byte_cap() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        store.total_bytes = MAX_TOTAL_BYTES - 512;
        assert!(store.put([1; 32], [1; 16], blob(512, 0), net(), now).is_ok());
        assert_eq!(
            store.put([2; 32], [2; 16], blob(512, 0), net(), now),
            Err(PutError::StoreFull)
        );
    }

    #[test]
    fn one_network_cannot_hold_more_than_its_share() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        let fits = MAX_BYTES_PER_NETWORK / 4608;
        for i in 0..fits {
            let mailbox = [(i % 200) as u8; 32];
            store
                .put(mailbox, (i as u128).to_le_bytes(), blob(4608, 0), net(), now)
                .unwrap();
        }
        assert_eq!(
            store.put([250; 32], [250; 16], blob(4608, 0), net(), now),
            Err(PutError::NetworkFull)
        );
        let other: IpAddr = "9.9.9.0".parse().unwrap();
        assert!(store.put([250; 32], [250; 16], blob(4608, 0), other, now).is_ok());
        assert_eq!(store.delete(&[0; 32], &[0u128.to_le_bytes()]), 1);
        assert!(
            store.put([251; 32], [251; 16], blob(4608, 0), net(), now).is_ok(),
            "a collected entry frees its network's share"
        );
        let later = now + ITEM_TTL + Duration::from_secs(1);
        store.prune_expired(later);
        assert!(store.network_bytes.is_empty(), "expiry frees it too");
    }

    #[test]
    fn a_full_store_makes_room_from_the_network_holding_the_most() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        let heavy: IpAddr = "8.8.8.0".parse().unwrap();
        let light: IpAddr = "9.9.9.0".parse().unwrap();
        for i in 0..4u8 {
            store.put([i; 32], [i; 16], blob(4608, 0), heavy, now).unwrap();
        }
        store.put([9; 32], [9; 16], blob(512, 0), light, now).unwrap();
        store.delete(&[1; 32], &[[1; 16]]);
        // Everything else the store holds, as far as the cap is concerned.
        store.total_bytes = MAX_TOTAL_BYTES - 256;

        assert!(store.put([20; 32], [20; 16], blob(512, 0), light, now).is_ok());
        assert!(store.fetch(&[[0; 32]], now, MAX_ITEMS_PER_FETCH).0.is_empty(), "its oldest went");
        assert_eq!(store.fetch(&[[2; 32]], now, MAX_ITEMS_PER_FETCH).0.len(), 1, "only as much as needed");
        assert_eq!(store.network_bytes[&heavy], 2 * 4608);
        store.total_bytes = MAX_TOTAL_BYTES - 256;
        assert_eq!(
            store.put([21; 32], [21; 16], blob(2048, 0), heavy, now),
            Err(PutError::StoreFull),
            "the network holding the most is refused, not given another's room"
        );
        assert_eq!(
            store.put([22; 32], [22; 16], blob(4608, 0), light, now),
            Err(PutError::StoreFull),
            "nor one that would then hold as much"
        );
        assert_eq!(store.network_bytes[&heavy], 2 * 4608, "a refused deposit evicts nothing");

        store.prune_expired(now);
        assert_eq!(store.network_order[&heavy].len(), 2, "the sweep forgets what went");
        store.delete(&[2; 32], &[[2; 16]]);
        store.delete(&[3; 32], &[[3; 16]]);
        assert!(!store.network_order.contains_key(&heavy), "and so does holding nothing");
    }

    #[test]
    fn ipv6_deposits_share_a_quota_per_48() {
        let a: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let c: IpAddr = "2001:db8:2:1::1".parse().unwrap();
        assert_eq!(quota_network(a), quota_network(b));
        assert_ne!(quota_network(a), quota_network(c));
        assert_eq!(
            quota_network("8.8.8.8".parse().unwrap()),
            "8.8.8.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn expired_entries_are_neither_served_nor_kept() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        store.put([1; 32], [1; 16], blob(512, 0), net(), now).unwrap();
        let later = now + ITEM_TTL + Duration::from_secs(1);
        assert!(store.fetch(&[[1; 32]], later, MAX_ITEMS_PER_FETCH).0.is_empty());
        assert_eq!(store.prune_expired(later), 1);
        assert_eq!(store.item_count(), 0);
        assert_eq!(store.total_bytes(), 0);
    }

    #[test]
    fn a_fetch_is_capped_and_says_more_is_waiting() {
        let mut store = ChatMailboxStore::default();
        let now = Instant::now();
        for i in 0..(MAX_ITEMS_PER_FETCH + 3) {
            let mailbox = [(i % 2) as u8; 32];
            store.put(mailbox, [i as u8; 16], blob(512, 0), net(), now).unwrap();
        }
        let (items, more) = store.fetch(&[[0; 32], [1; 32]], now, MAX_ITEMS_PER_FETCH);
        assert_eq!(items.len(), MAX_ITEMS_PER_FETCH);
        assert!(more);
    }

    #[test]
    fn deposits_are_limited_per_address_and_per_network() {
        let mut per_address = RateBucket::default();
        let mut per_network = RateBucket::default();
        let now = Instant::now();
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        for _ in 0..MAX_MAILBOX_REQUESTS_PER_MINUTE {
            assert!(admit_deposit(&mut per_address, &mut per_network, ip, now));
        }
        assert!(!admit_deposit(&mut per_address, &mut per_network, ip, now));

        let mut per_address = RateBucket::default();
        let mut per_network = RateBucket::default();
        let mut admitted = 0;
        for host in 1..=255u8 {
            for _ in 0..10 {
                let ip = IpAddr::from([9, 9, 9, host]);
                if admit_deposit(&mut per_address, &mut per_network, ip, now) {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted, MAX_MAILBOX_PUTS_PER_NETWORK_PER_MINUTE,
            "one /24 shares a deposit budget"
        );

        let mut per_address = RateBucket::default();
        let mut per_network = RateBucket::default();
        let mut admitted = 0;
        for subnet in 0..=255u16 {
            for _ in 0..10 {
                let ip = IpAddr::from([0x2001, 0xdb8, 1, subnet, 0, 0, 0, 1]);
                if admit_deposit(&mut per_address, &mut per_network, ip, now) {
                    admitted += 1;
                }
            }
        }
        assert_eq!(
            admitted, MAX_MAILBOX_PUTS_PER_NETWORK_PER_MINUTE,
            "and so does one IPv6 /48 across its /64s"
        );
    }

    #[tokio::test]
    async fn the_endpoints_round_trip_a_sealed_entry() {
        let state = crate::relay_ticket_tests::test_state();
        let addr: SocketAddr = "8.8.8.8:1000".parse().unwrap();
        let mailbox = hex::encode([7u8; 32]);
        let put = chat_mailbox_put(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Json(PutRequest {
                mailbox: mailbox.clone(),
                blob: hex::encode(blob(1024, 5)),
            }),
        )
        .await
        .expect("stored")
        .0;

        let fetched = chat_mailbox_fetch(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Json(FetchRequest {
                boxes: vec![mailbox.clone()],
            }),
        )
        .await
        .expect("fetched")
        .0;
        assert_eq!(fetched.items.len(), 1);
        assert_eq!(fetched.items[0].id, put.id);
        assert_eq!(fetched.items[0].blob, hex::encode(blob(1024, 5)));

        let deleted = chat_mailbox_delete(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Json(DeleteRequest {
                mailbox: mailbox.clone(),
                ids: vec![put.id],
            }),
        )
        .await
        .expect("deleted")
        .0;
        assert_eq!(deleted.deleted, 1);
        assert_eq!(state.chat_mailbox.read().await.item_count(), 0);
    }

    #[tokio::test]
    async fn malformed_requests_are_refused_before_they_cost_anything() {
        let state = crate::relay_ticket_tests::test_state();
        let addr: SocketAddr = "8.8.8.8:1000".parse().unwrap();
        for (mailbox, blob_hex) in [
            ("zz".to_string(), hex::encode(blob(512, 0))),
            (hex::encode([1u8; 31]), hex::encode(blob(512, 0))),
            (hex::encode([1u8; 32]), hex::encode(blob(100, 0))),
            (hex::encode([1u8; 32]), "not hex".to_string()),
        ] {
            let result = chat_mailbox_put(
                State(state.clone()),
                ConnectInfo(addr),
                HeaderMap::new(),
                Json(PutRequest {
                    mailbox,
                    blob: blob_hex,
                }),
            )
            .await;
            assert_eq!(result.err(), Some(StatusCode::BAD_REQUEST));
        }
        let too_many = chat_mailbox_fetch(
            State(state.clone()),
            ConnectInfo(addr),
            HeaderMap::new(),
            Json(FetchRequest {
                boxes: vec![hex::encode([1u8; 32]); MAX_BOXES_PER_FETCH + 1],
            }),
        )
        .await;
        assert_eq!(too_many.err(), Some(StatusCode::BAD_REQUEST));
        assert!(
            state.chat_mailbox_rate_limits.read().await.entries.is_empty(),
            "nothing was charged"
        );
    }
}
