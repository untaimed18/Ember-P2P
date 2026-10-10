//! Friends: endpoint reseeding, presence refresh, friend requests, and
//! rendezvous friend lookups.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Withdraw everything the network task holds for an identity that is no
/// longer a friend: sessions, online state, pending browses, attachment and
/// browse-scope state, and friend priority on their queue rows.
///
/// Shared by removal, blocking and their refusal of our request, which differ
/// only in why the friendship ended. The caller has already dropped the hash
/// from the friend sets.
pub(super) async fn forget_friend_network_state(
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    upload_queue: &ed2k::upload::UploadQueueRef,
    friend: [u8; 16],
    browse_error: &str,
) {
    ed2k::upload::revoke_all_secure_sessions(friend);
    state.online_friends.remove(&friend);
    let _ = retire_current_ember_session(&state.ember_sessions, friend).await;
    // A remove followed by a re-add must not wait out a stale search slot.
    state.outbound_session_tasks.remove(&friend);
    state.friend_reconnect_last.remove(&friend);
    state.recent_ember_chat.remove(&friend);
    super::browse::forget_friend_scope(friend);
    super::chat_attach::forget_friend(state, settings, &friend);

    if let Some(pending) = state.pending_browse_requests.remove(&friend) {
        for request in pending {
            let _ = app_handle.emit(
                "ember:browse-error",
                serde_json::json!({
                    "user_hash": hex::encode(friend),
                    "request_id": request.request_id,
                    "reason": browse_error,
                }),
            );
        }
    }

    // Queue entries outlive their originating TCP connection for eMule
    // seniority. Strip only the friend-priority bit; standard queue and
    // file-transfer behaviour and verified Ember accounting stay intact.
    let mut queue = upload_queue.lock().await;
    for entry in queue.iter_mut() {
        let matches_friend = entry.ember_pubkey.is_some_and(|pk| {
            crate::network::ember::crypto::verifying_key_from_bytes(&pk).is_some_and(|vk| {
                crate::network::ember::crypto::node_id_from_public_key(&vk) == friend
            })
        });
        if matches_friend {
            entry.is_friend_slot = false;
        }
    }
}

pub(super) fn matching_active_transfer_ids_for_hash(
    state: &NetworkState,
    transfer_manager: &TransferManager,
    file_hash_hex: &str,
) -> Vec<String> {
    state
        .active_source_senders.keys().filter_map(|tid| {
            transfer_manager
                .get_transfer(tid)
                .filter(|transfer| transfer.file_hash == file_hash_hex)
                .map(|_| tid.clone())
        })
        .collect()
}

/// After friend discovery learns a fresh dialable endpoint, relocate any
/// download sources already known for that peer and inject them into
/// active incomplete downloads. Closes the gap where `sources.met` still
/// holds a pre-relaunch IP:port while chat/browse already found the peer.
pub(super) async fn reseed_friend_endpoint(
    state: &mut NetworkState,
    source_manager: &Arc<RwLock<ed2k::sources::SourceManager>>,
    credit_manager: &Arc<RwLock<CreditManager>>,
    transfer_manager: &Arc<RwLock<TransferManager>>,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ember_hash: [u8; 16],
    peer_user_hash: Option<[u8; 16]>,
    ip: std::net::Ipv4Addr,
    port: u16,
) {
    if port == 0 || ip.is_unspecified() || crate::security::is_bogus_v4(ip) {
        return;
    }
    if state.ip_filter.is_blocked(ip) || state.banned_ips.contains(&ip) {
        return;
    }

    // Prefer an explicit Hello user_hash; otherwise use the credit binding
    // learned from a prior HELLO+hash↔pubkey check this session.
    let user_hash = match peer_user_hash.filter(|h| *h != [0u8; 16]) {
        Some(uh) => {
            // Read first so no friend-set lock is held across the credit write.
            // A binding to someone no longer a friend is stale and may move.
            let bound = credit_manager.read().await.persisted_ember_hash(&uh);
            let bound_to_other_friend = match bound {
                Some(other) if other != ember_hash => {
                    friend_hashes.read().await.contains(&other)
                }
                _ => false,
            };
            if !credit_manager
                .write()
                .await
                .claim_ember_hash(uh, ember_hash, |_| !bound_to_other_friend)
            {
                warn!(
                    "Friend {} claims eD2K user hash {}, which is bound to another friend; \
                     not relocating its sources",
                    crate::security::short_hash(&ember_hash),
                    crate::security::short_hash(&uh)
                );
                return;
            }
            uh
        }
        None => match credit_manager
            .read()
            .await
            .find_user_hash_by_ember(&ember_hash)
        {
            Some(uh) => uh,
            None => {
                debug!(
                    "Friend endpoint reseed for {}:{} skipped — no eD2K user_hash bound to {}",
                    ip,
                    port,
                    hex::encode(ember_hash)
                );
                return;
            }
        },
    };

    let relocated = {
        let mut sm = source_manager.write().await;
        sm.relocate_user_hash(user_hash, ip, port)
    };
    if relocated.is_empty() {
        debug!(
            "Friend endpoint {}:{} for {} — no sources.met rows to relocate",
            ip,
            port,
            hex::encode(ember_hash)
        );
        return;
    }

    let mut file_hashes = std::collections::HashSet::new();
    for (file_hash, old_ip, old_port) in &relocated {
        file_hashes.insert(*file_hash);
        // `relocate_user_hash` reports the *current* address when the peer was
        // already at this endpoint (deliberately — see its doc and
        // `relocate_user_hash_moves_endpoint_and_reports_old`), so `old ==
        // new` means nothing actually moved. Clearing the dead-source entries
        // in that case removed the last rate brake on a peer we may have just
        // failed against, on every repeat friend hello or reconnect. A real
        // relocation still clears both endpoints: the old address's block says
        // nothing about the new one.
        if (*old_ip, *old_port) == (ip, port) {
            continue;
        }
        state.dead_sources.remove(0, u32::from(*old_ip), *old_port);
        state
            .dead_sources
            .remove_for_file(file_hash, u32::from(*old_ip), *old_port);
        state.dead_sources.remove(0, u32::from(ip), port);
        state
            .dead_sources
            .remove_for_file(file_hash, u32::from(ip), port);
    }

    let mgr = transfer_manager.read().await;
    let mut total_injected = 0usize;
    for file_hash in file_hashes {
        let hash_hex = hex::encode(file_hash);
        let matching_ids = matching_active_transfer_ids_for_hash(state, &mgr, &hash_hex);
        for tid in &matching_ids {
            if let Some(pfs) = state.per_file_sources.get_mut(tid) {
                let _ = pfs.relocate_user_hash(user_hash, ip, port);
            }
        }
        if matching_ids.is_empty() {
            continue;
        }
        let ds = ed2k::multi_source::DownloadSource {
            peer_ip: ip.to_string(),
            peer_port: port,
            available_parts: Vec::new(),
            peer_user_hash: Some(user_hash),
            peer_connect_options: source_manager
                .read()
                .await
                .get_connect_options(&file_hash, ip, port),
        };
        let stats = inject_source_into_active_transfers(state, file_hash, &matching_ids, &ds, 0);
        total_injected += stats.injected;
    }
    if total_injected > 0 {
        info!(
            "Reseeded friend {} at {}:{} into {} active download source injection(s)",
            hex::encode(ember_hash),
            ip,
            port,
            total_injected
        );
    } else {
        info!(
            "Relocated friend {} sources to {}:{} (no live transfer inject)",
            hex::encode(ember_hash),
            ip,
            port
        );
    }
}

/// How long a rendezvous presence registration is treated as fresh.
pub(super) const PRESENCE_HEARTBEAT_SECS: u64 = 120;

/// How many friends the startup presence sweep looks up per bootstrap tick.
///
/// Every friend is queued once Ember has an external IP, but they go out a few
/// per 10s tick rather than all at once. A lookup is several signed HTTP round
/// trips to the rendezvous server — an identity lookup plus up to four
/// capability epochs — and nothing in that path handles a 429, so a lookup
/// refused for being one of two hundred simultaneous requests would surface as
/// a friend who is merely unreachable. Spread out, a large list still finishes
/// in well under two minutes.
pub(super) const INITIAL_FRIEND_SEARCH_PER_TICK: usize = 5;

/// Take the next slice of the startup presence sweep off `queue`, leaving the
/// rest in order for later ticks.
///
/// `skip` reports the friends nothing is owed for: unfriended mid-sweep,
/// already reachable, or a lookup already in flight from another path. Those
/// are dropped rather than deferred, and deliberately do not spend the per-tick
/// budget — a tick that finds four of its five already online should still send
/// a fifth lookup, or a mostly-online list would trickle out one useful lookup
/// per tick and take far longer than the list length suggests.
pub(super) fn drain_initial_friend_search(
    queue: &mut Vec<[u8; 16]>,
    per_tick: usize,
    skip: impl Fn(&[u8; 16]) -> bool,
) -> Vec<[u8; 16]> {
    let mut targets: Vec<[u8; 16]> = Vec::new();
    let mut deferred: Vec<[u8; 16]> = Vec::new();
    for fh in std::mem::take(queue) {
        if targets.len() >= per_tick {
            deferred.push(fh);
        } else if !skip(&fh) {
            targets.push(fh);
        }
    }
    *queue = deferred;
    targets
}

/// Longest the startup sweep waits, once our external IP is known, for the
/// rest of what a friend dial leans on. Past it the sweep runs regardless: a
/// rendezvous server that is down or a STUN probe that never answers must not
/// leave every friend unsearched until the five-minute auto-retry.
pub(super) const STARTUP_SWEEP_READY_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// Gap between the startup sweep's last lookup going out and its one
/// follow-up pass over whoever is still offline.
pub(super) const STARTUP_SWEEP_FOLLOWUP_AFTER: std::time::Duration =
    std::time::Duration::from_secs(60);

/// Whether the startup presence sweep can start.
///
/// It used to start the moment our external IP was known, which is the same
/// tick our first rendezvous registration goes out and usually before the NAT
/// probe has answered. A friend reachable by plain TCP came up; one behind a
/// NAT needs the hole-punch, which is ineligible without our external address
/// and QUIC endpoint, and a relay whose answer depends on our being
/// registered. So the sweep marked those friends offline, and they stayed that
/// way until the first auto-retry five minutes later — or until the user
/// pressed Reconnect, which by then found everything ready and worked.
pub(super) fn startup_sweep_ready(
    rendezvous_registered: bool,
    punch_inputs_ready: bool,
    waited: std::time::Duration,
) -> bool {
    (rendezvous_registered && punch_inputs_ready) || waited >= STARTUP_SWEEP_READY_WAIT
}

/// Floor on retrying a *failed* presence heartbeat. Successes keep using
/// [`PRESENCE_HEARTBEAT_SECS`] via [`should_refresh_presence`].
///
/// The first retry after a failure is one bootstrap tick (10s) so a
/// transient error recovers quickly. Subsequent failures double that
/// until the success-path interval, so a persistently down server is
/// not hit six times a minute forever.
pub(super) fn presence_failure_retry_secs(fail_streak: u32) -> u64 {
    let shift = fail_streak.saturating_sub(1).min(16);
    (10u64.saturating_mul(1u64 << shift)).min(PRESENCE_HEARTBEAT_SECS)
}

/// Whether the failure-path floor allows another heartbeat attempt.
///
/// `since_last_register == None` is the error case (the success clock was
/// cleared). `since_last_attempt == None` is the first retry, which is
/// allowed immediately.
pub(super) fn presence_failure_retry_due(
    since_last_register: Option<std::time::Duration>,
    since_last_attempt: Option<std::time::Duration>,
    fail_streak: u32,
) -> bool {
    if since_last_register.is_some() {
        return true;
    }
    since_last_attempt
        .map(|elapsed| {
            elapsed >= std::time::Duration::from_secs(presence_failure_retry_secs(fail_streak))
        })
        .unwrap_or(true)
}

/// Whether to publish our presence to the rendezvous server on this tick.
///
/// Keyed on having registered successfully at least once this session, not on
/// currently believing we still are. Failure clears the "registered" flag but
/// leaves this one set, and the initial-registration path is gated on this one
/// being unset — so keying the refresh on "registered" left no open path at
/// all, and a single failed heartbeat took the node off the rendezvous server
/// until the next reconnect.
pub(super) fn should_refresh_presence(
    presence_established: bool,
    register_in_flight: bool,
    since_last_register: Option<std::time::Duration>,
) -> bool {
    if !presence_established || register_in_flight {
        return false;
    }
    // `None` is the failure case: the clock is cleared whenever an attempt
    // comes back an error, which is precisely when another is wanted.
    since_last_register
        .map(|elapsed| elapsed >= std::time::Duration::from_secs(PRESENCE_HEARTBEAT_SECS))
        .unwrap_or(true)
}

/// Payload for `ember:friend-discoverable` after a successful classic
/// `/register`. Extra fields (`intro_ok`, pairwise counts, `reason`) are
/// ignored by the current frontend; `discoverable` stays true whenever
/// existing friends can still resolve us so the no-grace-period banner
/// is not tripped by a degraded-but-working intro failure.
/// Identity lookups spent per heartbeat on friends we hold no public key for.
/// Each is a rate-limited request on the same budget as the registration.
const HASH_ONLY_BACKFILL_PER_HEARTBEAT: usize = 3;
const HASH_ONLY_BACKFILL_BACKOFF_MIN: std::time::Duration = std::time::Duration::from_secs(10 * 60);
const HASH_ONLY_BACKFILL_BACKOFF_MAX: std::time::Duration =
    std::time::Duration::from_secs(6 * 3600);

/// Misses at the backoff cap (about a day's worth) before a friend stops
/// keeping the pubkey-derivable legacy intro published and is only looked up
/// weekly. In memory only, so a restart grants another day; the persisted
/// staleness test below is what bounds it across restarts.
const HASH_ONLY_GIVE_UP_MISSES_AT_CAP: u32 = 4;
const HASH_ONLY_GIVEN_UP_RETRY: std::time::Duration =
    std::time::Duration::from_secs(7 * 24 * 3600);
/// A mutual friend not seen for this long no longer keeps the legacy intro
/// published, whatever the lookups say.
const HASH_ONLY_STALE_AFTER_SECS: i64 = 14 * 24 * 3600;

#[derive(Debug, Clone, Copy)]
struct BackfillState {
    next: std::time::Instant,
    delay: std::time::Duration,
    misses_at_cap: u32,
}

impl BackfillState {
    fn given_up(&self) -> bool {
        self.misses_at_cap >= HASH_ONLY_GIVE_UP_MISSES_AT_CAP
    }
}

type BackfillBackoff = HashMap<[u8; 16], BackfillState>;

fn hash_only_backfill_backoff() -> &'static parking_lot::Mutex<BackfillBackoff> {
    static BACKOFF: std::sync::OnceLock<parking_lot::Mutex<BackfillBackoff>> =
        std::sync::OnceLock::new();
    BACKOFF.get_or_init(Default::default)
}

#[derive(Debug, Default)]
struct HashOnlyPlan {
    selection: rendezvous::HashOnlyFriends,
    /// Mutual keyless friends we no longer publish the legacy intro for.
    stranded: Vec<[u8; 16]>,
}

/// Decide, for friends we hold no key for, who to look up this round and who
/// still justifies publishing the legacy intro.
///
/// Only mutual friends count toward the latter. An outgoing request does
/// not need us findable: it is delivered by *our* lookups of them, and once
/// they accept they hold our key and we find them through the pairwise entry
/// they then register for us — at which point a session gives us theirs.
/// A mutual friend stops counting once stale or after repeated misses at the
/// backoff cap, so a deleted or long-gone account cannot keep our address
/// readable to everyone who knows our public key.
fn plan_hash_only_friends(
    friends: &[crate::storage::database::HashOnlyFriend],
    backoff: &mut BackfillBackoff,
    now: std::time::Instant,
    now_unix: i64,
) -> HashOnlyPlan {
    backoff.retain(|hash, _| friends.iter().any(|friend| friend.hash == *hash));
    let due = |hash: &[u8; 16]| backoff.get(hash).is_none_or(|state| now >= state.next);
    let backfill = friends
        .iter()
        .filter(|friend| friend.mutual)
        .chain(friends.iter().filter(|friend| !friend.mutual))
        .map(|friend| friend.hash)
        .filter(|hash| due(hash))
        .take(HASH_ONLY_BACKFILL_PER_HEARTBEAT)
        .collect();
    let mut plan = HashOnlyPlan::default();
    plan.selection.backfill = backfill;
    for friend in friends.iter().filter(|friend| friend.mutual) {
        let stale = now_unix.saturating_sub(friend.last_contact) > HASH_ONLY_STALE_AFTER_SECS;
        let given_up = backoff.get(&friend.hash).is_some_and(BackfillState::given_up);
        if stale || given_up {
            plan.stranded.push(friend.hash);
        } else {
            plan.selection.legacy_dependents.push(friend.hash);
        }
    }
    plan
}

fn note_hash_only_backfill_miss(
    backoff: &mut BackfillBackoff,
    hash: [u8; 16],
    now: std::time::Instant,
) {
    let state = backoff.entry(hash).or_insert(BackfillState {
        next: now,
        delay: std::time::Duration::ZERO,
        misses_at_cap: 0,
    });
    let was_given_up = state.given_up();
    if state.delay >= HASH_ONLY_BACKFILL_BACKOFF_MAX {
        state.misses_at_cap = state.misses_at_cap.saturating_add(1);
    }
    state.delay = if state.given_up() {
        HASH_ONLY_GIVEN_UP_RETRY
    } else if state.delay.is_zero() {
        HASH_ONLY_BACKFILL_BACKOFF_MIN
    } else {
        (state.delay * 2).min(HASH_ONLY_BACKFILL_BACKOFF_MAX)
    };
    state.next = now + state.delay;
    if state.given_up() && !was_given_up {
        info!(
            "Friend {}… has no public key on the rendezvous server after repeated lookups; no longer publishing the legacy intro for them",
            &hex::encode(hash)[..8]
        );
    }
}

/// One presence registration plus the friend bookkeeping around it: learn
/// keys for hash-only friends so pairwise presence covers them, and drop
/// intro secrets that pairwise presence has made redundant.
///
/// A friend's intro secret is only needed to find them before they add us
/// back. Once mutual *and* keyed on our side, the pairwise entry they
/// register for us is what we look up, so the secret is cleared. A mutual
/// friend with no key on our row keeps it until the backfill supplies one.
#[allow(clippy::too_many_arguments)]
pub(super) async fn register_presence(
    db: Arc<Database>,
    base_url: &str,
    ember_hash: &[u8; 16],
    port: u16,
    udp_port: u16,
    external_ip: std::net::Ipv4Addr,
    pubkey: &[u8; 32],
    secret_key: &[u8; 32],
    friend_identities: &[([u8; 16], [u8; 32])],
    channel_neighbors: &[([u8; 16], [u8; 32])],
) -> Result<rendezvous::RegistrationOutcome, String> {
    let db_read = db.clone();
    let (hash_only, cleared) = tokio::task::spawn_blocking(move || {
        let hash_only = db_read.get_hash_only_friends().unwrap_or_else(|e| {
            warn!("Failed to list friends without a public key: {e}");
            Vec::new()
        });
        let cleared = db_read
            .clear_keyed_mutual_friend_intro_secrets()
            .unwrap_or_else(|e| {
                debug!("Failed to clear redundant friend intro secrets: {e}");
                Vec::new()
            });
        (hash_only, cleared)
    })
    .await
    .unwrap_or_default();
    for hash in &cleared {
        crate::network::friend_intro::forget_friend_intro_secret(hash);
    }
    let plan = plan_hash_only_friends(
        &hash_only,
        &mut hash_only_backfill_backoff().lock(),
        std::time::Instant::now(),
        chrono::Utc::now().timestamp(),
    );

    let mut outcome = rendezvous::register(
        base_url,
        ember_hash,
        port,
        udp_port,
        external_ip,
        pubkey,
        secret_key,
        friend_identities,
        channel_neighbors,
        &plan.selection,
    )
    .await?;
    if !outcome.legacy_intro_ok {
        outcome.legacy_stranded_friends = plan
            .stranded
            .into_iter()
            .filter(|hash| !outcome.backfilled_pubkeys.iter().any(|(learned, _)| learned == hash))
            .collect();
    }

    {
        let mut backoff = hash_only_backfill_backoff().lock();
        let now = std::time::Instant::now();
        for (hash, _) in &outcome.backfilled_pubkeys {
            backoff.remove(hash);
        }
        for hash in &outcome.backfill_missed {
            note_hash_only_backfill_miss(&mut backoff, *hash, now);
        }
    }
    if !outcome.backfilled_pubkeys.is_empty() {
        let learned = outcome.backfilled_pubkeys.clone();
        let _ = tokio::task::spawn_blocking(move || {
            for (hash, key) in learned {
                if let Err(e) = db.set_friend_public_key(&hex::encode(hash), &key) {
                    warn!("Failed to store a backfilled friend public key: {e}");
                }
            }
        })
        .await;
        info!(
            "Rendezvous: learned {} friend public key(s); pairwise presence now covers them",
            outcome.backfilled_pubkeys.len()
        );
    }
    Ok(outcome)
}

pub(super) fn friend_discoverable_event(
    outcome: &rendezvous::RegistrationOutcome,
    initial: bool,
) -> serde_json::Value {
    let discoverable = !outcome.existing_friends_blocked();
    let mut payload = serde_json::json!({
        "discoverable": discoverable,
        "intro_ok": outcome.intro_ok,
        "sealed_intro": outcome.sealed_intro_ok,
        "legacy_intro": outcome.legacy_intro_ok,
        "pairwise_attempted": outcome.pairwise_attempted,
        "pairwise_failed": outcome.pairwise_failed,
    });
    if let Some(reason) = outcome.degraded_reason() {
        payload["reason"] = serde_json::Value::String(reason.to_string());
    }
    if !outcome.legacy_stranded_friends.is_empty() {
        payload["legacy_stranded_friends"] = outcome
            .legacy_stranded_friends
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .into();
    }
    // The friends store treats `discoverable: false` + `initial: true` as
    // confirmed failure and skips its 90s grace period. Only attach
    // `initial` in that genuine blocked case.
    if !discoverable {
        payload["initial"] = serde_json::Value::Bool(initial);
    }
    payload
}

const NEW_FRIEND_REQUEST_WINDOW: std::time::Duration = std::time::Duration::from_secs(600);
const NEW_FRIEND_REQUESTS_PER_IP: u32 = 3;
const NEW_VERIFIED_FRIEND_REQUESTS_TOTAL: u32 = 30;
const NEW_UNVERIFIED_FRIEND_REQUESTS_TOTAL: u32 = 30;

/// How many requests from identities not already pending we queue per window,
/// per source IP and in total. Each one is a row and a desktop notification,
/// and a fresh Ed25519 key costs nothing, so being verified does not stop a
/// flood. Unverified requests have their own total, so a flood of them cannot
/// use up the room genuine ones need. Charged only for requests actually
/// queued. Fixed windows: the per-IP map holds no more than the totals.
struct NewFriendRequestRate {
    window_start: std::time::Instant,
    verified: u32,
    unverified: u32,
    per_ip: HashMap<std::net::IpAddr, u32>,
}

impl NewFriendRequestRate {
    fn roll(&mut self, now: std::time::Instant) {
        if now.duration_since(self.window_start) >= NEW_FRIEND_REQUEST_WINDOW {
            self.window_start = now;
            self.verified = 0;
            self.unverified = 0;
            self.per_ip.clear();
        }
    }

    fn has_room(&mut self, ip: Option<std::net::IpAddr>, verified: bool, now: std::time::Instant) -> bool {
        self.roll(now);
        let total_full = if verified {
            self.verified >= NEW_VERIFIED_FRIEND_REQUESTS_TOTAL
        } else {
            self.unverified >= NEW_UNVERIFIED_FRIEND_REQUESTS_TOTAL
        };
        !total_full
            && ip.is_none_or(|ip| {
                self.per_ip.get(&ip).copied().unwrap_or(0) < NEW_FRIEND_REQUESTS_PER_IP
            })
    }

    fn charge(&mut self, ip: Option<std::net::IpAddr>, verified: bool, now: std::time::Instant) {
        self.roll(now);
        if verified {
            self.verified += 1;
        } else {
            self.unverified += 1;
        }
        if let Some(ip) = ip {
            *self.per_ip.entry(ip).or_insert(0) += 1;
        }
    }
}

static NEW_FRIEND_REQUEST_RATE: std::sync::LazyLock<parking_lot::Mutex<NewFriendRequestRate>> =
    std::sync::LazyLock::new(|| {
        parking_lot::Mutex::new(NewFriendRequestRate {
            window_start: std::time::Instant::now(),
            verified: 0,
            unverified: 0,
            per_ip: HashMap::new(),
        })
    });

/// Handle an inbound Ember friend request, shared by the download-side and
/// upload-side session event loops so the approval / auto-confirm / queue
/// policy can't drift between the two ingress paths (it previously lived as two
/// hand-maintained copies, which is how earlier divergences crept in).
///
/// `verified` is Ed25519 proof-of-possession on the emitting session
/// (`ember_auth_verified` / `secure_v2_authenticated`), including the
/// multi-source download path. Binding the advertised pubkey to ember_hash is
/// logged separately and is not enough: that check is replayable from a public
/// (pubkey, ember_hash) pair.
///
/// It only drives the DB row + UI verification badge for queued strangers.
/// Auto-promotion of an already-added (non-mutual) friend still requires
/// `verified` (Ed25519 PoP) so a hash-spoofing peer cannot force mutual
/// status. Adding them *was* the approval; their accept must not ask again.
pub(super) async fn process_inbound_friend_request(
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    online_friends: &mut HashMap<[u8; 16], i64>,
    mutual_friend_hashes: &crate::app_state::SharedFriendHashes,
    req_hash: [u8; 16],
    peer_pubkey: Option<[u8; 32]>,
    nickname: &str,
    peer_ip: &str,
    peer_port: u16,
    verified: bool,
) {
    enum FriendRequestDbOutcome {
        Blocked,
        AlreadyMutual,
        Promoted,
        PromotionSkipped,
        IgnoredUnverifiedReciprocal,
        RateLimited,
        NotQueued,
        Queued,
        Failed(String),
    }

    // Every wire ingress should already pass a bounded nickname, but keep the
    // durable/logging choke point defensive for future callers as well.
    let nickname = crate::security::sanitize_inbound_friend_nickname(nickname);
    let hash_hex = hex::encode(req_hash);
    info!(
        "Processing inbound friend request from {} (nickname_chars={}, ip={}:{}, verified={verified})",
        hash_hex,
        nickname.chars().count(),
        peer_ip,
        peer_port
    );
    let db_q = db.clone();
    let h_q = hash_hex.clone();
    let n_q = nickname.clone();
    let ip_q = peer_ip.to_string();
    let peer_pubkey_q = peer_pubkey;
    let db_outcome = tokio::task::spawn_blocking(move || {
        // Cheap early-out so a blocked identity costs nothing beyond this
        // lookup — no row, no notification, no reply confirming we are here.
        // Not the enforcement point: `add_friend_request` re-tests inside its
        // transaction, which is what makes the decision, so a lookup that
        // errors here merely forgoes the shortcut rather than letting anyone
        // through.
        if db_q.is_friend_blocked(&h_q).unwrap_or(false) {
            return FriendRequestDbOutcome::Blocked;
        }
        let (is_friend, already_mutual) = db_q
            .get_friends_full()
            .ok()
            .and_then(|rows| {
                rows.into_iter()
                    .find(|(h, ..)| h == &h_q)
                    .map(|(_, _, _, _, _, _, mutual)| (true, mutual))
            })
            .unwrap_or((false, false));
        if already_mutual {
            // Leftover queue rows from the old double-approval path.
            let _ = db_q.remove_friend_request(&h_q);
            FriendRequestDbOutcome::AlreadyMutual
        } else if is_friend && verified {
            // Reciprocal of an add we initiated: that add was the approval.
            // Still require Ed25519 PoP so a spoofed hash cannot promote a
            // listed friend to mutual.
            match db_q.set_friend_mutual(&h_q, &ip_q, peer_port, peer_pubkey_q.as_ref()) {
                Ok(n) if n > 0 => FriendRequestDbOutcome::Promoted,
                Ok(_) => FriendRequestDbOutcome::PromotionSkipped,
                Err(e) => FriendRequestDbOutcome::Failed(e.to_string()),
            }
        } else if is_friend {
            // Already added, but this session has no PoP — do not auto-promote
            // and do not ask again. A later verified session completes it.
            FriendRequestDbOutcome::IgnoredUnverifiedReciprocal
        } else {
            // A repeat from a sender already pending only refreshes its row.
            let source_ip: Option<std::net::IpAddr> = ip_q.parse().ok();
            let is_new = !db_q.has_friend_request(&h_q).unwrap_or(false);
            if is_new
                && !NEW_FRIEND_REQUEST_RATE
                    .lock()
                    .has_room(source_ip, verified, std::time::Instant::now())
            {
                return FriendRequestDbOutcome::RateLimited;
            }
            match db_q.add_friend_request(
                &h_q,
                peer_pubkey_q.as_ref(),
                &n_q,
                &ip_q,
                peer_port,
                verified,
            ) {
                Ok(true) => {
                    if is_new {
                        NEW_FRIEND_REQUEST_RATE.lock().charge(
                            source_ip,
                            verified,
                            std::time::Instant::now(),
                        );
                    }
                    FriendRequestDbOutcome::Queued
                }
                // Blocked between the check above and the insert, or the
                // table is full of requests this one may not displace.
                Ok(false) => FriendRequestDbOutcome::NotQueued,
                Err(e) => FriendRequestDbOutcome::Failed(e.to_string()),
            }
        }
    })
    .await
    .unwrap_or_else(|e| {
        FriendRequestDbOutcome::Failed(format!("friend-request DB task failed: {e}"))
    });

    match db_outcome {
        FriendRequestDbOutcome::Blocked => {
            debug!("Dropping friend request from blocked identity {}", hash_hex);
        }
        FriendRequestDbOutcome::AlreadyMutual => {
            info!(
                "Friend {} already mutual — ignoring redundant EmberFriendRequest",
                hash_hex
            );
        }
        FriendRequestDbOutcome::Promoted => {
            // Auto-confirm: the user already added this peer, so a reciprocal
            // request upgrades the friendship to mutual without prompting.
            // Strangers (not already in our list) still fall through to the
            // approval queue — we never auto-add an unknown peer.
            info!(
                "Auto-confirming friend {} (already added; their accept completes it)",
                hash_hex
            );
            // The DB row is now mutual, so grant browse / friends-only access
            // on the live set the wire consults.
            mutual_friend_hashes.write().await.insert(req_hash);
            // `set_friend_mutual` refuses a blocked identity outright, so this
            // covers only a block or removal that commits after it and before
            // the line above. Reading after the grant rather than before is
            // what makes that safe: both write the database before clearing
            // this set, so either we see it here, or their teardown has still
            // to run and will clear the entry itself.
            let db_b = db.clone();
            let h_b = hash_hex.clone();
            let still_mutual =
                tokio::task::spawn_blocking(move || db_b.is_unblocked_mutual_friend(&h_b))
                    .await
                    .map(|r| r.unwrap_or(true))
                    .unwrap_or(true);
            if !still_mutual {
                mutual_friend_hashes.write().await.remove(&req_hash);
                debug!(
                    "Revoked auto-confirm for {} — removed or blocked mid-flight",
                    hash_hex
                );
                return;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = online_friends.entry(req_hash) {
                e.insert(chrono::Utc::now().timestamp());
                let _ = app_handle.emit(
                    "ember:friend-online",
                    serde_json::json!({
                        "user_hash": hash_hex,
                    }),
                );
            }
            let _ = app_handle.emit(
                "ember:friend-confirmed",
                serde_json::json!({
                    "user_hash": hash_hex,
                }),
            );
            // Separate from `friend-confirmed`, which every rediscovery sweep
            // emits for an already-live session: this fires only on the
            // promotion itself, so the notice can't repeat every few minutes.
            // Without it the accept the user was waiting for is silent.
            let _ = app_handle.emit(
                "ember:friend-auto-confirmed",
                serde_json::json!({
                    "user_hash": hash_hex,
                    "nickname": nickname,
                }),
            );
        }
        FriendRequestDbOutcome::PromotionSkipped => {
            debug!(
                "Friend {} promotion skipped because no DB row changed",
                hash_hex
            );
        }
        FriendRequestDbOutcome::IgnoredUnverifiedReciprocal => {
            debug!(
                "Ignoring unverified reciprocal friend request from {} (already added; waiting for PoP)",
                hash_hex
            );
        }
        FriendRequestDbOutcome::RateLimited => {
            debug!(
                "Dropping friend request from {} ({}): too many new requests",
                hash_hex, peer_ip
            );
        }
        FriendRequestDbOutcome::NotQueued => {
            debug!(
                "Friend request from {} not queued: blocked, or the request list is full",
                hash_hex
            );
        }
        FriendRequestDbOutcome::Queued => {
            debug!("Queuing friend request from {} for user approval", hash_hex);
            let _ = app_handle.emit(
                "ember:friend-request",
                serde_json::json!({
                    "sender_hash": hash_hex,
                    "nickname": nickname,
                    "verified": verified,
                }),
            );
        }
        FriendRequestDbOutcome::Failed(e) => {
            warn!("Failed to persist inbound friend request from {hash_hex}: {e}");
        }
    }
}

/// A friend request that reached us through room `channel_id` in an envelope
/// dated `sent_at`, from a member that room's roster holds.
///
/// Queued for the user like one from a session, and marked verified: the
/// sender's signature over this envelope is proof of the key. Held to the
/// stricter rules [`Database::add_room_friend_request`] applies, since any key
/// a room carries can send one. Nothing more than queueing: someone already on
/// our list registers presence for them, so our own lookup or theirs will open
/// the session that settles it, and promoting here would call a friend online
/// who has no session with us. `nickname` is what the room calls them, since
/// the request carries none.
pub(super) async fn process_room_friend_request(
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    sender_pubkey: [u8; 32],
    nickname: &str,
    channel_id: [u8; 16],
    sent_at: i64,
) {
    let Some(hash) = crate::network::ember::crypto::node_id_from_ed25519_bytes(&sender_pubkey)
    else {
        return;
    };
    let hash_hex = hex::encode(hash);
    let nickname = crate::security::sanitize_inbound_friend_nickname(nickname);
    let db_q = db.clone();
    let h_q = hash_hex.clone();
    let n_q = nickname.clone();
    let queued = tokio::task::spawn_blocking(move || {
        db_q.add_room_friend_request(
            &h_q,
            &sender_pubkey,
            &n_q,
            &hex::encode(channel_id),
            sent_at,
            chrono::Utc::now().timestamp(),
        )
        .unwrap_or_else(|e| {
            warn!("Failed to persist a friend request from a room: {e}");
            false
        })
    })
    .await
    .unwrap_or(false);
    if !queued {
        debug!(
            "Room friend request from {hash_hex} not queued (blocked, listed, refused, over the \
             room's share, or failed)"
        );
        return;
    }
    let _ = app_handle.emit(
        "ember:friend-request",
        serde_json::json!({
            "sender_hash": hash_hex,
            "nickname": nickname,
            "verified": true,
        }),
    );
}

/// Which verdict on a friend request a queued courier dial is carrying.
///
/// The two queues are separate tables and opposite directions of the same
/// pair, but everything between reading a row and clearing it is identical:
/// try the stored address, fall back to rendezvous, re-read the row in case
/// the user countermanded it, dial, clear on success.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FriendRequestVerdict {
    /// We sent them a request and are taking it back.
    Withdraw,
    /// They sent us a request and we are refusing it.
    Decline,
}

impl FriendRequestVerdict {
    pub(super) fn noun(self) -> &'static str {
        match self {
            Self::Withdraw => "withdrawal",
            Self::Decline => "decline",
        }
    }

    pub(super) fn still_owed(self, db: &Database, hash_hex: &str) -> bool {
        let rows = match self {
            Self::Withdraw => db.pending_friend_request_retractions(),
            Self::Decline => db.pending_friend_request_declines(),
        };
        rows.map(|rows| rows.iter().any(|(hash, ..)| hash == hash_hex))
            .unwrap_or(false)
    }

    pub(super) fn clear(self, db: &Database, hash_hex: &str) -> anyhow::Result<()> {
        match self {
            Self::Withdraw => db.clear_friend_request_retraction(hash_hex),
            Self::Decline => db.clear_friend_request_decline(hash_hex),
        }
    }
}

/// Deliver one queued friend-request verdict, clearing its row once it lands.
///
/// The stored address is where the peer answered when the request itself was
/// delivered, so it is worth trying first and costs nothing when it still holds.
/// The rendezvous fallback is what makes the queue worth keeping though: a peer
/// on a dynamic address, or one we never had an address for, would otherwise sit
/// in the queue until it expired and keep the stale request on their screen
/// for good. The lookup is keyed by identity alone and does not consult the
/// friend list, which matters because in both directions they are not a friend.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn deliver_friend_request_verdict(
    verdict: FriendRequestVerdict,
    db: Arc<Database>,
    rendezvous_url: String,
    hash_hex: String,
    target: [u8; 16],
    stored: Option<SocketAddr>,
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
) {
    let noun = verdict.noun();
    let mut already_tried: Option<SocketAddr> = None;
    for use_rendezvous in [false, true] {
        let addr = if use_rendezvous {
            match rendezvous::lookup(
                &rendezvous_url,
                &our_ember_hash,
                &ed25519_pubkey,
                &ed25519_secret_key,
                &target,
            )
            .await
            {
                Ok(Some((ip, port))) => Some(SocketAddr::new(ip.into(), port)),
                Ok(None) => {
                    debug!("Rendezvous has no address to deliver the {noun} to {hash_hex}");
                    None
                }
                Err(e) => {
                    debug!("Rendezvous lookup for the {noun} to {hash_hex} failed: {e}");
                    None
                }
            }
        } else {
            stored
        };
        let Some(addr) = addr else { continue };
        // The rendezvous commonly reports exactly the address we just failed on.
        if already_tried == Some(addr) {
            continue;
        }
        already_tried = Some(addr);
        // Re-read the row rather than trusting the one we were handed. Adding
        // that identity back clears the queue, and a dial started before the
        // re-add would otherwise land afterwards and retract the request the
        // new add had just sent.
        let db_check = db.clone();
        let hash_for_check = hash_hex.clone();
        let still_owed = tokio::task::spawn_blocking(move || {
            verdict.still_owed(&db_check, &hash_for_check)
        })
        .await
        .unwrap_or(false);
        if !still_owed {
            debug!("The {noun} to {hash_hex} was countermanded before it was sent");
            return;
        }
        let sent = match verdict {
            FriendRequestVerdict::Withdraw => {
                ed2k::friend_connect::send_friend_request_retraction(
                    addr,
                    target,
                    our_user_hash,
                    our_ember_hash,
                    our_nickname.clone(),
                    our_client_id,
                    tcp_port,
                    udp_port,
                    obfuscate,
                    Some(ed25519_pubkey),
                    Some(ed25519_secret_key),
                )
                .await
            }
            FriendRequestVerdict::Decline => {
                ed2k::friend_connect::send_friend_request_decline(
                    addr,
                    target,
                    our_user_hash,
                    our_ember_hash,
                    our_nickname.clone(),
                    our_client_id,
                    tcp_port,
                    udp_port,
                    obfuscate,
                    Some(ed25519_pubkey),
                    Some(ed25519_secret_key),
                )
                .await
            }
        };
        match sent {
            Ok(()) => {
                let _ =
                    tokio::task::spawn_blocking(move || verdict.clear(&db, &hash_hex)).await;
                return;
            }
            Err(e) => {
                debug!("The {noun} to {hash_hex} at {addr} did not land: {e}");
            }
        }
    }
}

/// Ask a friend the rendezvous could not find, and who has not added us back,
/// again through a room we share with them. Paced by
/// `commands::channels::send_room_friend_request`, since the retry sweep
/// that lands here runs every few minutes.
async fn ask_unmatched_friend_through_rooms(app_handle: &tauri::AppHandle, target_hash: [u8; 16]) {
    let Some(app_state) = app_handle.try_state::<crate::app_state::AppState>() else {
        return;
    };
    let db = app_state.db.clone();
    let hash_hex = hex::encode(target_hash);
    let pubkey = tokio::task::spawn_blocking(move || {
        let mutual = db
            .get_friends_full()
            .ok()?
            .into_iter()
            .find(|(hash, ..)| *hash == hash_hex)
            .map(|(.., mutual)| mutual)?;
        if mutual {
            return None;
        }
        db.get_friend_public_keys()
            .ok()?
            .into_iter()
            .find(|(hash, _)| *hash == target_hash)
            .map(|(_, key)| key)
    })
    .await
    .ok()
    .flatten();
    if let Some(pubkey) = pubkey {
        crate::commands::channels::send_room_friend_request(&app_state, pubkey, false).await;
    }
}

/// Spawn a rendezvous lookup for a single friend and attempt to connect if found.
pub(super) fn spawn_rendezvous_friend_lookup(
    settings: &AppSettings,
    state: &NetworkState,
    ember_hash: [u8; 16],
    target_hash: [u8; 16],
    app_handle: &tauri::AppHandle,
    friend_hashes: &crate::app_state::SharedFriendHashes,
    ul_event_tx: &mpsc::Sender<upload_server::UploadEvent>,
    ed25519_pubkey: [u8; 32],
    ed25519_secret_key: [u8; 32],
) {
    let rv_url = settings.rendezvous_url.clone();
    let our_uh = state.user_hash;
    let our_eh = ember_hash;
    let nick = settings.nickname.clone();
    let cid = state
        .external_ip
        .map(|eip| u32::from_le_bytes(eip.octets()))
        .unwrap_or(0);
    let tcp = advertised_tcp_port(state);
    let udp = advertised_udp_port(state);
    let obfuscate = settings.friend_session_encryption;
    let app_fc = app_handle.clone();
    let fh_fc = friend_hashes.clone();
    let sess_fc = state.ember_sessions.clone();
    let offline_fc = state.user_offline.clone();
    let ultx_fc = ul_event_tx.clone();
    // Ember NAT-fallback context for `connect_friend_with_fallback`: a
    // plain `TcpStream::connect` alone can't reach a friend whose NAT
    // doesn't forward the advertised port, which used to be a hard dead
    // end for this — the single choke point every offline-friend lookup
    // (initial burst, auto-retry, disconnect-reconnect, manual
    // find/retry commands) funnels through. Cloning the Arc (not its
    // contents) here is cheap and lets `connect_friend_with_fallback`
    // re-read the live values later instead of this snapshot going stale.
    let nat_ctx_fc = state.friend_nat_context.clone();

    tokio::spawn(async move {
        match rendezvous::lookup(
            &rv_url,
            &our_eh,
            &ed25519_pubkey,
            &ed25519_secret_key,
            &target_hash,
        )
        .await
        {
            Ok(Some((ip, port))) => {
                info!(
                    "Rendezvous found friend {} at {}:{}",
                    hex::encode(target_hash),
                    ip,
                    port
                );
                let addr = std::net::SocketAddr::new(ip.into(), port);
                // Relocate download sources ASAP — do not wait for a full
                // friend session / FriendSeen. Best-effort when we already
                // know their eD2K user_hash from a prior HELLO binding.
                let _ = ultx_fc
                    .send(upload_server::UploadEvent {
                        transfer_id: String::new(),
                        kind: upload_server::UploadEventKind::FriendEndpointDiscovered {
                            ember_hash: target_hash,
                            ip,
                            port,
                        },
                    })
                    .await;

                // Fast path: a persistent session for this peer is
                // already alive (e.g. an inbound `FriendSeen` path
                // opened it concurrently, or a previous discovery
                // round just landed). Emit `friend-confirmed` /
                // `friend-online` for visibility — both events are
                // idempotent in the frontend's Set-based handlers
                // — and don't dial again.
                if sess_fc
                    .read()
                    .await
                    .get(&target_hash)
                    .is_some_and(|h| h.is_fresh())
                {
                    let _ = app_fc.emit(
                        "ember:friend-confirmed",
                        serde_json::json!({
                            "user_hash": hex::encode(target_hash),
                        }),
                    );
                    let _ = app_fc.emit(
                        "ember:friend-online",
                        serde_json::json!({
                            "user_hash": hex::encode(target_hash),
                        }),
                    );
                } else {
                    // Single-dial discovery. Earlier this site ran a
                    // short-lived `connect_and_send_friend_request`
                    // first, then only opened the persistent
                    // session if the peer happened to send back a
                    // reciprocal `OP_EMBER_FRIEND_REQ` on that same
                    // TCP. That flow silently broke for already-
                    // mutual friends because the upload-side handler
                    // for `OP_EMBER_FRIEND_REQ` deliberately does
                    // nothing on a duplicate ("already mutual —
                    // ignoring redundant"), so the reciprocal never
                    // arrived, both peers' transient dials returned
                    // `Ok(None)`, and neither side ever opened the
                    // persistent session. The friend's transient
                    // *inbound* TCP would still grab our
                    // `ember_sessions` slot during its handshake,
                    // get torn down 8 s later when the friend's
                    // transient gave up waiting, and fire a
                    // spurious `EmberFriendDisconnected` —
                    // exactly the "shows them online then starts
                    // searching for them again" loop the user
                    // reported.
                    //
                    // `open_and_run_friend_session` already does the
                    // full handshake, sends the friend request as
                    // part of the session start (see
                    // `friend_connect.rs::open_and_run_friend_session`
                    // around the `OP_EMBER_FRIEND_REQ` write), and
                    // atomically reserves the `ember_sessions` slot
                    // before sending so a racing inbound transient
                    // dial sees the slot occupied and bows out
                    // without claiming. Calling it directly skips
                    // the broken reciprocal-handshake step entirely
                    // and saves one redundant TCP round-trip per
                    // discovery.
                    info!(
                        "Opening persistent session to {} after rendezvous friend discovery",
                        addr
                    );
                    match ed2k::friend_connect::connect_friend_with_fallback(
                        addr,
                        target_hash,
                        our_uh,
                        our_eh,
                        nick,
                        cid,
                        tcp,
                        udp,
                        obfuscate,
                        sess_fc,
                        offline_fc,
                        ultx_fc.clone(),
                        fh_fc,
                        Some(ed25519_pubkey),
                        Some(ed25519_secret_key),
                        rv_url.clone(),
                        nat_ctx_fc,
                    )
                    .await
                    {
                        Ok(_) => {
                            // Session is up — only NOW are we sure
                            // the peer is reachable for chat /
                            // browse, so this is the correct moment
                            // to mark them online. `friend-confirmed`
                            // is emitted alongside to clear the
                            // searching spinner.
                            let _ = app_fc.emit(
                                "ember:friend-confirmed",
                                serde_json::json!({
                                    "user_hash": hex::encode(target_hash),
                                }),
                            );
                            let _ = app_fc.emit(
                                "ember:friend-online",
                                serde_json::json!({
                                    "user_hash": hex::encode(target_hash),
                                }),
                            );
                        }
                        Err(e) => {
                            info!("Persistent session to {} failed: {e}", addr);
                            let emsg = format!("{e}");
                            let reason =
                                if emsg.contains(ed2k::secure_stream::UPGRADE_REQUIRED_ERROR) {
                                    "secure_v2_required"
                                } else if emsg.contains("timeout") {
                                    "timeout"
                                } else if emsg.contains("refused") {
                                    "refused"
                                } else {
                                    "error"
                                };
                            // No `EmberFriendDisconnected` — we never
                            // emitted online for this peer so there's
                            // nothing to roll back. The trailing
                            // `EmberFriendSearchFailed` below releases
                            // the outbound-task slot, and the periodic
                            // auto-retry sweep will pick the friend
                            // up again without an immediate dogpiled
                            // retry.
                            let _ = app_fc.emit(
                                "ember:friend-search-failed",
                                serde_json::json!({
                                    "user_hash": hex::encode(target_hash),
                                    "reason": reason,
                                }),
                            );
                        }
                    }
                }
            }
            Ok(None) => {
                info!(
                    "Rendezvous lookup: friend {} not found",
                    hex::encode(target_hash)
                );
                // Without their intro secret the only intro we could try was
                // the legacy one, which current builds no longer register. For
                // someone who has not added us back that miss is expected, and
                // the fix is their new friend code rather than waiting.
                let legacy_code =
                    crate::network::friend_intro::friend_intro_secret(&target_hash).is_none();
                if legacy_code {
                    ask_unmatched_friend_through_rooms(&app_fc, target_hash).await;
                }
                let _ = app_fc.emit(
                    "ember:friend-search-failed",
                    serde_json::json!({
                        "user_hash": hex::encode(target_hash),
                        "reason": "not_found",
                        "legacy_code": legacy_code,
                    }),
                );
            }
            Err(e) => {
                debug!(
                    "Rendezvous lookup failed for {}: {e}",
                    hex::encode(target_hash)
                );
                if crate::network::friend_intro::friend_intro_secret(&target_hash).is_none() {
                    ask_unmatched_friend_through_rooms(&app_fc, target_hash).await;
                }
                let _ = app_fc.emit(
                    "ember:friend-search-failed",
                    serde_json::json!({
                        "user_hash": hex::encode(target_hash),
                        "reason": "error",
                    }),
                );
            }
        }

        // Always release the `outbound_session_tasks[target_hash]`
        // slot the caller reserved before spawning. Idempotent and
        // correct in every path:
        //
        //  - If we successfully opened a persistent session for
        //    `target_hash`, the live entry lives in `ember_sessions`;
        //    when that session eventually dies the
        //    `EmberFriendDisconnected` handler fires + schedules
        //    reconnect (it re-inserts the slot before respawning), so
        //    nothing is lost by clearing it here.
        //  - If we opened a session for a *different* friend
        //    (`remote_eh != target_hash`), that hash's lifecycle is
        //    independent of ours and we MUST clear `target_hash`'s
        //    slot or `FindFriendAndConnect` and the periodic
        //    auto-retry sweep will skip it for the next 10 min.
        //  - If no session was opened (rendezvous miss, dial error,
        //    no reciprocal, identity check failed), we have to clear
        //    or auto-retry won't fire again until the 10 min
        //    `outbound_session_tasks.retain` sweep prunes us.
        //
        // Distinct from `EmberFriendDisconnected` so we don't fire
        // misleading `ember:friend-offline` / `ember:browse-error`
        // events for a peer who was never online from the user's
        // point of view.
        if let Err(e) = ultx_fc
            .send(upload_server::UploadEvent {
                transfer_id: String::new(),
                kind: upload_server::UploadEventKind::EmberFriendSearchFailed {
                    ember_hash: target_hash,
                },
            })
            .await
        {
            warn!(
                "Failed to release rendezvous friend lookup slot for {}: {e}",
                hex::encode(target_hash)
            );
        }
    });
}

#[cfg(test)]
mod hash_only_backfill_tests {
    use super::*;
    use crate::storage::database::HashOnlyFriend;

    const NOW_UNIX: i64 = 1_800_000_000;

    fn friend(seed: u8, mutual: bool, age_secs: i64) -> HashOnlyFriend {
        HashOnlyFriend {
            hash: [seed; 16],
            mutual,
            last_contact: NOW_UNIX - age_secs,
        }
    }

    #[test]
    fn backfill_is_capped_prefers_mutual_and_skips_friends_in_backoff() {
        let now = std::time::Instant::now();
        let friends: Vec<HashOnlyFriend> = vec![
            friend(0, false, 60),
            friend(1, true, 60),
            friend(2, false, 60),
            friend(3, true, 60),
            friend(4, true, 60),
        ];
        let mut backoff = BackfillBackoff::new();
        note_hash_only_backfill_miss(&mut backoff, [1; 16], now);

        let plan = plan_hash_only_friends(&friends, &mut backoff, now, NOW_UNIX);
        assert_eq!(plan.selection.backfill, vec![[3; 16], [4; 16], [0; 16]]);

        let later = now + HASH_ONLY_BACKFILL_BACKOFF_MIN;
        let plan = plan_hash_only_friends(&friends, &mut backoff, later, NOW_UNIX);
        assert_eq!(plan.selection.backfill[0], [1; 16], "an expired backoff is retried");
    }

    #[test]
    fn only_mutual_friends_keep_the_legacy_intro() {
        let now = std::time::Instant::now();
        let friends = vec![friend(1, false, 60), friend(2, true, 60)];
        let plan = plan_hash_only_friends(&friends, &mut BackfillBackoff::new(), now, NOW_UNIX);
        assert_eq!(plan.selection.legacy_dependents, vec![[2; 16]]);
        assert!(plan.stranded.is_empty());
    }

    #[test]
    fn a_stale_mutual_friend_stops_keeping_the_legacy_intro() {
        let now = std::time::Instant::now();
        let friends = vec![
            friend(1, true, HASH_ONLY_STALE_AFTER_SECS + 1),
            friend(2, true, HASH_ONLY_STALE_AFTER_SECS - 1),
        ];
        let plan = plan_hash_only_friends(&friends, &mut BackfillBackoff::new(), now, NOW_UNIX);
        assert_eq!(plan.selection.legacy_dependents, vec![[2; 16]]);
        assert_eq!(plan.stranded, vec![[1; 16]]);
    }

    #[test]
    fn repeated_misses_at_the_cap_give_up_and_fall_back_to_weekly_lookups() {
        let now = std::time::Instant::now();
        let mut backoff = BackfillBackoff::new();
        let mut misses = 0;
        while !backoff.get(&[9; 16]).is_some_and(BackfillState::given_up) {
            note_hash_only_backfill_miss(&mut backoff, [9; 16], now);
            misses += 1;
            assert!(misses < 64, "gives up eventually");
        }
        let total_wait: std::time::Duration = {
            let mut probe = BackfillBackoff::new();
            let mut sum = std::time::Duration::ZERO;
            for _ in 0..misses - 1 {
                note_hash_only_backfill_miss(&mut probe, [9; 16], now);
                sum += probe[&[9; 16]].delay;
            }
            sum
        };
        assert!(
            total_wait >= std::time::Duration::from_secs(20 * 3600)
                && total_wait <= std::time::Duration::from_secs(48 * 3600),
            "roughly a day of lookups before giving up, was {total_wait:?}"
        );
        assert_eq!(backoff[&[9; 16]].delay, HASH_ONLY_GIVEN_UP_RETRY);

        let friends = vec![friend(9, true, 60)];
        let plan = plan_hash_only_friends(&friends, &mut backoff, now, NOW_UNIX);
        assert!(plan.selection.legacy_dependents.is_empty());
        assert_eq!(plan.stranded, vec![[9; 16]]);
        assert!(plan.selection.backfill.is_empty(), "not looked up again for a week");
        let plan =
            plan_hash_only_friends(&friends, &mut backoff, now + HASH_ONLY_GIVEN_UP_RETRY, NOW_UNIX);
        assert_eq!(plan.selection.backfill, vec![[9; 16]]);
    }

    #[test]
    fn backoff_forgets_friends_no_longer_hash_only() {
        let now = std::time::Instant::now();
        let mut backoff = BackfillBackoff::new();
        note_hash_only_backfill_miss(&mut backoff, [9; 16], now);
        let plan = plan_hash_only_friends(&[], &mut backoff, now, NOW_UNIX);
        assert!(plan.selection.backfill.is_empty());
        assert!(backoff.is_empty());
    }

    #[test]
    fn stranded_friends_reach_the_discoverability_event() {
        let outcome = rendezvous::RegistrationOutcome {
            intro_ok: true,
            sealed_intro_ok: true,
            legacy_stranded_friends: vec![[0xAB; 16]],
            ..Default::default()
        };
        let payload = friend_discoverable_event(&outcome, false);
        assert_eq!(
            payload["legacy_stranded_friends"],
            serde_json::json!([hex::encode([0xAB; 16])])
        );
        let quiet = friend_discoverable_event(&rendezvous::RegistrationOutcome::default(), false);
        assert!(quiet.get("legacy_stranded_friends").is_none());
    }
}

#[cfg(test)]
mod new_friend_request_rate_tests {
    use super::*;

    fn fresh(now: std::time::Instant) -> NewFriendRequestRate {
        NewFriendRequestRate { window_start: now, verified: 0, unverified: 0, per_ip: HashMap::new() }
    }

    fn admit(rate: &mut NewFriendRequestRate, ip: Option<std::net::IpAddr>, verified: bool, now: std::time::Instant) -> bool {
        let room = rate.has_room(ip, verified, now);
        if room {
            rate.charge(ip, verified, now);
        }
        room
    }

    #[test]
    fn one_address_gets_only_its_share_per_window() {
        let now = std::time::Instant::now();
        let mut rate = fresh(now);
        let ip: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        for _ in 0..NEW_FRIEND_REQUESTS_PER_IP {
            assert!(admit(&mut rate, Some(ip), true, now));
        }
        assert!(!admit(&mut rate, Some(ip), true, now));
        assert!(admit(&mut rate, Some("203.0.113.10".parse().unwrap()), true, now), "others are unaffected");
        assert!(admit(&mut rate, Some(ip), true, now + NEW_FRIEND_REQUEST_WINDOW), "and it comes back");
    }

    #[test]
    fn an_unverified_flood_leaves_room_for_verified_requests() {
        let now = std::time::Instant::now();
        let mut rate = fresh(now);
        for i in 0..NEW_UNVERIFIED_FRIEND_REQUESTS_TOTAL {
            let ip = std::net::IpAddr::from([10, 0, (i / 256) as u8, (i % 256) as u8]);
            assert!(admit(&mut rate, Some(ip), false, now));
        }
        assert!(!admit(&mut rate, Some("198.51.100.1".parse().unwrap()), false, now));
        assert!(!admit(&mut rate, None, false, now));
        assert!(admit(&mut rate, Some("198.51.100.2".parse().unwrap()), true, now));
        assert!(rate.per_ip.len() as u32 <= NEW_UNVERIFIED_FRIEND_REQUESTS_TOTAL + NEW_VERIFIED_FRIEND_REQUESTS_TOTAL);
    }

    #[test]
    fn checking_for_room_charges_nothing() {
        let now = std::time::Instant::now();
        let mut rate = fresh(now);
        let ip: std::net::IpAddr = "203.0.113.11".parse().unwrap();
        for _ in 0..10 {
            assert!(rate.has_room(Some(ip), true, now));
        }
        assert_eq!(rate.verified, 0);
    }
}