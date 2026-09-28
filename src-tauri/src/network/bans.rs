//! Persistent and reputation-driven IP bans, and syncing the banned set to
//! the upload listener.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// Apply a durable automatic IP ban: add it to the canonical in-memory
/// ban set (`state.banned_ips`), mirror the whole set to the shared
/// upload set, and persist it to the DB `banned_ips` table with a finite
/// expiry. Persisting is what lets these bans survive both a process
/// restart and the periodic `banned_ips` cap-reset (which rebuilds the
/// in-memory set from the database), as opposed to reputation bans whose
/// lifetime is already governed (with its own TTL) by `reputation.json` +
/// per-user-hash enforcement.
///
/// `ttl_secs` is the caller's judgement about what the ban is evidence *of*:
/// [`AUTO_BAN_TTL_BEHAVIOUR_SECS`] for a timing heuristic, and
/// [`AUTO_BAN_TTL_CONTENT_SECS`] for bytes that failed a hash or a broken
/// protocol exchange. One constant used to serve both, at the longer value.
pub(super) fn apply_persistent_ip_ban(
    banned_ips: &mut HashSet<Ipv4Addr>,
    shared_banned_ips: &ed2k::upload::SharedBannedIps,
    db: &Arc<Database>,
    ip: Ipv4Addr,
    reason: &str,
    ttl_secs: u64,
) {
    if banned_ips.insert(ip) {
        warn!(
            "Auto-ban: banning IP {ip} for {}h ({reason})",
            ttl_secs / 3600
        );
    }
    if let Ok(mut shared) = shared_banned_ips.write() {
        *shared = banned_ips.clone();
    }
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .saturating_add(ttl_secs);
    if let Err(e) = db.ban_ip(ip, reason, expires_at) {
        warn!("Failed to persist auto-ban for {ip}: {e}");
    }
}

/// Lifetime for a ban earned by *behaviour we inferred from timing* — asking too
/// often, or too many connections in a window.
///
/// eMule's `CLIENTBANTIME` (`Opcodes.h:122`), two hours, and it is what
/// `CUpDownClient::Ban()` grants for the `AddRequestCount` strike that Ember's
/// leech counter reproduces. Ember was applying seven days to the same evidence,
/// which is 84 times as long — and per IP, so one misbehaving client behind a
/// CGNAT or VPN egress took every other client at that address down with it for
/// a week.
///
/// It was also internally inconsistent: `AbuseTracker`'s own in-memory ban already
/// expires after `BAN_DURATION_SECS` (two hours, eMule's `BAN_TIMEOUT`), so the
/// tracker considered a peer forgiven while its persisted mirror kept the address
/// blocked for the rest of the week.
///
/// Unlike eMule's these are still written to the database. That is deliberate:
/// the periodic ban-set rebuild reads from durable sources, so an in-memory-only
/// entry would be dropped at an arbitrary moment rather than at a known time. A
/// two-hour ban that also survives a restart is both more predictable and
/// slightly stricter than eMule, which is the right direction for the one
/// property we are choosing not to copy.
pub(super) const AUTO_BAN_TTL_BEHAVIOUR_SECS: u64 = 2 * 3600;

/// Lifetime for a ban earned by *evidence about content*, where the peer either
/// sent bytes that failed a hash or broke the protocol outright.
///
/// eMule has no equivalent — its corruption handling drops the source rather than
/// banning the address — so this is Ember's own, and the long durable ban is
/// defensible here in a way it is not for a timing heuristic: the signal is
/// deterministic, the peer produced it by sending us data, and no honest client
/// behind a shared address can trip it on another's behalf.
pub(super) const AUTO_BAN_TTL_CONTENT_SECS: u64 = 7 * 24 * 3600;

// The split only means something while the two differ. Collapsing them — in
// either direction — would silently restore one lifetime for both kinds of
// evidence, which is the bug this pair replaced.
const _: () = assert!(AUTO_BAN_TTL_CONTENT_SECS > AUTO_BAN_TTL_BEHAVIOUR_SECS);

/// Ceiling on the enforced ban set, above which it is rebuilt from durable
/// sources rather than allowed to grow.
pub(super) const MAX_BANNED_IPS: usize = 10_000;

/// The durable half of the ban-set rebuild: `(peers, auto-banned IPs)`.
///
/// Read on the blocking pool and delivered back to the loop, because
/// `get_peers` and `get_banned_ips` are synchronous SQLite calls behind one
/// process-wide connection mutex. Running them inline on the 60s reputation
/// tick blocked the tokio worker driving the whole `select!` — UDP receive,
/// KAD timers and IPC included — and every other `Database` user with it.
pub(super) type BannedIpsSyncInputs = (Vec<crate::types::PeerInfo>, Vec<Ipv4Addr>);

/// Kick off the durable half of the ban-set rebuild on the blocking pool.
///
/// One outstanding read at a time, so a slow disk cannot queue a backlog of
/// identical queries. A failed read is reported as `None` so the receiver
/// keeps the current set instead of wiping bans.
pub(super) fn request_banned_ips_sync(
    in_flight: &mut bool,
    db: &Arc<Database>,
    tx: &mpsc::UnboundedSender<Option<BannedIpsSyncInputs>>,
) {
    if *in_flight {
        return;
    }
    *in_flight = true;
    let db = db.clone();
    let tx = tx.clone();
    tokio::task::spawn_blocking(move || match (db.get_peers(), db.get_banned_ips()) {
        (Ok(peers), Ok(auto_bans)) => {
            let _ = tx.send(Some((peers, auto_bans)));
        }
        _ => {
            warn!("banned_ips sync skipped: DB read failed; keeping in-memory set");
            let _ = tx.send(None);
        }
    });
}

/// Rebuild the in-memory enforced ban set from durable sources plus
/// still-active reputation bans. This is what makes:
/// - DB auto-ban TTLs actually expire in a long-running session (H2)
/// - reputation 24h bans leave `banned_ips` after `lift_expired_bans` (H1)
///
/// Fail-closed on DB errors: the caller keeps the current set rather than
/// wiping bans when the read half failed.
pub(super) fn apply_enforced_banned_ips(
    state: &mut NetworkState,
    shared_banned_ips: &ed2k::upload::SharedBannedIps,
    peers: Vec<crate::types::PeerInfo>,
    auto_bans: Vec<Ipv4Addr>,
) {
    let mut rebuilt: HashSet<Ipv4Addr> = peers
        .iter()
        .filter(|p| p.banned)
        .flat_map(|p| p.addresses.iter())
        .filter_map(|a| a.rsplit_once(':').and_then(|(ip, _)| ip.parse().ok()))
        .collect();
    rebuilt.extend(auto_bans);

    // The addresses a node ban was observed on are mirrored into IP reputation
    // when the ban is applied (`apply_reputation_ban_ips`), and the banned
    // identity itself is refused by user hash wherever sources are picked.
    // Nothing here re-derives addresses from the identity: the user hash on a
    // KAD source record and the ID of a routing-table contact are both
    // whatever the sender claimed, so a banned peer could otherwise point its
    // own ban at any address it liked.
    for ip in state.reputation.currently_banned_ips() {
        rebuilt.insert(ip);
    }

    state.banned_ips = rebuilt;
    if let Ok(mut shared) = shared_banned_ips.write() {
        *shared = state.banned_ips.clone();
    }
}

/// Soften/fail-closed helper used whenever a reputation event newly bans a
/// peer: mirror each observed IP into IP-reputation (so periodic
/// `sync_enforced_banned_ips` rebuilds keep them) and into `banned_ips`.
pub(super) fn apply_reputation_ban_ips(
    state: &mut NetworkState,
    shared_banned_ips: &ed2k::upload::SharedBannedIps,
    ips: impl IntoIterator<Item = Ipv4Addr>,
    user_hash: &[u8; 16],
) {
    let mut any = false;
    for ip in ips {
        state.reputation.mirror_node_ban_to_ip(ip);
        if state.banned_ips.insert(ip) {
            warn!(
                "Reputation ban: banning IP {} (user_hash {})",
                ip,
                hex::encode(user_hash)
            );
        }
        any = true;
    }
    if any {
        if let Ok(mut shared) = shared_banned_ips.write() {
            *shared = state.banned_ips.clone();
        }
    }
}

/// Upload `Failed` endings that are session/queue mechanics rather than
/// evidence the peer sent bad data — must not feed `FailedChunk`.
pub(super) fn is_neutral_upload_failure(error: &str) -> bool {
    let lower = error.to_lowercase();
    lower.contains("before any data")
        || lower.contains("slot rotated")
        || lower.contains("peer banned")
        || lower.contains("network disconnected")
        || lower.contains("cancelled")
        || lower.contains("auto-banned")
}
