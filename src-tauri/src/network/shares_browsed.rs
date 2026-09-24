//! Telling the user that someone viewed their shared files: an ed2k client's
//! "View Files", or a friend's browse over Ember. The UI writes it to the
//! server log and, depending on focus and settings, raises a toast or a
//! desktop notification.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// How long repeat browses by the same peer stay quiet once one is reported.
/// A client reconnecting to page through folders, or retrying after a denial,
/// is still one visit, and a peer should not be able to fill the log (or the
/// screen) by asking over and over.
const SHARES_BROWSED_QUIET: std::time::Duration = std::time::Duration::from_secs(10 * 60);
/// Peers remembered for [`SHARES_BROWSED_QUIET`]. Past this, entries whose
/// window has passed are dropped, and if every one is still live the oldest
/// goes.
const MAX_SHARES_BROWSERS_TRACKED: usize = 512;

/// Who viewed our shares, as far as rate limiting is concerned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum SharesBrowser {
    /// An ed2k client, known only by address.
    Peer(IpAddr),
    /// A friend, by Ember hash.
    Friend([u8; 16]),
}

/// Whether a browse by `who` should be reported now, recording it if so.
///
/// Answered and denied browses are tracked separately, so turning browsing on
/// does not hide the first real browse by someone who was just refused.
pub(super) fn shares_browse_is_new(
    seen: &mut HashMap<(SharesBrowser, bool), std::time::Instant>,
    who: SharesBrowser,
    allowed: bool,
    now: std::time::Instant,
) -> bool {
    let key = (who, allowed);
    if seen
        .get(&key)
        .is_some_and(|at| now.saturating_duration_since(*at) < SHARES_BROWSED_QUIET)
    {
        return false;
    }
    if seen.len() >= MAX_SHARES_BROWSERS_TRACKED && !seen.contains_key(&key) {
        seen.retain(|_, at| now.saturating_duration_since(*at) < SHARES_BROWSED_QUIET);
        if seen.len() >= MAX_SHARES_BROWSERS_TRACKED {
            if let Some(oldest) = seen.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k) {
                seen.remove(&oldest);
            }
        }
    }
    seen.insert(key, now);
    true
}

/// Report an ed2k client's request for our shared-file list.
pub(super) fn report_ed2k_shares_browsed(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    peer_addr: SocketAddr,
    peer_name: &str,
    client_software: &str,
    allowed: bool,
) {
    let who = SharesBrowser::Peer(peer_addr.ip());
    if !shares_browse_is_new(
        &mut state.shares_browsed_seen,
        who,
        allowed,
        std::time::Instant::now(),
    ) {
        return;
    }
    let _ = app_handle.emit(
        "shares-browsed",
        serde_json::json!({
            "via": "ed2k",
            "allowed": allowed,
            "peer_name": peer_name,
            "peer_ip": peer_addr.ip().to_string(),
            "client_software": client_software,
        }),
    );
}

/// Report a friend browsing our shares over Ember, or being refused because
/// friend browsing is off.
pub(super) fn report_friend_shares_browsed(
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    friend: [u8; 16],
    allowed: bool,
) {
    let who = SharesBrowser::Friend(friend);
    if !shares_browse_is_new(
        &mut state.shares_browsed_seen,
        who,
        allowed,
        std::time::Instant::now(),
    ) {
        return;
    }
    let _ = app_handle.emit(
        "shares-browsed",
        serde_json::json!({
            "via": "friend",
            "allowed": allowed,
            "friend_hash": hex::encode(friend),
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(last: u8) -> SharesBrowser {
        SharesBrowser::Peer(IpAddr::V4(Ipv4Addr::new(203, 0, 113, last)))
    }

    #[test]
    fn a_peer_is_reported_once_per_quiet_window() {
        let mut seen = HashMap::new();
        let t0 = std::time::Instant::now();
        assert!(shares_browse_is_new(&mut seen, peer(1), true, t0));
        assert!(!shares_browse_is_new(
            &mut seen,
            peer(1),
            true,
            t0 + std::time::Duration::from_secs(60)
        ));
        // Another peer is its own visit.
        assert!(shares_browse_is_new(&mut seen, peer(2), true, t0));
        // After the window the same peer counts again.
        assert!(shares_browse_is_new(
            &mut seen,
            peer(1),
            true,
            t0 + SHARES_BROWSED_QUIET
        ));
    }

    #[test]
    fn a_refusal_does_not_hide_the_first_answered_browse() {
        let mut seen = HashMap::new();
        let t0 = std::time::Instant::now();
        assert!(shares_browse_is_new(&mut seen, peer(1), false, t0));
        assert!(!shares_browse_is_new(&mut seen, peer(1), false, t0));
        assert!(shares_browse_is_new(&mut seen, peer(1), true, t0));
    }

    #[test]
    fn friends_and_peers_are_tracked_apart() {
        let mut seen = HashMap::new();
        let t0 = std::time::Instant::now();
        assert!(shares_browse_is_new(
            &mut seen,
            SharesBrowser::Friend([7; 16]),
            true,
            t0
        ));
        assert!(shares_browse_is_new(&mut seen, peer(7), true, t0));
    }

    #[test]
    fn the_tracker_stays_bounded() {
        let mut seen = HashMap::new();
        let t0 = std::time::Instant::now();
        for i in 0..(MAX_SHARES_BROWSERS_TRACKED as u32 + 50) {
            let who = SharesBrowser::Peer(IpAddr::V4(Ipv4Addr::from(0x0A00_0000 + i)));
            assert!(shares_browse_is_new(&mut seen, who, true, t0));
            assert!(seen.len() <= MAX_SHARES_BROWSERS_TRACKED);
        }
    }
}
