//! The status friends see for us while we are connected: the one the user
//! chose, or Away while they have been idle and chose Online.
//!
//! Shares the parent module's namespace through `use super::*`, the same
//! way `command.rs` does.

use super::*;

/// How often idle time is read. Well under the shortest idle choice, so Away
/// starts within a few seconds of it and ends within a few of the user's
/// return.
const IDLE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// The status to send: Away replaces Online while the user is idle, and a
/// status they chose by hand is sent as it is.
pub(super) fn effective_friend_status(
    state: &NetworkState,
    settings: &AppSettings,
) -> crate::types::FriendStatus {
    match settings.friend_status {
        crate::types::FriendStatus::Online if state.idle_away => crate::types::FriendStatus::Away,
        chosen => chosen,
    }
}

/// Whether the user has been idle long enough to show Away, by the setting.
fn idle_long_enough(idle_secs: Option<u64>, auto_away_minutes: u32) -> bool {
    auto_away_minutes > 0
        && idle_secs.is_some_and(|secs| secs >= u64::from(auto_away_minutes) * 60)
}

/// Tell a friend whose session just came up what status to show for us. Sent
/// even when it is online, so a friend never keeps one from before.
pub(super) async fn send_friend_status(
    state: &NetworkState,
    settings: &AppSettings,
    ed25519_secret_key: &[u8; 32],
    friend: [u8; 16],
) {
    let _ = send_encrypted_chat_ext(
        &state.ember_sessions,
        ed25519_secret_key,
        friend,
        ed2k::messages::EMBER_EXT_STATUS,
        &[effective_friend_status(state, settings).wire()],
    )
    .await;
}

/// Tell every friend connected now that our status changed.
pub(super) async fn announce_friend_status(
    state: &NetworkState,
    settings: &AppSettings,
    ed25519_secret_key: &[u8; 32],
) {
    let friends: Vec<[u8; 16]> = state.ember_sessions.read().await.keys().copied().collect();
    for friend in friends {
        send_friend_status(state, settings, ed25519_secret_key, friend).await;
    }
}

/// Read idle time now and record whether it is long enough for Away, telling
/// the UI when that changed.
pub(super) fn refresh_idle_away(
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
) {
    state.last_idle_check = Some(std::time::Instant::now());
    let idle_away = idle_long_enough(crate::idle::seconds_since_input(), settings.auto_away_minutes);
    if idle_away != state.idle_away {
        state.idle_away = idle_away;
        let _ = app_handle.emit("ember:idle-away", serde_json::json!({ "active": idle_away }));
    }
}

/// Start or end Away-while-idle. Called every second from the small tick,
/// and reads idle time itself only every [`IDLE_CHECK_INTERVAL`].
pub(super) async fn on_idle_check(
    state: &mut NetworkState,
    settings: &AppSettings,
    app_handle: &tauri::AppHandle,
    ed25519_secret_key: &[u8; 32],
) {
    if state.last_idle_check.is_some_and(|last| {
        std::time::Instant::now().saturating_duration_since(last) < IDLE_CHECK_INTERVAL
    }) {
        return;
    }
    let before = effective_friend_status(state, settings);
    refresh_idle_away(state, settings, app_handle);
    if effective_friend_status(state, settings) != before {
        announce_friend_status(state, settings, ed25519_secret_key).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_away_starts_at_the_chosen_minute_and_never_when_off() {
        assert!(!idle_long_enough(Some(599), 10));
        assert!(idle_long_enough(Some(600), 10));
        assert!(!idle_long_enough(Some(86_400), 0), "off is off");
        assert!(!idle_long_enough(None, 10), "unknown idle time is not idle");
    }
}
