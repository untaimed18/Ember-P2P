//! The chat mailbox's own cadence: leave what is queued for offline friends,
//! and collect what they left us. See `chat_mailbox.rs`.
//!
//! Called every second from the small-timer arm; a round starts at launch and
//! then every [`CHAT_MAILBOX_INTERVAL`], besides the ones events start early.

use super::*;

pub(in crate::network) fn on_chat_mailbox_tick(
    state: &mut NetworkState,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    settings: &AppSettings,
    ed25519_secret_key: [u8; 32],
    ed25519_pubkey: [u8; 32],
) {
    let due = state
        .chat_mailbox_last_round
        .is_none_or(|at| at.elapsed() >= CHAT_MAILBOX_INTERVAL);
    let rerun = chat_mailbox_rerun_due(state);
    if due || rerun {
        start_chat_mailbox_round(
            state,
            db,
            app_handle,
            settings,
            ed25519_secret_key,
            ed25519_pubkey,
            !due,
        );
    }
}
