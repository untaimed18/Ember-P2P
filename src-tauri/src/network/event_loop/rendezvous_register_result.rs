//! Applying the result of a background rendezvous registration.

use super::*;

pub(in crate::network) async fn on_rendezvous_register_result(
    result: RendezvousRegisterResult,
    state: &mut NetworkState,
    app_handle: &tauri::AppHandle,
    rendezvous_register_in_flight: &mut bool,
    rendezvous_register_started_at: &mut Option<tokio::time::Instant>,
) {
    if result.generation != state.rendezvous_register_generation {
        debug!(
            "Ignoring stale rendezvous result generation {} (current {})",
            result.generation, state.rendezvous_register_generation
        );
        return;
    }
    *rendezvous_register_in_flight = false;
    *rendezvous_register_started_at = None;
    match result.result {
        Ok(outcome) => {
            // Classic `/register` succeeded. Latch registered *and*
            // `friend_presence_initial_done` even when intro
            // presence failed: existing friends still resolve via
            // pairwise, and leaving the latch unset would retry
            // the full 1+1+N mutation sequence every 10s.
            state.rendezvous_registered = true;
            state.last_presence_blocked = outcome.existing_friends_blocked();
            state.rendezvous_last_register = Some(std::time::Instant::now());
            state.rendezvous_register_fail_streak = 0;
            // Nothing else moves the room beat, so the one this
            // registration selected with is still current.
            state.rendezvous_published_beat = state.rendezvous_room_beat;
            state.rendezvous_room_beat = state.rendezvous_room_beat.wrapping_add(1);
            if result.initial {
                state.friend_presence_initial_done = true;
            }
            if state.last_presence_blocked {
                warn!(
                    "Rendezvous: registered, but intro and all {} pairwise presence registration(s) failed — existing friends cannot resolve us (initial={})",
                    outcome.pairwise_attempted,
                    result.initial
                );
            } else if !outcome.intro_ok || outcome.pairwise_failed > 0 {
                debug!(
                    "Rendezvous: registered with degraded presence intro_ok={} pairwise {}/{} (initial={})",
                    outcome.intro_ok,
                    outcome.pairwise_succeeded(),
                    outcome.pairwise_attempted,
                    result.initial
                );
            }
            let _ = app_handle.emit(
                "ember:friend-discoverable",
                friend_discoverable_event(&outcome, result.initial),
            );
        }
        Err(e) => {
            if result.initial {
                debug!("Initial rendezvous register failed: {e}");
            } else {
                debug!("Rendezvous heartbeat failed: {e}");
            }
            state.rendezvous_registered = false;
            state.last_presence_blocked = false;
            state.rendezvous_last_register = None;
            if !result.initial {
                state.rendezvous_register_fail_streak =
                    state.rendezvous_register_fail_streak.saturating_add(1);
            }
            let _ = app_handle.emit(
                "ember:friend-discoverable",
                serde_json::json!({
                    "discoverable": false,
                    "reason": "rendezvous_error",
                    // Distinguishes "never established presence"
                    // from "held it and lost a heartbeat". Only the
                    // former justifies telling the user outright
                    // that friends cannot find them; a dropped
                    // heartbeat is retried on the next tick and is
                    // usually nothing, so the UI lets its own grace
                    // period decide instead of reacting to one
                    // missed beat.
                    "initial": result.initial,
                }),
            );
        }
    }
}
