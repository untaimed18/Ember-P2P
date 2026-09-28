//! eMule CKademlia::Process: at most one random lookup per ~100 ms tick, plus
//! draining transfers whose hash finished on the blocking pool.

use super::*;

pub(in crate::network) async fn on_kad_process_tick(
    udp_socket: &Arc<UdpSocket>,
    state: &mut NetworkState,
    settings: &AppSettings,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    db: &Arc<Database>,
    app_handle: &tauri::AppHandle,
    xfer_finish_rx: &mut mpsc::UnboundedReceiver<XferFinishResult>,
) {
    // Transfers whose hash finished on the blocking pool. Drained
    // here for the same branch-budget reason as the pacing below,
    // but ahead of both gates it sits under: the verification was
    // started while Ember was enabled and the overlay connected,
    // and the sender is waiting on a completion frame it has no
    // other way to obtain. Dropping the verdict because a setting
    // was toggled or the eMule side went down mid-hash would leave
    // that peer to time the transfer out as failed after it had
    // already succeeded.
    while let Ok(finished) = xfer_finish_rx.try_recv() {
        apply_xfer_finish(udp_socket, state, db, app_handle, finished).await;
    }
    // Ember Transfer pacing shares this 100ms tick rather than
    // taking its own arm — `tokio::select!` tops out at 64
    // branches and this loop is already at the limit. It runs
    // ahead of the KAD status gate below because Ember is a
    // separate overlay: a room transfer has no reason to stop
    // because the eMule network is disconnected. Returns straight
    // away when nothing is in flight.
    if settings.ember_native_enabled {
        drive_channel_transfers(
            udp_socket,
            state,
            db,
            app_handle,
            bandwidth_limiter,
        )
        .await;
    }
    if state.stats.status == NetworkStatus::Disconnected { return; }
    let now_bt = chrono::Utc::now().timestamp();
    if let Some(target) =
        state
            .routing_table
            .try_fire_big_timer(now_bt, state.last_kad_contact)
    {
        let closest = state
            .routing_table
            .find_closest(&target, SEARCH_INITIAL_CONTACTS);
        if !closest.is_empty() {
            let sid = start_kad_search(
                state,
                app_handle,
                target,
                SearchType::FindNode,
                closest,
            );
            if sid != SearchId(0) {
                debug!(
                    "BigTimer: started FindNode search {} (eMule RandomLookup)",
                    sid.0
                );
            }
        }
    }
}
