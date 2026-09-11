pub mod limiter;
pub mod schedule;
pub mod uss;

use std::collections::VecDeque;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

/// The highest speed, in bytes per second, that any configured limit may carry.
///
/// Generous against real links — 100 GiB/s — so it never constrains a user, but
/// it is not only an input-sanity bound. The limiter's refill adds roughly a
/// tenth of the rate per tick into a bucket capped at twice the rate, so a limit
/// near `u64::MAX` overflows that sum, and `[profile.release]` sets
/// `overflow-checks = true`. A panic there kills the refill task, which sets
/// `refill_alive = false`, after which every rate-limited transfer aborts for
/// the rest of the session.
///
/// Lives here rather than beside the settings validator because both the manual
/// limits and the schedule rules have to be held to it, and the limiter is what
/// they both end up in.
pub const MAX_CONFIGURED_SPEED_BPS: u64 = 100 * 1024 * 1024 * 1024;

/// Shared RTT samples from the network loop (KAD Ping/Pong) to the limiter loop (USS).
pub type UssRttQueue = Arc<Mutex<VecDeque<f64>>>;

/// Shared flag: whether USS is enabled by the user.
pub type UssEnabledFlag = Arc<AtomicBool>;

pub fn new_uss_rtt_queue() -> UssRttQueue {
    Arc::new(Mutex::new(VecDeque::with_capacity(64)))
}

pub fn new_uss_enabled_flag(enabled: bool) -> UssEnabledFlag {
    Arc::new(AtomicBool::new(enabled))
}
