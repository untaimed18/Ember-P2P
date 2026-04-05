pub mod limiter;
pub mod uss;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, atomic::AtomicBool};

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
