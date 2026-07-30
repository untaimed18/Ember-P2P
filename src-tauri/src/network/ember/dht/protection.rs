//! Per-IP rate limits for the Ember DHT.
//!
//! Transport-layer AEAD already rejects verbatim UDP replays; STORE
//! signature replay collapse lives in [super::engine::EmberDht]. This
//! module caps per-IP frame and STORE/PROXY_STORE rates once a Noise session is up.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::messages::{MSG_PROXY_STORE, MSG_STORE_RECORD};

/// Sliding window for per-IP message counts.
const MSG_WINDOW: Duration = Duration::from_secs(1);
/// Max DHT frames accepted from one IP per [MSG_WINDOW].
const MAX_MSGS_PER_WINDOW: u32 = 40;
/// Sliding window for STORE floods.
const STORE_WINDOW: Duration = Duration::from_secs(60);
/// Max STORE_RECORD / PROXY_STORE frames accepted from one IP per [STORE_WINDOW].
const MAX_STORES_PER_WINDOW: u32 = 30;
const MAX_IP_ENTRIES: usize = 10_000;

#[derive(Debug, Default)]
struct WindowCounter {
    count: u32,
    window_start: Option<Instant>,
}

impl WindowCounter {
    fn allow(&mut self, now: Instant, window: Duration, limit: u32) -> bool {
        match self.window_start {
            Some(start) if now.duration_since(start) < window => {
                if self.count >= limit {
                    return false;
                }
                self.count = self.count.saturating_add(1);
                true
            }
            _ => {
                self.window_start = Some(now);
                self.count = 1;
                true
            }
        }
    }
}

/// Flood gate consulted before EmberDht::handle_message.
pub struct DhtProtection {
    msg_counters: HashMap<IpAddr, WindowCounter>,
    store_counters: HashMap<IpAddr, WindowCounter>,
    dropped_rate: u64,
}

impl Default for DhtProtection {
    fn default() -> Self {
        Self::new()
    }
}

impl DhtProtection {
    pub fn new() -> Self {
        Self {
            msg_counters: HashMap::new(),
            store_counters: HashMap::new(),
            dropped_rate: 0,
        }
    }

    /// Count of frames refused by the rate limiter. Read by this module's
    /// tests; kept for the diagnostics surface to report drops.
    #[allow(dead_code)]
    pub fn dropped_rate_limited(&self) -> u64 {
        self.dropped_rate
    }

    /// Returns true when the frame should be processed.
    pub fn allow_message(&mut self, ip: IpAddr, msg_type: u8) -> bool {
        let now = Instant::now();
        self.maybe_trim(now);

        if self.msg_counters.len() >= MAX_IP_ENTRIES && !self.msg_counters.contains_key(&ip) {
            self.dropped_rate = self.dropped_rate.saturating_add(1);
            return false;
        }

        let msg_ok = self
            .msg_counters
            .entry(ip)
            .or_default()
            .allow(now, MSG_WINDOW, MAX_MSGS_PER_WINDOW);
        if !msg_ok {
            self.dropped_rate = self.dropped_rate.saturating_add(1);
            return false;
        }

        if msg_type == MSG_STORE_RECORD || msg_type == MSG_PROXY_STORE {
            if self.store_counters.len() >= MAX_IP_ENTRIES && !self.store_counters.contains_key(&ip)
            {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }
            let store_ok = self
                .store_counters
                .entry(ip)
                .or_default()
                .allow(now, STORE_WINDOW, MAX_STORES_PER_WINDOW);
            if !store_ok {
                self.dropped_rate = self.dropped_rate.saturating_add(1);
                return false;
            }
        }

        true
    }

    fn maybe_trim(&mut self, now: Instant) {
        if self.msg_counters.len() > MAX_IP_ENTRIES / 2 {
            self.msg_counters.retain(|_, c| {
                c.window_start
                    .map(|s| now.duration_since(s) < MSG_WINDOW * 4)
                    .unwrap_or(false)
            });
        }
        if self.store_counters.len() > MAX_IP_ENTRIES / 2 {
            self.store_counters.retain(|_, c| {
                c.window_start
                    .map(|s| now.duration_since(s) < STORE_WINDOW * 2)
                    .unwrap_or(false)
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::messages::MSG_PING;
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn rate_limits_messages_per_ip() {
        let mut p = DhtProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        for _ in 0..MAX_MSGS_PER_WINDOW {
            assert!(p.allow_message(ip, MSG_PING));
        }
        assert!(!p.allow_message(ip, MSG_PING));
        assert_eq!(p.dropped_rate_limited(), 1);
    }

    #[test]
    fn store_budget_independent_window() {
        let mut p = DhtProtection::new();
        let ip = IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9));
        for _ in 0..(MAX_MSGS_PER_WINDOW - 1) {
            assert!(p.allow_message(ip, MSG_PING));
        }
        assert!(p.allow_message(ip, MSG_STORE_RECORD));
        assert!(!p.allow_message(ip, MSG_STORE_RECORD));
    }
}
