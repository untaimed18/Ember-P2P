//! The UDP half of the connection doctor's outside-in probe.
//!
//! The rendezvous server's `/v4/reachability` connects back to the TCP port it
//! is given and sends one short datagram to the UDP port: [`PROBE_TAG`]
//! followed by the 16-byte nonce the request carried. Only we can say whether
//! it arrived, so the network loop hands every datagram of exactly that shape
//! to [`note_probe`] before anything else reads it, and the doctor asks
//! [`probe_received`] for its nonce.
//!
//! The shape cannot be mistaken for other traffic on the socket. It is not
//! QUIC (a short header whose connection id is not one we issued), not STUN
//! (no magic cookie), not Ember (no transport header), and no KAD or eD2K
//! packet begins `E` followed by `MBER`.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// What a probe datagram starts with. Mirrored in the rendezvous server.
pub const PROBE_TAG: &[u8; 16] = b"EMBER-REACH-V1\0\0";
/// The tag, then the nonce.
pub const PROBE_LEN: usize = PROBE_TAG.len() + 16;

/// How long a received nonce is remembered: the doctor waits a few seconds.
const REMEMBERED_FOR: Duration = Duration::from_secs(120);
/// Most nonces kept: one per check, and checks are rate-limited server-side.
const MAX_REMEMBERED: usize = 32;

fn received() -> &'static parking_lot::Mutex<VecDeque<([u8; 16], Instant)>> {
    static RECEIVED: std::sync::OnceLock<parking_lot::Mutex<VecDeque<([u8; 16], Instant)>>> =
        std::sync::OnceLock::new();
    RECEIVED.get_or_init(Default::default)
}

/// Whether `data` is a probe datagram, recording its nonce if it is. A probe is
/// consumed here and goes nowhere else.
pub fn note_probe(data: &[u8]) -> bool {
    let Some(nonce) = probe_nonce(data) else {
        return false;
    };
    let now = Instant::now();
    let mut seen = received().lock();
    seen.retain(|(_, at)| now.duration_since(*at) < REMEMBERED_FOR);
    if seen.len() >= MAX_REMEMBERED {
        seen.pop_front();
    }
    seen.push_back((nonce, now));
    true
}

fn probe_nonce(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() != PROBE_LEN || !data.starts_with(PROBE_TAG) {
        return None;
    }
    data[PROBE_TAG.len()..].try_into().ok()
}

/// Whether the probe carrying `nonce` arrived recently.
pub fn probe_received(nonce: &[u8; 16]) -> bool {
    let now = Instant::now();
    received()
        .lock()
        .iter()
        .any(|(seen, at)| seen == nonce && now.duration_since(*at) < REMEMBERED_FOR)
}

/// A probe datagram for `nonce`, as the server sends it.
#[cfg(test)]
pub fn probe_datagram(nonce: &[u8; 16]) -> [u8; PROBE_LEN] {
    let mut out = [0u8; PROBE_LEN];
    out[..PROBE_TAG.len()].copy_from_slice(PROBE_TAG);
    out[PROBE_TAG.len()..].copy_from_slice(nonce);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_probe_of_the_exact_shape_is_taken_and_its_nonce_remembered() {
        let nonce = [0x5Cu8; 16];
        assert!(!probe_received(&nonce));
        let datagram = probe_datagram(&nonce);
        assert!(note_probe(&datagram));
        assert!(probe_received(&nonce));
        assert!(!probe_received(&[0x5Du8; 16]));

        assert!(!note_probe(&datagram[..PROBE_LEN - 1]), "short");
        let mut longer = datagram.to_vec();
        longer.push(0);
        assert!(!note_probe(&longer), "long");
        let mut kad = datagram;
        kad[0] = 0xE4;
        assert!(!note_probe(&kad), "another tag");
    }

    #[test]
    fn a_probe_is_never_taken_for_quic() {
        let key = crate::network::ember::udp_mux::CidKey::random();
        assert!(!crate::network::ember::udp_mux::is_quic(&probe_datagram(&[1; 16]), &key));
    }
}
