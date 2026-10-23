//! The UDP half of the connection doctor's outside-in probe.
//!
//! The rendezvous server's `/v4/reachability` connects back to the TCP port it
//! is given and sends a short datagram to the UDP port, three times:
//! [`PROBE_TAG`] followed by the 16-byte nonce the request carried. Only we can
//! say whether it arrived, so the doctor registers its nonce before asking
//! ([`expect_probe`]), the network loop hands every datagram of exactly that
//! shape to [`note_probe`] before anything else reads it, and the doctor asks
//! [`probe_received`] for its nonce.
//!
//! The shape cannot be mistaken for other traffic on the socket. It is not
//! QUIC (a short header whose connection id is not one we issued), not STUN
//! (no magic cookie), not Ember (no transport header), and no KAD or eD2K
//! packet begins `E` followed by `MBER`. Anyone can send one, but only a
//! nonce the doctor is waiting on counts, so a flood of them can neither
//! fake an arrival nor push out the real one.

use std::time::Instant;

/// What a probe datagram starts with. Mirrored in the rendezvous server.
pub const PROBE_TAG: &[u8; 16] = b"EMBER-REACH-V1\0\0";
/// The tag, then the nonce.
pub const PROBE_LEN: usize = PROBE_TAG.len() + 16;

/// Checks waited on at once. A check is one at a time from the page; a few
/// cover one left behind by a closed page.
const MAX_EXPECTED: usize = 4;

struct Expected {
    nonce: [u8; 16],
    since: Instant,
    arrived: bool,
}

fn expected() -> &'static parking_lot::Mutex<Vec<Expected>> {
    static EXPECTED: std::sync::OnceLock<parking_lot::Mutex<Vec<Expected>>> = std::sync::OnceLock::new();
    EXPECTED.get_or_init(Default::default)
}

/// Waits on the probe carrying `nonce` until dropped.
pub struct ExpectedProbe([u8; 16]);

impl Drop for ExpectedProbe {
    fn drop(&mut self) {
        expected().lock().retain(|e| e.nonce != self.0);
    }
}

/// Start waiting on the probe carrying `nonce`, before asking for it.
pub fn expect_probe(nonce: [u8; 16]) -> ExpectedProbe {
    let mut waiting = expected().lock();
    if waiting.len() >= MAX_EXPECTED {
        if let Some(oldest) = waiting.iter().enumerate().min_by_key(|(_, e)| e.since).map(|(i, _)| i) {
            waiting.remove(oldest);
        }
    }
    waiting.push(Expected { nonce, since: Instant::now(), arrived: false });
    ExpectedProbe(nonce)
}

/// Whether `data` is a probe datagram, noting its arrival if it carries a
/// nonce being waited on. A probe is consumed here and goes nowhere else.
pub fn note_probe(data: &[u8]) -> bool {
    let Some(nonce) = probe_nonce(data) else {
        return false;
    };
    if let Some(waiting) = expected().lock().iter_mut().find(|e| e.nonce == nonce) {
        waiting.arrived = true;
    }
    true
}

fn probe_nonce(data: &[u8]) -> Option<[u8; 16]> {
    if data.len() != PROBE_LEN || !data.starts_with(PROBE_TAG) {
        return None;
    }
    data[PROBE_TAG.len()..].try_into().ok()
}

/// Whether the probe carrying `nonce` has arrived since [`expect_probe`].
pub fn probe_received(nonce: &[u8; 16]) -> bool {
    expected().lock().iter().any(|e| e.nonce == *nonce && e.arrived)
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
    fn only_a_probe_of_the_exact_shape_is_taken_and_only_an_awaited_nonce_counts() {
        let nonce = [0x5Cu8; 16];
        let datagram = probe_datagram(&nonce);
        assert!(note_probe(&datagram), "taken even when nobody waits");
        let waiting = expect_probe(nonce);
        assert!(!probe_received(&nonce), "an arrival before the wait is not this check's");
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

        drop(waiting);
        assert!(!probe_received(&nonce), "forgotten once the check is over");
    }

    #[test]
    fn a_flood_of_other_nonces_cannot_push_out_the_awaited_one() {
        let nonce = [0x61u8; 16];
        let _waiting = expect_probe(nonce);
        for i in 0..1_000u16 {
            let mut other = [0u8; 16];
            other[..2].copy_from_slice(&i.to_le_bytes());
            note_probe(&probe_datagram(&other));
        }
        note_probe(&probe_datagram(&nonce));
        assert!(probe_received(&nonce));
    }

    #[test]
    fn a_probe_is_never_taken_for_quic() {
        let key = crate::network::ember::udp_mux::CidKey::random();
        assert!(!crate::network::ember::udp_mux::is_quic(&probe_datagram(&[1; 16]), &key));
    }
}
