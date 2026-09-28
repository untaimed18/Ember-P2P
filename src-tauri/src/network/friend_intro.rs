//! Intro secrets for friend-code discovery.
//!
//! Our own secret decides which intro capability we advertise on the
//! rendezvous server; a friend's secret (learned from their `ember3:` code)
//! is what lets us look theirs up before they have added us back. Both are
//! process-wide so every rendezvous call site sees the same values without
//! threading them through the network task, and so a reset takes effect on
//! the next heartbeat.

use std::collections::HashMap;
use std::sync::OnceLock;

use parking_lot::RwLock;

use crate::network::ember::crypto::INTRO_SECRET_LEN;

pub(crate) type IntroSecret = [u8; INTRO_SECRET_LEN];

static OWN: RwLock<Option<IntroSecret>> = RwLock::new(None);

fn friends() -> &'static RwLock<HashMap<[u8; 16], IntroSecret>> {
    static FRIENDS: OnceLock<RwLock<HashMap<[u8; 16], IntroSecret>>> = OnceLock::new();
    FRIENDS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub(crate) fn set_own_intro_secret(secret: IntroSecret) {
    *OWN.write() = Some(secret);
}

/// `None` only before startup has loaded the identity.
pub(crate) fn own_intro_secret() -> Option<IntroSecret> {
    *OWN.read()
}

pub(crate) fn remember_friend_intro_secret(ember_hash: [u8; 16], secret: IntroSecret) {
    friends().write().insert(ember_hash, secret);
}

pub(crate) fn forget_friend_intro_secret(ember_hash: &[u8; 16]) {
    friends().write().remove(ember_hash);
}

pub(crate) fn friend_intro_secret(ember_hash: &[u8; 16]) -> Option<IntroSecret> {
    friends().read().get(ember_hash).copied()
}

pub(crate) fn load_friend_intro_secrets(entries: impl IntoIterator<Item = ([u8; 16], IntroSecret)>) {
    let mut map = friends().write();
    for (hash, secret) in entries {
        map.insert(hash, secret);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_secrets_round_trip_and_forget() {
        let hash = [0xE1u8; 16];
        assert_eq!(friend_intro_secret(&hash), None);
        remember_friend_intro_secret(hash, [3u8; INTRO_SECRET_LEN]);
        assert_eq!(friend_intro_secret(&hash), Some([3u8; INTRO_SECRET_LEN]));
        load_friend_intro_secrets([(hash, [4u8; INTRO_SECRET_LEN])]);
        assert_eq!(friend_intro_secret(&hash), Some([4u8; INTRO_SECRET_LEN]));
        forget_friend_intro_secret(&hash);
        assert_eq!(friend_intro_secret(&hash), None);
    }
}
