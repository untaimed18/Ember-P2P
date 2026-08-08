//! eMule CPacketTracking legacy Hello challenges for Kad < 7 (and
//! plaintext verification when obfuscation is disabled).
//!
//! Pre-0.49a peers cannot do HELLO_RES_ACK / UDP-key handshakes. eMule proves
//! their IP by sending a KADEMLIA2_REQ with a random target; a matching
//! KADEMLIA2_RES verifies the contact. Version 7 uses a Ping/Pong challenge
//! the same way. Ember also uses the Req challenge when obfuscation is off so
//! modern peers can still be verified without encrypted HelloResAck.

use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::messages::{KADEMLIA2_PING, KADEMLIA2_REQ};
use super::types::KadId;

/// eMule listChallengeRequests entry TTL (SEC2MS(180)).
const CHALLENGE_TTL: Duration = Duration::from_secs(180);

/// Hard ceiling on outstanding challenges.
///
/// The reachable path is every `KADEMLIA2_HELLO_REQ` from a peer that isn't
/// UDP-firewalled and has no valid receiver key, selected by
/// `version < KADEMLIA_VERSION7_49A` — and `version` is a field of the
/// attacker's own HelloReq. Entries used to be removed only by the 180-second
/// TTL, so a spoofed-source flood at ~1,000 packets/s parked ~180,000 of them
/// (~10 MB) in an unbounded list that every later packet walked end to end.
/// eMule's own `listChallengeRequests` never grows past a handful of pending
/// verifications, so a few hundred is generous for real traffic.
const MAX_CHALLENGES: usize = 256;

#[derive(Debug, Clone)]
struct TrackChallenge {
    inserted_at: Instant,
    /// Identifies which `order` record belongs to this entry, so a record
    /// superseded by a later challenge for the same IP can be discarded
    /// without touching the live entry.
    seq: u64,
    contact_id: KadId,
    /// Zero for Ping challenges; random non-zero for Req challenges.
    challenge: KadId,
    opcode: u8,
}

#[derive(Debug, Default)]
pub struct LegacyChallengeTracker {
    /// eMule permits at most one outstanding challenge per IP, so the IP is
    /// the natural key: `has_active` and `take_match` are then O(1) lookups
    /// instead of walks over every pending challenge.
    challenges: HashMap<Ipv4Addr, TrackChallenge>,
    /// Insertion order, oldest first, for O(1) expiry and oldest-first
    /// eviction. Records whose `seq` no longer matches the map entry are
    /// superseded (or already consumed) and get dropped on sight.
    order: VecDeque<(Ipv4Addr, u64)>,
    next_seq: u64,
}

impl LegacyChallengeTracker {
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            order: VecDeque::new(),
            next_seq: 0,
        }
    }

    /// Drop the leading run of consumed/superseded/expired records. `order`
    /// is in insertion order and `inserted_at` rises with `seq`, so the first
    /// live record that is still inside its TTL means every later one is too.
    fn expire(&mut self) {
        let now = Instant::now();
        while let Some(&(ip, seq)) = self.order.front() {
            // `None` here means the record was consumed by `take_match` or
            // superseded by a later challenge for the same IP.
            let expired = self
                .challenges
                .get(&ip)
                .filter(|entry| entry.seq == seq)
                .map(|entry| now.duration_since(entry.inserted_at) >= CHALLENGE_TTL);
            match expired {
                Some(false) => break,
                Some(true) => {
                    self.challenges.remove(&ip);
                }
                None => {}
            }
            self.order.pop_front();
        }
    }

    /// eMule HasActiveLegacyChallenge — at most one outstanding challenge per IP.
    pub fn has_active(&mut self, ip: Ipv4Addr) -> bool {
        self.expire();
        self.challenges.contains_key(&ip)
    }

    /// eMule AddLegacyChallenge.
    pub fn add(&mut self, contact_id: KadId, challenge: KadId, ip: Ipv4Addr, opcode: u8) {
        self.expire();
        // Oldest-first eviction keeps the table bounded when arrivals
        // outrun the TTL. Capping `order` (not just `challenges`) also
        // bounds the superseded records, which are only reclaimed once they
        // reach the front.
        while self.order.len() >= MAX_CHALLENGES {
            let Some((old_ip, old_seq)) = self.order.pop_front() else {
                break;
            };
            if self
                .challenges
                .get(&old_ip)
                .is_some_and(|entry| entry.seq == old_seq)
            {
                self.challenges.remove(&old_ip);
            }
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.order.push_back((ip, seq));
        self.challenges.insert(
            ip,
            TrackChallenge {
                inserted_at: Instant::now(),
                seq,
                contact_id,
                challenge,
                opcode,
            },
        );
    }

    /// eMule IsLegacyChallenge. On match, removes the entry and returns the
    /// contact id that should be marked verified.
    pub fn take_match(&mut self, challenge_id: &KadId, ip: Ipv4Addr, opcode: u8) -> Option<KadId> {
        self.expire();
        let entry = self.challenges.get(&ip)?;
        if entry.opcode != opcode {
            return None;
        }
        if entry.challenge != KadId::zero() && entry.challenge != *challenge_id {
            tracing::debug!("Kad legacy challenge: wrong answer from {ip} (opcode 0x{opcode:02X})");
            return None;
        }
        let contact_id = entry.contact_id;
        // The `order` record is left for `expire` to reclaim: its `seq` no
        // longer resolves to a map entry, so it is inert.
        self.challenges.remove(&ip);
        Some(contact_id)
    }

    pub const OPCODE_REQ: u8 = KADEMLIA2_REQ;
    pub const OPCODE_PING: u8 = KADEMLIA2_PING;
}

#[cfg(test)]
mod legacy_challenge_tests {
    use super::*;

    fn ip(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, last)
    }

    #[test]
    fn req_challenge_round_trips_and_is_consumed_once() {
        let mut tracker = LegacyChallengeTracker::new();
        let contact = KadId([0x11; 16]);
        let challenge = KadId([0x22; 16]);

        assert!(!tracker.has_active(ip(1)));
        tracker.add(contact, challenge, ip(1), LegacyChallengeTracker::OPCODE_REQ);
        assert!(tracker.has_active(ip(1)));

        assert_eq!(
            tracker.take_match(&challenge, ip(1), LegacyChallengeTracker::OPCODE_REQ),
            Some(contact)
        );
        assert!(
            !tracker.has_active(ip(1)),
            "a matched challenge must be consumed"
        );
        assert_eq!(
            tracker.take_match(&challenge, ip(1), LegacyChallengeTracker::OPCODE_REQ),
            None
        );
    }

    #[test]
    fn wrong_answer_and_wrong_opcode_do_not_verify() {
        let mut tracker = LegacyChallengeTracker::new();
        let contact = KadId([0x11; 16]);
        let challenge = KadId([0x22; 16]);
        tracker.add(contact, challenge, ip(2), LegacyChallengeTracker::OPCODE_REQ);

        assert_eq!(
            tracker.take_match(&KadId([0x33; 16]), ip(2), LegacyChallengeTracker::OPCODE_REQ),
            None,
            "a wrong target must not verify the contact"
        );
        assert_eq!(
            tracker.take_match(&challenge, ip(2), LegacyChallengeTracker::OPCODE_PING),
            None,
            "the answer must arrive on the opcode we challenged with"
        );
        assert!(
            tracker.has_active(ip(2)),
            "a failed answer must leave the challenge outstanding"
        );
    }

    /// Ping challenges carry a zero target, which matches any KadId.
    #[test]
    fn zero_challenge_matches_any_answer() {
        let mut tracker = LegacyChallengeTracker::new();
        let contact = KadId([0x44; 16]);
        tracker.add(
            contact,
            KadId::zero(),
            ip(3),
            LegacyChallengeTracker::OPCODE_PING,
        );
        assert_eq!(
            tracker.take_match(&KadId([0x99; 16]), ip(3), LegacyChallengeTracker::OPCODE_PING),
            Some(contact)
        );
    }

    /// A spoofed-source HelloReq flood inserts once per datagram. The table
    /// must stay capped, evict oldest-first, and keep lookups O(1).
    #[test]
    fn flood_is_capped_and_evicts_oldest_first() {
        let mut tracker = LegacyChallengeTracker::new();
        for i in 0..(MAX_CHALLENGES * 4) {
            let addr = Ipv4Addr::from((i as u32).to_be_bytes());
            tracker.add(
                KadId::random(),
                KadId::random(),
                addr,
                LegacyChallengeTracker::OPCODE_REQ,
            );
            assert!(tracker.challenges.len() <= MAX_CHALLENGES);
            assert!(tracker.order.len() <= MAX_CHALLENGES);
        }
        assert_eq!(tracker.challenges.len(), MAX_CHALLENGES);
        assert!(
            !tracker.has_active(Ipv4Addr::from(0u32)),
            "the oldest challenge must be the one evicted"
        );
        assert!(
            tracker.has_active(Ipv4Addr::from((MAX_CHALLENGES * 4 - 1) as u32)),
            "the newest challenge must survive"
        );
    }

    /// Re-challenging an IP replaces its entry rather than stacking a second
    /// one, and the superseded order record must not evict the live entry.
    #[test]
    fn rechallenging_an_ip_replaces_its_entry() {
        let mut tracker = LegacyChallengeTracker::new();
        let contact = KadId([0x55; 16]);
        let first = KadId([0x66; 16]);
        let second = KadId([0x77; 16]);
        tracker.add(contact, first, ip(4), LegacyChallengeTracker::OPCODE_REQ);
        tracker.add(contact, second, ip(4), LegacyChallengeTracker::OPCODE_REQ);
        assert_eq!(tracker.challenges.len(), 1);
        assert_eq!(
            tracker.take_match(&first, ip(4), LegacyChallengeTracker::OPCODE_REQ),
            None,
            "the superseded challenge target must no longer answer"
        );
        assert_eq!(
            tracker.take_match(&second, ip(4), LegacyChallengeTracker::OPCODE_REQ),
            Some(contact)
        );
    }
}
