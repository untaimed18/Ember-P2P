//! eMule CPacketTracking legacy Hello challenges for Kad < 7 (and
//! plaintext verification when obfuscation is disabled).
//!
//! Pre-0.49a peers cannot do HELLO_RES_ACK / UDP-key handshakes. eMule proves
//! their IP by sending a KADEMLIA2_REQ with a random target; a matching
//! KADEMLIA2_RES verifies the contact. Version 7 uses a Ping/Pong challenge
//! the same way. Ember also uses the Req challenge when obfuscation is off so
//! modern peers can still be verified without encrypted HelloResAck.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use super::messages::{KADEMLIA2_PING, KADEMLIA2_REQ};
use super::types::KadId;

/// eMule listChallengeRequests entry TTL (SEC2MS(180)).
const CHALLENGE_TTL: Duration = Duration::from_secs(180);

#[derive(Debug, Clone)]
struct TrackChallenge {
    inserted_at: Instant,
    ip: Ipv4Addr,
    contact_id: KadId,
    /// Zero for Ping challenges; random non-zero for Req challenges.
    challenge: KadId,
    opcode: u8,
}

#[derive(Debug, Default)]
pub struct LegacyChallengeTracker {
    challenges: VecDeque<TrackChallenge>,
}

impl LegacyChallengeTracker {
    pub fn new() -> Self {
        Self {
            challenges: VecDeque::new(),
        }
    }

    fn expire(&mut self) {
        let now = Instant::now();
        while let Some(front) = self.challenges.front() {
            if now.duration_since(front.inserted_at) >= CHALLENGE_TTL {
                self.challenges.pop_front();
            } else {
                break;
            }
        }
    }

    /// eMule HasActiveLegacyChallenge — at most one outstanding challenge per IP.
    pub fn has_active(&mut self, ip: Ipv4Addr) -> bool {
        self.expire();
        self.challenges.iter().any(|c| c.ip == ip)
    }

    /// eMule AddLegacyChallenge.
    pub fn add(&mut self, contact_id: KadId, challenge: KadId, ip: Ipv4Addr, opcode: u8) {
        self.expire();
        self.challenges.push_back(TrackChallenge {
            inserted_at: Instant::now(),
            ip,
            contact_id,
            challenge,
            opcode,
        });
    }

    /// eMule IsLegacyChallenge. On match, removes the entry and returns the
    /// contact id that should be marked verified.
    pub fn take_match(
        &mut self,
        challenge_id: &KadId,
        ip: Ipv4Addr,
        opcode: u8,
    ) -> Option<KadId> {
        self.expire();
        let mut wrong_answer = false;
        let mut found: Option<usize> = None;
        for (i, tc) in self.challenges.iter().enumerate() {
            if tc.ip == ip && tc.opcode == opcode {
                if tc.challenge == KadId::zero() || tc.challenge == *challenge_id {
                    found = Some(i);
                    break;
                }
                wrong_answer = true;
            }
        }
        if let Some(i) = found {
            let contact_id = self.challenges.remove(i).map(|c| c.contact_id)?;
            return Some(contact_id);
        }
        if wrong_answer {
            tracing::debug!(
                "Kad legacy challenge: wrong answer from {ip} (opcode 0x{opcode:02X})"
            );
        }
        None
    }

    pub const OPCODE_REQ: u8 = KADEMLIA2_REQ;
    pub const OPCODE_PING: u8 = KADEMLIA2_PING;
}