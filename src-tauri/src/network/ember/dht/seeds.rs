//! Hardcoded Ember DHT seed peers (slice 11).
//!
//! A brand-new install with no `nodes_ember.dat` and an empty or
//! unreachable rendezvous `/bootstrap` pool still needs *somewhere* to
//! dial. This module bakes a small, known-good set of bootstrap peers into
//! the build — the Ember-native equivalent of eMule's hardcoded server
//! list. On a cold start the entries are seeded into the routing table and
//! a self-lookup expands the neighbourhood from them.
//!
//! The list lives in [`seeds.txt`](./seeds.txt), one peer per line, and is
//! embedded at compile time via `include_str!`. It is intentionally empty
//! until real long-lived seed nodes are deployed; the parser and wiring
//! exist so populating it later is a one-line *data* change, not a code
//! change. See `seeds.txt` for the line format.

use super::bootstrap::BootstrapNode;
use super::EmberContact;

/// The embedded seed list. Edit `seeds.txt` to add or remove peers.
const SEEDS_TXT: &str = include_str!("seeds.txt");

/// Parse the seeds-file format into bootstrap nodes. Blank lines and `#`
/// comments are ignored; a line whose field count is wrong is skipped
/// (key/address *validity* is enforced later, in [`BootstrapNode::to_contact`]).
///
/// Split out from [`hardcoded_contacts`] so tests can feed synthetic
/// content without touching the embedded file.
fn parse_seeds(text: &str) -> Vec<BootstrapNode> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let addr = fields.next()?;
            let ed25519_pub = fields.next()?;
            let noise_pub = fields.next()?;
            // Reject a line with trailing junk rather than half-parsing it,
            // so a malformed entry is dropped instead of silently accepted.
            if fields.next().is_some() {
                return None;
            }
            Some(BootstrapNode {
                addr: addr.to_string(),
                ed25519_pub: ed25519_pub.to_string(),
                noise_pub: noise_pub.to_string(),
            })
        })
        .collect()
}

/// The compiled-in hardcoded seed peers, parsed and validated into
/// contacts. Returns an empty vec when no seeds are baked in (the default)
/// or when every entry is malformed. Each contact's node ID is derived
/// from its Ed25519 key and re-verified on the first PING, exactly like a
/// rendezvous-fetched bootstrap node.
pub fn hardcoded_contacts() -> Vec<EmberContact> {
    parse_seeds(SEEDS_TXT)
        .iter()
        .filter_map(BootstrapNode::to_contact)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A whitespace-separated seed line for a real Ed25519 keypair, so the
    /// on-curve check in `to_contact` passes and the derived id is stable.
    fn valid_line(seed: u8, addr: &str) -> (String, [u8; 32]) {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let ed = sk.verifying_key().to_bytes();
        let line = format!("{addr} {} {}", hex::encode(ed), hex::encode([seed; 32]));
        (line, ed)
    }

    #[test]
    fn parse_skips_comments_blanks_and_trailing_junk() {
        let (good, _) = valid_line(5, "1.2.3.4:4772");
        let text = format!(
            "# a comment\n\n   \n{good}\n9.9.9.9:1 deadbeef tooshort\nfour fields are too many here\n9.9.9.9:2 onlytwo\n",
        );
        let nodes = parse_seeds(&text);
        // Kept: the good line and the "deadbeef tooshort" line (both have
        // exactly 3 fields — structural parse only). Dropped: comment,
        // blanks, the 6-field line, and the 2-field line.
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].addr, "1.2.3.4:4772");
    }

    #[test]
    fn invalid_keys_are_rejected_at_contact_conversion() {
        let (good, ed) = valid_line(7, "203.0.113.10:4772");
        // 3 fields but the keys are bad hex/length — parses structurally,
        // fails to_contact and is dropped from the contact list.
        let text = format!("{good}\n203.0.113.11:4772 deadbeef tooshort\n");
        let parsed = parse_seeds(&text);
        assert_eq!(parsed.len(), 2);
        let contacts: Vec<EmberContact> =
            parsed.iter().filter_map(BootstrapNode::to_contact).collect();
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].ed25519_pub, ed);
        assert_eq!(contacts[0].addr, "203.0.113.10:4772".parse().unwrap());
    }

    #[test]
    fn empty_text_yields_no_contacts() {
        assert!(parse_seeds("").is_empty());
        assert!(parse_seeds("# only a comment\n\n").is_empty());
    }

    /// Guard against shipping a malformed baked-in seed: every line that
    /// parses structurally from the embedded file must also convert to a
    /// valid contact. Passes trivially while the list is empty (0 == 0).
    #[test]
    fn embedded_seeds_are_all_valid() {
        let parsed = parse_seeds(SEEDS_TXT);
        let contacts = hardcoded_contacts();
        assert_eq!(
            parsed.len(),
            contacts.len(),
            "a baked-in seed in seeds.txt failed to_contact() — check its address/keys",
        );
    }
}
