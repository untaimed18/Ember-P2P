# First Ember-Native Slice

Status: **integrated behind a feature flag**.

The Ember-native Noise transport now carries `EmberControlMessage::Ping`
and `Pong` payloads through the live UDP receive loop. The integration
is intentionally narrow:

- Off by default (`AppSettings::ember_native_enabled = false`).
- Reachable only on the existing KAD UDP socket — no extra ports.
- Routes solely on the two-byte Ember magic `0xEB 0x3E`. KAD/eD2K
  packets begin with `0xE3` or `0xC5`, so the magic-prefix dispatch
  cannot misroute production traffic. A unit test pins this property.
- Drops Ember-magic packets (without warning spam) when the flag is
  off, so a future Ember-native peer cannot induce log noise on a
  build that hasn't opted in.
- Resets all sessions when the flag flips off, so a session
  established during the "on" period cannot decrypt later traffic if
  the user re-enables (different harness session, different intent).

## What landed

- Persistent Noise X25519 keypair already lived in
  [`storage/identity.rs`](src-tauri/src/storage/identity.rs); each
  Ember node has a stable Ember-native key tied to its data dir.
- `NetworkState::ember_transport` is initialised at startup with the
  identity's Noise keys.
- New `AppSettings::ember_native_enabled` flag, default off, plumbed
  through `update_settings` so it can be toggled at runtime without
  restarting the app.
- New dispatch in `handle_udp_packet`: Ember-magic packets reach
  `EmberTransport::process_incoming` instead of the eMule parser.
- Ping/Pong loop in `handle_ember_native_udp`: incoming `Ping` is
  answered by a Noise-encrypted `Pong`; incoming `Pong` resolves the
  matching pending-ping oneshot.
- `NetworkCommand::SendEmberPing` plus the
  `ember_ping_peer(peer_ip, peer_port, peer_pubkey_hex, timeout_ms?)`
  Tauri command for harness validation. Returns
  `{ success, rtt_ms?, error? }`.
- `EmberDiagnostics` now reports `ember_native_enabled`,
  `ember_sessions`, `ember_pings_sent`, `ember_pings_received`,
  `ember_pongs_received`, and the local Noise public key (so the
  harness can dial this node without a separate command).

## Out of scope for this slice

- DHT lookup, native file transfer, key rotation, peer discovery for
  Noise pubkeys outside the harness, and any UI surface beyond the
  developer Tauri commands.
- The transport is reachable on the existing KAD UDP port. A
  dedicated socket and per-process tuning will follow once the
  feature is moving real volume.

## Verifying the round-trip

With two harness nodes running (`scripts\harness.ps1 node -Node a` and
`-Node b`) and `ember_native_enabled` set to `true` in each node's
`config.json`:

1. Call `get_ember_diagnostics` on node A; copy `local_noise_public_key`.
2. Call `get_ember_diagnostics` on node B; copy `local_noise_public_key`.
3. From node A, invoke `ember_ping_peer` with B's address and pubkey.
   Expect `{ success: true, rtt_ms: <small> }`.
4. Re-fetch `get_ember_diagnostics` on both: A's `ember_pings_sent` and
   `ember_pongs_received` should both be `1`; B's `ember_pings_received`
   should be `1`. Both should report `ember_sessions: 1`.

## Follow-on order

1. Add a rendezvous/bootstrap exchange that uses
   `EmberControlMessage` for liveness checks before introducing new
   wire formats.
2. Persist last-seen Noise pubkeys for known peers (likely on the
   KAD contact record) so peers can dial each other without harness
   intervention.
3. Wire the smallest Ember DHT lookup using the verified transport.
4. Defer native file transfer until transport and discovery have live
   observability through the harness.
