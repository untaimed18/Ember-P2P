# First Ember-Native Slice

Status: **designed and unit-tested, not yet integrated**.

The first Ember-native vertical slice is the encrypted control message
on top of the existing Noise transport in
`src-tauri/src/network/ember/transport.rs`. The protocol bits are in
place and proven by tests; integration into the live UDP loop is
intentionally deferred until after the harness work and is the next
thing to land before any DHT or native-transfer work begins.

## What exists today

- `EmberControlMessage::Ping { nonce }` and `EmberControlMessage::Pong { nonce }`
  with a fixed 10-byte versioned encoding (`encode` / `decode` round-trip).
- `EmberTransport::prepare_outgoing` / `process_incoming` already speak
  Noise IK and Noise XX with full handshake and transport state.
- A focused unit test
  (`control_message_crosses_established_noise_session`) drives a Noise
  IK handshake between two `EmberTransport` instances and verifies the
  encoded Ping payload arrives intact, then sends a Pong on the
  established session.

## What integration requires (next)

1. Decide where Ember-native UDP traffic should bind: alongside the
   existing KAD UDP socket via shared dispatch, or on a dedicated
   socket. (Recommendation: shared socket with `is_ember_packet`
   dispatch on first three bytes — zero cost when no Ember peers are
   talking to us.)
2. Persist the local Noise X25519 keypair in the data directory under
   the EMBER_DATA_DIR-aware path resolver so each harness node has its
   own identity.
3. Add a feature flag (settings or env-only) to opt the live network
   loop into Ember-native UDP receive, so the integration can be tested
   on a single harness node without affecting eMule compatibility for
   everyone else.
4. Add a tiny in-app diagnostic that issues a `Ping` to a peer's
   advertised Noise key and reports the round-trip time, mirroring how
   we'd verify the path against a real network.

## Why not skip ahead

- Integration without a harness or diagnostic surface invites silent
  regressions in the production eMule path.
- The DHT and native transfer slices both depend on this transport
  layer; landing them first means re-doing them once transport
  evolves.
- The EPX + LowID-to-LowID path is the user-visible Ember mesh today.
  It deserves stable telemetry before a parallel transport starts
  attracting bug reports.

## Acceptance criteria when integration lands

1. Live UDP loop dispatches Ember-magic packets to `EmberTransport`
   without mis-routing them as KAD/eD2K.
2. Two harness nodes can complete a Noise IK handshake over real UDP
   and exchange a `Ping` / `Pong`.
3. eMule KAD/eD2K behavior is unchanged for builds where the Ember
   feature flag is off.
4. Connection state, key material, and counters reset cleanly on
   shutdown and on `EMBER_DATA_DIR` swaps.

## Follow-on order

1. Attach the proven control message to the UDP receive loop behind
   the feature flag.
2. Add a rendezvous/bootstrap exchange that uses `EmberControlMessage`
   for liveness checks.
3. Wire the smallest Ember DHT lookup using the verified transport.
4. Defer native file transfer until transport and discovery have live
   observability through the harness.
