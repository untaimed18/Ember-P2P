# First Ember-Native Slice

The first Ember-native vertical slice should be the transport control message,
not DHT search or native file transfer.

## Slice

Use `src-tauri/src/network/ember/transport.rs` to carry one authenticated
`EmberControlMessage` over the existing Noise UDP framing:

```text
EmberTransport.prepare_outgoing(peer, remote_noise_pub, Ping.encode())
peer UDP socket
EmberTransport.process_incoming(packet, from)
IncomingResult::HandshakeComplete { decrypted_payload: Ping.encode(), ... }
EmberTransport.prepare_outgoing(peer, remote_noise_pub, Pong.encode())
IncomingResult::Message { payload: Pong.encode(), ... }
```

## Why This Slice First

- It validates the dormant Noise transport without changing file transfer
  behavior.
- It gives the Ember DHT a secure message carrier later.
- It can be tested locally with two in-memory `EmberTransport` instances before
  it is attached to the main UDP loop.
- It avoids taking a dependency on the unfinished Ember DHT store/search
  semantics or the higher-risk BLAKE3 chunk transfer protocol.

## Acceptance Criteria

1. A focused unit test completes a Noise handshake between two transports and
   delivers a decrypted `Ping`/`Pong` control payload.
2. The control payload is versioned, small, and distinct from future DHT/file
   messages.
3. The main network loop still ignores Ember-native UDP packets until a later
   integration step explicitly routes them.
4. No eMule KAD/eD2K behavior changes while this slice is being proven.

## Follow-On Order

1. Attach the proven control message to the UDP receive loop behind a feature
   flag or internal setting.
2. Add a rendezvous/bootstrap control exchange.
3. Wire the smallest Ember DHT lookup.
4. Defer native file transfer until transport and discovery have live
   observability.

