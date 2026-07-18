# Ember DHT — remaining work and future improvements

Status: **protocol slices complete** behind `ember_native_enabled`
(default **off**). Keyword/source publish, search, bootstrap (rendezvous
`/bootstrap` + KAD bridge), buddy `PROXY_STORE`, peer announce, BLAKE3
integrity digests, rate limits, and diagnostics are live on `develop`.

This replaces the old survival / slice plan docs. For multi-node local
setup see [`ember-network-harness.md`](./ember-network-harness.md).

Code: [`src-tauri/src/network/ember/dht/`](../src-tauri/src/network/ember/dht/).

---

## What's left (before shipping to main)

These are release gates, not missing protocol slices. Private testing is
enough; a public beta is optional.

1. **Private multi-node smoke** — cold join (rendezvous, ideally without
   KAD) → contacts grow → share a file → Ember search finds it → download
   with BLAKE3 verify when a digest is known. Exercise LowID /
   `PROXY_STORE` if you can.
2. **Production rendezvous** — `/register` + signed `/bootstrap` healthy
   with at least a few always-on DHT-on nodes in the pool so fresh clients
   get first contact.
3. **Version + notes for main** — `develop` is `1.5.0-a`, `main` is
   `1.2.0`. Bump to a release version (drop `-a`), merge, and note that
   Ember DHT is opt-in under Settings → Network and stays off by default.
4. **Keep the flag off by default** — ship the code; only users who enable
   Ember join the DHT. Transfers remain eD2K after source discovery.

---

## Known limits (document for users / release notes)

- Multi-keyword search uses sparse DHT intersection (missing secondary
  keys are skipped) plus filename AND at emit time — not a strict
  worldwide AND of every keyword key.
- Gossip contacts from `ANNOUNCE_PEER` / `PEER_LIST` / `FOUND_NODE` are
  unverified until the node hears from them directly (same as Kademlia).
- Download content transfer is still eD2K c2c; the Ember-native chunk
  transfer module is dormant.
- BLAKE3 verify runs when an expected digest is available (search hit,
  DHT source record, known.met / library). Deep links without a digest
  still complete and hash for future share.

---

## Future improvements

Ordered roughly by leverage. None block a main merge if the gates above
pass.

### Bootstrap and network health

- Long-lived seed / always-on operators and monitoring for empty
  `/bootstrap` pools.
- Stronger observed-IP / STUN interplay under weird NATs (soak data).
- Table quality: prefer verified contacts over long-lived gossip; tune
  announce vs bucket-refresh balance under load.

### Search and publish

- Richer keyword indexing (stemming / more than space-split tokens) if
  recall lags KAD for real libraries.
- Clearer search UI when Ember is joining (empty table) vs enabled-but-
  quiet.
- Publish/replication telemetry dashboards beyond `/ember` counters.

### Integrity and downloads

- Surface BLAKE3 verify pass/fail clearly in the transfer UI.
- Seed `emberFileHash` from more UI entry points when the digest is
  already known.
- Optional: finish Ember-native chunk transfer (`transfer.rs`) so
  Ember-to-Ember downloads need no eD2K wire.

### Hardening and ops

- Longer fuzz / property tests in CI; soak jobs overnight.
- Cap or score gossip to limit table poisoning under Sybil pressure.
- Version negotiation story when wire formats evolve past v1.

### Product / UX

- Ember Network page polish for non-dev users (less `/dev/ember`-only
  language).
- Clear "Ember DHT on / off / joining / ready" status in the shell.
- Migration guidance when turning DHT on alongside existing KAD/eD2K.

### Explicitly not planned

- Hardcoded `seeds.txt` or DNS SRV seed lists — join stays rendezvous +
  KAD bridge.

---

## Quick reference

| Area | Location |
| --- | --- |
| DHT engine / wire | `src-tauri/src/network/ember/dht/` |
| Network loop / publish / search drivers | `src-tauri/src/network/mod.rs` |
| Settings toggle | Settings → Network (`ember_native_enabled`) |
| User diagnostics | `/ember` |
| Dev harness panel | `/dev/ember` |
| Local multi-node | [`ember-network-harness.md`](./ember-network-harness.md) |
