# Ember Network Harness

The harness keeps Ember-network development focused on the production
path: EPX, friend rendezvous, QUIC punch, and relay fallback. Each
node runs as an isolated process via the `EMBER_DATA_DIR` override
shipped in `crate::storage::paths`, so config, identity, database,
downloads, and logs do not collide.

## What's automated

- `EMBER_DATA_DIR` resolves the data directory across config, identity,
  database, sharing, network startup, and logging.
- When `EMBER_DATA_DIR` is set, `tauri-plugin-single-instance` is
  skipped automatically so two or more harness nodes can run together.
- `scripts\harness.ps1` builds the rendezvous server and Ember client
  in release mode and launches isolated nodes with sane defaults.

## Quick start

```powershell
# Terminal 1 — local rendezvous server (port 8080 by default).
.\scripts\harness.ps1 rendezvous

# Terminal 2 — node A (HighID-style seeder, tcp 4662 / udp 4672).
.\scripts\harness.ps1 node -Node a

# Terminal 3 — node B (downloader, tcp 4762 / udp 4772).
.\scripts\harness.ps1 node -Node b

# Terminal 4 — node C (LowID candidate, tcp 4862 / udp 4872).
.\scripts\harness.ps1 node -Node c

# Wipe harness state when done (.harness folder).
.\scripts\harness.ps1 reset
```

The first node launch seeds `<EMBER_DATA_DIR>\config.json` with the
matching ports, the local rendezvous URL, KAD auto-connect disabled,
and the setup wizard skipped, so each subsequent launch starts cleanly
without manual configuration.

## Diagnostics

Each running node exposes the new `get_ember_diagnostics` Tauri command,
which returns:

- EPX events received this session
- Mesh peers known
- Broker punch attempts / successes / failures
- Broker relay attempts / successes / failures
- Ember-native: `ember_native_enabled`, session count, pings sent /
  received, pongs received, and the local Noise public key

This is the right surface to watch for harness scenarios; the regular
status bar continues to show only user-facing state.

## Ember-native ping (feature-flagged)

The harness can drive the Ember-native transport end-to-end without
DHT or native file transfer:

1. Edit each node's `<EMBER_DATA_DIR>\config.json` to set
   `"ember_native_enabled": true` (off by default — no production
   builds route Ember-magic UDP).
2. Call `get_ember_diagnostics` on the target node and copy its
   `local_noise_public_key`.
3. From the initiator, invoke `ember_ping_peer` with the target's IP,
   UDP port, and Noise pubkey. The command returns
   `{ success: true, rtt_ms: <ms> }` on success.
4. Refresh `get_ember_diagnostics` on both nodes — counters for
   `ember_pings_sent`, `ember_pings_received`, `ember_pongs_received`,
   and `ember_sessions` should reflect the round trip.

Toggling `ember_native_enabled` off via `update_settings` clears the
transport's sessions immediately, so a re-enable starts from a clean
state.

## Scenarios

1. **EPX source discovery**
   - Share the same file from node A.
   - Start the same download on node B; confirm it discovers A through
     normal KAD/eD2K, then through EPX.
   - `epx_events_received` and `ember_peers_known` should grow on B.

2. **Friend rendezvous**
   - Register A and B on the local rendezvous server (default URL is
     pre-seeded in their configs).
   - Add each other by Friend ID; confirm online events, request /
     accept, chat, and browse.

3. **LowID-to-LowID broker**
   - Make node C firewalled while keeping rendezvous reachable.
   - Trigger a download where both sides would normally be
     LowID-to-LowID.
   - `broker_punch_attempts` should increment first.
   - If punch cannot complete, `broker_punch_failures` and
     `broker_relay_attempts` should increment, followed by either
     `broker_punch_successes` or `broker_relay_successes` before the
     source enters the transfer path.

## Notes

- All node defaults use `127.0.0.1`; firewall hardening should treat
  the harness as trusted local traffic.
- The script uses `cargo run --release` for the rendezvous server and
  `npm run tauri build -- --no-bundle` plus the resulting `ember.exe`
  for nodes. The release flag matters: debug builds are an order of
  magnitude slower, which masks real punch / relay timing behavior.
