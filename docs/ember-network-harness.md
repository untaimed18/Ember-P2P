# Ember Network Harness

This harness keeps the next Ember-network work focused on the production path:
EPX, friend rendezvous, QUIC punch, and relay fallback. It is intentionally
manual until the app supports per-process data directories; running multiple
desktop instances against the same app data risks shared SQLite/config state.

## Services

Start a local rendezvous server:

```powershell
cd rendezvous-server
$env:PORT = "8080"
$env:RUST_LOG = "ember_rendezvous=debug"
cargo run
```

Set every test client to `http://127.0.0.1:8080` in Settings > Network >
Rendezvous URL.

## Client Matrix

Use three independent machines, VMs, or Windows users until a per-process data
directory override exists.

| Node | TCP | UDP | Role | Expected path |
| --- | ---: | ---: | --- | --- |
| A | 4662 | 4672 | Seeder, HighID when possible | Sends EPX and normal eD2K transfers |
| B | 4762 | 4772 | Downloader, HighID when possible | Receives EPX sources |
| C | 4862 | 4872 | Downloader, intentionally LowID | Exercises punch and relay fallback |

## Scenarios

1. **EPX source discovery**
   - Share the same file from A and start the download on B.
   - Confirm B discovers A through normal KAD/eD2K first.
   - Add C as another source, then confirm B's `epx_events_received` and
     `epx_sources_received` increase after connecting to an Ember peer.

2. **Friend rendezvous**
   - Register A and B with the local rendezvous server.
   - Add each other by Friend ID.
   - Confirm friend online events, request/accept flow, chat, and browse.

3. **LowID-to-LowID broker**
   - Make C firewalled or unforwarded while keeping rendezvous reachable.
   - Start a download where both sides would normally be LowID-to-LowID.
   - Confirm `broker_punch_attempts` increments first.
   - If punch cannot complete, confirm `broker_punch_failures` and
     `broker_relay_attempts` increment.
   - Confirm either `broker_punch_successes` or `broker_relay_successes`
     increments before the source enters the transfer path.

## Automation Gate

Before converting this into a script, add a supported data-dir override used by
network startup, settings, identity, database, and sharing commands. A good
shape is a single helper that resolves `EMBER_DATA_DIR` first and falls back to
Tauri/ProjectDirs. Once that exists, a PowerShell harness can spawn:

```powershell
$env:EMBER_DATA_DIR = "$PWD\.harness\node-a"
npm run tauri dev -- -- --profile node-a
```

Each node should then have its own config, identity, database, downloads, and
logs, while sharing the same local rendezvous server.

