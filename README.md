# Ember — Decentralized P2P File Sharing

Ember is a modern, open-source P2P file sharing client built on the **eMule KAD network** and **eD2K servers**. It is fully compatible with the existing eMule ecosystem while bringing a modern tech stack, improved source discovery, and a clean interface.

No spyware. No ads. No nonsense.

## Design Philosophy

Ember is a ground-up rewrite of the eMule concept using modern technologies:

- **Rust backend** — Memory-safe, async networking powered by Tokio. No buffer overflows, no dangling pointers, no data races. The entire protocol stack (KAD DHT, eD2K client/server, obfuscation, credits) is implemented in safe Rust.
- **Lightweight shell** — Tauri v2 produces a small, fast desktop app without bundling a full browser engine. The frontend is a SvelteKit SPA that communicates with the Rust backend over Tauri's IPC bridge.
- **Full protocol compliance** — Ember speaks the same KAD and eD2K wire protocols as eMule 0.50a and compatible clients (aMule, eMule Xtreme, etc.). It participates in the same network, finds the same sources, and respects the same credit system. Your downloads and uploads work alongside every other eMule-family client.
- **Modern UI** — A responsive light/dark interface (follows the OS theme by default) with real-time transfer monitoring, inline search spam detection, virtual-scrolling tables, and a first-time setup wizard.

## EPX — Ember Peer Exchange

EPX is an Ember-exclusive extension to the eMule protocol that accelerates source discovery between Ember peers.

### How it works

When two Ember clients connect (during a download or upload), they exchange compact lists of the files they are currently downloading along with the sources they know about for each file. If the receiving peer is downloading one of those files, it immediately gains new sources it may not have found through KAD or eD2K alone.

### Wire protocol

EPX uses opcode `0xF0` on the eMule extended protocol (`OP_EMULEPROT`). The current version is **v4**. The payload format:

```
version       (1 byte, currently 0x04)
file_count    (u16 LE)
  for each file:
    ed2k_hash   (16 bytes)
    file_size   (u64 LE)
    file_flags  (u8, bit 0 = has AICH root hash)
    aich_root   (20 bytes, only present if bit 0 of file_flags is set)
    source_count (u16 LE)
      for each source:
        ipv4      (4 bytes, network order)
        tcp_port  (u16 LE)
        udp_port  (u16 LE)
        flags     (u8, bit 0 = firewalled, bit 1 = obfuscation, bit 2 = relay-capable)
peer_count    (u16 LE)
  for each peer:
    ipv4      (4 bytes, network order)
    tcp_port  (u16 LE)
```

v4 is layout-identical to v3 and adds only a new per-source flag bit
(`relay-capable = 0x04`) used by the LowID-to-LowID broker; v3 parsers
ignore unknown flag bits, so v4 payloads are backward-compatible. v3
additions over v2: per-file AICH root hashes for corruption recovery,
UDP port and capability flags per source, and a peer discovery section
for Ember mesh building. v2 and v3 payloads are still accepted.

### Safety limits

| Limit | Value |
|-------|-------|
| Max files per packet | 200 |
| Max sources per file | 100 |
| Max payload size | 64 KB |
| Max packets per TCP connection | 3 |
| Max total sources per event | 2,000 |
| Max relay attestations (ERAT trailer) | 16 |
| Relay attestation max TTL | 30 minutes |

Private/reserved IPs and zero-port entries are silently dropped. These caps prevent abuse from poisoned or malicious payloads.

TCP EPX ingest and send require Ed25519 proof-of-possession on the session (same bar as Ember chat/browse). UDP EPX (`ExchangeData`) requires an authenticated Noise_IK session. The per-source `relay-capable` flag is advisory only — relay candidates are admitted solely from verified ERAT trailers.

### ERAT — relay attestation trailer (v4)

After the peer list, a v4 payload may append an optional trailer:

```
"ERAT"            (4 bytes magic)
version           (1 byte, currently 0x01)
count             (u16 LE, max 16)
  for each attestation:
    ed25519_pubkey  (32 bytes)
    relay_ipv4      (4 bytes, network order)
    relay_port      (u16 LE)
    expires_at      (u64 LE, unix seconds)
    capability_bits (u32 LE; bit 0 = relay v1)
    reserved        (u16 LE)
    signature       (64 bytes Ed25519 over a domain-separated payload)
```

Attestations are verified before the connection broker records a relay candidate. Invalid, expired, over-TTL, or special-use-IP attestations are dropped.

### Backward compatibility

Non-Ember eMule clients silently ignore the `0xF0` opcode — it causes no errors, disconnects, or side effects. Ember detects peer support via the private `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` handshake (not `ET_MOD_VERSION` or `CT_EMULE_MISCOPTIONS2`). EPX is only exchanged with peers that complete Ember Hello and Ed25519 PoP on that TCP session.

## Friends — Ember-Exclusive Social Features

Ember includes a built-in friend system that works exclusively between Ember users. It is powered by a separate cryptographic identity called the **Ember Hash**, which is distinct from the standard ed2k `user_hash` used for protocol operations and credits.

### How it works

Each Ember client generates a unique 16-byte Ember Hash on first launch. This hash serves as your **Friend ID** — share it with someone and they can find you on the network instantly.

Friend discovery is powered by a lightweight **rendezvous server**. When you connect, Ember registers your presence (a SHA-256 hash of your Friend ID — never the raw ID) with the server. When you search for a friend, Ember queries the server for their hashed ID and gets back their IP and port for a direct connection. The entire lookup takes about 100ms.

Once a friend is found, Ember opens a direct TCP connection for the friend request. After both sides accept, a persistent session is established for chat, file browsing, and priority uploads.

### Features

- **Add by Friend ID** — Share your Friend ID with another user (displayed on the Friends page) and add theirs. Ember finds them through the rendezvous server and sends a friend request.
- **Mutual Friend Requests** — The recipient sees an incoming request notification on the Friends page and can accept or reject it. Chat, file browsing, and priority upload features only activate once both sides have accepted.
- **Real-Time Online Status** — Ember detects when a friend comes online and shows a live online/offline indicator on their card.
- **Direct Messaging** — Send and receive chat messages with mutual friends through a slide-out sidebar. Messages are stored locally for conversation history.
- **Remote File Browsing** — Browse a mutual friend's shared file library while they are online and start downloads directly from the browse results.
- **Priority Upload Slots** — Mutual friends automatically receive priority in your upload queue, giving them faster access to your shared files.
- **Discoverable Banner** — The Friends page shows a confirmation banner when your Friend ID is registered and discoverable on the network.

### Privacy

The rendezvous server only stores SHA-256 hashes of Friend IDs paired with IP/port — it never sees raw Friend IDs. Entries expire automatically after 5 minutes without a heartbeat. Ember identity (Friend ID / Ember Hash and Ed25519 public key) is exchanged only via the private `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` handshake — never via public EmuleInfo tags — so only other Ember clients see it.

## Network Compatibility

Ember is a first-class citizen of the eMule network:

- **KAD (Kademlia DHT)** — Fully implements the KAD v8/v9 protocol for decentralized peer and file discovery, including firewall checks, buddy relay for firewalled peers, keyword publishing, and note publishing.
- **eD2K servers** — Connects to traditional eD2K servers for centralized search and source finding. Supports server-list updates, UDP global search, and server-side IP filtering.
- **Credits & SecIdent** — Implements the eMule credit system with RSA-based Secure Identification to prevent credit theft. Upload priority is determined by the standard credit ratio formula.
- **Protocol obfuscation** — RC4-based TCP and UDP obfuscation (header encryption) to help with ISP throttling, matching eMule's implementation.
- **AICH** — Advanced Intelligent Corruption Handling for part-level hash verification and recovery.

## Features

- **KAD Network & eD2K Servers** — Connect to the decentralized KAD DHT and traditional eD2K servers for peer discovery and search.
- **Advanced Search** — Multi-tab keyword search with type, size, source, and extension filters. Built-in spam detection with balanced and aggressive profiles.
- **Multi-Source Downloads** — Download from multiple peers simultaneously with part-level hash verification, automatic source rotation, and queue management.
- **EPX Source Exchange** — Ember peers share source lists with each other for faster downloads (see above).
- **Library Management** — Shared-folder library with virtualized browsing, sorting/filtering (including duplicate ED2K hashes), share/unshare and upload priorities applied hash-wide across identical copies, folder priorities, pending share/priority intents while files are still hashing, session and all-time upload stats with a Top Uploads panel, in-app audio/video playback via a scoped `ember-media` protocol, media metadata, comments/ratings, eD2K collection create/load through native OS dialogs, scan progress with stop/resume hashing, and a clear warning when a folder hits the 100,000-file indexing cap.
- **Transfer Monitoring** — Real-time progress bars, per-source detail drawers, upload tracking, health indicators, and archive recovery.
- **Friends** — Ember-exclusive friend system powered by a rendezvous server for instant discovery. Add other Ember users by their Friend ID, see real-time online status, chat directly, browse their shared files remotely, and give them priority upload slots.
- **Deep links** — `ed2k://` links and `.emulecollection` files open in Ember (delivered to the running instance when already open).
- **Auto-update** — Signed updates from GitHub Releases (optional background check; always available from Settings → About).
- **Internationalization** — UI strings via Paraglide (`en`, `es`, `fr`, `pt-BR`, `de`, `zh-CN`); see [docs/i18n.md](docs/i18n.md).
- **Security** — RC4 protocol obfuscation, IP filtering (ipfilter.dat / ipfilter.zip) with configurable incoming connection filtering (off by default for VPN compatibility), private IP blocking, path traversal protection, and Content Security Policy headers. Library media uses a custom `ember-media` scheme (Tauri's asset protocol is disabled); each request re-validates that the file is under a current shared or download root.
- **NAT Traversal** — UPnP automatic port mapping, firewall detection, and KAD buddy relay for LowID peers.
- **Statistics** — Session and cumulative transfer statistics, connection uptime, and network health indicators.
- **First-Time Setup Wizard** — Guided configuration on first launch: nickname, download folder, ports, speed limits, KAD auto-connect, and theme.

## Getting Started

### For users

1. Download the latest release from the [Releases page](https://github.com/untaimed18/Ember-P2P/releases).
2. Run the installer (`.exe` on Windows).
3. On first launch, the **Setup Wizard** walks you through essential settings — nickname, download folder, ports, speed limits, KAD auto-connect, and theme.
4. Ember connects to the KAD network automatically. You can enable eD2K server connections later in Settings.

### Port forwarding

Ember uses two ports for peer communication:

| Port | Protocol | Purpose |
|------|----------|---------|
| 4662 | TCP | Peer-to-peer file transfers |
| 4672 | UDP | KAD DHT communication |

These are configurable in **Settings > Network**. For best performance (HighID), forward both ports on your router or enable **UPnP** in settings to have Ember map them automatically.

### For developers

#### Prerequisites

- [Rust](https://rustup.rs/) (1.94+ — required by `Cargo.toml` / rusqlite 0.40)
- [Node.js](https://nodejs.org/) (20+ — matches CI)
- **Windows**: Visual Studio Build Tools with C++ workload

#### Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

The production build produces Windows installers under `src-tauri/target/release/bundle/` (NSIS `.exe` and MSI).

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Svelte 5 + TypeScript + Vite |
| App Shell | Tauri v2 |
| Backend | Rust (2021 edition) |
| Database | SQLite via rusqlite |
| Networking | Tokio async runtime |
| Friend Discovery | Rendezvous server (Axum on Fly.io) |
| GeoIP | MaxMind DB (dbip-country-lite) |
| i18n | Paraglide JS (`messages/*.json`) |
| Updates | tauri-plugin-updater |
| Dialogs | tauri-plugin-dialog (collections, file picks) |

## Project structure

| Path | Role |
|------|------|
| `src/` | SvelteKit frontend (routes, components, Tauri invoke wrappers) |
| `src-tauri/` | Rust backend (network, sharing, commands, storage) |
| `messages/` | Paraglide locale JSON |
| `docs/` | Extra docs (e.g. i18n) |
| `rendezvous-server/` | Friend discovery service |
| `scripts/` | Version bump and helper scripts |

## License

GPLv3 — see [LICENSE](LICENSE) for details.
