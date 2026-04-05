# Ember — Decentralized P2P File Sharing

Ember is a modern, open-source P2P file sharing client built on the **eMule KAD network** and **eD2K servers**. It is fully compatible with the existing eMule ecosystem while bringing a modern tech stack, improved source discovery, and a clean interface.

No spyware. No ads. No nonsense.

## Design Philosophy

Ember is a ground-up rewrite of the eMule concept using modern technologies:

- **Rust backend** — Memory-safe, async networking powered by Tokio. No buffer overflows, no dangling pointers, no data races. The entire protocol stack (KAD DHT, eD2K client/server, obfuscation, credits) is implemented in safe Rust.
- **Lightweight shell** — Tauri v2 produces a small, fast desktop app (~15 MB installed) without bundling a full browser engine. The frontend is a SvelteKit SPA that communicates with the Rust backend over Tauri's IPC bridge.
- **Full protocol compliance** — Ember speaks the same KAD and eD2K wire protocols as eMule 0.50a and compatible clients (aMule, eMule Xtreme, etc.). It participates in the same network, finds the same sources, and respects the same credit system. Your downloads and uploads work alongside every other eMule-family client.
- **Modern UI** — A responsive, dark-mode-first interface with real-time transfer monitoring, inline search spam detection, virtual-scrolling tables, and a first-time setup wizard.

## EPX — Ember Peer Exchange

EPX is an Ember-exclusive extension to the eMule protocol that accelerates source discovery between Ember peers.

### How it works

When two Ember clients connect (during a download or upload), they exchange compact lists of the files they are currently downloading along with the sources they know about for each file. If the receiving peer is downloading one of those files, it immediately gains new sources it may not have found through KAD or eD2K alone.

### Wire protocol

EPX uses opcode `0xF0` on the eMule extended protocol (`OP_EMULEPROT`). The current version is **v3**. The payload format:

```
version       (1 byte, currently 0x03)
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
        flags     (u8, bit 0 = firewalled, bit 1 = obfuscation)
peer_count    (u16 LE)
  for each peer:
    ipv4      (4 bytes, network order)
    tcp_port  (u16 LE)
```

v3 additions over v2: per-file AICH root hashes for corruption recovery, UDP port and capability flags per source, and a peer discovery section for Ember mesh building. v2 payloads are still accepted.

### Safety limits

| Limit | Value |
|-------|-------|
| Max files per packet | 200 |
| Max sources per file | 100 |
| Max payload size | 64 KB |
| Max packets per TCP connection | 3 |
| Max total sources per event | 2,000 |

Private/reserved IPs and zero-port entries are silently dropped. These caps prevent abuse from poisoned or malicious payloads.

### Backward compatibility

Non-Ember eMule clients silently ignore the `0xF0` opcode — it causes no errors, disconnects, or side effects. Ember detects peer support via the `ET_MOD_VERSION` tag (must start with `"Ember"`) and the Ember capability bit in `CT_EMULE_MISCOPTIONS2`. EPX is only sent to confirmed Ember peers.

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

The rendezvous server only stores SHA-256 hashes of Friend IDs paired with IP/port — it never sees raw Friend IDs. Entries expire automatically after 5 minutes without a heartbeat. The Ember Hash is also exchanged between peers during the EmuleInfo handshake using a dedicated tag (`0x56`), but only to other Ember clients.

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
- **Library Management** — Browse and manage shared files with sorting, filtering, bulk operations, comments, ratings, and eD2K collection support.
- **Transfer Monitoring** — Real-time progress bars, per-source detail drawers, upload tracking, health indicators, and archive recovery.
- **Friends** — Ember-exclusive friend system powered by a rendezvous server for instant discovery. Add other Ember users by their Friend ID, see real-time online status, chat directly, browse their shared files remotely, and give them priority upload slots.
- **Security** — RC4 protocol obfuscation, IP filtering (ipfilter.dat / ipfilter.zip) with configurable incoming connection filtering (off by default for VPN compatibility), private IP blocking, path traversal protection, and Content Security Policy headers.
- **NAT Traversal** — UPnP automatic port mapping, firewall detection, and KAD buddy relay for LowID peers.
- **Statistics** — Session and cumulative transfer statistics, connection uptime, and network health indicators.
- **First-Time Setup Wizard** — Guided configuration on first launch: nickname, download folder, ports, speed limits, KAD auto-connect, and theme.

## Getting Started

### For users

1. Download the latest release from the [Releases page](https://github.com/untaimed18/Ember-KAD/releases).
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

- [Rust](https://rustup.rs/) (1.75+)
- [Node.js](https://nodejs.org/) (18+)
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

The production build produces an NSIS installer in `src-tauri/target/release/bundle/`.

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

## License

GPLv3 — see [LICENSE](LICENSE) for details.
