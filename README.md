# Nexus — Decentralized P2P File Sharing

Nexus is a decentralized, peer-to-peer file sharing application built with **Tauri v2** (Rust backend) and **SvelteKit** (TypeScript frontend). It implements the **eMule KAD** (Kademlia) protocol and **ED2K** file transfer protocol, providing full compatibility with the existing eMule network — no central servers required.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Svelte Frontend                        │
│  Dashboard │ Search │ Transfers │ Sharing │ Peers        │
├────────────────────────┬─────────────────────────────────┤
│      Tauri IPC         │        Tauri Events             │
├────────────────────────┴─────────────────────────────────┤
│                     Rust Backend                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │
│  │ Network  │ │ Sharing  │ │  Search  │ │  Security  │  │
│  │(KAD+ED2K)│ │ (Files)  │ │  (DHT)   │ │ (Filters)  │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────────┐  │
│  │Bandwidth │ │ Storage  │ │     Command Handlers     │  │
│  │ (Limiter)│ │ (SQLite) │ │     (Tauri Commands)     │  │
│  └──────────┘ └──────────┘ └──────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Tech Stack

| Layer       | Technology                                    |
|-------------|-----------------------------------------------|
| Frontend    | SvelteKit 5 + TypeScript + Vite               |
| App Shell   | Tauri v2                                      |
| Backend     | Rust (2021 edition)                           |
| Networking  | eMule KAD (Kademlia DHT) + ED2K protocol      |
| Database    | SQLite via rusqlite                           |
| Hashing     | MD4 (ED2K file hashes), MD5 (obfuscation keys)|

### Protocols

- **Kademlia DHT (KAD)** — Peer discovery, keyword search, source finding, and DHT publish/store over UDP
- **ED2K** — Client-to-client file transfers over TCP with multi-source download support
- **Protocol Obfuscation** — RC4-based packet encryption compatible with eMule's obfuscation layer
- **UPnP** — Automatic router port mapping for NAT traversal
- **Buddy System** — Relay-based connectivity for firewalled clients

## Features

- **eMule Network Compatible** — Connects to the existing eMule KAD network; interoperates with eMule, aMule, and other compatible clients
- **File Sharing** — Share folders, auto-index files with ED2K (MD4) hashes
- **Distributed Search** — Keyword search across the KAD DHT with source and notes lookup
- **Multi-Source Downloads** — Download from multiple peers simultaneously with part-level hash verification
- **Bandwidth Control** — Token bucket rate limiting for uploads and downloads
- **Peer Management** — View connected peers, ban/unban with network-level enforcement
- **NAT Traversal** — UPnP port mapping, firewall detection, and buddy relay system
- **ED2K Links** — Parse and generate `ed2k://` file links
- **Notes & Ratings** — Publish and search file comments/ratings on the DHT
- **Desktop-Only** — Runs as a native desktop application (no browser launch, no web interface)

## Security

Nexus implements comprehensive security measures compatible with the eMule/KAD network:

- **Protocol Obfuscation** — RC4 encryption for KAD UDP packets (toggleable in settings)
- **IP Filter** — eMule-compatible `ipfilter.dat` support to block known-bad IP ranges
- **Private IP Blocking** — Rejects RFC1918/loopback/link-local addresses in the routing table to prevent poisoning
- **Flood Protection** — Per-IP rate limiting, DNS port 53 rejection, and unsolicited response validation
- **Tag Size Limits** — Enforced maximum sizes on all parsed tag fields to prevent memory exhaustion
- **Decompression Bomb Protection** — Size-limited incremental decompression for KAD and ED2K payloads
- **TCP Connection Limits** — Per-IP connection cap on the upload server
- **Path Traversal Protection** — Filename sanitization for all downloaded files
- **Source IP Verification** — DHT store always overrides publisher source IP with verified packet sender
- **Content Security Policy** — Restrictive CSP for the Tauri webview
- **Peer Banning** — Network-level packet rejection for banned peers (O(1) IP lookup)
- **Routing Table Hardening** — Per-IP and per-subnet contact limits matching eMule's implementation
- **Download Integrity** — Per-part MD4 hash verification with automatic retry on mismatch

All security features can be configured in Settings > Security.

## Prerequisites

- [Rust](https://rustup.rs/) (1.75+)
- [Node.js](https://nodejs.org/) (18+)
- Platform-specific build dependencies:
  - **Linux**: `libgtk-3-dev libwebkit2gtk-4.1-dev libsoup-3.0-dev libjavascriptcoregtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`
  - **Windows**: Visual Studio Build Tools with C++ workload
  - **macOS**: Xcode Command Line Tools

## Development

### Install Dependencies

```bash
npm install
```

### Run in Development Mode

```bash
npm run tauri dev
```

This starts the Vite dev server (localhost only) with hot reload for the frontend and compiles the Rust backend. The first build will take several minutes as it compiles all Rust dependencies.

### Build for Production

```bash
npm run tauri build
```

This produces an installer in `src-tauri/target/release/bundle/`.

## Project Structure

```
src/                        # Svelte frontend
  routes/                   # SvelteKit pages
    +layout.svelte          # App shell (sidebar + status bar)
    +page.svelte            # Dashboard
    search/+page.svelte     # Network file search
    transfers/+page.svelte  # Active/completed transfers
    sharing/+page.svelte    # Manage shared folders
    peers/+page.svelte      # Connected peers
    settings/+page.svelte   # App settings (network, security, bandwidth)
  lib/
    api/                    # Typed Tauri IPC wrappers
    stores/                 # Svelte stores (reactive state)
    components/             # Reusable UI components
    types/                  # Shared TypeScript interfaces

src-tauri/                  # Rust backend
  src/
    lib.rs                  # App setup, plugin + command registration
    main.rs                 # Entry point
    types.rs                # Shared data types (FileInfo, PeerInfo, Transfer, etc.)
    app_state.rs            # Global application state
    security.rs             # Filename sanitization, path traversal protection
    network/
      mod.rs                # Network event loop, UDP/TCP handling, command dispatch
      upnp.rs               # UPnP port mapping
      kad/                  # KAD (Kademlia) protocol implementation
        types.rs            # KadId, KadContact, KadTag, KadUDPKey
        messages.rs         # KAD message encode/decode (all KAD2 opcodes)
        routing.rs          # Kademlia routing table with IP/subnet limits
        search.rs           # Iterative lookup + fetch search engine
        store.rs            # DHT key/source/notes store with tolerance zone
        publish.rs          # Keyword and source publishing
        bootstrap.rs        # nodes.dat read/write, bootstrap contacts
        buddy.rs            # Buddy relay system for firewalled clients
        obfuscation.rs      # RC4 packet encryption/decryption
        protection.rs       # Flood protection, rate limiting, response validation
        ip_filter.rs        # IP filter (ipfilter.dat + private IP blocking)
      ed2k/                 # ED2K file transfer protocol
        messages.rs         # ED2K packet format, Hello, EmuleInfo, file requests
        hash.rs             # ED2K (MD4) file hashing
        transfer.rs         # Single-source file download with resume
        multi_source.rs     # Multi-source parallel download
        part_tracker.rs     # Part completion tracking (.part.met)
        server.rs           # TCP upload server with queue management
    sharing/
      indexer.rs            # Directory scanner + ED2K hasher
      manager.rs            # Transfer queue management
    search/
      index.rs              # Local file index for keyword matching
    bandwidth/
      limiter.rs            # Token bucket rate limiter
    storage/
      database.rs           # SQLite schema + operations
      config.rs             # App configuration persistence
    commands/               # Tauri command handlers
      search.rs             # Search, ED2K links, notes
      transfers.rs          # Download/upload control
      sharing.rs            # Shared folder management
      peers.rs              # Peer listing, ban/unban
      settings.rs           # Settings read/write, nodes.dat download
```

## Connecting to the Network

### Bootstrap (nodes.dat)

Nexus bootstraps into the KAD network using a `nodes.dat` file. On first launch, it uses hardcoded bootstrap nodes. You can download the latest `nodes.dat` from Settings > Network > "Download Latest nodes.dat".

### Ports

| Port | Protocol | Purpose                                      |
|------|----------|----------------------------------------------|
| 4662 | TCP      | ED2K client-to-client file transfers          |
| 4672 | UDP      | KAD DHT communication                         |

These can be changed in Settings > Network. If UPnP is enabled, ports are automatically mapped on your router.

### Firewall / NAT

If you're behind a firewall or NAT, Nexus will:
1. Attempt UPnP port mapping (if enabled)
2. Probe external IP and port via KAD peers
3. Find a "buddy" relay node to receive incoming connections

## License

MIT
