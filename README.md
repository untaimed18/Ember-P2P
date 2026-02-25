# Nexus — Decentralized P2P File Sharing

Nexus is a decentralized, peer-to-peer file sharing application built with **Tauri v2** (Rust backend) and **SvelteKit** (TypeScript frontend). It uses **libp2p** for all networking — peer discovery, encrypted communication, distributed search, and file transfers — with zero central servers.

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Svelte Frontend                        │
│  Dashboard │ Search │ Transfers │ Sharing │ Chat │ Peers  │
├────────────────────────┬─────────────────────────────────┤
│      Tauri IPC         │        Tauri Events             │
├────────────────────────┴─────────────────────────────────┤
│                     Rust Backend                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────┐  │
│  │ Network  │ │ Sharing  │ │  Search  │ │    Chat    │  │
│  │ (libp2p) │ │ (Files)  │ │  (DHT)   │ │ (Gossipsub)│  │
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
| App Shell   | Tauri v2 (Windows 64-bit)                     |
| Backend     | Rust (2021 edition)                           |
| Networking  | libp2p (Kademlia, Gossipsub, Noise, Yamux)    |
| Database    | SQLite via rusqlite                           |
| Hashing     | BLAKE3                                        |

### libp2p Protocols Used

- **Kademlia DHT** — Peer discovery and content routing
- **Gossipsub** — Pub/sub messaging for chat channels
- **Request-Response** — File transfers and search queries
- **Noise** — End-to-end encryption for all connections
- **Yamux** — Stream multiplexing
- **mDNS** — Local network peer discovery (development)
- **AutoNAT** — NAT type detection
- **Relay + DCUtR** — NAT traversal via relay and hole punching

## Features

- **File Sharing** — Share folders, auto-index files with BLAKE3 hashes
- **Distributed Search** — Search across the network via Kademlia DHT
- **Chunked Transfers** — Resumable file transfers with progress tracking
- **Chat Channels** — Topic-based chat rooms via Gossipsub
- **Bandwidth Control** — Token bucket rate limiting for uploads/downloads
- **Peer Management** — View connected peers, ban/unban
- **Encrypted** — All connections use Noise protocol encryption
- **Lightweight** — Tauri produces small binaries with low memory usage

## Prerequisites

- [Rust](https://rustup.rs/) (1.75+ required)
- [Node.js](https://nodejs.org/) (18+ recommended)
- Windows 10/11 64-bit
- Visual Studio Build Tools with C++ workload (for Rust compilation on Windows)

## Development

### Install Dependencies

```bash
npm install
```

### Run in Development Mode

```bash
npm run tauri dev
```

This starts the Vite dev server with hot reload for the frontend and compiles the Rust backend. The first build will take several minutes as it compiles all Rust dependencies.

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
    chat/+page.svelte       # Chat channels
    peers/+page.svelte      # Connected peers
    settings/+page.svelte   # App settings
  lib/
    api/                    # Typed Tauri IPC wrappers
    stores/                 # Svelte stores (reactive state)
    components/             # Reusable UI components
    types/                  # Shared TypeScript interfaces

src-tauri/                  # Rust backend
  src/
    lib.rs                  # App setup, command registration
    types.rs                # Shared data types
    app_state.rs            # Global application state
    network/                # libp2p networking layer
      behaviour.rs          # Composed NetworkBehaviour
      protocol.rs           # Request-response codec
      events.rs             # Swarm event handler
      discovery.rs          # Bootstrap configuration
    sharing/                # File sharing engine
      indexer.rs            # Directory scanner + BLAKE3 hasher
      transfer.rs           # Chunked file transfer
      manager.rs            # Transfer queue management
    search/                 # Distributed search
      index.rs              # Local inverted index
      query.rs              # Search engine
    chat/                   # Chat system
      channel.rs            # Channel management
      message.rs            # Message history
    bandwidth/              # Bandwidth control
      limiter.rs            # Token bucket rate limiter
    storage/                # Persistence
      database.rs           # SQLite schema + operations
      config.rs             # App configuration
    commands/               # Tauri command handlers
      search.rs, transfers.rs, chat.rs,
      sharing.rs, peers.rs, settings.rs
```

## Connecting to Peers

### Local Development (mDNS)

Peers on the same local network are discovered automatically via mDNS. Run Nexus on two machines on the same LAN and they will find each other.

### Remote Peers (Bootstrap Nodes)

Add bootstrap node addresses in Settings > Network > Bootstrap Nodes using multiaddr format:

```
/ip4/203.0.113.1/tcp/4001/p2p/12D3KooW...
```

### Manual Connection

Peers exchange their multiaddr strings out-of-band and add them as bootstrap nodes.

## License

MIT
