# Ember — Decentralized P2P File Sharing

Ember is a modern, open-source P2P file sharing client built on the **eMule KAD network** and **eD2K servers**. It is fully compatible with the existing eMule ecosystem while bringing a modern tech stack, improved source discovery, and a clean interface.

It also runs a network of its own: the [**Ember Network**](#ember-network) is an encrypted, server-less overlay where Ember nodes find each other, publish their shared files, and resolve download sources over their own DHT. It is on by default and runs alongside KAD and eD2K rather than replacing them.

No spyware. No ads. No nonsense.

## Design Philosophy

Ember is a ground-up rewrite of the eMule concept using modern technologies:

- **Rust backend** — Memory-safe, async networking powered by Tokio. No buffer overflows, no dangling pointers, no data races. The entire protocol stack (KAD DHT, eD2K client/server, obfuscation, credits) is implemented in safe Rust.
- **Lightweight shell** — Tauri v2 produces a small, fast desktop app (~15 MB installed) without bundling a full browser engine. The frontend is a SvelteKit SPA that communicates with the Rust backend over Tauri's IPC bridge.
- **Full protocol compliance** — Ember speaks the same KAD and eD2K wire protocols as eMule 0.50a and compatible clients (aMule, eMule Xtreme, etc.). It participates in the same network, finds the same sources, and respects the same credit system. Your downloads and uploads work alongside every other eMule-family client.
- **A network of its own** — On top of that compatibility, Ember runs the [Ember Network](#ember-network): its own Kademlia DHT over an encrypted Noise transport, with no directory server, no tracker, and no shipped seed list. Peers join through the networks they are already on.
- **Modern UI** — A responsive, dark-mode-first interface with real-time transfer monitoring, inline search spam detection, virtual-scrolling tables, and a first-time setup wizard.

## Ember Network

The Ember Network is Ember's own encrypted peer-to-peer overlay: a second network Ember nodes run between themselves, in parallel with KAD and eD2K. Nodes find each other directly, publish the files they share, and resolve download sources over their own Kademlia DHT. There is no directory server, no tracker, and no shipped seed list.

It is **always on** (`ember_native_enabled`). The switch on the **Ember Network** page and in **Settings → Network** stays visible but cannot be turned off. Code lives in [`src-tauri/src/network/ember/`](src-tauri/src/network/ember/) with the DHT under [`dht/`](src-tauri/src/network/ember/dht/); the protocol specification is [docs/ember-dht-specification.pdf](docs/ember-dht-specification.pdf), and standing work notes are in [docs/ember-dht.md](docs/ember-dht.md).

> **Beta.** The overlay is on by default and in daily use, but see [Current limits](#current-limits) before relying on it.

### Transport

Ember frames ride the KAD UDP socket (4672 by default) and are told apart by a two-byte magic (`0xEB 0x3E`), so one forwarded port serves both networks. Everything after the magic is encrypted.

- **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** when the peer's static X25519 key is already known.
- **`Noise_XX_25519_ChaChaPoly_BLAKE2s`** for first contact, with a stateless retry cookie handed to initiators whose source address is not yet proven return-routable. The cookie is only sent once the unvalidated-handshake budget is spent, so a peer that does not know the packet type still completes first contact whenever we are not under a flood.
- Control frames and DHT frames share one decrypted byte stream and are namespaced by a leading version byte (`0xC1` for control), chosen so the two decoders cannot alias each other.
- Sessions idle for 5 minutes are evicted; concurrent sessions (4096) and pending handshakes (512) are capped.

### DHT

| Property | Value |
|----------|-------|
| Node ID | 128-bit, BLAKE3 of the node's Ed25519 public key |
| Bucket size (k) | 20 |
| Lookup concurrency (α) | 5 |
| Contacts per response | 20 |
| Contact liveness | 600s timeout, evicted after 3 consecutive unanswered queries |
| Subnet diversity | 3 per subnet per bucket; global cap scales with table occupancy |
| Wire version | 2 (`EMBER_DHT_VERSION`, `EMBER_DHT_MIN_VERSION`) |
| Persisted contacts | 200 (`nodes_ember.dat`) |

Frames are Ed25519-signed, and a contact counts as verified only once it has answered directly — gossip from `FOUND_NODE` / `PEER_LIST` and entries read back from disk are leads until they reply. The version byte is checked against a *range* rather than a single value, so an incompatible peer is refused cleanly at the version instead of accumulating malformed-frame counters that read like packet loss. A future change that only adds to the format can lower the minimum instead of raising both.

### Joining

There is no bootstrap server and no bundled address list. A cold node gets in through the following, in rough order of who arrives first:

1. **The KAD rendezvous key** — Ember nodes advertise themselves under one fixed KAD key as an ordinary source record carrying their Noise pubkey tag; a node with a near-empty table runs a plain source lookup there. Re-advertised every 5 hours (matching KAD's source TTL) and only while the node is reachable and already publishing something, so a leecher never generates publish traffic purely to list itself. Lookups are spaced 10 minutes apart and stop once the table reaches one k-bucket.
2. **The KAD bridge** — Ember peers noticed in ordinary KAD traffic get DHT-pinged so their signed `PONG` folds them into the routing table. Rate-capped per maintenance cycle and quiet above a contact threshold.
3. **eD2K client-to-client sessions** — Peers that advertise the Ember capability bit over a normal eD2K transfer are cached with their UDP port and bridged in, via Noise_XX when no static key is known. This is the path for a client running with no KAD at all.
4. **DHT gossip and `nodes_ember.dat`** — `FOUND_NODE` / `PEER_LIST` / `ANNOUNCE_PEER`, plus up to 200 persisted contacts, once the node has been online before.

The rendezvous server behind [Friends](#friends--ember-exclusive-social-features) has **no role** in DHT bootstrap. A server-hosted bootstrap pool is explicitly not planned: it would hand whoever runs the server an identity-to-IP roster of every participant. Hardcoded seed lists and DNS SRV seeds are ruled out for the same reason — joining stays the rendezvous key, the bridges, gossip, and the persisted contact file.

The consequence is that every path except `nodes_ember.dat` presupposes either a live KAD connection or an eD2K transfer with an Ember-capable peer, so **a first run with KAD off and no servers has no way in**. Ember rides eMule's bootstrap by design. A fresh node can also legitimately sit at zero contacts for a minute or two while its first maintenance cycle runs the bridge; the Ember Network page reports **Connecting** for that window rather than claiming a fault.

### Publish and search

Shared files are published as keyword records (findable by name) and source records (fetchable), and republished on a cycle to stay alive. Publishing starts once the node has contacts.

- **Search** — The Search page exposes an **Ember Only** method, and **Global** queries Ember alongside KAD and servers, merging into one de-duplicated result list. With KAD and eD2K both offline, Global falls back to Ember alone.
- **Source lookup** — Downloads resolve sources on the Ember DHT in addition to KAD and servers, so a file found elsewhere can still gain Ember sources.
- **Publish badge** — The Library marks a shared file with an **Ember** badge (`shared_ember` on `FileInfo`) once a source record is placed, which is the point at which other Ember users can actually fetch it.
- **Firewalled publishing** — LowID and firewalled nodes publish through a buddy `PROXY_STORE` fan-out instead of storing directly.
- **BLAKE3 integrity** — Records carry a BLAKE3 digest and a download verifies against it whenever one is available (search hit, DHT source record, `known.met` / library). Deep links without a digest still complete and are hashed for future sharing.
- **Adaptive abuse limits** — Admission and storage limits scale with observed network size ([`dht/scale.rs`](src-tauri/src/network/ember/dht/scale.rs)): per-IP and per-subnet caps, return-routability checks before a node spends anything substantial on a request (so Ember cannot be used as a traffic reflector), and per-publisher storage quotas so one peer cannot fill the space this node offers the network or sidestep its quota by changing port.

### Current limits

- **Content still moves over eD2K.** [`ember/transfer.rs`](src-tauri/src/network/ember/transfer.rs) holds a 256 KiB chunk protocol and a BLAKE3 hash tree, but nothing imports it yet. Ember discovers the source; the bytes travel the eMule wire. Wiring it up is the largest remaining piece toward a network that does not need the eMule wire at all.
- **Bootstrap depends on eMule** — as described above; seed lists are deliberately not planned.
- **Version mismatches are silent** — incompatible peers refuse each other cleanly, but neither side is told why and there is no upgrade prompt. They simply never fold each other into a routing table.
- **Multi-keyword search is approximate** — sparse DHT intersection (missing secondary keys are skipped) plus a filename match at emit time, not a strict worldwide AND of every keyword.
- **No reputation scoring on gossip** — admission is bounded by the diversity caps above, but gossip itself is not scored, so table poisoning under sustained Sybil pressure is only rate-limited.
- **Not yet exercised end to end** — LowID publishing through buddy `PROXY_STORE`, a cold join from an empty contact file with no KAD, and republish behaviour across a full record TTL on a large library.

## EPX — Ember Peer Exchange

EPX is an Ember-exclusive extension to the eMule protocol that accelerates source discovery between Ember peers.

EPX and the [Ember Network](#ember-network) are separate mechanisms that are easy to conflate. EPX is an extra opcode on the *eMule* wire, exchanged with Ember peers you are already transferring with; the Ember Network is a whole overlay with its own DHT and its own transport. They work independently — EPX still helps with the overlay switched off.

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

Private/reserved IPs and zero-port entries are silently dropped, as is our own address when a peer hands it back. These caps prevent abuse from poisoned or malicious payloads.

The 64 KB ceiling applies to the TCP path, which streams. UDP EPX has to fit one Noise datagram, so it is packed to a separate, much smaller budget derived from the transport's frame size — the same files and sources in the same wire format, just fewer of them.

TCP EPX ingest and send require the Ember HELLO handshake plus a verified BLAKE3 binding between the peer's advertised Ed25519 public key and its Ember hash. That binding is an offline consistency check rather than proof the peer holds the matching private key — an attacker who observed the pair on the wire can replay it — so it is deliberately a lower bar than the proof-of-possession required for chat, browse and other friend privileges. EPX carries source data only, bounded by the caps above, and never grants those privileges. UDP EPX (`ExchangeData`) requires an authenticated Noise_IK session. The per-source `relay-capable` flag is advisory only — relay candidates are admitted solely from verified ERAT trailers.

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

Non-Ember eMule clients silently ignore the `0xF0` opcode — it causes no errors, disconnects, or side effects. Ember detects peer support via the private `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` handshake (not `ET_MOD_VERSION` or `CT_EMULE_MISCOPTIONS2`). EPX is only exchanged with peers that complete Ember Hello and whose advertised key binds to their Ember hash on that TCP session.

## Friends — Ember-Exclusive Social Features

Ember includes a friend system that works only between Ember users. It runs on a separate cryptographic identity from the eD2K one: an Ed25519 identity keypair generated on first launch, whose truncated BLAKE3 digest (`BLAKE3(ed25519_pub)[..16]`) is the 16-byte **Ember Hash**. That hash is distinct from the standard eD2K `user_hash` used for protocol operations and credits.

### Friend Codes

The Ember Hash is your **Friend ID**. The Friends page presents it as a **v2 Friend Code**, which carries the public key alongside it:

```
ember2:<32 hex — Ember Hash>:<64 hex — Ed25519 public key>
```

The key must BLAKE3-bind to the hash or the code is rejected at parse time (`verify_ember_hash_binding`), so a code cannot advertise an identity its holder does not own. Bare-hex Friend IDs are still accepted for compatibility with older codes.

### Discovery

Discovery runs through a lightweight **rendezvous server** ([`rendezvous-server/`](rendezvous-server/)). Ember registers presence under 32-byte *capabilities* derived from the friend relationship rather than under a raw Friend ID, and every register and lookup is Ed25519-signed by the identity that owns it, so an entry cannot be spoofed with a stolen hash alone. Pairwise capabilities rotate on a 15-minute epoch (`PAIRWISE_CAPABILITY_EPOCH_SECS`) and server-side entries expire 5 minutes after the last heartbeat (`ENTRY_TTL`), so nothing stored there is a long-lived identifier. Adding or accepting a friend forces a presence refresh instead of waiting out the normal heartbeat interval.

Between Ember peers, the Ember Hash and its public key are exchanged over the private `OP_EMBER_HELLO` / `OP_EMBER_HELLOANSWER` handshake. The legacy EmuleInfo tag harvest (`ET_EMBER_HASH`, `0x56`) has been removed — nothing is learned from ordinary eMule metadata any more.

### Sessions

Once a friend is located, Ember opens a direct TCP connection and negotiates a **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** secure stream ([`ed2k/secure_stream.rs`](src-tauri/src/network/ed2k/secure_stream.rs)) with Ed25519 proof of possession — a signature round trip over a fresh nonce (`friend_connect::perform_ember_auth`), not just the offline hash↔pubkey binding check. The X25519 static key that IK authenticates is checked against the standard Ed25519→X25519 conversion of the advertised identity key, so the session and the Friend ID cannot disagree. Chat, browse, offers, friends-only shares and verified requests unlock only on that authenticated session; when ordinary HighID or callback routes are unavailable, friend file transfers can also run over it.

### Chat encryption

Friend chat (`OP_EMBER_CHAT_MSG`) is encrypted end to end, inside the Noise session:

- The AEAD key is HKDF-derived (info `ember-friend-chat-v1`) from an X25519 Diffie-Hellman between the two friends' Ed25519 identity keys, converted to Montgomery form. No separate chat keypair is minted, advertised or rotated: both sides have already proven possession of the identity key.
- Bodies are sealed with **XChaCha20-Poly1305** in a versioned envelope (`version || 24-byte nonce || ciphertext‖tag`), so old and new builds cannot silently misread each other. Once encryption is available, a plaintext fallback is refused rather than accepted.
- Conversation history is encrypted at rest under a dedicated random key stored beside the database (`chat-history.key`); plaintext rows are migrated forward and a plaintext read is refused. If the key cannot be recovered, history stays sealed and says so rather than failing obscurely.
- Outbound messages queue locally and retry once the friend is reachable again.

This is a **static** DH, not a ratchet. It gives confidentiality and integrity against anyone observing or relaying the session — including a compromised rendezvous or relay hop — but **no forward secrecy** if an identity key is compromised later. IP addresses, capabilities, message size and timing remain observable. The in-app UI states the same caveat rather than implying more.

### Friend features

- **v2 Friend Codes** — Share the code from the Friends page and add theirs. Ember finds them through the rendezvous server and sends a friend request.
- **Mutual Friend Requests** — The recipient sees an incoming request on the Friends page and can accept or reject it. Chat, browse, offers and priority uploads activate only once both sides have accepted **and** a secure session is up.
- **Real-Time Online Status** — Live online/offline indicators, plus a banner when your own identity is registered and discoverable (and a warning when registration failed, so you know friends may not find you).
- **End-to-End Encrypted Chat** — A slide-out conversation sidebar with an **Encrypted** badge, durable history, and messages that queue while a friend is offline.
- **Remote File Browsing** — Browse a mutual friend's shared library while they are online and start downloads straight from the results.
- **Friends-Only Shares** — Mark Library files as friends-only so they stay out of public search and only mutual friends can request them.
- **Friend File Offers** — Push a specific shared file to a mutual friend; it arrives as an actionable notification they can accept or decline.
- **Friend Transfers Without HighID** — Mutual-friend downloads can use the secure friend session (and optional peer relay) when HighID or callback paths are unavailable.
- **Priority Upload Slots** — Mutual friends jump ahead in your upload queue on authenticated sessions. Ordinary eMule file connections do not.
- **Friend Block List** — Block a Friend ID to reject future requests, chat, browse and offers from that identity. Blocking removes any existing mutual friendship, and unblocking does not restore it.
- **Optional Peer Relaying** — **Relay for other peers** (Settings) lets your client carry traffic for peers that cannot reach each other directly. It is what makes transfers work behind strict NATs, and it spends your upload bandwidth on people you are not trading with, so it can be turned off.

## Network Compatibility

Ember is a first-class citizen of the eMule network:

- **KAD (Kademlia DHT)** — Fully implements the KAD v8/v9 protocol for decentralized peer and file discovery, including firewall checks, buddy relay for firewalled peers, keyword publishing, and note publishing.
- **eD2K servers & peer exchange** — Connects to traditional eD2K servers for centralized search and source finding, and takes part in server-mediated peer/source exchange once connected. Supports server-list updates, UDP global search, and server-side IP filtering.
- **Credits & SecIdent** — Implements the eMule credit system with RSA-based Secure Identification to prevent credit theft. Upload priority is determined by the standard credit ratio formula.
- **Protocol obfuscation** — RC4-based TCP and UDP obfuscation (header encryption) to help with ISP throttling, matching eMule's implementation.
- **AICH** — Advanced Intelligent Corruption Handling for part-level hash verification and recovery.

Ember's own additions — the [Ember Network](#ember-network) overlay and the [EPX](#epx--ember-peer-exchange) source-exchange extension — only involve other Ember clients. Neither is visible to other eMule-family clients, and neither affects the compatibility above.

## Features

### Networking

- **Ember Network** — Ember's own encrypted, server-less overlay for peer discovery, keyword search, publishing, and source lookup. On by default, joins automatically, runs alongside KAD and eD2K (see [above](#ember-network)).
- **KAD Network & eD2K Servers** — Connect to the decentralized KAD DHT and traditional eD2K servers for peer discovery and search. A community `server.met` can be downloaded from emule-security.org, and fresh KAD `nodes.dat` bootstrap contacts can be fetched from Settings → Network when KAD will not connect.
- **Auto-Connect** — Optionally reconnect KAD and your last eD2K server on launch; with no server history, Auto-Connect Server falls back to eMule Sunrise.
- **EPX Source Exchange** — Ember peers share source lists with each other for faster downloads (see above).
- **NAT Traversal** — Layered fallbacks, not one mechanism: UPnP port mapping, KAD firewall checks, STUN keep-alive, Ember QUIC hole-punch, KAD buddy, EPX peer-relay (ERAT), and a friend-only WebSocket relay. A session uses a subset; the stack as a whole is required because each piece covers a different NAT class or peer population — see [docs/nat-traversal.md](docs/nat-traversal.md).
- **STUN Port Keep-Alive** — Periodic STUN plus a TCP hold from the listen port keeps NAT mappings alive and advertises the discovered public ports for HighID. Aimed at CGNAT and full-cone NAT without UPnP; auto-suspends on symmetric or unstable remapping. Distinct from the STUN NAT-type probe that decides whether a QUIC hole-punch is worth attempting.
- **Protocol Obfuscation** — RC4-based TCP and UDP header encryption to help with ISP throttling.
- **Deep Links** — Opens `ed2k://` URIs and `.emulecollection` files from the OS, including while Ember is already running. Incoming links require confirm/review before opening, and pending links can be reviewed later.

### Transfers

- **Multi-Source Downloads** — Download from multiple peers simultaneously with part-level hash verification, automatic source rotation, and queue management.
- **Transfer Monitoring** — Real-time progress bars, per-source detail drawers, upload tracking, health indicators, peer country flags, and archive recovery.
- **Bulk Transfer Actions** — Pause, resume, stop or cancel many downloads at once via checkbox selection or the Pause/Resume/Stop/Cancel All commands; finished and failed rows can be selected and removed from the list together, keeping the files.
- **Upload Speed Sense (USS)** — Optionally adjusts upload speed from network latency to prevent congestion. Requires an upload speed limit to be set.
- **AICH** — Part-level hash verification and recovery for corrupted chunks.

### Search & library

- **Advanced Search** — Multi-tab keyword search across Global, KAD Only, Server Only and Ember Only methods, with type, size, source, and extension filters.
- **Spam Detection** — Built-in detection with balanced and aggressive profiles, a configurable threshold, and automatic result hiding.
- **Copy eD2K Links** — Copy the link for one result, every ticked result, or the whole result list, from the context menu, the selection toolbar, or Ctrl+C.
- **Library Management** — Virtual-scrolling tables that handle thousands of files, with sorting, filtering, bulk priority edits, comments, ratings, eD2K collection support, a scan for missing files, and copy-all-links for the current view.
- **In-App Media Player** — Play supported audio and video from the Library detail drawer; Open Externally is still available.

### Social

- **Friends** — Ember-exclusive friend system with v2 Friend Codes, Noise-secured sessions, end-to-end encrypted chat, remote browsing, friends-only shares, file offers, priority uploads, a block list, and transfers that can work without HighID (see [above](#friends--ember-exclusive-social-features)).
- **Credits & SecIdent** — RSA-based Secure Identification prevents credit theft; upload priority follows the standard credit ratio formula.

### Security

- **Security Page** — A dedicated page for IP filter management: download the default list, import a file, fetch from an HTTPS URL, enable or disable filtering, maintain custom ranges, and review per-range hit counts.
- **IP Filtering** — Loads `ipfilter.dat` / `ipfilter.zip` with update support. Incoming connection filtering is off by default, because VPN ranges commonly appear in ipfilter hosting blocks and would silently block legitimate peers; outbound filtering stays active regardless.
- **Anti-Leech Filter** — Rejects incoming connections from known leech client patterns, via a customizable regex list.
- **Signed Anti-Rollback Updates** — Ember checks for updates on launch and installs cryptographically signed builds in-app, gated by security epochs so an install only advances when the signed epoch allows. Manual checks live under Settings → About.
- **Safer File Opens** — Deep links require confirm/review, Library drag-and-drop folders ask for a system folder-picker confirmation, and media and upload paths pin approved handles to avoid path-swap races.
- **Hardening** — Private IP blocking, path traversal protection, and strict Content Security Policy headers in the Tauri webview.

### User experience

- **First-Time Setup Wizard** — Guided configuration on first launch: nickname, download folder, ports, speed limits, KAD auto-connect, and theme.
- **Backup & Restore** — Save your profile to a single passphrase-encrypted `.emberbackup` file and restore it on another machine or after a reinstall (Settings → Backup). Covers identity and SecIdent keys, credits, settings, shared-folder list, known files, friends, chat history, transfers, server/Kad contacts, IP filter and learned spam data; excludes the shared files themselves and part-finished downloads. Identity keys are DPAPI-unwrapped into the encrypted archive and re-wrapped for the restoring Windows account, so a restore keeps your user hash, credits and friendships. Restores are staged and applied during the next launch, with the replaced files preserved in a `pre-restore-<timestamp>` folder.
- **Close to Tray** — Choose what the title-bar X does: ask each time, minimize to tray, or exit. The tray icon stays available either way.
- **Keyboard Shortcuts** — `?` opens a shortcut cheat sheet, and Alt+1–9 jump to the first nine sidebar pages.
- **Statistics** — Session and cumulative transfer statistics, connection uptime, network health indicators, and a peer reputation snapshot.
- **Internationalization** — UI strings via Paraglide (`en`, `es`, `fr`, `pt-BR`, `de`, `zh-CN`, `it`, `ru`, `zh-TW`), with a Settings language picker whose **System** option follows the OS locale; see [docs/i18n.md](docs/i18n.md).
- **GeoIP** — Country identification for connected peers from a bundled MaxMind database.

## Getting Started

### For users

Ember currently ships for **Windows 10 and Windows 11**. No external runtimes are required — no Java, no .NET, no separate browser engine download.

1. Download the latest release from the [Releases page](https://github.com/untaimed18/Ember-P2P/releases).
2. Run the installer (`.exe`).
3. On first launch, the **Setup Wizard** walks you through essential settings — nickname, download folder, ports, speed limits, KAD auto-connect, and theme.
4. Press **Connect** on the KAD Network page and/or connect from the eD2K Servers page, or enable Auto-Connect KAD / Auto-Connect Server in Settings so Ember reconnects on launch. A community `server.met` list can be downloaded from emule-security.org on first run.
5. The [Ember Network](#ember-network) needs no connect step — it is on by default and joins on its own. It finds its first peers *through* KAD and eD2K, though, so keep at least one of them available on a fresh install.
6. Add folders to your library, search with the Global / KAD / Server / Ember methods, open `ed2k://` links, and start downloading. Ember handles multi-source transfers, queueing and source discovery on its own.
7. Optionally open the Friends page, share your Friend Code and add theirs. Once mutual and online you get end-to-end encrypted chat, remote browsing and priority upload slots — see [Friends](#friends--ember-exclusive-social-features).

### Port forwarding

Ember uses two configured ports, plus a QUIC UDP socket that usually lands on the TCP port number:

| Port | Protocol | Purpose |
|------|----------|---------|
| 4662 | TCP | Peer-to-peer file transfers |
| 4672 | UDP | KAD DHT and Ember Network communication (both share this socket) |
| 4662 (typical) | UDP | Ember QUIC — hole-punch and peer-relay. Own socket, not shared with 4672; may fall back to a neighbour port if that UDP port is taken |

These are configurable in **Settings > Network**. For best performance (HighID), forward the TCP and KAD UDP ports on your router, enable **UPnP** so Ember maps them (and QUIC) automatically, or leave **STUN port keep-alive** on. You do not need every NAT feature on every network — UPnP, STUN, QUIC punch, buddy, and relay are fallbacks for different NAT classes; the map is in [docs/nat-traversal.md](docs/nat-traversal.md).

STUN keep-alive (on by default) periodically refreshes your NAT mappings with STUN, holds a TCP connection from the listen port, and advertises the discovered public ports so peers connect to the right place. It is aimed at CGNAT and full-cone NAT where UPnP is unavailable, and auto-suspends on Open/Symmetric NAT or unstable remapping, falling back to your configured ports. Symmetric NAT or a VPN that remaps ports unstably still generally needs a VPN with a fixed forwarded port.

### High ID vs Low ID

An ID is derived from your IP address and assigned by the eD2K server when Ember connects. It reflects whether other peers can reach you:

- **High ID** — your TCP port is reachable from the internet. This is the state you want.
- **Low ID** — your port is blocked or unreachable, typically by a firewall, router or NAT. Any ID below **16,777,216** is a Low ID.

A Low ID routes control messages through the server instead of peer to peer, which adds overhead, and two Low ID clients cannot connect to each other at all, so you see fewer sources. On busy servers, messages can also be dropped, costing you queue progress. The ID affects control traffic only — file data always moves client to client — and past the High ID threshold a larger numeric value confers no advantage.

If you are stuck on a Low ID: confirm 4662/TCP and 4672/UDP are forwarded, check your OS firewall allows Ember on both protocols, enable UPnP, and leave STUN keep-alive on. Two Low ID eMule clients still cannot TCP to each other; Ember-to-Ember then tries QUIC hole-punch (friends) or EPX peer-relay (downloads). eD2K Low ID and KAD Firewalled are separate verdicts — the first is TCP reachability as judged by the server, the second is KAD's own assessment of your UDP reachability, so you can legitimately be High ID and Firewalled at once.

### For developers

#### Prerequisites

- [Rust](https://rustup.rs/) (1.94+, matching `rust-version` in [`src-tauri/Cargo.toml`](src-tauri/Cargo.toml))
- [Node.js](https://nodejs.org/) (20.19+, 22.12+ or 24+, matching `engines` in [`package.json`](package.json); CI builds on 24)
- **Windows**: Visual Studio Build Tools with C++ workload
- **Linux**: WebKitGTK 4.1 and GTK 3 development packages. On Debian/Ubuntu:

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
  libayatana-appindicator3-dev librsvg2-dev pkg-config file
```

Official releases are still Windows-only. A Linux build from this tree produces a `.deb` and an AppImage locally; those formats are not yet published or auto-updated.

#### Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Type-check the frontend
npm run check

# Run the release policy, locale, and error code tests
npm test

# Build for production
npm run tauri build
```

The production build writes platform packages under `src-tauri/target/release/bundle/`: NSIS/MSI on Windows, `.deb` and AppImage on Linux.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Svelte 5 + TypeScript + Vite |
| App Shell | Tauri v2 |
| Backend | Rust (2021 edition) |
| Database | SQLite via rusqlite |
| Networking | Tokio async runtime |
| Ember Overlay Transport | Noise IK / XX over UDP (ChaCha20-Poly1305 + BLAKE2s) |
| Ember NAT / punch / relay | STUN, Quinn QUIC (`ember/1`), rendezvous punch + WebSocket relay |
| Ember DHT | Kademlia, 128-bit BLAKE3 node IDs, Ed25519-signed frames |
| Friend Discovery | Rendezvous server (Axum on Fly.io) |
| Friend Sessions | Noise IK + Ed25519 proof of possession |
| Friend Chat Crypto | X25519 ECDH → HKDF → XChaCha20-Poly1305 (E2E) |
| GeoIP | MaxMind DB (dbip-country-lite) |

## License

GPLv3 — see [LICENSE](LICENSE) for details.
