use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::net::UdpSocket;
use tracing::debug;

use super::server_list::ServerEntry;

pub const OP_EDONKEYPROT: u8 = 0xE3;

#[allow(dead_code)]
pub const OP_GLOBSEARCHREQ: u8 = 0x98;
#[allow(dead_code)]
pub const OP_GLOBSEARCHREQ2: u8 = 0x92;
#[allow(dead_code)]
pub const OP_GLOBSEARCHREQ3: u8 = 0x90;
pub const OP_GLOBSEARCHRES: u8 = 0x99;
pub const OP_GLOBGETSOURCES: u8 = 0x9A;
pub const OP_GLOBGETSOURCES2: u8 = 0x94;
pub const OP_GLOBFOUNDSOURCES: u8 = 0x9B;
pub const OP_GLOBSERVSTATREQ: u8 = 0x96;
pub const OP_GLOBSERVSTATRES: u8 = 0x97;

// Server UDP capability flags (from eMule Opcodes.h)
pub const SRV_UDPFLG_EXT_GETSOURCES: u32 = 0x0001;
pub const SRV_UDPFLG_EXT_GETFILES: u32 = 0x0002;
pub const SRV_UDPFLG_NEWTAGS: u32 = 0x0008;
pub const SRV_UDPFLG_UNICODE: u32 = 0x0010;
pub const SRV_UDPFLG_EXT_GETSOURCES2: u32 = 0x0020;
pub const SRV_UDPFLG_LARGEFILES: u32 = 0x0100;
pub const SRV_UDPFLG_UDPOBFUSCATION: u32 = 0x0200;
pub const SRV_UDPFLG_TCPOBFUSCATION: u32 = 0x0400;

/// Minimum seconds between status pings to the same server
const MIN_PING_INTERVAL_SECS: i64 = 5;
/// Normal server status ping interval (4.5 hours)
pub const STAT_REASK_INTERVAL_SECS: i64 = 16200;

const MAX_TRACKED_SERVERS: usize = 500;

/// Wrap a plain server UDP packet in eMule's UDP-obfuscation envelope
/// when the destination server has both advertised the capability AND
/// a non-zero `BaseKey`. Returns the bytes that should actually go on
/// the wire and the address they should be sent to (which switches
/// from the standard UDP port to the server's `obfuscation_port_udp`
/// when set).
///
/// This is the single choke point for "do I obfuscate this packet" so
/// that `build_get_sources_packet`, `build_multi_get_sources_packet`,
/// `build_global_search_packet`, and `send_status_ping` all behave
/// consistently. Callers that hold a `(packet, addr)` queue entry
/// don't need to know anything about obfuscation — they just push the
/// returned tuple.
fn maybe_obfuscate_packet(
    packet: Vec<u8>,
    plain_addr: SocketAddr,
    server: &ServerEntry,
) -> (Vec<u8>, SocketAddr) {
    if server.server_udp_key == 0 {
        return (packet, plain_addr);
    }
    if server.udp_flags & SRV_UDPFLG_UDPOBFUSCATION == 0 {
        return (packet, plain_addr);
    }
    let encrypted = super::server_obfuscation::encrypt_send_server(&packet, server.server_udp_key);
    let mut wire_addr = plain_addr;
    if server.obfuscation_port_udp != 0 {
        wire_addr.set_port(server.obfuscation_port_udp);
    }
    (encrypted, wire_addr)
}

pub struct ServerUdpSocket {
    socket: Arc<UdpSocket>,
    last_ping_times: std::collections::HashMap<SocketAddr, i64>,
    /// Pending UDP challenge values per server (eMule: anti-spoof)
    pending_challenges: std::collections::HashMap<SocketAddr, u32>,
}

impl ServerUdpSocket {
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self {
            socket: Arc::new(socket),
            last_ping_times: std::collections::HashMap::new(),
            pending_challenges: std::collections::HashMap::new(),
        }
    }

    /// Get a clone of the underlying socket for use in spawned tasks.
    pub fn socket_handle(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Remove and return a pending challenge for the given address (for verification).
    pub fn take_challenge(&mut self, addr: &SocketAddr) -> Option<u32> {
        self.pending_challenges.remove(addr)
    }

    /// Build a single-file get-sources packet. Returns (packet, addr).
    pub fn build_get_sources_packet(
        server: &ServerEntry,
        file_hash: &[u8; 16],
        file_size: u64,
    ) -> Option<(Vec<u8>, SocketAddr)> {
        Self::build_multi_get_sources_packet(server, &[(file_hash, file_size)])
    }

    /// Build a multi-file get-sources packet (eMule packs up to MAX_REQUESTS_PER_SERVER
    /// file hashes per UDP packet, max MAX_UDP_PACKET_DATA bytes of payload).
    /// Returns (packet, addr) or None if the server address is invalid.
    pub fn build_multi_get_sources_packet(
        server: &ServerEntry,
        files: &[(&[u8; 16], u64)],
    ) -> Option<(Vec<u8>, SocketAddr)> {
        const MAX_UDP_PACKET_DATA: usize = 510;
        const MAX_REQUESTS_PER_SERVER: usize = 35;

        if files.is_empty() {
            return None;
        }
        let udp_port = server.port.checked_add(4)?;
        let addr: SocketAddr = format!("{}:{}", server.ip, udp_port).parse().ok()?;

        let supports_getsources2 = (server.udp_flags & SRV_UDPFLG_EXT_GETSOURCES2) != 0;
        let supports_large = (server.udp_flags & SRV_UDPFLG_LARGEFILES) != 0;

        let opcode = if supports_getsources2 {
            OP_GLOBGETSOURCES2
        } else {
            OP_GLOBGETSOURCES
        };
        let mut packet = Vec::with_capacity(2 + MAX_UDP_PACKET_DATA);
        packet.push(OP_EDONKEYPROT);
        packet.push(opcode);

        let mut count = 0usize;
        for (hash, size) in files {
            if count >= MAX_REQUESTS_PER_SERVER {
                break;
            }
            // eMule's IsLargeFile() boundary is OLD_MAX_EMULE_FILE_SIZE, not
            // u32::MAX: files in the (OLD_MAX_EMULE_FILE_SIZE, u32::MAX] window
            // must use the 64-bit encoding so the server's large-file index
            // matches (see the constant's doc). Using u32::MAX here silently
            // dropped sources for ~4 GiB files on every UDP server.
            let is_large = *size > super::messages::OLD_MAX_EMULE_FILE_SIZE;
            if is_large && !supports_large {
                continue;
            }
            let entry_size = if !supports_getsources2 {
                16 // hash only
            } else if is_large {
                16 + 4 + 8 // hash + 0u32 sentinel + u64 size
            } else {
                16 + 4 // hash + u32 size
            };
            if packet.len() - 2 + entry_size > MAX_UDP_PACKET_DATA {
                break;
            }
            packet.extend_from_slice(*hash);
            if supports_getsources2 {
                if is_large {
                    packet.extend_from_slice(&0u32.to_le_bytes());
                    packet.extend_from_slice(&size.to_le_bytes());
                } else {
                    packet.extend_from_slice(&(*size as u32).to_le_bytes());
                }
            }
            count += 1;
        }

        if count == 0 {
            return None;
        }
        // Apply UDP obfuscation if this server supports it AND we
        // have a BaseKey. Without this, V2 silently sends plaintext
        // GETSOURCES to obfuscation-only servers and they ignore us.
        // The same gate runs in `send_status_ping` and matches eMule
        // `UDPSocket.cpp`. Returns (final_wire_bytes, final_dest_addr)
        // so the caller's queue + send loop are unchanged — they just
        // see different bytes for obfuscated servers.
        let (wire_packet, wire_addr) = maybe_obfuscate_packet(packet, addr, server);
        Some((wire_packet, wire_addr))
    }

    /// Build a global search packet, selecting the best opcode based on server
    /// UDP capabilities (eMule SearchResultsWnd.cpp OnTimer logic):
    ///  - `OP_GLOBSEARCHREQ3`: server supports EXT_GETFILES + LARGEFILES
    ///  - `OP_GLOBSEARCHREQ2`: server supports EXT_GETFILES
    ///  - `OP_GLOBSEARCHREQ`:  fallback for all other servers
    ///
    /// Live caller: the search-command handler in `network/mod.rs`
    /// fans this out to every eligible server in the list when a
    /// keyword search runs (`run_udp` branch). Replies arrive as
    /// `ServerUdpResponse::SearchResult` and merge into the same UI
    /// search-results stream as TCP and KAD results.
    pub fn build_global_search_packet(
        server: &ServerEntry,
        search_expr: &[u8],
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let udp_port = server.port.checked_add(4)?;
        let addr: SocketAddr = format!("{}:{}", server.ip, udp_port).parse().ok()?;

        let ext_getfiles = (server.udp_flags & SRV_UDPFLG_EXT_GETFILES) != 0;
        let large_files = (server.udp_flags & SRV_UDPFLG_LARGEFILES) != 0;

        let plain = if ext_getfiles && large_files {
            // OP_GLOBSEARCHREQ3: prepend a tag set with SRVCAP_UDP_NEWTAGS_LARGEFILES
            const CT_SERVER_UDPSEARCH_FLAGS: u8 = 0x0E;
            const SRVCAP_UDP_NEWTAGS_LARGEFILES: u8 = 0x01;
            let mut packet = Vec::with_capacity(2 + 7 + search_expr.len());
            packet.push(OP_EDONKEYPROT);
            packet.push(OP_GLOBSEARCHREQ3);
            packet.extend_from_slice(&1u32.to_le_bytes()); // tag count = 1
            packet.push(0x01 | 0x80); // TAGTYPE_UINT8 | short-name flag
            packet.push(CT_SERVER_UDPSEARCH_FLAGS);
            packet.push(SRVCAP_UDP_NEWTAGS_LARGEFILES);
            packet.extend_from_slice(search_expr);
            packet
        } else if ext_getfiles {
            // OP_GLOBSEARCHREQ2: same as basic but tells server to use new-style tags
            let mut packet = Vec::with_capacity(2 + search_expr.len());
            packet.push(OP_EDONKEYPROT);
            packet.push(OP_GLOBSEARCHREQ2);
            packet.extend_from_slice(search_expr);
            packet
        } else {
            let mut packet = Vec::with_capacity(2 + search_expr.len());
            packet.push(OP_EDONKEYPROT);
            packet.push(OP_GLOBSEARCHREQ);
            packet.extend_from_slice(search_expr);
            packet
        };
        let (wire_packet, wire_addr) = maybe_obfuscate_packet(plain, addr, server);
        Some((wire_packet, wire_addr))
    }

    pub async fn send_status_ping(&mut self, server: &ServerEntry) -> anyhow::Result<()> {
        let udp_port = server.port.checked_add(4).ok_or_else(|| {
            anyhow::anyhow!("Server port {} too high for UDP offset", server.port)
        })?;
        // `plain_addr` is the **canonical** server addr (TCP port + 4).
        // We use it as the cooldown / challenge tracking key so the
        // recv path — which canonicalises obfuscated source addrs to
        // this same value — finds the matching challenge regardless
        // of whether the reply came from `obfuscation_port_udp` or
        // the standard UDP port. Without this, an obfuscated reply
        // arrived as `(ip, obf_port)`, was canonicalised to
        // `(ip, TCP+4)`, but the challenge map was keyed by
        // `(ip, obf_port)` → `take_challenge` returned `None` and we
        // dropped every obfuscated status reply.
        let plain_addr: SocketAddr = format!("{}:{}", server.ip, udp_port)
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid server address: {e}"))?;

        // Apply UDP obfuscation if this server has advertised both the
        // capability AND a BaseKey we've previously learned. eMule's
        // `UDPSocket.cpp` uses the same gate
        // (`pServer->GetServerKeyUDP() != 0 && pServer->SupportsObfuscationUDP()`).
        // First ping always goes plain (key not yet known); subsequent
        // pings obfuscate.
        let use_obf =
            server.server_udp_key != 0 && server.udp_flags & SRV_UDPFLG_UDPOBFUSCATION != 0;
        let mut wire_addr = plain_addr;
        if use_obf && server.obfuscation_port_udp != 0 {
            wire_addr.set_port(server.obfuscation_port_udp);
        }

        let now = chrono::Utc::now().timestamp();
        // Dedup keyed by the canonical (plain) addr — so toggling
        // obfuscation on/off for a server doesn't bypass the
        // cooldown by switching to a "different" key.
        if let Some(&last) = self.last_ping_times.get(&plain_addr) {
            if now - last < MIN_PING_INTERVAL_SECS {
                return Ok(());
            }
        }

        // eMule: send 4-byte random challenge with status ping (anti-spoof).
        // CSPRNG (OsRng) so the anti-spoof value is unpredictable.
        let challenge = rand::RngCore::next_u32(&mut rand::rngs::OsRng).wrapping_add(1);
        let mut packet = Vec::with_capacity(6);
        packet.push(OP_EDONKEYPROT);
        packet.push(OP_GLOBSERVSTATREQ);
        packet.extend_from_slice(&challenge.to_le_bytes());

        let wire_packet = if use_obf {
            super::server_obfuscation::encrypt_send_server(&packet, server.server_udp_key)
        } else {
            packet
        };

        self.socket.send_to(&wire_packet, wire_addr).await?;
        // Tracking keyed by canonical addr — see comment above.
        self.last_ping_times.insert(plain_addr, now);
        self.pending_challenges.insert(plain_addr, challenge);

        if self.last_ping_times.len() > MAX_TRACKED_SERVERS {
            let cutoff = now - STAT_REASK_INTERVAL_SECS;
            self.last_ping_times.retain(|_, &mut ts| ts > cutoff);
            self.pending_challenges
                .retain(|a, _| self.last_ping_times.contains_key(a));
        }
        debug!(
            "Sent status ping to {}:{} (challenge=0x{challenge:08X})",
            server.ip, server.port
        );
        Ok(())
    }

    /// Receive and process one UDP packet. Returns the parsed result
    /// AND the raw byte length of the packet that came off the wire,
    /// so the caller can attribute accurate overhead bytes to the
    /// right Statistics category (StatusResponse → Server,
    /// FoundSources → SourceExchange, etc.). Returning the length is
    /// what lets us avoid both double-counting (previously every
    /// response was charged a flat 64 bytes "Server" plus an estimate
    /// per category) and under-counting (the previous SourceExchange
    /// estimate was `sources.len() * 10`, missing the packet header
    /// and per-source overhead).
    /// Backwards-compatible plain-only receive. Used by tests; live
    /// recv goes through `try_recv_with` so we can attempt UDP
    /// obfuscation decryption when the first byte ≠ `0xE3`.
    #[allow(dead_code)]
    pub async fn try_recv(&self) -> Option<(usize, ServerUdpResponse)> {
        self.try_recv_with(|_ip, _port| None).await
    }

    // `recv_packet` / `process_received` were drafted as building
    // blocks for an event-driven recv arm but the actual integration
    // shortened the existing ping timer's interval instead (cleaner
    // diff against the giant inline dispatch block). Kept as
    // `#[cfg(test)]`-only helpers below so the API surface is still
    // tested even though prod uses `try_recv_with` from the timer.
    #[cfg(test)]
    #[allow(dead_code)]
    pub async fn recv_packet(&self) -> std::io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = [0u8; 65536];
        let (len, addr) = self.socket.recv_from(&mut buf).await?;
        Ok((buf[..len].to_vec(), addr))
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn process_received<F>(
        data: &[u8],
        addr: SocketAddr,
        key_lookup: F,
    ) -> Option<(usize, ServerUdpResponse)>
    where
        F: Fn(Ipv4Addr, u16) -> Option<(u32, u16)>,
    {
        let len = data.len();
        if len < 2 {
            return None;
        }
        if data[0] == OP_EDONKEYPROT {
            return parse_server_udp_response(&data[1..], addr).map(|resp| (len, resp));
        }
        let src_ip = match addr.ip() {
            std::net::IpAddr::V4(v4) => v4,
            _ => return None,
        };
        let (base_key, tcp_port) = key_lookup(src_ip, addr.port())?;
        if base_key == 0 {
            return None;
        }
        use super::server_obfuscation::{decrypt_received_server, DecryptOutcome};
        match decrypt_received_server(data, base_key) {
            DecryptOutcome::Decrypted(plain) => {
                if plain.len() < 2 || plain[0] != OP_EDONKEYPROT {
                    return None;
                }
                let canonical_addr = SocketAddr::new(addr.ip(), tcp_port.saturating_add(4));
                parse_server_udp_response(&plain[1..], canonical_addr).map(|resp| (len, resp))
            }
            _ => None,
        }
    }

    /// Same as `try_recv`, plus an opportunity to attempt UDP-server
    /// obfuscation decryption when the first byte is not `OP_EDONKEYPROT`
    /// (`0xE3`). The closure is asked "what server does this inbound
    /// `(src_ip, src_port)` belong to, and what's its BaseKey?" —
    /// return `Some((base_key, tcp_port))` to attempt decryption,
    /// `None` to drop the packet (matches the historical behaviour
    /// for every non-`0xE3` datagram).
    ///
    /// `tcp_port` is used to **canonicalise** the source address on a
    /// successful decrypt: the response is emitted with
    /// `addr.port() == tcp_port + 4` so downstream handlers (which
    /// derive the server's TCP identity as `addr.port() - 4`) keep
    /// working unchanged. Without this, replies from a server's
    /// `obfuscation_port_udp` would silently fail every list lookup
    /// (`update_server_stats`, `update_udp_flags`, `update_udp_obfuscation`,
    /// `register_lowid_source`, the L-2 callback flush, …).
    ///
    /// Decryption failures (bad magic, bad padding) silently drop the
    /// packet so random noise from non-server sources doesn't corrupt
    /// anything.
    ///
    /// Wire reference: `CEncryptedDatagramSocket::DecryptReceivedServer`
    /// in eMule's `EncryptedDatagramSocket.cpp`.
    pub async fn try_recv_with<F>(&self, key_lookup: F) -> Option<(usize, ServerUdpResponse)>
    where
        F: Fn(Ipv4Addr, u16) -> Option<(u32, u16)>,
    {
        let mut buf = [0u8; 65536];
        match self.socket.try_recv_from(&mut buf) {
            Ok((len, addr)) => {
                if len < 2 {
                    return None;
                }
                if buf[0] == OP_EDONKEYPROT {
                    // Plain packet — historical fast path. addr is
                    // already canonical: a plain reply only comes
                    // from the standard UDP port = TCP+4.
                    return parse_server_udp_response(&buf[1..len], addr).map(|resp| (len, resp));
                }
                // Obfuscation candidate: only servers we know the
                // BaseKey for can have sent us an encrypted packet.
                let src_ip = match addr.ip() {
                    std::net::IpAddr::V4(v4) => v4,
                    _ => return None,
                };
                let (base_key, tcp_port) = key_lookup(src_ip, addr.port())?;
                if base_key == 0 {
                    // We know the server but haven't learned its key
                    // yet — can't decrypt. The original status
                    // exchange must have been plain (which it is,
                    // for the first ping).
                    return None;
                }
                use super::server_obfuscation::{decrypt_received_server, DecryptOutcome};
                match decrypt_received_server(&buf[..len], base_key) {
                    DecryptOutcome::Decrypted(plain) => {
                        if plain.len() < 2 || plain[0] != OP_EDONKEYPROT {
                            return None;
                        }
                        // Canonicalise: emit the response with the
                        // standard UDP port so handlers' `addr.port()
                        // - 4` math gives the right TCP port. We
                        // report the *wire* length (`len`) for stats
                        // — that's the actual on-the-wire cost.
                        let canonical_port = tcp_port.saturating_add(4);
                        let canonical_addr = SocketAddr::new(addr.ip(), canonical_port);
                        parse_server_udp_response(&plain[1..], canonical_addr)
                            .map(|resp| (len, resp))
                    }
                    // Plain (shouldn't happen — first byte ≠ 0xE3
                    // here), or magic mismatch / too short / no key /
                    // invalid padding: drop quietly. Random noise on
                    // a UDP socket is normal; logging would be spam.
                    _ => None,
                }
            }
            Err(_) => None,
        }
    }
}

#[derive(Debug)]
pub enum ServerUdpResponse {
    StatusResponse {
        addr: SocketAddr,
        challenge: u32,
        user_count: u32,
        file_count: u32,
        /// Server's soft per-client file limit (extended status, offset 16,
        /// u32 LE). `0` if not advertised. eMule caps OP_OFFERFILES at this
        /// (or 200), so we learn + persist it to apply the same cap.
        soft_files: u32,
        obfuscation_port_tcp: u16,
        /// Alternate UDP port the server uses for **obfuscated** UDP
        /// traffic (extended status, offset 32, u16 LE). `0` if the
        /// server didn't advertise it; senders fall back to the
        /// regular UDP port.
        obfuscation_port_udp: u16,
        udp_flags: u32,
        /// Per-server BaseKey for client⇄server UDP obfuscation
        /// (extended status, offset 36, u32 LE). `0` if the server
        /// didn't advertise it; obfuscation cannot be used until a
        /// future status reply lands one.
        server_udp_key: u32,
    },
    FoundSources {
        addr: SocketAddr,
        /// One entry per file the server returned sources for. eMule's UDP
        /// servers can pack multiple file responses into a single
        /// `OP_GLOBFOUNDSOURCES` datagram (see `parse_server_udp_response`
        /// for the wire format) — the receive handler iterates and emits
        /// one event per file.
        files: Vec<([u8; 16], Vec<(Ipv4Addr, u16, u32)>)>,
    },
    SearchResult {
        results: Vec<ServerSearchResult>,
    },
}

#[derive(Debug)]
pub struct ServerSearchResult {
    pub file_hash: [u8; 16],
    pub client_id: u32,
    pub client_port: u16,
    pub file_name: String,
    pub file_size: u64,
    pub rating: Option<u8>,
    pub comment: Option<String>,
    pub media: crate::types::MediaMetadata,
}

fn parse_server_udp_response(data: &[u8], addr: SocketAddr) -> Option<ServerUdpResponse> {
    if data.is_empty() {
        return None;
    }

    let opcode = data[0];
    let payload = &data[1..];

    match opcode {
        OP_GLOBSERVSTATRES => {
            // eMule extended status: challenge(4) users(4) files(4)
            // [max_users(4)] [soft(4) hard(4)] [udp_flags(4)] [lowid_users(4)]
            // [udp_obf_port(2) tcp_obf_port(2) server_udp_key(4)]
            if payload.len() < 12 {
                return None;
            }
            let mut cursor = Cursor::new(payload);
            let challenge = cursor.read_u32::<LittleEndian>().ok()?;
            let user_count = cursor.read_u32::<LittleEndian>().ok()?;
            let file_count = cursor.read_u32::<LittleEndian>().ok()?;

            let mut soft_files: u32 = 0;
            let udp_flags = if payload.len() >= 28 {
                let _ = cursor.read_u32::<LittleEndian>(); // max_users (offset 12)
                soft_files = cursor.read_u32::<LittleEndian>().unwrap_or(0); // soft_files (offset 16)
                let _ = cursor.read_u32::<LittleEndian>(); // hard_files (offset 20)
                cursor.read_u32::<LittleEndian>().unwrap_or(0) // udp_flags (offset 24)
            } else {
                0
            };

            debug!(
                "Server UDP flags: ext_getsrc={} ext_getfiles={} newtags={} unicode={} getsrc2={} large={} udp_obf={} tcp_obf={}",
                udp_flags & SRV_UDPFLG_EXT_GETSOURCES != 0,
                udp_flags & SRV_UDPFLG_EXT_GETFILES != 0,
                udp_flags & SRV_UDPFLG_NEWTAGS != 0,
                udp_flags & SRV_UDPFLG_UNICODE != 0,
                udp_flags & SRV_UDPFLG_EXT_GETSOURCES2 != 0,
                udp_flags & SRV_UDPFLG_LARGEFILES != 0,
                udp_flags & SRV_UDPFLG_UDPOBFUSCATION != 0,
                udp_flags & SRV_UDPFLG_TCPOBFUSCATION != 0,
            );

            let mut tcp_obf_port: u16 = 0;
            let mut udp_obf_port: u16 = 0;
            let mut server_udp_key: u32 = 0;
            if payload.len() >= 40 {
                // skip low_id_users (offset 28)
                let _ = cursor.read_u32::<LittleEndian>();
                udp_obf_port = cursor.read_u16::<LittleEndian>().unwrap_or(0); // offset 32
                tcp_obf_port = cursor.read_u16::<LittleEndian>().unwrap_or(0); // offset 34
                                                                               // dwServerUDPKey (offset 36, u32 LE) — eMule's
                                                                               // `pServer->SetServerKeyUDP(dwServerUDPKey)` source.
                                                                               // Required as the BaseKey for `EncryptSendServer` /
                                                                               // `DecryptReceivedServer` (see `server_obfuscation.rs`).
                                                                               // Previously this field was skipped, which silently
                                                                               // disabled all UDP obfuscation against this server even
                                                                               // when `SRV_UDPFLG_UDPOBFUSCATION` was set.
                server_udp_key = cursor.read_u32::<LittleEndian>().unwrap_or(0);
                // offset 36
            }
            // eMule default: if flag says TCP obfuscation but no port, use the main TCP port
            if tcp_obf_port == 0 && (udp_flags & SRV_UDPFLG_TCPOBFUSCATION) != 0 {
                tcp_obf_port = addr.port().saturating_sub(4) as u16;
            }

            Some(ServerUdpResponse::StatusResponse {
                addr,
                challenge,
                user_count,
                file_count,
                soft_files,
                obfuscation_port_tcp: tcp_obf_port,
                obfuscation_port_udp: udp_obf_port,
                udp_flags,
                server_udp_key,
            })
        }
        OP_GLOBFOUNDSOURCES => {
            // eMule/Lugdunum UDP servers PACK MULTIPLE file responses into a
            // single OP_GLOBFOUNDSOURCES datagram, laid out CONTIGUOUSLY with
            // NO per-block separator: <hash><count><sources> repeats back to
            // back until the datagram ends. (eMule's own client parser proves
            // this — for files it doesn't recognise it manually skips
            // `count * 6` bytes to reach the next block, which is only
            // necessary because there is no header to scan for.)
            //
            // A previous version required a re-emitted
            // `<OP_EDONKEYPROT><OP_GLOBFOUNDSOURCES>` header between blocks and
            // stopped at the first block not preceded by one — i.e. every
            // block after the first in a packed reply. That silently dropped
            // the sources for all-but-one file whenever more than one download
            // was active (we batch hashes into OP_GLOBGETSOURCES2), which
            // surfaced as "UDP returned no sources". We now read every
            // contiguous block until the datagram is exhausted, and we do NOT
            // probe for an inter-block header: a file hash legitimately
            // starting with the two header bytes would otherwise misalign the
            // whole rest of the packet.
            //
            // Per-entry layout: <file_hash[16]><source_count u8><sources(6 each)>.
            // Per-source layout: <id u32 LE><port u16 LE>. id < LOWID_THRESHOLD
            // means this entry is a LowID peer — store with the client_id slot
            // populated, IP unspecified (same convention as before).
            if payload.len() < 17 {
                return None;
            }
            let mut all_files: Vec<([u8; 16], Vec<(Ipv4Addr, u16, u32)>)> = Vec::new();
            let mut cursor = Cursor::new(payload);
            loop {
                let mut file_hash = [0u8; 16];
                if std::io::Read::read_exact(&mut cursor, &mut file_hash).is_err() {
                    break;
                }
                let source_count = match cursor.read_u8() {
                    Ok(c) => c as usize,
                    Err(_) => break,
                };
                let mut sources = Vec::with_capacity(source_count);
                let mut entry_ok = true;
                for _ in 0..source_count {
                    let id = match cursor.read_u32::<LittleEndian>() {
                        Ok(v) => v,
                        Err(_) => {
                            entry_ok = false;
                            break;
                        }
                    };
                    let port = match cursor.read_u16::<LittleEndian>() {
                        Ok(v) => v,
                        Err(_) => {
                            entry_ok = false;
                            break;
                        }
                    };
                    if id < super::server::LOWID_THRESHOLD {
                        sources.push((Ipv4Addr::UNSPECIFIED, port, id));
                    } else {
                        let ip = Ipv4Addr::from(id.to_le_bytes());
                        sources.push((ip, port, 0));
                    }
                }
                if !entry_ok {
                    // Truncated source list — drop this entry but keep what
                    // we successfully parsed so far. Matches eMule's
                    // "swallow leftover bytes silently" tolerance.
                    break;
                }
                all_files.push((file_hash, sources));
                // Next iteration reads the following contiguous block (if any);
                // `read_exact` of the file hash fails cleanly at end-of-datagram.
            }
            if all_files.is_empty() {
                return None;
            }
            Some(ServerUdpResponse::FoundSources {
                addr,
                files: all_files,
            })
        }
        OP_GLOBSEARCHRES => parse_search_results(payload),
        _ => None,
    }
}
/// Parse an eMule media-length string ("h:mm:ss"/"mm:ss"/"ss") into seconds.
fn parse_media_length_str(s: &str) -> Option<u32> {
    let parts: Vec<u32> = s
        .split(':')
        .map(|p| p.trim().parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    match parts.as_slice() {
        // Saturating: a malicious/garbage wire string like "99999:99999:99999"
        // would otherwise wrap in release and report a nonsense duration.
        [h, m, sec] => Some(
            h.saturating_mul(3600)
                .saturating_add(m.saturating_mul(60))
                .saturating_add(*sec),
        ),
        [m, sec] => Some(m.saturating_mul(60).saturating_add(*sec)),
        [sec] => Some(*sec),
        _ => None,
    }
}

/// Route a string tag value (by id or lowercased name) into filename, comment,
/// or media fields. Mirrors the TCP server parser's `apply_string`.
fn apply_udp_string_tag(
    name_id: u8,
    name: Option<&str>,
    value: String,
    file_name: &mut String,
    comment: &mut Option<String>,
    media: &mut crate::types::MediaMetadata,
) {
    if name_id == 0x01 {
        *file_name = value;
        return;
    }
    if value.is_empty() {
        return;
    }
    let is = |n: &str| name == Some(n);
    match name_id {
        0xF6 => *comment = Some(value),
        0xD0 => media.artist = Some(value),
        0xD1 => media.album = Some(value),
        0xD2 => media.title = Some(value),
        0xD5 => media.codec = Some(value),
        0xD3 => media.duration = parse_media_length_str(&value),
        _ if is("comment") || is("description") => *comment = Some(value),
        _ if is("artist") => media.artist = Some(value),
        _ if is("album") => media.album = Some(value),
        _ if is("title") => media.title = Some(value),
        _ if is("codec") => media.codec = Some(value),
        _ if is("length") => media.duration = parse_media_length_str(&value),
        _ => {}
    }
}

/// Route an unsigned-int tag value (by id or name) into rating/media fields.
fn apply_udp_uint_tag(
    name_id: u8,
    name: Option<&str>,
    value: u64,
    rating: &mut Option<u8>,
    media: &mut crate::types::MediaMetadata,
) {
    let is = |n: &str| name == Some(n);
    match name_id {
        0xD3 if value > 0 => media.duration = Some(value as u32),
        0xD4 if value > 0 => media.bitrate = Some(value as u32),
        0xF7 => *rating = Some(value as u8),
        _ if is("bitrate") && value > 0 => media.bitrate = Some(value as u32),
        _ if is("length") && value > 0 => media.duration = Some(value as u32),
        _ if is("filerating") || is("rating") => *rating = Some(value as u8),
        _ => {}
    }
}

fn parse_search_results(payload: &[u8]) -> Option<ServerUdpResponse> {
    let mut cursor = Cursor::new(payload);
    let mut results = Vec::new();

    const MIN_UDP_SEARCH_ENTRY: usize = 16 + 4 + 2 + 4; // hash + client_id + port + tag_count
    while (cursor.position() as usize) + MIN_UDP_SEARCH_ENTRY <= payload.len() {
        let mut file_hash = [0u8; 16];
        if std::io::Read::read_exact(&mut cursor, &mut file_hash).is_err() {
            break;
        }
        let client_id = cursor.read_u32::<LittleEndian>().ok()?;
        let client_port = cursor.read_u16::<LittleEndian>().ok()?;
        let tag_count = cursor.read_u32::<LittleEndian>().ok()? as usize;

        let mut file_name = String::new();
        let mut file_size: u64 = 0;
        let mut rating: Option<u8> = None;
        let mut comment: Option<String> = None;
        let mut media = crate::types::MediaMetadata::default();

        // Consume up to MAX_APPLIED_TAGS tags. The old cap of 50 stopped parsing
        // the WHOLE packet whenever a (benign) record declared >50 tags, because
        // the surplus tag bytes were never consumed and the cursor desynced —
        // dropping every subsequent result. Real search results carry well under
        // a dozen tags, so 256 keeps the cursor aligned for any realistic record
        // while still treating an absurd count as abusive (break below).
        const MAX_APPLIED_TAGS: usize = 256;
        // Cap a single tag-name length the same way the TCP parser does
        // (read_tag_header's MAX_TAG_NAME_LEN). Otherwise a malicious reply could
        // declare names up to the ~64 KiB UDP payload size, forcing large
        // transient allocations (×tags ×results).
        const MAX_UDP_TAG_NAME_LEN: usize = 256;
        let applied_tags = tag_count.min(MAX_APPLIED_TAGS);
        let mut tags_in_sync = true;
        for _ in 0..applied_tags {
            let raw_type = cursor.read_u8().ok()?;
            let (name_id, tag_type, tag_name) = if raw_type & 0x80 != 0 {
                let t = raw_type & 0x7F;
                let n = cursor.read_u8().ok()?;
                (n, t, None)
            } else {
                let name_len = cursor.read_u16::<LittleEndian>().ok()? as usize;
                if name_len == 1 {
                    let n = cursor.read_u8().ok()?;
                    (n, raw_type, None)
                } else {
                    if name_len > MAX_UDP_TAG_NAME_LEN {
                        return None;
                    }
                    // Bound the name allocation by the bytes actually left in
                    // the packet so a bogus length can't force a large transient
                    // buffer (the read would fail anyway).
                    let remaining = payload.len().saturating_sub(cursor.position() as usize);
                    if name_len > remaining {
                        return None;
                    }
                    // Preserve the string name so ED2K media tags
                    // ("length"/"bitrate"/"codec"/...) can be matched.
                    let mut name_buf = vec![0u8; name_len];
                    std::io::Read::read_exact(&mut cursor, &mut name_buf).ok()?;
                    (
                        0u8,
                        raw_type,
                        Some(String::from_utf8_lossy(&name_buf).to_ascii_lowercase()),
                    )
                }
            };
            let tag_name = tag_name.as_deref();

            let ok = match tag_type {
                0x01 => {
                    // TAGTYPE_HASH
                    let mut buf = [0u8; 16];
                    std::io::Read::read_exact(&mut cursor, &mut buf).is_ok()
                }
                0x02 => {
                    // TAGTYPE_STRING
                    let slen = cursor.read_u16::<LittleEndian>().ok().unwrap_or(0) as usize;
                    let start = cursor.position() as usize;
                    let end = start.saturating_add(slen);
                    if end > payload.len() {
                        false
                    } else {
                        let bytes = &payload[start..end];
                        cursor.set_position(end as u64);
                        let keep = &bytes[..bytes.len().min(8192)];
                        let value = String::from_utf8_lossy(keep).to_string();
                        apply_udp_string_tag(
                            name_id,
                            tag_name,
                            value,
                            &mut file_name,
                            &mut comment,
                            &mut media,
                        );
                        true
                    }
                }
                0x03 => {
                    // TAGTYPE_UINT32
                    if let Ok(v) = cursor.read_u32::<LittleEndian>() {
                        match name_id {
                            0x02 => file_size = (file_size & 0xFFFF_FFFF_0000_0000) | v as u64,
                            0x3A => {
                                file_size = (file_size & 0x0000_0000_FFFF_FFFF) | ((v as u64) << 32)
                            }
                            _ => apply_udp_uint_tag(
                                name_id,
                                tag_name,
                                v as u64,
                                &mut rating,
                                &mut media,
                            ),
                        }
                        true
                    } else {
                        false
                    }
                }
                0x04 => {
                    let mut b = [0u8; 4];
                    std::io::Read::read_exact(&mut cursor, &mut b).is_ok()
                }
                0x05 => {
                    let _ = cursor.read_u8();
                    true
                }
                0x06 => {
                    // TAGTYPE_BOOLARRAY
                    if let Ok(count) = cursor.read_u16::<LittleEndian>() {
                        let bc = (count as usize + 7) / 8;
                        let pos = cursor.position() as usize;
                        if pos + bc <= payload.len() {
                            cursor.set_position((pos + bc) as u64);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                0x07 => {
                    // TAGTYPE_BLOB
                    if let Ok(bl) = cursor.read_u32::<LittleEndian>() {
                        let bl = bl as usize;
                        let pos = cursor.position() as usize;
                        if bl <= 1_000_000 && pos + bl <= payload.len() {
                            cursor.set_position((pos + bl) as u64);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                0x08 => {
                    // TAGTYPE_UINT16
                    if let Ok(v) = cursor.read_u16::<LittleEndian>() {
                        if name_id == 0x02 {
                            file_size = v as u64;
                        } else {
                            apply_udp_uint_tag(
                                name_id,
                                tag_name,
                                v as u64,
                                &mut rating,
                                &mut media,
                            );
                        }
                        true
                    } else {
                        false
                    }
                }
                0x09 => {
                    // TAGTYPE_UINT8
                    if let Ok(v) = cursor.read_u8() {
                        if name_id == 0x02 {
                            file_size = v as u64;
                        } else {
                            apply_udp_uint_tag(
                                name_id,
                                tag_name,
                                v as u64,
                                &mut rating,
                                &mut media,
                            );
                        }
                        true
                    } else {
                        false
                    }
                }
                0x0A => {
                    // TAGTYPE_BSOB
                    if let Ok(bl) = cursor.read_u8() {
                        let pos = cursor.position() as usize + bl as usize;
                        if pos <= payload.len() {
                            cursor.set_position(pos as u64);
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                0x0B => {
                    // TAGTYPE_UINT64
                    if let Ok(v) = cursor.read_u64::<LittleEndian>() {
                        if name_id == 0x02 {
                            file_size = v;
                        } else {
                            apply_udp_uint_tag(name_id, tag_name, v, &mut rating, &mut media);
                        }
                        true
                    } else {
                        false
                    }
                }
                t if (0x11..=0x20).contains(&t) => {
                    // TAGTYPE_STR1..STR16
                    let slen = (t - 0x11 + 1) as usize;
                    let mut sbuf = vec![0u8; slen];
                    if std::io::Read::read_exact(&mut cursor, &mut sbuf).is_ok() {
                        let value = String::from_utf8_lossy(&sbuf).to_string();
                        apply_udp_string_tag(
                            name_id,
                            tag_name,
                            value,
                            &mut file_name,
                            &mut comment,
                            &mut media,
                        );
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if !ok {
                tags_in_sync = false;
                break;
            }
        }

        results.push(ServerSearchResult {
            file_hash,
            client_id,
            client_port,
            file_name,
            file_size,
            rating,
            comment,
            media,
        });

        // If a tag failed to decode, or the record declared more tags than the
        // cap (so surplus tag bytes remain unconsumed), the cursor is no longer
        // aligned to the next record. Stop here rather than decoding subsequent
        // "results" from a mid-tag offset, which would emit garbage entries.
        if !tags_in_sync || tag_count > applied_tags {
            break;
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(ServerUdpResponse::SearchResult { results })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_found_sources_distinguishes_lowid_and_highid() {
        let addr: SocketAddr = "127.0.0.1:4665".parse().unwrap();
        let file_hash = [0x66; 16];
        let high_id = u32::from_le_bytes([1, 2, 3, 4]);
        let low_id = 42u32;
        let mut packet = vec![OP_GLOBFOUNDSOURCES];
        packet.extend_from_slice(&file_hash);
        packet.push(2);
        packet.extend_from_slice(&high_id.to_le_bytes());
        packet.extend_from_slice(&4662u16.to_le_bytes());
        packet.extend_from_slice(&low_id.to_le_bytes());
        packet.extend_from_slice(&4672u16.to_le_bytes());

        let parsed = parse_server_udp_response(&packet, addr).unwrap();
        match parsed {
            ServerUdpResponse::FoundSources { files, .. } => {
                assert_eq!(
                    files.len(),
                    1,
                    "single-file response should produce exactly one entry"
                );
                let (parsed_hash, sources) = &files[0];
                assert_eq!(*parsed_hash, file_hash);
                assert_eq!(sources[0], (Ipv4Addr::new(1, 2, 3, 4), 4662, 0));
                assert_eq!(sources[1], (Ipv4Addr::UNSPECIFIED, 4672, low_id));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// eMule/Lugdunum UDP servers pack multiple OP_GLOBFOUNDSOURCES file
    /// responses CONTIGUOUSLY in a single datagram, with NO separator between
    /// blocks. Verify the parser walks every contiguous entry.
    ///
    /// Regression: a previous parser required a re-emitted
    /// `<OP_EDONKEYPROT><OP_GLOBFOUNDSOURCES>` header between blocks and
    /// dropped every file after the first in a packed reply — surfacing as
    /// "UDP returned no sources" whenever more than one download was active.
    #[test]
    fn parse_multi_file_globfoundsources_packet_drains_all_entries() {
        let addr: SocketAddr = "10.0.0.1:4665".parse().unwrap();
        let hash_a = [0x11u8; 16];
        let hash_b = [0x22u8; 16];
        let hash_c = [0x33u8; 16];
        let high_a = u32::from_le_bytes([1, 2, 3, 4]);
        let high_b = u32::from_le_bytes([5, 6, 7, 8]);
        let low_c = 7u32;

        let mut packet = vec![OP_GLOBFOUNDSOURCES];
        // First file: 1 source — the next block follows immediately, no header.
        packet.extend_from_slice(&hash_a);
        packet.push(1);
        packet.extend_from_slice(&high_a.to_le_bytes());
        packet.extend_from_slice(&4662u16.to_le_bytes());
        // Second file, contiguous: 1 HighID source.
        packet.extend_from_slice(&hash_b);
        packet.push(1);
        packet.extend_from_slice(&high_b.to_le_bytes());
        packet.extend_from_slice(&4663u16.to_le_bytes());
        // Third file, contiguous: 1 LowID source.
        packet.extend_from_slice(&hash_c);
        packet.push(1);
        packet.extend_from_slice(&low_c.to_le_bytes());
        packet.extend_from_slice(&4664u16.to_le_bytes());

        let parsed = parse_server_udp_response(&packet, addr).unwrap();
        match parsed {
            ServerUdpResponse::FoundSources { files, .. } => {
                assert_eq!(files.len(), 3, "must drain ALL contiguous file entries");
                assert_eq!(files[0].0, hash_a);
                assert_eq!(files[0].1[0], (Ipv4Addr::new(1, 2, 3, 4), 4662, 0));
                assert_eq!(files[1].0, hash_b);
                assert_eq!(files[1].1[0], (Ipv4Addr::new(5, 6, 7, 8), 4663, 0));
                assert_eq!(files[2].0, hash_c);
                assert_eq!(files[2].1[0], (Ipv4Addr::UNSPECIFIED, 4664, low_c));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    /// A file hash whose first two bytes happen to equal
    /// `<OP_EDONKEYPROT><OP_GLOBFOUNDSOURCES>` must NOT be mistaken for an
    /// inter-block header — doing so would misalign the rest of the packet.
    /// Guards the fix from regressing back into header-probing.
    #[test]
    fn parse_globfoundsources_does_not_treat_hash_prefix_as_separator() {
        let addr: SocketAddr = "10.0.0.2:4665".parse().unwrap();
        let hash_a = [0xABu8; 16];
        let mut hash_b = [0x55u8; 16];
        hash_b[0] = OP_EDONKEYPROT;
        hash_b[1] = OP_GLOBFOUNDSOURCES;
        let high_a = u32::from_le_bytes([1, 2, 3, 4]);
        let high_b = u32::from_le_bytes([9, 9, 9, 9]);

        let mut packet = vec![OP_GLOBFOUNDSOURCES];
        packet.extend_from_slice(&hash_a);
        packet.push(1);
        packet.extend_from_slice(&high_a.to_le_bytes());
        packet.extend_from_slice(&4662u16.to_le_bytes());
        packet.extend_from_slice(&hash_b);
        packet.push(1);
        packet.extend_from_slice(&high_b.to_le_bytes());
        packet.extend_from_slice(&4663u16.to_le_bytes());

        let parsed = parse_server_udp_response(&packet, addr).unwrap();
        match parsed {
            ServerUdpResponse::FoundSources { files, .. } => {
                assert_eq!(files.len(), 2, "both blocks must parse");
                assert_eq!(
                    files[1].0, hash_b,
                    "hash starting with header bytes must parse intact"
                );
                assert_eq!(files[1].1[0], (Ipv4Addr::new(9, 9, 9, 9), 4663, 0));
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn loopback_status_response_is_received() {
        let recv_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv_socket.local_addr().unwrap();
        let server_udp = ServerUdpSocket::from_socket(recv_socket);
        let send_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let challenge = 0x55AA_1234u32;
        let mut packet = vec![OP_EDONKEYPROT, OP_GLOBSERVSTATRES];
        packet.extend_from_slice(&challenge.to_le_bytes());
        packet.extend_from_slice(&123u32.to_le_bytes());
        packet.extend_from_slice(&456u32.to_le_bytes());
        send_socket.send_to(&packet, recv_addr).await.unwrap();

        let (recv_len, response) = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if let Some(parsed) = server_udp.try_recv().await {
                    break parsed;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert!(recv_len >= 14); // 2 header + 12 payload (challenge+users+files)
        match response {
            ServerUdpResponse::StatusResponse {
                challenge: parsed,
                user_count,
                file_count,
                obfuscation_port_tcp,
                ..
            } => {
                assert_eq!(parsed, challenge);
                assert_eq!(user_count, 123);
                assert_eq!(file_count, 456);
                assert_eq!(obfuscation_port_tcp, 0);
            }
            other => panic!("unexpected response: {other:?}"),
        }
    }
}
