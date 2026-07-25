use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::ember_auth::{sign_auth_nonce, verify_auth_nonce};
use super::messages::*;
use super::secure_stream;
use super::upload::{EmberSessionHandle, EmberSessionMap, UploadEvent, UploadEventKind};
use crate::network::ember::crypto;
use crate::network::ember::crypto::{decrypt_chat_payload, MAX_CHAT_WIRE_LEN};

/// True when `existing` is safe to reuse as the canonical outbound router for
/// a newly authenticated dial to the same friend identity.
fn reusable_secure_friend_session(existing: &EmberSessionHandle, peer_pk: &[u8; 32]) -> bool {
    existing.is_fresh() && existing.is_secure_v2() && existing.peer_ember_pubkey() == *peer_pk
}

/// Result from a successfully established friend session: the outbound sender
/// so the caller can immediately send packets before the loop consumes them.
pub struct FriendSessionHandle {
    pub outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    pub session_id: u64,
    /// The friend's PoP-verified Ed25519 identity public key for this
    /// session — see `EmberSessionHandle::peer_ember_pubkey`. Callers use
    /// this together with their own Ed25519 secret to encrypt outbound
    /// `OP_EMBER_CHAT_MSG` payloads via `ember::crypto::encrypt_chat_for_peer`.
    pub peer_ember_pubkey: [u8; 32],
}

/// Establishes a persistent outbound friend session. Performs the full
/// Hello/EmuleInfo handshake, sends a friend request, then runs a
/// bidirectional select loop: reading incoming packets from the TCP stream
/// and writing outbound packets from the mpsc channel.
///
/// Incoming chat messages and browse responses are forwarded via the
/// `ul_event_tx` channel so the network loop can process them identically
/// to inbound (upload-side) friend packets.
///
/// `expected_ember_hash` is the friend we intend to reach at `addr` (from a
/// friend row, a rendezvous lookup, or a `FriendSeen` event). If the peer
/// that actually answers identifies as a *different* Ember peer, the session
/// is refused. A stale or reused address (or a misbehaving rendezvous) could
/// otherwise land us in a session with friend B when the caller asked for
/// friend A — delivering A's outbound chat to B and showing A online when
/// only B is reachable. The Ed25519 PoP below proves the peer owns whatever
/// hash it claims, but only this equality check catches the *wrong friend*.
///
/// The session automatically unregisters from `ember_sessions` on exit and
/// emits an `EmberFriendDisconnected` event.
pub async fn open_and_run_friend_session(
    addr: SocketAddr,
    expected_ember_hash: [u8; 16],
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ember_sessions: EmberSessionMap,
    ul_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
) -> anyhow::Result<FriendSessionHandle> {
    let stream = tokio::time::timeout(std::time::Duration::from_secs(15), TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout"))??;
    super::multi_source::tune_peer_stream(&stream);

    let (raw_r, raw_w) = stream.into_split();
    run_friend_session_over_transport(
        Box::new(raw_r),
        Box::new(raw_w),
        addr,
        expected_ember_hash,
        our_user_hash,
        our_ember_hash,
        our_nickname,
        our_client_id,
        tcp_port,
        udp_port,
        obfuscate,
        ember_sessions,
        ul_event_tx,
        friend_hashes,
        ed25519_pubkey,
        ed25519_secret_key,
    )
    .await
}

/// Like [`open_and_run_friend_session`] but drives the full Ember
/// handshake (EmuleInfo / `OP_EMBER_HELLO` / Ed25519 PoP / friend request)
/// over an already-established bidirectional transport instead of dialing
/// TCP itself. Used by [`connect_friend_with_fallback`] for the QUIC
/// hole-punch and rendezvous-relay transports, which hand back boxed
/// `AsyncRead`/`AsyncWrite` halves rather than a `TcpStream`.
///
/// `addr` is used only for logging and the identity-guard error message —
/// for non-TCP transports pass the best available description of where
/// the peer was actually reached (e.g. the rendezvous-reported punch
/// address, or `0.0.0.0:0` for a pure relay hop).
#[allow(clippy::too_many_arguments)]
pub async fn run_friend_session_over_transport(
    raw_r: Box<dyn tokio::io::AsyncRead + Unpin + Send>,
    raw_w: Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
    addr: SocketAddr,
    expected_ember_hash: [u8; 16],
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ember_sessions: EmberSessionMap,
    ul_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
) -> anyhow::Result<FriendSessionHandle> {
    let our_pk =
        ed25519_pubkey.ok_or_else(|| anyhow::anyhow!(secure_stream::UPGRADE_REQUIRED_ERROR))?;
    let our_sk =
        ed25519_secret_key.ok_or_else(|| anyhow::anyhow!(secure_stream::UPGRADE_REQUIRED_ERROR))?;
    let secure = secure_stream::initiate(
        raw_r,
        raw_w,
        our_ember_hash,
        expected_ember_hash,
        our_pk,
        our_sk,
    )
    .await?;
    let peer_pk = secure.peer.ed25519_public_key;
    let peer_ember_hash = secure.peer.ember_hash;
    let mut reader = tokio::io::BufReader::new(secure.reader);
    let mut writer = tokio::io::BufWriter::new(secure.writer);

    let hello_options = HelloOptions {
        udp_port,
        kad_port: udp_port,
        supports_crypt_layer: obfuscate,
        requests_crypt_layer: obfuscate,
        requires_crypt_layer: false,
        supports_direct_udp_callback: false,
        supports_captcha: false,
        server_ip: 0,
        server_port: 0,
        kad_version: 0x09,
    };
    let hello_payload = build_hello_with_buddy_opts(
        &our_user_hash,
        our_client_id,
        tcp_port,
        &our_nickname,
        None,
        &hello_options,
    );
    write_packet(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload).await?;

    let (proto, opcode, data) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for HelloAnswer")?;
    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }
    let (_peer_user_hash, mut hello_caps) = parse_hello_answer(&data).map_err(|e| {
        tracing::debug!("Failed to parse HelloAnswer from {addr}: {e}");
        e
    })?;

    let emule_payload = build_emule_info(udp_port, false, Some(&our_ember_hash), None);
    write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

    let (proto, opcode, payload) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for EmuleInfo")?;
    if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
        merge_caps(&mut hello_caps, parse_emule_info(&payload));
        if opcode == OP_EMULEINFO {
            let answer = build_emule_info(udp_port, false, Some(&our_ember_hash), None);
            write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &answer).await?;
        }
    }

    // The outer Noise IK handshake is now the sole privilege-bearing
    // identity proof.  Do not run the legacy nonce-signing exchange inside
    // the stream: keeping two authenticators would preserve the v1 live
    // signing oracle and create ambiguous downgrade semantics.
    hello_caps.is_ember = true;
    hello_caps.ember_hash = Some(peer_ember_hash);
    hello_caps.ember_pubkey = Some(peer_pk);

    // Membership is authoritative before any session reuse or slot claim.
    let is_friend = friend_hashes.read().await.contains(&peer_ember_hash);
    if !is_friend {
        anyhow::bail!(
            "remote peer {} is not in our friend list",
            hex::encode(peer_ember_hash)
        );
    }

    // Early duplicate-session check. Prefer an existing fresh secure session
    // with the *same* PoP-bound pubkey so a concurrent dial does not flap the
    // outbound router. Authorization for chat/browse on the peer's inbound
    // half no longer depends on who owns this map slot (see upload.rs).
    //
    // When we reuse, this new socket is deterministically closed by dropping
    // the Noise halves below — the peer's matching inbound sees EOF.
    {
        let sessions = ember_sessions.read().await;
        if let Some(existing) = sessions.get(&peer_ember_hash) {
            if reusable_secure_friend_session(existing, &peer_pk) {
                info!(
                    "Friend session for {} already exists after secure handshake; reusing canonical outbound slot and closing duplicate dial",
                    hex::encode(peer_ember_hash)
                );
                // Explicitly shut down any half-open work on this dial's
                // transport by dropping reader/writer at return.
                drop(reader);
                drop(writer);
                return Ok(FriendSessionHandle {
                    outbound_tx: existing.tx.clone(),
                    session_id: existing.session_id(),
                    peer_ember_pubkey: existing.peer_ember_pubkey(),
                });
            }
        }
    }

    let ember_hash_binding_verified = true;

    // Reserve the session slot atomically BEFORE we send our friend
    // request. If another concurrent dial raced us and claimed the
    // slot in the window between the pre-auth check above and here,
    // reuse that winner when it matches pubkey; otherwise supersede a
    // stale or key-mismatched entry.
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    let ember_session_handle =
        EmberSessionHandle::new_secure(outbound_tx.clone(), peer_pk, peer_ember_hash);
    {
        let mut sessions = ember_sessions.write().await;
        match sessions.get(&peer_ember_hash) {
            Some(existing) if reusable_secure_friend_session(existing, &peer_pk) => {
                info!(
                    "Friend session for {} already exists (post-handshake race); reusing winner and closing this dial",
                    hex::encode(peer_ember_hash)
                );
                let reused = FriendSessionHandle {
                    outbound_tx: existing.tx.clone(),
                    session_id: existing.session_id(),
                    peer_ember_pubkey: existing.peer_ember_pubkey(),
                };
                // Drop the secure registration for the unused handle by
                // closing it so revocation index / shutdown stay consistent.
                ember_session_handle.close();
                drop(reader);
                drop(writer);
                return Ok(reused);
            }
            Some(stale_or_mismatched) => {
                debug!(
                    "Friend session slot for {} held by a stale or key-mismatched entry; closing and claiming it",
                    hex::encode(peer_ember_hash)
                );
                stale_or_mismatched.close();
            }
            None => {}
        }
        sessions.insert(peer_ember_hash, ember_session_handle.clone());
    }

    // Only send the friend request once the slot is reserved. If
    // this write fails we must remove the slot we just inserted —
    // otherwise the map leaks an entry whose receiver is about to
    // be dropped, and every subsequent `outbound_tx.send(...)` from
    // lookups on that hash would fail with "channel closed".
    if let Err(e) = write_packet(
        &mut writer,
        OP_EMULEPROT,
        OP_EMBER_FRIEND_REQ,
        our_nickname.as_bytes(),
    )
    .await
    {
        let mut sessions = ember_sessions.write().await;
        let remove_current = sessions
            .get(&peer_ember_hash)
            .is_some_and(|current| current.tx.same_channel(&ember_session_handle.tx));
        if remove_current {
            sessions.remove(&peer_ember_hash);
        }
        return Err(anyhow::Error::from(e).context("failed to send OP_EMBER_FRIEND_REQ"));
    }

    info!("Friend session handshake with {} complete (hash={}, binding_verified={ember_hash_binding_verified})", addr, hex::encode(peer_ember_hash));

    let peer_user_hash = _peer_user_hash;
    let listen_port = if hello_caps.tcp_port > 0 {
        hello_caps.tcp_port
    } else {
        addr.port()
    };
    let peer_v4 = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => std::net::Ipv4Addr::UNSPECIFIED,
    };
    // Tell the network task this friend is reachable now, not just once
    // they happen to send us a chat/browse message. See the variant's doc
    // comment for why the UI-only `ember:friend-online` emits already at
    // every caller's success branch aren't enough on their own. Include
    // the dialable endpoint so incomplete downloads can relocate sources.
    let _ = ul_event_tx
        .send(UploadEvent {
            transfer_id: String::new(),
            kind: UploadEventKind::EmberFriendConnected {
                ember_hash: peer_ember_hash,
                peer_user_hash,
                ip: peer_v4,
                port: listen_port,
            },
        })
        .await;

    let handle = FriendSessionHandle {
        outbound_tx,
        session_id: ember_session_handle.session_id(),
        peer_ember_pubkey: peer_pk,
    };

    let session_ember_sessions = ember_sessions.clone();
    let session_ember_session_handle = ember_session_handle.clone();
    let session_ul_event_tx = ul_event_tx.clone();
    let session_friend_hashes = friend_hashes.clone();
    let mut session_shutdown = ember_session_handle.subscribe_shutdown();
    let session_our_ed25519_secret = our_sk;
    let session_peer_ember_pubkey = peer_pk;
    tokio::spawn(async move {
        const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(90);
        // L8: dead-peer detector. The eMule wire protocol has no
        // ack on application-level packets, so a peer whose NAT
        // mapping silently expired (or whose process is hung) will
        // happily accept our outbound bytes for ages before the
        // OS-level TCP retransmission storm finally surfaces an
        // error — typically 5–15 minutes on Windows. We instead
        // track the last *inbound* activity and disconnect when
        // we've heard nothing back in 3× the keepalive interval
        // (~4.5 min). 3× is the minimum that tolerates a single
        // lost keepalive in each direction without flapping; the
        // peer's reciprocal keepalive should reach us within one
        // window in steady state.
        const STALL_TIMEOUT: std::time::Duration =
            std::time::Duration::from_secs(KEEPALIVE_INTERVAL.as_secs() * 3);
        let mut last_activity = tokio::time::Instant::now();
        let mut last_inbound = tokio::time::Instant::now();

        // Dedicated reader task: reading an ed2k packet requires multiple
        // sequential awaits (protocol byte, length, opcode, payload). If the
        // outer tokio::select! cancelled the read mid-packet, we'd desync the
        // stream. Spawning a reader task keeps the framing state private and
        // only surfaces whole packets (or errors) through a channel, which is
        // cancel-safe at the select! site.
        let (pkt_tx, mut pkt_rx) =
            tokio::sync::mpsc::channel::<std::io::Result<(u8, u8, Vec<u8>)>>(8);
        let reader_task = tokio::spawn(async move {
            loop {
                let res = read_packet_inner(&mut reader).await;
                let is_err = res.is_err();
                if pkt_tx.send(res).await.is_err() {
                    break;
                }
                if is_err {
                    break;
                }
            }
        });

        loop {
            let keepalive = tokio::time::sleep_until(last_activity + KEEPALIVE_INTERVAL);
            tokio::select! {
                changed = session_shutdown.changed() => {
                    if changed.is_err() || *session_shutdown.borrow() {
                        info!(
                            "Friend session to {} ({}) was explicitly closed",
                            addr,
                            hex::encode(peer_ember_hash)
                        );
                        break;
                    }
                }
                result = pkt_rx.recv() => {
                    let result = match result {
                        Some(r) => r,
                        None => {
                            debug!("Friend session reader task from {addr} ended");
                            break;
                        }
                    };
                    match result {
                        Ok((proto, opcode, payload)) => {
                            let now = tokio::time::Instant::now();
                            last_activity = now;
                            // Even an OP_EMBER_KEEPALIVE (which we
                            // otherwise drop in the match below)
                            // counts as inbound liveness — that's
                            // exactly what the peer is signalling
                            // by sending it.
                            last_inbound = now;
                            // Mirror the same liveness signal into the
                            // shared `ember_sessions` map so lookups from
                            // other tasks (command handlers, the
                            // duplicate-session checks above) see this
                            // session as fresh for as long as it's
                            // actually exchanging traffic.
                            session_ember_session_handle.touch();
                            if !session_friend_hashes.read().await.contains(&peer_ember_hash) {
                                info!(
                                    "Friend {} removed; dropping inbound packet and terminating secure session",
                                    hex::encode(peer_ember_hash)
                                );
                                break;
                            }
                            match (proto, opcode) {
                                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) => {
                                    if payload.len() > MAX_CHAT_WIRE_LEN {
                                        warn!(
                                            "Friend {} chat payload oversized ({} bytes); dropping without decrypt",
                                            hex::encode(peer_ember_hash),
                                            payload.len()
                                        );
                                    } else if let Some(msg) = decrypt_chat_payload(
                                        &session_our_ed25519_secret,
                                        &session_peer_ember_pubkey,
                                        &payload,
                                    ) {
                                        let _ = session_ul_event_tx
                                            .send(UploadEvent {
                                                transfer_id: String::new(),
                                                kind: UploadEventKind::EmberChatMessage {
                                                    ember_hash: peer_ember_hash,
                                                    message: msg,
                                                },
                                            })
                                            .await;
                                    } else {
                                        // Never log or forward ciphertext.  A
                                        // dedicated UploadEvent + UI toast needs
                                        // a network/mod.rs match arm (owned by
                                        // another agent).
                                        warn!(
                                            "Friend {} chat decrypt failed (len={}); dropping ciphertext",
                                            hex::encode(peer_ember_hash),
                                            payload.len()
                                        );
                                    }
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ) => {
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseRequest {
                                            ember_hash: peer_ember_hash,
                                            session_id: session_ember_session_handle.session_id(),
                                            reply_tx: session_ember_session_handle.tx.clone(),
                                            supports_ebr1:
                                                super::multi_source::browse_request_supports_v1(
                                                    &payload,
                                                ),
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) => {
                                    let entries = parse_browse_response(&payload);
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseResponse {
                                            ember_hash: peer_ember_hash,
                                    session_id: session_ember_session_handle.session_id(),
                                            entries,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_FRIEND_REQ) => {
                                    let nick = std::str::from_utf8(&payload).unwrap_or("").to_string();
                                    // `verified` is the session-scoped
                                    // `ember_hash_binding_verified`
                                    // flag set during session setup.
                                    // For Ember-to-Ember sessions
                                    // this folds in the result of
                                    // `perform_ember_auth` (a real
                                    // Ed25519 proof of possession);
                                    // for peers that didn't advertise
                                    // a pubkey it falls back to the
                                    // offline BLAKE3 binding check.
                                    info!("Received friend request on outbound friend session from {} (nick='{}', verified={ember_hash_binding_verified})", addr, nick);
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberFriendRequest {
                                            ember_hash: peer_ember_hash,
                                            pubkey: Some(peer_pk),
                                            nickname: nick,
                                            peer_ip: addr.ip().to_string(),
                                            peer_port: addr.port(),
                                            verified: ember_hash_binding_verified,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_KEEPALIVE) => {}
                                _ => {
                                    debug!("Friend session ignoring proto=0x{proto:02X} op=0x{opcode:02X} from {addr}");
                                }
                            }
                        }
                        Err(e) => {
                            // Root cause of the session ending — the "session
                            // ended" log itself is already `info!`-level, but
                            // without this at the same level the actual reason
                            // (vs. a clean keepalive-stall disconnect) is
                            // invisible at default log verbosity.
                            warn!("Friend session read error from {addr}: {e}");
                            break;
                        }
                    }
                }
                Some(outbound_data) = outbound_rx.recv() => {
                    last_activity = tokio::time::Instant::now();
                    if writer.write_all(&outbound_data).await.is_err() {
                        warn!("Friend session write error to {addr}");
                        break;
                    }
                    if writer.flush().await.is_err() {
                        warn!("Friend session flush error to {addr}");
                        break;
                    }
                }
                _ = keepalive => {
                    if !session_friend_hashes.read().await.contains(&peer_ember_hash) {
                        info!("Friend {} removed, terminating outbound session", hex::encode(peer_ember_hash));
                        break;
                    }
                    // L8: stall check. Run BEFORE we send another
                    // keepalive so we don't pointlessly burn one more
                    // round trip on a peer that's already dead. The
                    // STALL_TIMEOUT is wider than KEEPALIVE_INTERVAL
                    // by enough margin to absorb a single
                    // packet-loss-and-retry cycle in either
                    // direction; if the peer is genuinely alive its
                    // reciprocal keepalive will have refreshed
                    // `last_inbound` long before we get here.
                    if last_inbound.elapsed() >= STALL_TIMEOUT {
                        info!(
                            "Friend session to {} ({}) stalled — no inbound traffic in {:?}; disconnecting",
                            addr,
                            hex::encode(peer_ember_hash),
                            last_inbound.elapsed(),
                        );
                        break;
                    }
                    if write_packet(&mut writer, OP_EMULEPROT, OP_EMBER_KEEPALIVE, &[]).await.is_err() {
                        warn!("Friend session keepalive to {addr} failed");
                        break;
                    }
                    last_activity = tokio::time::Instant::now();
                }
            }
        }

        reader_task.abort();
        let _ = reader_task.await;

        {
            let mut sessions = session_ember_sessions.write().await;
            let remove_current = sessions
                .get(&peer_ember_hash)
                .is_some_and(|current| current.tx.same_channel(&session_ember_session_handle.tx));
            if remove_current {
                sessions.remove(&peer_ember_hash);
            } else {
                debug!(
                    "Friend session to {} ended, but a newer session for {} is active; preserving it",
                    addr,
                    hex::encode(peer_ember_hash)
                );
            }
        }
        let _ = session_ul_event_tx
            .send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::EmberFriendDisconnected {
                    ember_hash: peer_ember_hash,
                    session_id: session_ember_session_handle.session_id(),
                },
            })
            .await;
        info!(
            "Friend session to {} ({}) ended",
            addr,
            hex::encode(peer_ember_hash)
        );
    });

    Ok(handle)
}

/// Number of signed `/v2/punch/poll` requests to make after registering, and the delay
/// between them. A friend's own offline-retry loop fires independently of
/// ours (there is no request/response coupling before this point — see
/// [`punch_friend`]), so this window exists purely to catch two
/// independently-scheduled retries landing close together. The rendezvous
/// server only retains a punch registration for 30 s
/// (`rendezvous-server/src/main.rs::PUNCH_TTL`), so polling much past
/// that would just poll a registration that already expired.
const FRIEND_PUNCH_POLL_ATTEMPTS: usize = 12;
const FRIEND_PUNCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Reach a friend who isn't directly dialable by trying, in order: a
/// plain TCP dial to `addr` (the previous, sole behaviour), an Ember QUIC
/// hole-punch coordinated via the rendezvous server, and finally a
/// rendezvous WebSocket relay hop. Returns as soon as any method produces
/// a live, authenticated Ember session.
///
/// Before this, friend sessions had zero fallback beyond
/// `TcpStream::connect` — two friends who are both behind a NAT that
/// doesn't forward the advertised port (extremely common for LowID /
/// firewalled peers) could never open chat or browse with each other even
/// though the exact same hole-punch/relay machinery already existed for
/// file-transfer sources.
///
/// `rendezvous_url` empty or `nat_ctx`'s `quic_endpoint` absent degrade
/// gracefully to TCP-only, matching the previous behaviour exactly.
///
/// `nat_ctx` is read fresh (not snapshotted by the caller) right before the
/// hole-punch attempt, after the TCP-first attempt above has already had a
/// chance to fail — see [`crate::network::ember::nat::FriendNatContext`]'s
/// doc comment for why that matters.
#[allow(clippy::too_many_arguments)]
pub async fn connect_friend_with_fallback(
    addr: SocketAddr,
    expected_ember_hash: [u8; 16],
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ember_sessions: EmberSessionMap,
    ul_event_tx: tokio::sync::mpsc::Sender<UploadEvent>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
    rendezvous_url: String,
    nat_ctx: crate::network::ember::nat::SharedFriendNatContext,
) -> anyhow::Result<FriendSessionHandle> {
    let tcp_err = match open_and_run_friend_session(
        addr,
        expected_ember_hash,
        our_user_hash,
        our_ember_hash,
        our_nickname.clone(),
        our_client_id,
        tcp_port,
        udp_port,
        obfuscate,
        ember_sessions.clone(),
        ul_event_tx.clone(),
        friend_hashes.clone(),
        ed25519_pubkey,
        ed25519_secret_key,
    )
    .await
    {
        Ok(handle) => return Ok(handle),
        Err(e) => e,
    };

    if rendezvous_url.is_empty() {
        return Err(tcp_err);
    }
    info!(
        "Friend TCP connect to {} ({}) failed ({tcp_err}); trying Ember NAT traversal",
        addr,
        hex::encode(expected_ember_hash)
    );

    // Re-read the NAT context now, not at task-spawn time. The TCP attempt
    // above can take up to ~15s (`open_and_run_friend_session`'s connect
    // timeout) on its own; a value snapshotted before that started could be
    // stale by a wide margin — most importantly, `external_addr`/`nat_type`
    // may have still been `Unknown`/`None` (probe not yet finished) at spawn
    // time but resolved by now. See `FriendNatContext`'s doc comment.
    let (our_nat_type, our_external_addr, quic_endpoint) = {
        let ctx = nat_ctx.read().unwrap_or_else(|p| p.into_inner());
        (ctx.nat_type, ctx.external_addr, ctx.quic_endpoint.clone())
    };

    if let (Some(endpoint), Some(ext_addr), Some(punch_secret)) = (
        quic_endpoint.as_ref(),
        our_external_addr,
        ed25519_secret_key.as_ref(),
    ) {
        if our_nat_type != crate::network::ember::nat::NatType::Symmetric {
            match punch_friend(
                &rendezvous_url,
                endpoint,
                our_ember_hash,
                expected_ember_hash,
                ext_addr,
                our_nat_type,
                punch_secret,
            )
            .await
            {
                Ok((send, recv)) => {
                    info!(
                        "Friend hole-punch to {} succeeded",
                        hex::encode(expected_ember_hash)
                    );
                    return run_friend_session_over_transport(
                        Box::new(recv),
                        Box::new(send),
                        addr,
                        expected_ember_hash,
                        our_user_hash,
                        our_ember_hash,
                        our_nickname.clone(),
                        our_client_id,
                        tcp_port,
                        udp_port,
                        obfuscate,
                        ember_sessions.clone(),
                        ul_event_tx.clone(),
                        friend_hashes.clone(),
                        ed25519_pubkey,
                        ed25519_secret_key,
                    )
                    .await;
                }
                Err(e) => {
                    debug!(
                        "Friend hole-punch to {} failed: {e}",
                        hex::encode(expected_ember_hash)
                    );
                }
            }
        }
    }

    // Server relay tickets are deliberately restricted to a manually-known
    // friend. The transport's later Ember handshake also verifies the peer,
    // but refusing before issuing a ticket avoids turning arbitrary source
    // addresses into authenticated relay capabilities.
    if !friend_hashes.read().await.contains(&expected_ember_hash) {
        return Err(anyhow::anyhow!(
            "server relay is restricted to known friends"
        ));
    }
    let relay_secret = ed25519_secret_key.ok_or_else(|| {
        anyhow::anyhow!("server relay requires the local registered identity key")
    })?;

    match relay_friend(
        &rendezvous_url,
        our_ember_hash,
        expected_ember_hash,
        ed25519_pubkey
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("server relay requires local v2 identity"))?,
        &relay_secret,
    )
    .await
    {
        Ok(ws_stream) => {
            info!(
                "Friend relay to {} connected",
                hex::encode(expected_ember_hash)
            );
            let (r, w) = tokio::io::split(ws_stream);
            run_friend_session_over_transport(
                Box::new(r),
                Box::new(w),
                addr,
                expected_ember_hash,
                our_user_hash,
                our_ember_hash,
                our_nickname,
                our_client_id,
                tcp_port,
                udp_port,
                obfuscate,
                ember_sessions,
                ul_event_tx,
                friend_hashes,
                ed25519_pubkey,
                ed25519_secret_key,
            )
            .await
        }
        Err(e) => {
            debug!(
                "Friend relay to {} failed: {e}",
                hex::encode(expected_ember_hash)
            );
            Err(anyhow::anyhow!(
                "all connection methods failed for friend {}: tcp={tcp_err}; relay={e}",
                hex::encode(expected_ember_hash)
            ))
        }
    }
}

/// Coordinate a QUIC hole-punch with a friend via the rendezvous server,
/// keyed directly by `ember_hash` rather than the synthetic IP:port id
/// the download broker uses for anonymous sources — both friends already
/// know each other's stable identity, so no synthetic scheme is needed.
///
/// This is purely best-effort: it only succeeds if the friend's own
/// client is *at the same time* trying to reach us — e.g. its own
/// offline-friend retry loop fired within the rendezvous server's 30 s
/// punch-registration window — and therefore registers a reciprocal
/// punch back at us. There is no separate "responder" role to implement
/// here: each side's normal reconnect attempt already plays both parts,
/// since [`connect_friend_with_fallback`] is exactly what runs whenever
/// either side's retry loop wakes up for this friend.
async fn punch_friend(
    rendezvous_url: &str,
    endpoint: &quinn::Endpoint,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    our_external_addr: SocketAddr,
    our_nat_type: crate::network::ember::nat::NatType,
    secret_key: &[u8; 32],
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    // Register the port our QUIC endpoint is actually bound to, not
    // `our_external_addr.port()` — that address comes from the KAD UDP
    // STUN probe (a *different* socket than the QUIC endpoint the friend
    // will actually dial), so advertising it here would misdirect the
    // friend's `punch_quic` connect at a socket we're not listening on.
    let advertise_port = endpoint
        .local_addr()
        .map(|a| a.port())
        .unwrap_or_else(|_| our_external_addr.port());
    // Bind the exact observed/canonical external IP into the signed register
    // payload — port alone is insufficient after the rendezvous IP-binding change.
    crate::network::ember::relay::register_punch_with_ip(
        rendezvous_url,
        &our_ember_hash,
        &friend_ember_hash,
        advertise_port,
        our_nat_type.as_u8(),
        our_external_addr.ip(),
        secret_key,
        &our_ember_hash,
    )
    .await?;

    let our_pubkey = ed25519_dalek::SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes();

    for _ in 0..FRIEND_PUNCH_POLL_ATTEMPTS {
        tokio::time::sleep(FRIEND_PUNCH_POLL_INTERVAL).await;
        match crate::network::ember::relay::poll_punch(rendezvous_url, &our_ember_hash, secret_key)
            .await
        {
            Ok(Some(info)) => {
                // poll_punch already verifies the IP-bound register proof.
                let expected_capability =
                    match crate::network::rendezvous::fetch_identity_pubkey_authenticated(
                        rendezvous_url,
                        &friend_ember_hash,
                        &our_ember_hash,
                        &our_pubkey,
                        secret_key,
                    )
                    .await
                    {
                        Ok(Some(pubkey)) => {
                            crate::network::ember::crypto::derive_pairwise_presence_capability(
                                secret_key,
                                &pubkey,
                                &our_pubkey,
                                info.epoch,
                            )
                        }
                        Ok(None) => None,
                        Err(error) => {
                            debug!("Friend punch: identity lookup failed: {error}");
                            None
                        }
                    };
                let expected_capability = match expected_capability {
                    Some(capability) => capability,
                    None => {
                        let _ = crate::network::ember::relay::ack_punch(
                            rendezvous_url,
                            &our_ember_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            secret_key,
                        )
                        .await;
                        continue;
                    }
                };
                if info.from_id != crate::network::rendezvous::hashed_id(&friend_ember_hash)
                    || info.capability != expected_capability
                {
                    let _ = crate::network::ember::relay::ack_punch(
                        rendezvous_url,
                        &our_ember_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        secret_key,
                    )
                    .await;
                    continue;
                }
                let peer_nat = crate::network::ember::nat::NatType::from_u8(info.nat_type);
                let Ok(ip) = info.ip.parse::<std::net::IpAddr>() else {
                    let _ = crate::network::ember::relay::ack_punch(
                        rendezvous_url,
                        &our_ember_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        secret_key,
                    )
                    .await;
                    continue;
                };
                let routable = match ip {
                    std::net::IpAddr::V4(v4) => !crate::security::is_special_use_v4(v4),
                    std::net::IpAddr::V6(_) => !crate::security::is_private_ip(ip),
                };
                if !routable || info.port == 0 {
                    debug!(
                        "Friend punch: ignoring non-routable target {ip}:{}",
                        info.port
                    );
                    let _ = crate::network::ember::relay::ack_punch(
                        rendezvous_url,
                        &our_ember_hash,
                        &info.punch_id,
                        &info.capability,
                        info.epoch,
                        secret_key,
                    )
                    .await;
                    continue;
                }
                let peer_addr = SocketAddr::new(ip, info.port);
                debug!("Friend punch: signed peer at {peer_addr} reports NAT {peer_nat:?}");
                match super::super::ember::broker::punch_quic(endpoint, peer_addr, None).await {
                    Ok(streams) => {
                        crate::network::ember::relay::ack_punch(
                            rendezvous_url,
                            &our_ember_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            secret_key,
                        )
                        .await?;
                        return Ok(streams);
                    }
                    Err(error) => {
                        debug!("Friend QUIC punch to {peer_addr} failed: {error}");
                        let _ = crate::network::ember::relay::ack_punch(
                            rendezvous_url,
                            &our_ember_hash,
                            &info.punch_id,
                            &info.capability,
                            info.epoch,
                            secret_key,
                        )
                        .await;
                    }
                }
            }
            Ok(None) => {}
            Err(e) => debug!("Friend punch poll error: {e}"),
        }
    }
    Err("no reciprocal punch registration found before timeout".to_string())
}

/// Fall back to a rendezvous-brokered WebSocket relay to reach a friend
/// whose hole-punch (if attempted) didn't land.
///
/// The ticket is addressed to the friend's registered Ember identity, not a
/// synthetic IP:port. The peer's signed ticket poller accepts it only after
/// confirming that our identity is in its known-friend set.
async fn relay_friend(
    rendezvous_url: &str,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    our_pubkey: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<crate::network::ember::relay::WsStream, String> {
    let offer = crate::network::rendezvous::offer_friend_relay_ticket(
        rendezvous_url,
        &our_ember_hash,
        &friend_ember_hash,
        our_pubkey,
        secret_key,
    )
    .await?;

    // The responder polls independently. Keep this a total deadline rather
    // than 45 request iterations: a stalled status request must not extend
    // the capability's useful lifetime indefinitely.
    let deadline = tokio::time::Instant::now()
        + crate::network::rendezvous::FRIEND_RELAY_TICKET_INITIATOR_WAIT;
    let mut status_retry_delay = std::time::Duration::from_secs(1);
    while tokio::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(remaining.min(status_retry_delay)).await;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        let status_timeout =
            remaining.min(crate::network::rendezvous::FRIEND_RELAY_TICKET_ACTION_TIMEOUT);
        match tokio::time::timeout(
            status_timeout,
            crate::network::rendezvous::friend_relay_ticket_accepted(
                rendezvous_url,
                &our_ember_hash,
                &offer.ticket_id,
                secret_key,
            ),
        )
        .await
        {
            Ok(Ok(true)) => {
                return crate::network::ember::relay::connect_server_relay(
                    rendezvous_url,
                    &offer.ticket_id,
                    &offer.initiator_token,
                )
                .await;
            }
            Ok(Ok(false)) => {}
            Ok(Err(e)) => {
                if crate::network::rendezvous::is_transient_relay_ticket_read_error(&e) {
                    status_retry_delay =
                        (status_retry_delay * 2).min(std::time::Duration::from_secs(5));
                    continue;
                }
                return Err(format!("friend relay ticket status failed: {e}"));
            }
            Err(_) => {
                status_retry_delay =
                    (status_retry_delay * 2).min(std::time::Duration::from_secs(5));
                continue;
            }
        }
        status_retry_delay = std::time::Duration::from_secs(1);
    }
    Err("friend relay ticket was not accepted before timeout".to_string())
}

use super::multi_source::parse_browse_response;

#[cfg(test)]
mod tests {
    use super::*;

    /// With an empty `rendezvous_url`, `connect_friend_with_fallback` must
    /// behave exactly like the old TCP-only `open_and_run_friend_session`
    /// — no punch/relay attempted, and the original TCP error is returned
    /// promptly rather than hanging. Regression guard for the "friend
    /// connections have zero NAT-traversal fallback" gap: this confirms
    /// the new fallback path is strictly additive and degrades cleanly
    /// when no rendezvous server is configured.
    #[tokio::test]
    async fn fallback_degrades_to_tcp_only_when_rendezvous_url_empty() {
        // Reserve a port and then close it so the subsequent connect is a
        // fast, deterministic refusal rather than depending on some
        // hopefully-unused port number.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);

        let ember_sessions: EmberSessionMap =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        let (ul_tx, _ul_rx) = tokio::sync::mpsc::channel(8);
        let friend_hashes = Arc::new(RwLock::new(std::collections::HashSet::new()));

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connect_friend_with_fallback(
                addr,
                [0x11; 16],
                [0x22; 16],
                [0x33; 16],
                "tester".to_string(),
                0,
                4662,
                4672,
                false,
                ember_sessions,
                ul_tx,
                friend_hashes,
                None,
                None,
                String::new(),
                crate::network::ember::nat::new_shared_friend_nat_context(),
            ),
        )
        .await
        .expect("connect_friend_with_fallback must not hang with no rendezvous URL");

        assert!(result.is_err());
    }

    /// Regression guard for the "online_friends not updated on successful
    /// outbound rendezvous connect" gap: drives a full mock peer through
    /// the real Hello / EmuleInfo / OP_EMBER_HELLO / Ed25519 PoP handshake
    /// over an in-memory duplex pipe and asserts that a successful
    /// `run_friend_session_over_transport` call — the single choke point
    /// every outbound dial (rendezvous lookup, chat/browse auto-connect,
    /// proactive `FriendSeen` dial) funnels through — emits
    /// `UploadEventKind::EmberFriendConnected` so the network loop's
    /// `state.online_friends` bookkeeping (and therefore `GetOnlineFriends`)
    /// reflects the session immediately, not only after the peer happens to
    /// send a chat/browse message.
    #[tokio::test]
    async fn successful_outbound_session_emits_ember_friend_connected() {
        let our_sk = SigningKey::generate(&mut OsRng);
        let our_pk_bytes = our_sk.verifying_key().to_bytes();
        let our_sk_bytes = our_sk.to_bytes();
        let our_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&our_sk.verifying_key());

        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_pk_bytes = peer_sk.verifying_key().to_bytes();
        let peer_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&peer_sk.verifying_key());

        let (client, server) = tokio::io::duplex(8192);
        let (client_r, client_w) = tokio::io::split(client);
        let (mut server_r, server_w) = tokio::io::split(server);

        let ember_sessions: EmberSessionMap =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        let (ul_tx, mut ul_rx) = tokio::sync::mpsc::channel(16);
        let friend_hashes = Arc::new(RwLock::new(std::collections::HashSet::from([
            peer_ember_hash,
        ])));
        let addr: SocketAddr = "127.0.0.1:4662".parse().unwrap();

        let session_task = tokio::spawn(run_friend_session_over_transport(
            Box::new(client_r),
            Box::new(client_w),
            addr,
            peer_ember_hash,
            [0x11; 16],
            our_ember_hash,
            "tester".to_string(),
            0,
            4662,
            4672,
            false,
            ember_sessions,
            ul_tx,
            friend_hashes,
            Some(our_pk_bytes),
            Some(our_sk_bytes),
        ));

        // Mock peer: plays the responder side of the handshake so the
        // client-side function under test runs its real success path.
        let mock_peer = async {
            let first = server_r.read_u8().await.unwrap();
            let secure = super::secure_stream::accept_after_first(
                Box::new(server_r),
                Box::new(server_w),
                first,
                peer_ember_hash,
                peer_pk_bytes,
                peer_sk.to_bytes(),
            )
            .await
            .unwrap();
            let mut server_r = secure.reader;
            let mut server_w = secure.writer;
            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EDONKEYHEADER, OP_HELLO));
            let hello_answer = build_hello_answer_with_buddy_opts(
                &[0x99; 16],
                0,
                4662,
                "peer",
                None,
                &HelloOptions::default_for_udp_port(4672),
            );
            write_packet(
                &mut server_w,
                OP_EDONKEYHEADER,
                OP_HELLOANSWER,
                &hello_answer,
            )
            .await
            .unwrap();

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMULEINFO));
            let info_answer = build_emule_info(4672, false, None, None);
            write_packet(
                &mut server_w,
                OP_EMULEPROT,
                OP_EMULEINFOANSWER,
                &info_answer,
            )
            .await
            .unwrap();

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMBER_FRIEND_REQ));
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), mock_peer)
            .await
            .expect("mock peer handshake must not hang");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), session_task)
            .await
            .expect("session task must not hang")
            .expect("session task must not panic");
        assert!(
            result.is_ok(),
            "handshake against a well-behaved mock peer must succeed: {:?}",
            result.err().map(|e| e.to_string())
        );

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), ul_rx.recv())
            .await
            .expect("must receive an UploadEvent before timeout")
            .expect("event channel must not be closed");
        assert!(
            matches!(
                event.kind,
                UploadEventKind::EmberFriendConnected { ember_hash, .. } if ember_hash == peer_ember_hash
            ),
            "expected the first event to be EmberFriendConnected for the peer's hash"
        );
    }

    /// Regression guard for `med-ember-sessions-stale`: a pre-existing
    /// `ember_sessions` entry for the peer that hasn't been heard from in
    /// over `EMBER_SESSION_FRESH_SECS` must NOT short-circuit a fresh
    /// dial via the early duplicate-session check (see the comment above
    /// that check in `run_friend_session_over_transport`). Before this
    /// fix, any stale entry — however old — caused the dial to return the
    /// old, dead sender immediately without attempting a real handshake,
    /// silently blackholing the session for up to the ~4.5 min
    /// `STALL_TIMEOUT` in the original session's own reader loop.
    #[tokio::test]
    async fn stale_existing_session_does_not_block_fresh_dial() {
        let our_sk = SigningKey::generate(&mut OsRng);
        let our_pk_bytes = our_sk.verifying_key().to_bytes();
        let our_sk_bytes = our_sk.to_bytes();
        let our_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&our_sk.verifying_key());

        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_pk_bytes = peer_sk.verifying_key().to_bytes();
        let peer_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&peer_sk.verifying_key());

        let (client, server) = tokio::io::duplex(8192);
        let (client_r, client_w) = tokio::io::split(client);
        let (mut server_r, server_w) = tokio::io::split(server);

        let ember_sessions: EmberSessionMap =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        // Seed the map with a stale entry for this exact peer before the
        // dial starts — simulating a previous session whose connection
        // died silently without a clean teardown.
        let (dead_tx, dead_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let stale_handle = EmberSessionHandle::new(dead_tx, [0u8; 32]);
        // Comfortably past `EMBER_SESSION_FRESH_SECS` (180s; private to
        // `upload.rs`) without depending on that exact constant here.
        stale_handle.backdate_for_test(3600);
        drop(dead_rx); // the "dead" side: receiver already gone
        ember_sessions
            .write()
            .await
            .insert(peer_ember_hash, stale_handle);

        let (ul_tx, mut ul_rx) = tokio::sync::mpsc::channel(16);
        let friend_hashes = Arc::new(RwLock::new(std::collections::HashSet::from([
            peer_ember_hash,
        ])));
        let addr: SocketAddr = "127.0.0.1:4662".parse().unwrap();

        let session_task = tokio::spawn(run_friend_session_over_transport(
            Box::new(client_r),
            Box::new(client_w),
            addr,
            peer_ember_hash,
            [0x11; 16],
            our_ember_hash,
            "tester".to_string(),
            0,
            4662,
            4672,
            false,
            ember_sessions,
            ul_tx,
            friend_hashes,
            Some(our_pk_bytes),
            Some(our_sk_bytes),
        ));

        let mock_peer = async {
            let first = server_r.read_u8().await.unwrap();
            let secure = super::secure_stream::accept_after_first(
                Box::new(server_r),
                Box::new(server_w),
                first,
                peer_ember_hash,
                peer_pk_bytes,
                peer_sk.to_bytes(),
            )
            .await
            .unwrap();
            let mut server_r = secure.reader;
            let mut server_w = secure.writer;
            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EDONKEYHEADER, OP_HELLO));
            let hello_answer = build_hello_answer_with_buddy_opts(
                &[0x99; 16],
                0,
                4662,
                "peer",
                None,
                &HelloOptions::default_for_udp_port(4672),
            );
            write_packet(
                &mut server_w,
                OP_EDONKEYHEADER,
                OP_HELLOANSWER,
                &hello_answer,
            )
            .await
            .unwrap();

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMULEINFO));
            let info_answer = build_emule_info(4672, false, None, None);
            write_packet(
                &mut server_w,
                OP_EMULEPROT,
                OP_EMULEINFOANSWER,
                &info_answer,
            )
            .await
            .unwrap();

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMBER_FRIEND_REQ));
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), mock_peer)
            .await
            .expect("mock peer handshake must not hang — a stale session entry must not short-circuit the dial");

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), session_task)
            .await
            .expect("session task must not hang")
            .expect("session task must not panic");
        assert!(
            result.is_ok(),
            "a real handshake must still occur despite the pre-existing stale session entry: {:?}",
            result.err().map(|e| e.to_string())
        );

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), ul_rx.recv())
            .await
            .expect("must receive an UploadEvent before timeout")
            .expect("event channel must not be closed");
        assert!(
            matches!(
                event.kind,
                UploadEventKind::EmberFriendConnected { ember_hash, .. } if ember_hash == peer_ember_hash
            ),
            "expected EmberFriendConnected once the fresh session actually completes"
        );
    }

    #[test]
    fn reusable_secure_session_requires_fresh_secure_matching_pubkey() {
        let (tx, _rx) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let pk = [0x42u8; 32];
        let hash = [0x11u8; 16];
        let secure = EmberSessionHandle::new_secure(tx.clone(), pk, hash);
        assert!(reusable_secure_friend_session(&secure, &pk));
        assert!(!reusable_secure_friend_session(&secure, &[0x43u8; 32]));

        let (tx2, _rx2) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let legacy = EmberSessionHandle::new(tx2, pk);
        assert!(
            !reusable_secure_friend_session(&legacy, &pk),
            "non-v2 handles must never be reused as secure friend sessions"
        );

        let (tx3, _rx3) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let stale = EmberSessionHandle::new_secure(tx3, pk, hash);
        stale.backdate_for_test(3600);
        assert!(!reusable_secure_friend_session(&stale, &pk));
    }

    #[tokio::test]
    async fn early_reuse_rejects_missing_friend_membership() {
        let our_sk = SigningKey::generate(&mut OsRng);
        let our_pk_bytes = our_sk.verifying_key().to_bytes();
        let our_sk_bytes = our_sk.to_bytes();
        let our_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&our_sk.verifying_key());

        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_pk_bytes = peer_sk.verifying_key().to_bytes();
        let peer_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&peer_sk.verifying_key());

        let (client, server) = tokio::io::duplex(8192);
        let (client_r, client_w) = tokio::io::split(client);
        let (mut server_r, server_w) = tokio::io::split(server);

        let ember_sessions: EmberSessionMap =
            Arc::new(RwLock::new(std::collections::HashMap::new()));
        // Pre-seed a fresh secure session as if a prior dial already won.
        let (existing_tx, _existing_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
        let existing = EmberSessionHandle::new_secure(existing_tx, peer_pk_bytes, peer_ember_hash);
        ember_sessions
            .write()
            .await
            .insert(peer_ember_hash, existing);

        let (ul_tx, _ul_rx) = tokio::sync::mpsc::channel(16);
        // Empty friend set — reuse must fail membership before returning the
        // pre-seeded handle.
        let friend_hashes = Arc::new(RwLock::new(std::collections::HashSet::new()));
        let addr: SocketAddr = "127.0.0.1:4662".parse().unwrap();

        let session_task = tokio::spawn(run_friend_session_over_transport(
            Box::new(client_r),
            Box::new(client_w),
            addr,
            peer_ember_hash,
            [0x11; 16],
            our_ember_hash,
            "tester".to_string(),
            0,
            4662,
            4672,
            false,
            ember_sessions,
            ul_tx,
            friend_hashes,
            Some(our_pk_bytes),
            Some(our_sk_bytes),
        ));

        let mock_peer = async {
            let first = server_r.read_u8().await.unwrap();
            let secure = super::secure_stream::accept_after_first(
                Box::new(server_r),
                Box::new(server_w),
                first,
                peer_ember_hash,
                peer_pk_bytes,
                peer_sk.to_bytes(),
            )
            .await
            .unwrap();
            let mut server_r = secure.reader;
            let mut server_w = secure.writer;
            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EDONKEYHEADER, OP_HELLO));
            let hello_answer = build_hello_answer_with_buddy_opts(
                &[0x22; 16],
                0,
                4662,
                "peer",
                None,
                &HelloOptions::default_for_udp_port(4672),
            );
            write_packet(
                &mut server_w,
                OP_EDONKEYHEADER,
                OP_HELLOANSWER,
                &hello_answer,
            )
            .await
            .unwrap();
            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.unwrap();
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMULEINFO));
            let answer = build_emule_info(4672, false, Some(&peer_ember_hash), None);
            write_packet(&mut server_w, OP_EMULEPROT, OP_EMULEINFOANSWER, &answer)
                .await
                .unwrap();
            // Dialer should bail on membership; keep the socket open briefly.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };

        let (session_res, _) = tokio::join!(session_task, mock_peer);
        let err = match session_res.expect("join") {
            Ok(_) => panic!("non-friend must not reuse a secure session"),
            Err(e) => e,
        };
        assert!(
            format!("{err}").contains("not in our friend list"),
            "got {err}"
        );
    }
}

async fn write_packet<W: AsyncWriteExt + Unpin + ?Sized>(
    writer: &mut W,
    protocol: u8,
    opcode: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    writer.write_u8(protocol).await?;
    let pkt_len = (1 + payload.len()) as u32;
    writer.write_u32_le(pkt_len).await?;
    writer.write_u8(opcode).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_packet_inner<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    let len = reader.read_u32_le().await?;
    if len == 0 || len > 5_000_000 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid packet length",
        ));
    }
    let opcode = reader.read_u8().await?;
    let payload_len = (len - 1) as usize;
    // Grow the buffer as bytes actually arrive rather than allocating the full
    // declared length (up to ~5 MiB) before reading. A peer that announces a
    // large packet then stalls would otherwise pin that allocation per
    // friend-connect session (mirrors `read_packet_async` in transfer.rs).
    let mut payload = Vec::new();
    let mut remaining = payload_len;
    const READ_STEP: usize = 65536;
    while remaining > 0 {
        let want = remaining.min(READ_STEP);
        let start = payload.len();
        payload.resize(start + want, 0);
        reader.read_exact(&mut payload[start..start + want]).await?;
        remaining -= want;
    }
    Ok((protocol, opcode, payload))
}

/// Maximum time we'll wait for the peer's `OP_EMBER_HELLO` /
/// `OP_EMBER_HELLOANSWER` after we send ours. Short enough that a
/// vanilla eMule peer (which will never respond) doesn't add noticeable
/// latency to friend-connect; long enough to absorb normal-internet
/// jitter for the small handful of packets that may queue ahead of the
/// Ember hello.
#[allow(dead_code)]
const EMBER_HELLO_TIMEOUT_SECS: u64 = 5;
/// Cap on the number of unrelated packets we'll consume while looking
/// for the peer's Ember hello. A well-behaved Ember peer sends its
/// hello immediately after the EmuleInfo exchange, so 0–1 unrelated
/// packets are normal (e.g. `OP_SECIDENTSTATE`); a higher count may
/// indicate the peer is racing in unrelated traffic. Bounded so a
/// chatty peer can't pin us in this loop.
#[allow(dead_code)]
const EMBER_HELLO_MAX_LOOKAHEAD: usize = 4;

/// Drives a synchronous `OP_EMBER_HELLO` exchange right after the
/// EmuleInfo round-trip. We send our hello (with our Ed25519 pubkey
/// when available) and then read packets for up to
/// [`EMBER_HELLO_TIMEOUT_SECS`] looking for the peer's hello. On
/// success we populate `hello_caps.is_ember`, `.ember_hash`,
/// `.ember_pubkey`, `.mod_version`, and `.peer_name` from the parsed
/// payload — the only place in `friend_connect.rs` that ever sets
/// `is_ember = true` (the public Hello / EmuleInfo handshake is kept
/// byte-identical to vanilla eMule so anti-leecher mods don't queue-ban
/// us, see the long comment in `messages.rs::build_emule_info`).
///
/// If the peer beat us to it and sent `OP_EMBER_HELLO` instead of an
/// answer, we reply with our own `OP_EMBER_HELLOANSWER` so they also
/// learn our pubkey in the same round-trip. Vanilla peers and older
/// Ember peers that don't speak this opcode just hit the timeout and
/// the handshake proceeds without `ember_pubkey` set — the downstream
/// `is_ember` check at the call sites then bails cleanly.
#[allow(dead_code)]
async fn exchange_ember_hello<R, W>(
    reader: &mut R,
    writer: &mut W,
    our_ember_hash: &[u8; 16],
    our_nickname: &str,
    our_pubkey: Option<&[u8; 32]>,
    hello_caps: &mut PeerCapabilities,
    addr: SocketAddr,
) -> std::io::Result<()>
where
    R: AsyncReadExt + Unpin + ?Sized,
    W: AsyncWriteExt + Unpin + ?Sized,
{
    let payload = build_ember_hello(our_ember_hash, our_nickname, our_pubkey);
    write_packet(writer, OP_EMULEPROT, OP_EMBER_HELLO, &payload).await?;

    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(EMBER_HELLO_TIMEOUT_SECS);
    for _ in 0..EMBER_HELLO_MAX_LOOKAHEAD {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, read_packet_inner(reader)).await {
            Ok(Ok((proto, opcode, packet_payload))) => {
                if proto == OP_EMULEPROT
                    && (opcode == OP_EMBER_HELLO || opcode == OP_EMBER_HELLOANSWER)
                {
                    if let Some(ident) = parse_ember_hello(&packet_payload) {
                        hello_caps.is_ember = true;
                        if !ident.mod_version.is_empty() {
                            hello_caps.mod_version = ident.mod_version;
                        }
                        if !ident.nickname.is_empty() {
                            hello_caps.peer_name = ident.nickname;
                        }
                        if ident.ember_hash != [0u8; 16] {
                            hello_caps.ember_hash = Some(ident.ember_hash);
                        }
                        if let Some(pk) = ident.ed25519_pubkey {
                            hello_caps.ember_pubkey = Some(pk);
                        }
                        if opcode == OP_EMBER_HELLO {
                            let answer =
                                build_ember_hello(our_ember_hash, our_nickname, our_pubkey);
                            let _ =
                                write_packet(writer, OP_EMULEPROT, OP_EMBER_HELLOANSWER, &answer)
                                    .await;
                        }
                    }
                    return Ok(());
                }
                debug!(
                    "friend_connect {addr}: skipping proto=0x{proto:02X} op=0x{opcode:02X} while waiting for OP_EMBER_HELLO"
                );
            }
            // Timeout or read error → peer is vanilla eMule, an older
            // Ember release, or the connection died. Either way the
            // caller will surface the actual failure mode (auth skipped
            // or `is_ember` bail).
            _ => return Ok(()),
        }
    }
    Ok(())
}

/// Maximum unrelated packets we'll skip while looking for a
/// specific Ember auth opcode. Bounded to prevent a chatty peer
/// from pinning us in this loop forever; in practice we expect
/// 0–1 skips (just OP_SECIDENTSTATE).
const AUTH_PACKET_MAX_SKIPS: usize = 3;
/// Per-attempt timeout while waiting for the next packet during
/// auth. L7: tightened from 10 s × 8 skips (~80 s worst case) to
/// 5 s × 3 skips (~15 s worst case). The previous 80 s window let
/// a chatty peer pin our auth path for over a minute by spraying
/// unrelated frames, which made friend-connect look hung. In
/// practice the only legitimate skip is a single OP_SECIDENTSTATE
/// emitted by the upload side as part of its initial burst, so
/// 3 skips is plenty of headroom while still bounding the total
/// stall a misbehaving peer can inflict.
const AUTH_PACKET_TIMEOUT_SECS: u64 = 5;

/// Read the next packet matching `expected_opcode` (with
/// `expected_payload_len`), skipping a bounded number of unrelated
/// packets first.
///
/// `on_deferred` is invoked for each intervening non-AUTH packet so
/// callers that care about those packets (e.g. the multi-source
/// download loop, which must process `OP_SECIDENTSTATE` to keep
/// SecIdent credit accounting correct) can capture them for later
/// replay. Pass a no-op callback (`|_, _, _| {}`) to restore the
/// original drop-on-the-floor behaviour used by friend-connect,
/// which doesn't process SecIdent itself.
///
/// Returns the matched packet's payload. Errors if we hit the
/// per-packet read timeout, hit `AUTH_PACKET_MAX_SKIPS` non-matching
/// packets, or read a stream error.
async fn read_specific_auth_packet<R, D>(
    reader: &mut R,
    expected_opcode: u8,
    expected_payload_len: usize,
    addr: SocketAddr,
    label: &'static str,
    mut on_deferred: D,
) -> anyhow::Result<Vec<u8>>
where
    R: AsyncReadExt + Unpin + ?Sized,
    D: FnMut(u8, u8, Vec<u8>),
{
    for _ in 0..=AUTH_PACKET_MAX_SKIPS {
        let (proto, opcode, payload) = read_packet_with_timeout(reader, AUTH_PACKET_TIMEOUT_SECS)
            .await
            .map_err(|e| anyhow::anyhow!("Ember auth: failed to read {label} from {addr}: {e}"))?;
        if proto == OP_EMULEPROT && opcode == expected_opcode {
            if payload.len() != expected_payload_len {
                anyhow::bail!(
                    "Ember auth: {label} from {addr} has wrong payload length: got {}, expected {}",
                    payload.len(),
                    expected_payload_len,
                );
            }
            return Ok(payload);
        }
        debug!(
            "Ember auth: deferring intervening proto=0x{proto:02X} op=0x{opcode:02X} from {addr} while awaiting {label}"
        );
        on_deferred(proto, opcode, payload);
    }
    anyhow::bail!(
        "Ember auth: never received {label} from {addr} after {AUTH_PACKET_MAX_SKIPS} unrelated packets"
    );
}

async fn read_packet_with_timeout<R: AsyncReadExt + Unpin + ?Sized>(
    reader: &mut R,
    timeout_secs: u64,
) -> std::io::Result<(u8, u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(timeout_secs),
        read_packet_inner(reader),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timed out"))?
}

/// Perform the Ember Ed25519 challenge-response authentication exchange.
///
/// Both sides send a 32-byte random nonce as `OP_EMBER_AUTH_CHALLENGE`, then
/// sign the received nonce with their Ed25519 key and send the signature as
/// `OP_EMBER_AUTH_RESPONSE` (32-byte pubkey + 64-byte signature).
///
/// Ember authentication for callers that must preserve intervening
/// non-AUTH packets while waiting for the challenge and response.
///
/// Any packet read off the stream while waiting for `OP_EMBER_AUTH_CHALLENGE` /
/// `OP_EMBER_AUTH_RESPONSE` is appended to `deferred_packets` so the
/// caller can re-dispatch it through its main loop. This is what
/// unblocks the multi-source download path: the uploader sends
/// `OP_SECIDENTSTATE` (and sometimes EPX) in the same packet burst as
/// its OP_EMBER_HELLO, and dropping those frames would break
/// SecIdent credit accounting and silently lose source-exchange
/// data for every Ember-to-Ember download.
///
/// On success (or cryptographic failure), `deferred_packets` holds the
/// full sequence of non-AUTH frames observed during the auth round
/// trip, in arrival order. On a timeout / read error the partial
/// buffer is preserved so the caller can still drain it.
pub(crate) async fn perform_ember_auth_buffered<R, W>(
    reader: &mut R,
    writer: &mut W,
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    peer_pubkey: &[u8; 32],
    peer_ember_hash: Option<&[u8; 16]>,
    addr: SocketAddr,
    deferred_packets: &mut std::collections::VecDeque<(u8, u8, Vec<u8>)>,
) -> anyhow::Result<()>
where
    R: AsyncReadExt + Unpin + ?Sized,
    W: AsyncWriteExt + Unpin + ?Sized,
{
    // Same pubkey ↔ ember_hash check as the non-buffered path.
    if let Some(expected_hash) = peer_ember_hash {
        let peer_vk = VerifyingKey::from_bytes(peer_pubkey)
            .map_err(|e| anyhow::anyhow!("invalid peer Ed25519 pubkey: {e}"))?;
        let derived_hash = crypto::node_id_from_public_key(&peer_vk);
        if derived_hash != *expected_hash {
            anyhow::bail!(
                "Ember auth: peer pubkey does not match ember_hash (derived={}, advertised={})",
                hex::encode(derived_hash),
                hex::encode(expected_hash)
            );
        }
    }

    let mut our_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut our_nonce);
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_CHALLENGE, &our_nonce).await?;

    let peer_nonce_payload = read_specific_auth_packet(
        reader,
        OP_EMBER_AUTH_CHALLENGE,
        32,
        addr,
        "AUTH_CHALLENGE",
        |p, o, pl| deferred_packets.push_back((p, o, pl)),
    )
    .await?;

    let signing_key = SigningKey::from_bytes(our_secret_key);
    let signature = sign_auth_nonce(&signing_key, &peer_nonce_payload);
    let mut response = Vec::with_capacity(96);
    response.extend_from_slice(our_pubkey);
    response.extend_from_slice(&signature.to_bytes());
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE, &response).await?;

    let peer_response = read_specific_auth_packet(
        reader,
        OP_EMBER_AUTH_RESPONSE,
        96,
        addr,
        "AUTH_RESPONSE",
        |p, o, pl| deferred_packets.push_back((p, o, pl)),
    )
    .await?;

    let resp_pubkey: [u8; 32] = peer_response[..32].try_into().unwrap();
    if resp_pubkey != *peer_pubkey {
        anyhow::bail!("Ember auth: response pubkey doesn't match advertised pubkey from {addr}");
    }

    let peer_vk = VerifyingKey::from_bytes(peer_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid peer Ed25519 pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = peer_response[32..96].try_into().unwrap();
    let peer_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    if !verify_auth_nonce(&peer_vk, &our_nonce, &peer_sig) {
        anyhow::bail!("Ember auth: signature verification failed for {addr}");
    }

    info!(
        "Ember auth (buffered): verified peer {} at {} ({} deferred packet(s) captured)",
        hex::encode(&peer_pubkey[..8]),
        addr,
        deferred_packets.len(),
    );
    Ok(())
}
