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

/// Result from a successfully established friend session.
pub struct FriendSessionHandle {
    pub session_id: u64,
}

/// Bounds on the withdrawal courier. Shorter than a friend dial's 15s: nothing
/// waits on the result, an unreachable peer is retried on the next sweep, and
/// these attempts run in bursts when several requests are cancelled at once.
const RETRACTION_DIAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);
const RETRACTION_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

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

/// Tell `expected_ember_hash` that a friend request we sent is withdrawn, over
/// a connection that exists for nothing else.
///
/// Deliberately not a friend session. By the time this runs the peer has been
/// removed, so [`open_and_run_friend_session`] would refuse the dial on the
/// membership guard below — and loosening that guard to let a withdrawal
/// through would open the friend-session path to non-friends for the sake of a
/// single packet. Instead this completes the same Noise IK handshake, writes one
/// packet and hangs up: no `ember_sessions` entry, no read loop, no keepalive,
/// so the peer is granted nothing by having answered.
///
/// The handshake is still what makes it safe in the other direction: the
/// recipient only acts on a withdrawal whose sender proved possession of the
/// identity that sent the request.
///
/// The eD2K greeting is not optional padding. A listener drops the connection
/// outright if the first inner frame is anything other than `OP_HELLO`, so the
/// withdrawal has to follow the same greeting every other dial sends — and the
/// `OP_HELLOANSWER` is read before writing it, because that answer is the proof
/// the peer accepted the greeting and is now dispatching frames.
#[allow(clippy::too_many_arguments)]
pub async fn send_friend_request_retraction(
    addr: SocketAddr,
    expected_ember_hash: [u8; 16],
    our_user_hash: [u8; 16],
    our_ember_hash: [u8; 16],
    our_nickname: String,
    our_client_id: u32,
    tcp_port: u16,
    udp_port: u16,
    obfuscate: bool,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
) -> anyhow::Result<()> {
    let our_pk =
        ed25519_pubkey.ok_or_else(|| anyhow::anyhow!(secure_stream::UPGRADE_REQUIRED_ERROR))?;
    let our_sk =
        ed25519_secret_key.ok_or_else(|| anyhow::anyhow!(secure_stream::UPGRADE_REQUIRED_ERROR))?;

    let stream = tokio::time::timeout(RETRACTION_DIAL_TIMEOUT, TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timeout"))??;
    super::multi_source::tune_peer_stream(&stream);
    let (raw_r, raw_w) = stream.into_split();

    // `initiate` refuses any peer whose authenticated static key does not match
    // `expected_ember_hash`, so a stale address cannot make us announce a
    // withdrawal to whoever happens to answer on it now.
    let secure = tokio::time::timeout(
        RETRACTION_HANDSHAKE_TIMEOUT,
        secure_stream::initiate(
            Box::new(raw_r),
            Box::new(raw_w),
            our_ember_hash,
            expected_ember_hash,
            our_pk,
            our_sk,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("secure handshake timeout"))??;

    let mut reader = tokio::io::BufReader::new(secure.reader);
    let mut writer = tokio::io::BufWriter::new(secure.writer);

    let hello_options = HelloOptions {
        udp_port,
        kad_port: udp_port,
        supports_crypt_layer: obfuscate,
        requests_crypt_layer: obfuscate,
        requires_crypt_layer: false,
        supports_direct_udp_callback:
            crate::network::kad::firewall::advertised_direct_udp_callback(),
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
    write_packet(&mut writer, OP_EDONKEYHEADER, OP_HELLO, &hello_payload)
        .await
        .context("failed to greet the peer we are withdrawing from")?;

    let (proto, opcode, _) = read_packet_with_timeout(&mut reader, 10)
        .await
        .context("waiting for HelloAnswer before withdrawing")?;
    if proto != OP_EDONKEYHEADER || opcode != OP_HELLOANSWER {
        anyhow::bail!("expected HelloAnswer, got proto=0x{proto:02X} op=0x{opcode:02X}");
    }

    let emule_payload = build_emule_info(udp_port, false, Some(&our_ember_hash), None);
    write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload)
        .await
        .context("failed to complete the eMule greeting")?;

    write_packet(
        &mut writer,
        OP_EMULEPROT,
        OP_EMBER_EXT,
        &build_ember_ext(EMBER_EXT_FRIEND_RETRACT, &[]),
    )
    .await
    .context("failed to send friend-request withdrawal")?;

    // Leave no half-open socket behind: this connection has said everything it
    // was opened to say.
    let _ = writer.shutdown().await;
    info!(
        "Withdrew friend request at {} ({})",
        addr,
        crate::security::short_hash(&expected_ember_hash)
    );
    Ok(())
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
        supports_direct_udp_callback: crate::network::kad::firewall::advertised_direct_udp_callback(),
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
            crate::security::short_hash(&peer_ember_hash)
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
                    crate::security::short_hash(&peer_ember_hash)
                );
                // Explicitly shut down any half-open work on this dial's
                // transport by dropping reader/writer at return.
                drop(reader);
                drop(writer);
                return Ok(FriendSessionHandle {
                    session_id: existing.session_id(),
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
                    crate::security::short_hash(&peer_ember_hash)
                );
                let reused = FriendSessionHandle {
                    session_id: existing.session_id(),
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
                    crate::security::short_hash(&peer_ember_hash)
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

    info!("Friend session handshake with {} complete (hash={}, binding_verified={ember_hash_binding_verified})", addr, crate::security::short_hash(&peer_ember_hash));

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
    // The dedicated friend-connect path never went through upload.rs, so a
    // relayed or NAT-traversed session never emitted EmberPeerDiscovered.
    // Without that, a live Ember friend never became a DHT introduction
    // (`session_peers=0` while they were chatting). Same guards as the
    // inbound upload path.
    if !peer_v4.is_unspecified()
        && listen_port > 0
        && !crate::security::is_bogus_v4(peer_v4)
    {
        let _ = ul_event_tx
            .send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::EmberPeerDiscovered {
                    ip: peer_v4,
                    tcp_port: listen_port,
                    udp_port: hello_caps.udp_port,
                },
            })
            .await;
    }

    let handle = FriendSessionHandle {
        session_id: ember_session_handle.session_id(),
    };

    let session_ember_sessions = ember_sessions.clone();
    let session_ember_session_handle = ember_session_handle.clone();
    let session_ul_event_tx = ul_event_tx.clone();
    let session_friend_hashes = friend_hashes.clone();
    let session_listen_port = listen_port;
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
                            crate::security::short_hash(&peer_ember_hash)
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
                                    crate::security::short_hash(&peer_ember_hash)
                                );
                                break;
                            }
                            match (proto, opcode) {
                                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) => {
                                    if payload.len() > MAX_CHAT_WIRE_LEN {
                                        warn!(
                                            "Friend {} chat payload oversized ({} bytes); dropping without decrypt",
                                            crate::security::short_hash(&peer_ember_hash),
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
                                            crate::security::short_hash(&peer_ember_hash),
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
                                    let nick =
                                        crate::security::normalize_inbound_friend_nickname(&payload);
                                    // Always true on this path, and a real
                                    // proof of possession rather than the
                                    // replayable binding check: the session
                                    // exists only because `secure_stream::
                                    // initiate` authenticated the responder's
                                    // Noise IK static key against the key
                                    // bound to `expected_ember_hash`. The
                                    // recipient promotes an already-added
                                    // friend to mutual on this flag, so it
                                    // must not weaken to binding-only.
                                    debug!(
                                        "Received friend request on outbound friend session from {} (nickname_chars={}, verified={ember_hash_binding_verified})",
                                        addr,
                                        nick.chars().count()
                                    );
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberFriendRequest {
                                            ember_hash: peer_ember_hash,
                                            pubkey: Some(peer_pk),
                                            nickname: nick,
                                            peer_ip: addr.ip().to_string(),
                                            peer_port: session_listen_port,
                                            verified: ember_hash_binding_verified,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_XFER_REQ) => {
                                    if let Some(request) = parse_ember_xfer_req(&payload) {
                                        let _ = session_ul_event_tx.send(UploadEvent {
                                            transfer_id: String::new(),
                                            kind: UploadEventKind::EmberTransferRequest {
                                                ember_hash: peer_ember_hash,
                                                request,
                                                reply_tx: session_ember_session_handle.tx.clone(),
                                                peer_addr: addr,
                                            },
                                        }).await;
                                    } else {
                                        debug!(
                                            "Friend {} sent an unparseable OP_EMBER_XFER_REQ ({} bytes)",
                                            crate::security::short_hash(&peer_ember_hash),
                                            payload.len()
                                        );
                                    }
                                }
                                (OP_EMULEPROT, OP_EMBER_XFER_ACK) => {
                                    if let Some((status, nonce)) = parse_ember_xfer_ack(&payload) {
                                        let _ = session_ul_event_tx.send(UploadEvent {
                                            transfer_id: String::new(),
                                            kind: UploadEventKind::EmberTransferAck {
                                                ember_hash: peer_ember_hash,
                                                status,
                                                nonce,
                                            },
                                        }).await;
                                    }
                                }
                                (OP_EMULEPROT, super::messages::OP_EMBER_FILE_OFFER) => {
                                    if let Some(offer) =
                                        super::messages::parse_ember_file_offer(&payload)
                                    {
                                        let _ = session_ul_event_tx.send(UploadEvent {
                                            transfer_id: String::new(),
                                            kind: UploadEventKind::EmberFileOffer {
                                                ember_hash: peer_ember_hash,
                                                offer,
                                                reply_tx: session_ember_session_handle.tx.clone(),
                                            },
                                        }).await;
                                    } else {
                                        debug!(
                                            "Friend {} sent an unparseable OP_EMBER_FILE_OFFER ({} bytes)",
                                            crate::security::short_hash(&peer_ember_hash),
                                            payload.len()
                                        );
                                    }
                                }
                                (OP_EMULEPROT, super::messages::OP_EMBER_FILE_OFFER_ACK) => {
                                    if let Some((status, file_hash)) =
                                        super::messages::parse_ember_file_offer_ack(&payload)
                                    {
                                        let _ = session_ul_event_tx.send(UploadEvent {
                                            transfer_id: String::new(),
                                            kind: UploadEventKind::EmberFileOfferAck {
                                                ember_hash: peer_ember_hash,
                                                status,
                                                file_hash,
                                            },
                                        }).await;
                                    }
                                }
                                // Mirrors the arm in `upload.rs`. Without it this
                                // loop dropped relay offers into the catch-all
                                // below, and since there is one session per pair
                                // keyed by Ember hash, whichever side dialled
                                // never learned the other's relays. Attestations
                                // then flowed one way only — in exactly the
                                // isolated-pair case the gossip exists to serve.
                                (OP_EMULEPROT, super::messages::OP_EMBER_EXT) => {
                                    match super::messages::parse_ember_ext(&payload) {
                                        Some((super::messages::EMBER_EXT_RELAY_OFFER, body)) => {
                                            // Parsed here, verified in the network
                                            // loop that owns the broker: a
                                            // forwarded attestation is only bytes
                                            // until its own signature checks out.
                                            let attestations =
                                                crate::network::ember::parse_relay_attestation_block(body);
                                            if !attestations.is_empty() {
                                                let _ = session_ul_event_tx.send(UploadEvent {
                                                    transfer_id: String::new(),
                                                    kind: UploadEventKind::EmberRelayOffer {
                                                        ember_hash: peer_ember_hash,
                                                        attestations,
                                                    },
                                                }).await;
                                            }
                                        }
                                        Some((super::messages::EMBER_EXT_FRIEND_RETRACT, _)) => {
                                            // They are taking back a request we
                                            // have not answered. The session
                                            // itself is the proof of possession
                                            // this needs, and the handler only
                                            // ever clears a queued request.
                                            debug!(
                                                "Friend {} withdrew its friend request",
                                                crate::security::short_hash(&peer_ember_hash)
                                            );
                                            let _ = session_ul_event_tx.send(UploadEvent {
                                                transfer_id: String::new(),
                                                kind: UploadEventKind::EmberFriendRetract {
                                                    ember_hash: peer_ember_hash,
                                                },
                                            }).await;
                                        }
                                        // A sub-type this build predates. Ignoring
                                        // it is the whole point of the envelope.
                                        Some((other, _)) => debug!(
                                            "Friend {} sent unknown OP_EMBER_EXT sub-type {other:#04x}",
                                            crate::security::short_hash(&peer_ember_hash)
                                        ),
                                        None => debug!(
                                            "Friend {} sent an empty OP_EMBER_EXT payload",
                                            crate::security::short_hash(&peer_ember_hash)
                                        ),
                                    }
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
                        info!("Friend {} removed, terminating outbound session", crate::security::short_hash(&peer_ember_hash));
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
                            crate::security::short_hash(&peer_ember_hash),
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
                    crate::security::short_hash(&peer_ember_hash)
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
            crate::security::short_hash(&peer_ember_hash)
        );
    });

    Ok(handle)
}

/// Number of signed punch polls after registering, and the delay between them.
/// A friend's own offline-retry loop fires independently of ours (there is no
/// request/response coupling before this point — see [`punch_friend_until`]),
/// so this window exists purely to catch two independently-scheduled retries
/// landing close together. The rendezvous server only retains a punch
/// registration for 30 s (`rendezvous-server/src/main.rs::PUNCH_TTL`), so
/// polling much past that would just poll a registration that already expired.
const FRIEND_PUNCH_POLL_ATTEMPTS: usize = 12;
const FRIEND_PUNCH_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// Exclusive punch time before the relay is *dialed*. The relay task is
/// spawned at fallback t=0 so this sleep overlaps punch-registration HTTP;
/// three 2 s poll intervals is long enough that a friend who is *also* in
/// this function (the only case a punch can succeed) usually appears, and
/// short enough that the high-probability relay is not starved.
const FRIEND_PUNCH_RELAY_RACE_AFTER: std::time::Duration = std::time::Duration::from_secs(6);
/// Combined punch+relay budget after TCP fails. Covers the 6 s exclusive punch
/// window, the 45 s friend-relay ticket wait, and a few seconds of offer/WS
/// connect, and replaces the previous unbounded 12×(2 s sleep + 10 s HTTP)
/// punch ceiling (~154 s).
const FRIEND_FALLBACK_PHASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Cap on one reciprocal-punch completion (identity lookup + QUIC dial + ack)
/// so a hung QUIC idle timeout cannot starve a ready relay.
const FRIEND_PUNCH_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Reach a friend who isn't directly dialable by trying a plain TCP dial
/// to `addr` first (the previous, sole behaviour). If that fails, an Ember
/// QUIC hole-punch and a rendezvous WebSocket relay hop are raced: the
/// relay's [`FRIEND_PUNCH_RELAY_RACE_AFTER`] delay starts at fallback t=0
/// (overlapping punch-registration HTTPS) and the first transport to
/// produce a live hop is handed to a single handshake. Returns as soon as
/// that handshake produces an authenticated Ember session.
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
    let (our_nat_type, our_external_addr, quic_endpoint, our_quic_public_port) = {
        let ctx = nat_ctx.read().unwrap_or_else(|p| p.into_inner());
        (
            ctx.nat_type,
            ctx.external_addr,
            ctx.quic_endpoint.clone(),
            ctx.quic_public_port,
        )
    };

    let fallback_deadline = tokio::time::Instant::now() + FRIEND_FALLBACK_PHASE_TIMEOUT;
    let punch_eligible = quic_endpoint.is_some()
        && our_external_addr.is_some()
        && ed25519_secret_key.is_some()
        && our_nat_type != crate::network::ember::nat::NatType::Symmetric;

    match nat_fallback_transport(
        &rendezvous_url,
        quic_endpoint,
        our_quic_public_port,
        our_ember_hash,
        expected_ember_hash,
        our_external_addr,
        our_nat_type,
        punch_eligible,
        ed25519_pubkey,
        ed25519_secret_key,
        friend_hashes.clone(),
        fallback_deadline,
    )
    .await
    {
        Ok(FallbackTransport::Punch(send, recv)) => {
            info!(
                "Friend hole-punch to {} succeeded",
                hex::encode(expected_ember_hash)
            );
            run_friend_session_over_transport(
                Box::new(recv),
                Box::new(send),
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
        Ok(FallbackTransport::Relay(ws_stream)) => {
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
                "Friend NAT fallback to {} failed: {e}",
                hex::encode(expected_ember_hash)
            );
            Err(anyhow::anyhow!(
                "all connection methods failed for friend {}: tcp={tcp_err}; fallback={e}",
                hex::encode(expected_ember_hash)
            ))
        }
    }
}

/// One per friend connection that had to fall back, chosen at setup and then
/// held for the session. Boxing the larger arm to even the variants out would
/// buy nothing: the value is moved once and read through thereafter.
#[allow(clippy::large_enum_variant)]
enum FallbackTransport {
    Punch(quinn::SendStream, quinn::RecvStream),
    Relay(crate::network::ember::relay::WsStream),
}

struct AbortOnDropTask<T>(Option<tokio::task::JoinHandle<T>>);

impl<T> AbortOnDropTask<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self(Some(handle))
    }

    fn as_mut(&mut self) -> Option<&mut tokio::task::JoinHandle<T>> {
        self.0.as_mut()
    }

    fn take(&mut self) -> Option<tokio::task::JoinHandle<T>> {
        self.0.take()
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

async fn ack_observed_punch(
    rendezvous_url: &str,
    our_ember_hash: &[u8; 16],
    info: &crate::network::ember::relay::PunchInfo,
    secret_key: &[u8; 32],
) {
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        crate::network::ember::relay::ack_punch(
            rendezvous_url,
            our_ember_hash,
            &info.punch_id,
            &info.capability,
            info.epoch,
            secret_key,
        ),
    )
    .await;
}

fn relay_arm_delay(punch_will_be_attempted: bool) -> std::time::Duration {
    if punch_will_be_attempted {
        FRIEND_PUNCH_RELAY_RACE_AFTER
    } else {
        std::time::Duration::ZERO
    }
}

fn punch_attempt_deadline(
    now: tokio::time::Instant,
    phase_deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    phase_deadline.min(now + FRIEND_PUNCH_ATTEMPT_TIMEOUT)
}

fn join_task_error<T>(result: Result<Result<T, String>, tokio::task::JoinError>) -> String {
    match result {
        Ok(Err(error)) => error,
        Ok(Ok(_)) => "task returned success after being treated as failure".to_string(),
        Err(error) if error.is_panic() => "task panicked".to_string(),
        Err(error) if error.is_cancelled() => "task cancelled".to_string(),
        Err(error) => format!("task failed: {error}"),
    }
}

fn combine_transport_errors(punch: Option<String>, relay: Option<String>) -> String {
    match (punch, relay) {
        (Some(punch), Some(relay)) => format!("punch={punch}; relay={relay}"),
        (Some(punch), None) => format!("punch={punch}"),
        (None, Some(relay)) => format!("relay={relay}"),
        (None, None) => "NAT fallback failed".to_string(),
    }
}

enum FallbackRace<P, R> {
    Punch {
        value: P,
        leftover_relay: Option<R>,
    },
    Relay {
        value: R,
    },
    Failed(String),
    Timeout {
        leftover_relay: Option<R>,
    },
}

enum FirstFinished<P, R> {
    Punch(Result<Result<P, String>, tokio::task::JoinError>),
    Relay(Result<Result<R, String>, tokio::task::JoinError>),
    Timeout,
}

enum OtherWait {
    Missing,
    Timeout,
}

async fn abort_and_reap<T>(guard: Option<AbortOnDropTask<Result<T, String>>>) -> Option<T> {
    let mut guard = guard?;
    let handle = guard.take()?;
    handle.abort();
    match handle.await {
        Ok(Ok(value)) => Some(value),
        _ => None,
    }
}

async fn await_other_until<T>(
    guard: Option<AbortOnDropTask<Result<T, String>>>,
    deadline: tokio::time::Instant,
) -> Result<Result<T, String>, OtherWait> {
    let Some(mut guard) = guard else {
        return Err(OtherWait::Missing);
    };
    let Some(mut handle) = guard.take() else {
        return Err(OtherWait::Missing);
    };
    let abort = handle.abort_handle();
    match tokio::time::timeout_at(deadline, &mut handle).await {
        Ok(Ok(Ok(value))) => Ok(Ok(value)),
        Ok(Ok(Err(error))) => Ok(Err(error)),
        Ok(Err(join)) => Ok(Err(join_task_error::<T>(Err(join)))),
        Err(_) => {
            abort.abort();
            match handle.await {
                Ok(Ok(value)) => Ok(Ok(value)),
                _ => Err(OtherWait::Timeout),
            }
        }
    }
}

fn spawn_relay_then_punch<P, R>(
    punch: impl std::future::Future<Output = Result<P, String>> + Send + 'static,
    relay: impl std::future::Future<Output = Result<R, String>> + Send + 'static,
) -> (
    tokio::task::JoinHandle<Result<P, String>>,
    tokio::task::JoinHandle<Result<R, String>>,
)
where
    P: Send + 'static,
    R: Send + 'static,
{
    // Relay first so its delay starts at t=0 and overlaps punch registration
    // HTTP. `punch` must own that registration; awaiting it before this spawn
    // is the ordering bug this helper exists to prevent.
    let relay = tokio::spawn(relay);
    let punch = tokio::spawn(punch);
    (punch, relay)
}

async fn drive_fallback_race<P, R>(
    punch: Option<tokio::task::JoinHandle<Result<P, String>>>,
    relay: Option<tokio::task::JoinHandle<Result<R, String>>>,
    deadline: tokio::time::Instant,
) -> FallbackRace<P, R> {
    let mut punch_guard = punch.map(AbortOnDropTask::new);
    let mut relay_guard = relay.map(AbortOnDropTask::new);

    let first = tokio::select! {
        biased;
        result = async {
            punch_guard
                .as_mut()
                .expect("punch branch is gated on is_some")
                .as_mut()
                .expect("punch handle")
                .await
        }, if punch_guard.is_some() => {
            let _ = punch_guard.take();
            FirstFinished::Punch(result)
        }
        result = async {
            relay_guard
                .as_mut()
                .expect("relay branch is gated on is_some")
                .as_mut()
                .expect("relay handle")
                .await
        }, if relay_guard.is_some() => {
            let _ = relay_guard.take();
            FirstFinished::Relay(result)
        }
        _ = tokio::time::sleep_until(deadline) => FirstFinished::Timeout,
    };

    match first {
        FirstFinished::Punch(Ok(Ok(value))) => FallbackRace::Punch {
            value,
            leftover_relay: abort_and_reap(relay_guard.take()).await,
        },
        FirstFinished::Punch(fail) => {
            let punch_err = join_task_error(fail);
            match await_other_until(relay_guard.take(), deadline).await {
                Ok(Ok(value)) => FallbackRace::Relay { value },
                Ok(Err(relay_err)) => FallbackRace::Failed(combine_transport_errors(
                    Some(punch_err),
                    Some(relay_err),
                )),
                Err(OtherWait::Timeout) => FallbackRace::Failed(combine_transport_errors(
                    Some(punch_err),
                    Some("timed out".to_string()),
                )),
                Err(OtherWait::Missing) => {
                    FallbackRace::Failed(combine_transport_errors(Some(punch_err), None))
                }
            }
        }
        FirstFinished::Relay(Ok(Ok(value))) => {
            let _ = abort_and_reap(punch_guard.take()).await;
            FallbackRace::Relay { value }
        }
        FirstFinished::Relay(fail) => {
            let relay_err = join_task_error(fail);
            match await_other_until(punch_guard.take(), deadline).await {
                Ok(Ok(value)) => FallbackRace::Punch {
                    value,
                    leftover_relay: None,
                },
                Ok(Err(punch_err)) => FallbackRace::Failed(combine_transport_errors(
                    Some(punch_err),
                    Some(relay_err),
                )),
                Err(OtherWait::Timeout) => FallbackRace::Failed(combine_transport_errors(
                    Some("timed out".to_string()),
                    Some(relay_err),
                )),
                Err(OtherWait::Missing) => {
                    FallbackRace::Failed(combine_transport_errors(None, Some(relay_err)))
                }
            }
        }
        FirstFinished::Timeout => {
            let _ = abort_and_reap(punch_guard.take()).await;
            FallbackRace::Timeout {
                leftover_relay: abort_and_reap(relay_guard.take()).await,
            }
        }
    }
}

async fn abandon_offered_ticket(slot: &Arc<std::sync::Mutex<Option<String>>>) {
    let ticket_id = slot.lock().ok().and_then(|mut guard| guard.take());
    if let Some(ticket_id) = ticket_id {
        crate::network::ember::relay::abandon_offered_friend_relay_ticket(&ticket_id).await;
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
///
/// The relay task is spawned at fallback t=0, before punch registration
/// HTTPS is awaited, so its [`FRIEND_PUNCH_RELAY_RACE_AFTER`] sleep overlaps
/// those round-trips. The first transport that yields streams wins; the
/// loser is aborted. Handshake/session registration happens only on the
/// winner, so `ember_sessions` cannot gain two slots from this race. There is
/// no rendezvous withdraw route: our punch registration expires with the
/// server's 30 s `PUNCH_TTL`, and a later dial's register replaces the
/// `(target, from)` entry. An offered-but-unjoined relay ticket has no
/// cancel route either and lives until the server's 90 s `RELAY_TICKET_TTL`.
#[allow(clippy::too_many_arguments)]
async fn nat_fallback_transport(
    rendezvous_url: &str,
    quic_endpoint: Option<Arc<quinn::Endpoint>>,
    our_quic_public_port: Option<u16>,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    our_external_addr: Option<SocketAddr>,
    our_nat_type: crate::network::ember::nat::NatType,
    punch_eligible: bool,
    ed25519_pubkey: Option<[u8; 32]>,
    ed25519_secret_key: Option<[u8; 32]>,
    friend_hashes: Arc<RwLock<std::collections::HashSet<[u8; 16]>>>,
    deadline: tokio::time::Instant,
) -> Result<FallbackTransport, String> {
    let punch_will_attempt = punch_eligible
        && quic_endpoint.is_some()
        && our_external_addr.is_some()
        && ed25519_secret_key.is_some();
    let is_friend = friend_hashes.read().await.contains(&friend_ember_hash);
    let can_relay = is_friend && ed25519_secret_key.is_some() && ed25519_pubkey.is_some();
    if !punch_will_attempt && !can_relay {
        if !is_friend {
            return Err("server relay is restricted to known friends".to_string());
        }
        if ed25519_secret_key.is_none() {
            return Err("server relay requires the local registered identity key".to_string());
        }
        return Err("server relay requires local v2 identity".to_string());
    }

    let (skip_tx, skip_rx) = tokio::sync::watch::channel(false);
    let offered_ticket = Arc::new(std::sync::Mutex::new(None::<String>));

    let (punch_handle, relay_handle) = match (punch_will_attempt, can_relay) {
        (true, true) => {
            let endpoint = quic_endpoint.clone().expect("punch_will_attempt");
            let ext_addr = our_external_addr.expect("punch_will_attempt");
            let secret = ed25519_secret_key.expect("punch_will_attempt");
            let pubkey = ed25519_pubkey.expect("can_relay");
            let offered = offered_ticket.clone();
            let (punch, relay) = spawn_relay_then_punch(
                punch_from_register(
                    rendezvous_url.to_string(),
                    endpoint,
                    our_quic_public_port,
                    our_ember_hash,
                    friend_ember_hash,
                    ext_addr,
                    our_nat_type,
                    secret,
                    deadline,
                    skip_tx,
                ),
                delayed_relay_friend(
                    rendezvous_url.to_string(),
                    relay_arm_delay(true),
                    skip_rx,
                    deadline,
                    our_ember_hash,
                    friend_ember_hash,
                    pubkey,
                    secret,
                    offered,
                ),
            );
            (Some(punch), Some(relay))
        }
        (true, false) => {
            drop(skip_rx);
            let endpoint = quic_endpoint.clone().expect("punch_will_attempt");
            let ext_addr = our_external_addr.expect("punch_will_attempt");
            let secret = ed25519_secret_key.expect("punch_will_attempt");
            (
                Some(tokio::spawn(punch_from_register(
                    rendezvous_url.to_string(),
                    endpoint,
                    our_quic_public_port,
                    our_ember_hash,
                    friend_ember_hash,
                    ext_addr,
                    our_nat_type,
                    secret,
                    deadline,
                    skip_tx,
                ))),
                None,
            )
        }
        (false, true) => {
            drop(skip_tx);
            let secret = ed25519_secret_key.expect("can_relay");
            let pubkey = ed25519_pubkey.expect("can_relay");
            let offered = offered_ticket.clone();
            (
                None,
                Some(tokio::spawn(delayed_relay_friend(
                    rendezvous_url.to_string(),
                    relay_arm_delay(false),
                    skip_rx,
                    deadline,
                    our_ember_hash,
                    friend_ember_hash,
                    pubkey,
                    secret,
                    offered,
                ))),
            )
        }
        (false, false) => unreachable!("eligibility already returned"),
    };

    match drive_fallback_race(punch_handle, relay_handle, deadline).await {
        FallbackRace::Punch {
            value,
            leftover_relay,
        } => {
            if let Some(stream) = leftover_relay {
                crate::network::ember::relay::close_server_relay(stream).await;
            }
            abandon_offered_ticket(&offered_ticket).await;
            Ok(FallbackTransport::Punch(value.0, value.1))
        }
        FallbackRace::Relay { value } => Ok(FallbackTransport::Relay(value)),
        FallbackRace::Failed(error) => {
            abandon_offered_ticket(&offered_ticket).await;
            if !is_friend && punch_will_attempt && !can_relay {
                Err("server relay is restricted to known friends".to_string())
            } else {
                Err(error)
            }
        }
        FallbackRace::Timeout { leftover_relay } => {
            if let Some(stream) = leftover_relay {
                crate::network::ember::relay::close_server_relay(stream).await;
            }
            abandon_offered_ticket(&offered_ticket).await;
            Err("NAT fallback timed out".to_string())
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn punch_from_register(
    rendezvous_url: String,
    endpoint: Arc<quinn::Endpoint>,
    our_quic_public_port: Option<u16>,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    ext_addr: SocketAddr,
    our_nat_type: crate::network::ember::nat::NatType,
    secret_key: [u8; 32],
    deadline: tokio::time::Instant,
    skip_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    // Register a port on the QUIC endpoint's own socket, not
    // `our_external_addr.port()` — that address comes from the KAD UDP
    // STUN probe (a *different* socket than the QUIC endpoint the friend
    // will actually dial), so advertising it here would misdirect the
    // friend's `punch_quic` connect at a socket we're not listening on.
    //
    // Prefer that socket's own STUN reading: a NAT that re-maps ports (CGNAT)
    // gives it a public port unrelated to the bound one, and the friend dials
    // from outside the NAT. The bound port is the fallback, correct whenever
    // the NAT preserves ports or UPnP forwarded it.
    let advertise_port = our_quic_public_port
        .filter(|port| *port != 0)
        .or_else(|| endpoint.local_addr().map(|a| a.port()).ok())
        .unwrap_or_else(|| ext_addr.port());
    match tokio::time::timeout_at(
        deadline,
        crate::network::ember::relay::register_punch_with_ip(
            &rendezvous_url,
            &our_ember_hash,
            &friend_ember_hash,
            advertise_port,
            our_nat_type.as_u8(),
            ext_addr.ip(),
            &secret_key,
            &our_ember_hash,
        ),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            let _ = skip_tx.send(true);
            return Err(error);
        }
        Err(_) => {
            let _ = skip_tx.send(true);
            return Err("punch register timed out".to_string());
        }
    }
    punch_friend_until(
        &rendezvous_url,
        endpoint.as_ref(),
        our_ember_hash,
        friend_ember_hash,
        &secret_key,
        deadline,
    )
    .await
}

async fn wait_relay_arm(
    delay: std::time::Duration,
    mut skip_rx: tokio::sync::watch::Receiver<bool>,
    deadline: tokio::time::Instant,
) -> Result<(), String> {
    tokio::select! {
        _ = tokio::time::sleep(delay) => {}
        _ = async {
            loop {
                if *skip_rx.borrow() {
                    break;
                }
                if skip_rx.changed().await.is_err() {
                    // Sender dropped without skip=true: punch ended (success
                    // or abort). Do not treat that as "register failed"; wait
                    // out the remaining delay or the phase deadline instead.
                    std::future::pending::<()>().await;
                }
            }
        } => {}
        _ = tokio::time::sleep_until(deadline) => {
            return Err("NAT fallback timed out".to_string());
        }
    }
    if tokio::time::Instant::now() >= deadline {
        return Err("NAT fallback timed out".to_string());
    }
    Ok(())
}

async fn delayed_relay_friend(
    rendezvous_url: String,
    delay: std::time::Duration,
    skip_rx: tokio::sync::watch::Receiver<bool>,
    deadline: tokio::time::Instant,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    pubkey: [u8; 32],
    secret: [u8; 32],
    offered_ticket: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<crate::network::ember::relay::WsStream, String> {
    wait_relay_arm(delay, skip_rx, deadline).await?;
    relay_friend(
        &rendezvous_url,
        our_ember_hash,
        friend_ember_hash,
        &pubkey,
        &secret,
        deadline,
        offered_ticket,
    )
    .await
}

async fn punch_friend_until(
    rendezvous_url: &str,
    endpoint: &quinn::Endpoint,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    secret_key: &[u8; 32],
    deadline: tokio::time::Instant,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    for _ in 0..FRIEND_PUNCH_POLL_ATTEMPTS {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(FRIEND_PUNCH_POLL_INTERVAL) => {}
            _ = tokio::time::sleep_until(deadline) => break,
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        match tokio::time::timeout_at(
            deadline,
            crate::network::ember::relay::poll_punch(rendezvous_url, &our_ember_hash, secret_key),
        )
        .await
        {
            Ok(Ok(Some(info))) => {
                let info_for_timeout = info.clone();
                match tokio::time::timeout_at(
                    punch_attempt_deadline(tokio::time::Instant::now(), deadline),
                    try_complete_friend_punch(
                        rendezvous_url,
                        endpoint,
                        our_ember_hash,
                        friend_ember_hash,
                        secret_key,
                        info,
                    ),
                )
                .await
                {
                    Ok(Ok(streams)) => return Ok(streams),
                    Ok(Err(e)) => debug!("Friend hole-punch attempt failed: {e}"),
                    Err(_) => {
                        ack_observed_punch(
                            rendezvous_url,
                            &our_ember_hash,
                            &info_for_timeout,
                            secret_key,
                        )
                        .await;
                        debug!("Friend hole-punch attempt timed out");
                    }
                }
            }
            Ok(Ok(None)) => {}
            Ok(Err(e)) => debug!("Friend punch poll error: {e}"),
            Err(_) => break,
        }
    }
    Err("no reciprocal punch registration found before timeout".to_string())
}

async fn try_complete_friend_punch(
    rendezvous_url: &str,
    endpoint: &quinn::Endpoint,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    secret_key: &[u8; 32],
    info: crate::network::ember::relay::PunchInfo,
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let our_pubkey = ed25519_dalek::SigningKey::from_bytes(secret_key)
        .verifying_key()
        .to_bytes();
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
            Ok(Some(pubkey)) => crate::network::ember::crypto::derive_pairwise_presence_capability(
                secret_key,
                &pubkey,
                &our_pubkey,
                info.epoch,
            ),
            Ok(None) => None,
            Err(error) => {
                debug!("Friend punch: identity lookup failed: {error}");
                None
            }
        };
    let expected_capability = match expected_capability {
        Some(capability) => capability,
        None => {
            // Leave the mailbox entry: a channel punch uses a different
            // capability, and acknowledging here would delete it before
            // the channel poller sees it.
            return Err("punch identity lookup failed".to_string());
        }
    };
    if info.from_id != crate::network::rendezvous::hashed_id(&friend_ember_hash)
        || info.capability != expected_capability
    {
        return Err("punch identity or capability mismatch".to_string());
    }
    let peer_nat = crate::network::ember::nat::NatType::from_u8(info.nat_type);
    let Ok(ip) = info.ip.parse::<std::net::IpAddr>() else {
        ack_observed_punch(rendezvous_url, &our_ember_hash, &info, secret_key).await;
        return Err("punch target ip unparseable".to_string());
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
        ack_observed_punch(rendezvous_url, &our_ember_hash, &info, secret_key).await;
        return Err("punch target is not routable".to_string());
    }
    let peer_addr = SocketAddr::new(ip, info.port);
    debug!("Friend punch: signed peer at {peer_addr} reports NAT {peer_nat:?}");
    // Pin to the friend's node id rather than accepting any Ed25519
    // cert: `info.from_id` was matched against
    // `hashed_id(&friend_ember_hash)` above and the pairwise
    // capability checked, so the identity we expect is already
    // established from a signed record before we dial.
    match super::super::ember::broker::punch_quic_pinned(
        endpoint,
        peer_addr,
        secret_key,
        friend_ember_hash,
    )
    .await
    {
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
            Ok(streams)
        }
        Err(error) => {
            debug!("Friend QUIC punch to {peer_addr} failed: {error}");
            ack_observed_punch(rendezvous_url, &our_ember_hash, &info, secret_key).await;
            Err(error)
        }
    }
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
    deadline: tokio::time::Instant,
    offered_ticket: Arc<std::sync::Mutex<Option<String>>>,
) -> Result<crate::network::ember::relay::WsStream, String> {
    let offer = tokio::time::timeout_at(
        deadline,
        crate::network::rendezvous::offer_friend_relay_ticket(
            rendezvous_url,
            &our_ember_hash,
            &friend_ember_hash,
            our_pubkey,
            secret_key,
        ),
    )
    .await
    .map_err(|_| "friend relay ticket offer timed out".to_string())??;

    *offered_ticket
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = Some(offer.ticket_id.clone());

    let ticket_deadline = deadline.min(
        tokio::time::Instant::now()
            + crate::network::rendezvous::FRIEND_RELAY_TICKET_INITIATOR_WAIT,
    );
    let mut status_retry_delay = std::time::Duration::from_secs(1);
    while tokio::time::Instant::now() < ticket_deadline {
        let remaining = ticket_deadline.saturating_duration_since(tokio::time::Instant::now());
        tokio::time::sleep(remaining.min(status_retry_delay)).await;
        let remaining = ticket_deadline.saturating_duration_since(tokio::time::Instant::now());
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
                return tokio::time::timeout_at(
                    deadline,
                    crate::network::ember::relay::connect_server_relay(
                        rendezvous_url,
                        &offer.ticket_id,
                        &offer.initiator_token,
                    ),
                )
                .await
                .map_err(|_| "server relay connect timed out".to_string())?;
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

    #[test]
    fn punch_relay_race_is_delayed_and_fallback_phase_is_bounded() {
        assert_eq!(
            FRIEND_PUNCH_RELAY_RACE_AFTER,
            FRIEND_PUNCH_POLL_INTERVAL * 3
        );
        assert!(FRIEND_FALLBACK_PHASE_TIMEOUT > FRIEND_PUNCH_RELAY_RACE_AFTER);
        assert!(FRIEND_FALLBACK_PHASE_TIMEOUT < std::time::Duration::from_secs(154));
        assert!(
            FRIEND_FALLBACK_PHASE_TIMEOUT
                >= FRIEND_PUNCH_RELAY_RACE_AFTER
                    + crate::network::rendezvous::FRIEND_RELAY_TICKET_INITIATOR_WAIT
        );
        assert_eq!(relay_arm_delay(true), FRIEND_PUNCH_RELAY_RACE_AFTER);
        assert_eq!(relay_arm_delay(false), std::time::Duration::ZERO);
    }

    #[test]
    fn punch_attempt_deadline_is_capped_by_the_phase() {
        let now = tokio::time::Instant::now();
        let phase = now + FRIEND_FALLBACK_PHASE_TIMEOUT;
        assert_eq!(
            punch_attempt_deadline(now, phase),
            now + FRIEND_PUNCH_ATTEMPT_TIMEOUT
        );
        let late = phase - std::time::Duration::from_millis(100);
        assert_eq!(punch_attempt_deadline(late, phase), phase);
        assert!(punch_attempt_deadline(late, phase) < late + FRIEND_PUNCH_ATTEMPT_TIMEOUT);
    }

    /// Production `nat_fallback_transport` cannot be driven without HTTPS/QUIC.
    /// These tests drive the extracted race: spawn order, relay arm delay vs
    /// skip, punch win after the relay delay, combined errors, and panics.
    /// `tokio::time::pause()` is unavailable (`test-util` is not enabled on
    /// this crate's tokio dependency, which this agent does not own).
    #[tokio::test]
    async fn relay_starts_while_punch_register_is_outstanding() {
        let (block_tx, block_rx) = tokio::sync::oneshot::channel::<()>();
        let (register_started_tx, register_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (relay_started_tx, relay_started_rx) = tokio::sync::oneshot::channel::<()>();

        let punch = async move {
            let _ = register_started_tx.send(());
            let _ = block_rx.await;
            Err::<(), _>("register still outstanding".to_string())
        };
        let relay = async move {
            let _ = relay_started_tx.send(());
            std::future::pending::<()>().await;
            Err::<(), _>("unused".to_string())
        };

        let (punch_handle, relay_handle) = spawn_relay_then_punch(punch, relay);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            register_started_rx.await.expect("punch register started");
            relay_started_rx.await.expect("relay started");
        })
        .await
        .expect("relay must be running while punch registration is still blocked");
        assert!(
            !punch_handle.is_finished(),
            "punch/register must still be outstanding"
        );
        assert!(!relay_handle.is_finished());
        drop(block_tx);
        punch_handle.abort();
        relay_handle.abort();
    }

    #[tokio::test]
    async fn relay_arm_delay_overlaps_outstanding_register_and_honors_skip() {
        let delay = std::time::Duration::from_millis(50);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);

        let (skip_tx, skip_rx) = tokio::sync::watch::channel(false);
        let started = tokio::time::Instant::now();
        let wait = tokio::spawn(wait_relay_arm(delay, skip_rx, deadline));
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            !wait.is_finished(),
            "relay must not dial before the delay while register is outstanding"
        );
        wait.await
            .expect("wait_relay_arm join")
            .expect("wait_relay_arm");
        assert!(started.elapsed() >= delay);
        drop(skip_tx);

        let (skip_tx, skip_rx) = tokio::sync::watch::channel(false);
        let wait = tokio::spawn(wait_relay_arm(
            std::time::Duration::from_secs(5),
            skip_rx,
            tokio::time::Instant::now() + std::time::Duration::from_secs(6),
        ));
        skip_tx.send(true).expect("skip");
        tokio::time::timeout(std::time::Duration::from_millis(200), wait)
            .await
            .expect("failed register must start the relay immediately")
            .expect("join")
            .expect("wait_relay_arm skip");

        let (skip_tx, skip_rx) = tokio::sync::watch::channel(false);
        let delay = std::time::Duration::from_millis(50);
        let started = tokio::time::Instant::now();
        let wait = tokio::spawn(wait_relay_arm(
            delay,
            skip_rx,
            tokio::time::Instant::now() + std::time::Duration::from_secs(2),
        ));
        drop(skip_tx);
        wait.await
            .expect("join")
            .expect("drop without skip must not fail the wait");
        assert!(
            started.elapsed() >= delay,
            "dropping the skip sender must not start the relay immediately"
        );
    }

    #[tokio::test]
    async fn punch_win_after_relay_delay_aborts_leftover_relay() {
        let delay = std::time::Duration::from_millis(40);
        let (offered_tx, offered_rx) = tokio::sync::oneshot::channel::<()>();
        let punch = async move {
            tokio::time::sleep(delay + std::time::Duration::from_millis(20)).await;
            Ok::<_, String>("punch")
        };
        let relay = async move {
            tokio::time::sleep(delay).await;
            let _ = offered_tx.send(());
            std::future::pending::<()>().await;
            Err::<&'static str, _>("relay still waiting to connect".to_string())
        };
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let (punch_handle, relay_handle) = spawn_relay_then_punch(punch, relay);
        match drive_fallback_race(Some(punch_handle), Some(relay_handle), deadline).await {
            FallbackRace::Punch {
                value,
                leftover_relay,
            } => {
                assert_eq!(value, "punch");
                assert!(
                    leftover_relay.is_none(),
                    "aborted pre-connect relay must not yield a stream"
                );
            }
            FallbackRace::Relay { .. } => panic!("punch should have won after the relay delay"),
            FallbackRace::Failed(error) => panic!("unexpected failure: {error}"),
            FallbackRace::Timeout { .. } => panic!("race timed out"),
        }
        offered_rx
            .await
            .expect("relay must have passed its delay (offered) before punch won");
    }

    #[tokio::test]
    async fn fallback_race_reports_both_errors_and_distinguishes_panic() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let punch = async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Err::<(), _>("no reciprocal punch registration found before timeout".to_string())
        };
        let relay = async { Err::<(), _>("friend relay ticket status failed: 503".to_string()) };
        let (punch_handle, relay_handle) = spawn_relay_then_punch(punch, relay);
        match drive_fallback_race(Some(punch_handle), Some(relay_handle), deadline).await {
            FallbackRace::Failed(error) => {
                assert!(
                    error.contains("punch=no reciprocal punch registration found before timeout"),
                    "{error}"
                );
                assert!(
                    error.contains("relay=friend relay ticket status failed: 503"),
                    "{error}"
                );
            }
            _ => panic!("expected combined transport failure"),
        }

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        let punch = async {
            panic!("punch boom");
            #[allow(unreachable_code)]
            Err::<(), _>("unused".to_string())
        };
        let relay = async {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            Err::<(), _>("friend relay ticket status failed: 503".to_string())
        };
        let (punch_handle, relay_handle) = spawn_relay_then_punch(punch, relay);
        match drive_fallback_race(Some(punch_handle), Some(relay_handle), deadline).await {
            FallbackRace::Failed(error) => {
                assert!(error.contains("punch=task panicked"), "{error}");
                assert!(
                    error.contains("relay=friend relay ticket status failed: 503"),
                    "{error}"
                );
            }
            _ => panic!("expected panic to be distinguishable in the combined error"),
        }
    }

    /// A listener drops the connection when the first inner frame is not
    /// `OP_HELLO`, so a withdrawal that skipped the eD2K greeting was accepted
    /// by the socket and silently discarded — the recipient kept the request on
    /// screen and nothing reported a failure. This pins the whole sequence, and
    /// asserts the withdrawal is an empty-bodied `OP_EMBER_EXT` sub-type rather
    /// than a second friend request.
    #[tokio::test]
    async fn withdrawal_greets_the_peer_before_announcing_itself() {
        let our_sk = SigningKey::generate(&mut OsRng);
        let our_pk_bytes = our_sk.verifying_key().to_bytes();
        let our_sk_bytes = our_sk.to_bytes();
        let our_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&our_sk.verifying_key());

        let peer_sk = SigningKey::generate(&mut OsRng);
        let peer_pk_bytes = peer_sk.verifying_key().to_bytes();
        let peer_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&peer_sk.verifying_key());

        // A real socket: the courier dials for itself, so there is no transport
        // to inject.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut server_r, server_w) = tokio::io::split(stream);
            let first = server_r.read_u8().await.expect("discriminator");
            let secure = super::secure_stream::accept_after_first(
                Box::new(server_r),
                Box::new(server_w),
                first,
                peer_ember_hash,
                peer_pk_bytes,
                peer_sk.to_bytes(),
            )
            .await
            .expect("secure accept");
            let mut server_r = secure.reader;
            let mut server_w = secure.writer;

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.expect("greeting");
            assert_eq!(
                (proto, opcode),
                (OP_EDONKEYHEADER, OP_HELLO),
                "a listener refuses anything but Hello first"
            );
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
            .expect("hello answer");

            let (proto, opcode, _) = read_packet_inner(&mut server_r).await.expect("emule info");
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMULEINFO));

            let (proto, opcode, payload) =
                read_packet_inner(&mut server_r).await.expect("withdrawal");
            assert_eq!((proto, opcode), (OP_EMULEPROT, OP_EMBER_EXT));
            assert_eq!(
                parse_ember_ext(&payload),
                Some((EMBER_EXT_FRIEND_RETRACT, &[][..])),
                "the withdrawal carries its sub-type and nothing else"
            );
        });

        send_friend_request_retraction(
            addr,
            peer_ember_hash,
            [0x11; 16],
            our_ember_hash,
            "tester".to_string(),
            0,
            4662,
            4672,
            false,
            Some(our_pk_bytes),
            Some(our_sk_bytes),
        )
        .await
        .expect("withdrawal must reach a well-behaved peer");

        tokio::time::timeout(std::time::Duration::from_secs(5), peer)
            .await
            .expect("mock peer must not hang")
            .expect("mock peer must not panic");
    }

    /// A stale address may now answer for somebody else. Announcing a
    /// withdrawal to whoever picks up would tell an unrelated peer about a
    /// friend request they were never part of.
    #[tokio::test]
    async fn withdrawal_refuses_a_peer_with_the_wrong_identity() {
        let our_sk = SigningKey::generate(&mut OsRng);
        let our_pk_bytes = our_sk.verifying_key().to_bytes();
        let our_sk_bytes = our_sk.to_bytes();
        let our_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&our_sk.verifying_key());

        let squatter_sk = SigningKey::generate(&mut OsRng);
        let squatter_pk_bytes = squatter_sk.verifying_key().to_bytes();
        let squatter_ember_hash =
            crate::network::ember::crypto::node_id_from_public_key(&squatter_sk.verifying_key());
        let intended_hash = [0x5A; 16];
        assert_ne!(squatter_ember_hash, intended_hash);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");

        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (mut server_r, server_w) = tokio::io::split(stream);
            let first = server_r.read_u8().await.expect("discriminator");
            // Whether this completes does not matter: the dialer must refuse
            // the identity either way.
            let _ = super::secure_stream::accept_after_first(
                Box::new(server_r),
                Box::new(server_w),
                first,
                squatter_ember_hash,
                squatter_pk_bytes,
                squatter_sk.to_bytes(),
            )
            .await;
        });

        let result = send_friend_request_retraction(
            addr,
            intended_hash,
            [0x11; 16],
            our_ember_hash,
            "tester".to_string(),
            0,
            4662,
            4672,
            false,
            Some(our_pk_bytes),
            Some(our_sk_bytes),
        )
        .await;

        assert!(
            result.is_err(),
            "a withdrawal must not be announced to an identity we did not ask for"
        );
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), peer).await;
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
