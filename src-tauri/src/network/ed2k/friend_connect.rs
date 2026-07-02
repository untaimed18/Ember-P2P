use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::messages::*;
use super::upload::{EmberSessionMap, UploadEvent, UploadEventKind};
use crate::network::ember::crypto;

/// Result from a successfully established friend session: the outbound sender
/// so the caller can immediately send packets before the loop consumes them.
pub struct FriendSessionHandle {
    pub outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
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
    let mut reader = tokio::io::BufReader::new(raw_r);
    let mut writer = tokio::io::BufWriter::new(raw_w);

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

    let pk_ref = ed25519_pubkey.as_ref();
    let emule_payload = build_emule_info(udp_port, false, Some(&our_ember_hash), pk_ref);
    write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFO, &emule_payload).await?;

    let (proto, opcode, payload) = read_packet_with_timeout(&mut reader, 15)
        .await
        .context("waiting for EmuleInfo")?;
    if proto == OP_EMULEPROT && (opcode == OP_EMULEINFOANSWER || opcode == OP_EMULEINFO) {
        merge_caps(&mut hello_caps, parse_emule_info(&payload));
        if opcode == OP_EMULEINFO {
            let answer = build_emule_info(udp_port, false, Some(&our_ember_hash), pk_ref);
            write_packet(&mut writer, OP_EMULEPROT, OP_EMULEINFOANSWER, &answer).await?;
        }
    }

    // Synchronous Ember-Hello round-trip. Without this,
    // `hello_caps.is_ember` stays false (the public Hello / EmuleInfo
    // no longer signals Ember-ness), the bail below always fires,
    // and friend sessions can't open at all. This also populates
    // `hello_caps.ember_pubkey`, which gates the `perform_ember_auth`
    // call below.
    exchange_ember_hello(
        &mut reader,
        &mut writer,
        &our_ember_hash,
        &our_nickname,
        ed25519_pubkey.as_ref(),
        &mut hello_caps,
        addr,
    )
    .await?;

    if !hello_caps.is_ember {
        anyhow::bail!("remote peer is not an Ember client");
    }
    let peer_ember_hash = hello_caps
        .ember_hash
        .ok_or_else(|| anyhow::anyhow!("Ember peer has no ember_hash"))?;

    // Identity guard (see the function doc): refuse a session whose peer
    // identifies as someone other than the friend the caller asked us to
    // dial. Runs before the duplicate-session check and the expensive PoP
    // round trip so a stale/reused address is rejected as cheaply as
    // possible. PoP below still proves possession of the claimed hash; this
    // check is what prevents a *wrong but otherwise-valid* friend from
    // standing in for the one we intended to reach.
    if peer_ember_hash != expected_ember_hash {
        anyhow::bail!(
            "dialed {} expecting friend {} but peer identifies as {}; refusing session",
            addr,
            hex::encode(expected_ember_hash),
            hex::encode(peer_ember_hash)
        );
    }

    // Early duplicate-session check. As soon as we know the peer's
    // ember_hash (from `exchange_ember_hello` above) we can tell whether
    // a session is already live for them, and bail out BEFORE the
    // expensive Ed25519 challenge-response round trip and before we
    // send `OP_EMBER_FRIEND_REQ`. Previously we did this check only
    // after `perform_ember_auth` + FRIEND_REQ had both completed, which:
    //   1. Wasted ~4 RTTs of auth on a connection we immediately drop.
    //   2. Left the peer with a ghost `EmberFriendRequest` UploadEvent
    //      whose sender's half-connection was already being closed, so
    //      any accept from the UI raced a TCP RST and silently failed.
    //
    // We re-verify the slot is still empty when we finally claim it
    // below (after auth), so no race window widens here.
    {
        let sessions = ember_sessions.read().await;
        if let Some(existing_tx) = sessions.get(&peer_ember_hash) {
            info!(
                "Friend session for {} already exists after Ember-Hello; skipping duplicate handshake",
                hex::encode(peer_ember_hash)
            );
            return Ok(FriendSessionHandle {
                outbound_tx: existing_tx.clone(),
            });
        }
    }

    // Ember auth challenge-response. Now that `OP_EMBER_HELLO` is
    // exchanged above, `hello_caps.ember_pubkey` is populated and
    // this branch performs a real Ed25519 proof-of-possession round
    // trip — verifies BLAKE3(peer_pk)[0..16] == peer_ember_hash and
    // that the peer can sign a fresh nonce with the matching secret
    // key. A failure here propagates as `?` and aborts the friend
    // session, so a peer that fails PoP never gets friend-session
    // privileges (chat, browse, etc.).
    //
    // V1 hardening (M1): if the peer didn't advertise an Ed25519
    // pubkey at all (legacy / spoofed `OP_EMBER_HELLO` from a
    // vanilla eMule), we refuse to open the friend session
    // entirely — the only thing we'd have to bind chat/browse to
    // is the unproven 16-byte hash claim. Pre-V1 we used to
    // continue with `ember_hash_binding_verified=false`; that
    // window let an attacker iterate Ember hashes from EPX dumps,
    // dial us, and claim an existing friend's hash without ever
    // proving possession. Closing the door here is safe: every
    // honest Ember client builds its hash from its own pubkey so
    // it always advertises one in the same `OP_EMBER_HELLO`.
    let our_have_keys = ed25519_pubkey.is_some() && ed25519_secret_key.is_some();
    let peer_pk = match hello_caps.ember_pubkey {
        Some(pk) => pk,
        None => {
            anyhow::bail!(
                "remote peer {} did not advertise an Ed25519 pubkey in OP_EMBER_HELLO; refusing friend session",
                hex::encode(peer_ember_hash)
            );
        }
    };
    let ember_pop_verified = if our_have_keys {
        let our_pk = ed25519_pubkey.unwrap();
        let our_sk = ed25519_secret_key.unwrap();
        perform_ember_auth(
            &mut reader,
            &mut writer,
            &our_pk,
            &our_sk,
            &peer_pk,
            Some(&peer_ember_hash),
            addr,
        )
        .await?;
        true
    } else {
        // We can't drive the challenge-response without our own
        // identity. Refuse rather than silently downgrading.
        anyhow::bail!(
            "local node has no Ed25519 identity; refusing friend session with {}",
            hex::encode(peer_ember_hash)
        );
    };

    let is_friend = friend_hashes.read().await.contains(&peer_ember_hash);
    if !is_friend {
        anyhow::bail!(
            "remote peer {} is not in our friend list",
            hex::encode(peer_ember_hash)
        );
    }

    // Verification flag passed into the spawned reader task below
    // so any `OP_EMBER_FRIEND_REQ` we receive on this session
    // reports an honest `verified` value to the UI. By the time we
    // reach this line PoP has already succeeded (otherwise we
    // bailed above), so this is `true`. Kept as a named binding
    // for clarity at the use sites below.
    let ember_hash_binding_verified = ember_pop_verified;

    // Reserve the session slot atomically BEFORE we send our friend
    // request. If another concurrent dial raced us and claimed the
    // slot in the window between the pre-auth check above and here,
    // we must NOT send our own FRIEND_REQ (the peer would get a
    // duplicate request from the racing connection too) — return
    // the winner's handle instead and drop this socket cleanly.
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(32);
    {
        let mut sessions = ember_sessions.write().await;
        if let Some(existing_tx) = sessions.get(&peer_ember_hash) {
            info!(
                "Friend session for {} already exists (post-auth race); skipping duplicate",
                hex::encode(peer_ember_hash)
            );
            return Ok(FriendSessionHandle {
                outbound_tx: existing_tx.clone(),
            });
        }
        sessions.insert(peer_ember_hash, outbound_tx.clone());
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
        sessions.remove(&peer_ember_hash);
        return Err(anyhow::Error::from(e).context("failed to send OP_EMBER_FRIEND_REQ"));
    }

    info!("Friend session handshake with {} complete (hash={}, binding_verified={ember_hash_binding_verified})", addr, hex::encode(peer_ember_hash));

    let handle = FriendSessionHandle { outbound_tx };

    let session_ember_sessions = ember_sessions.clone();
    let session_ul_event_tx = ul_event_tx.clone();
    let session_friend_hashes = friend_hashes.clone();
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
                            match (proto, opcode) {
                                (OP_EMULEPROT, OP_EMBER_CHAT_MSG) => {
                                    if payload.len() <= 4096 {
                                        if let Ok(msg) = std::str::from_utf8(&payload) {
                                            let _ = session_ul_event_tx.send(UploadEvent {
                                                transfer_id: String::new(),
                                                kind: UploadEventKind::EmberChatMessage {
                                                    ember_hash: peer_ember_hash,
                                                    message: msg.to_string(),
                                                },
                                            }).await;
                                        }
                                    }
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_REQ) => {
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseRequest {
                                            ember_hash: peer_ember_hash,
                                        },
                                    }).await;
                                }
                                (OP_EMULEPROT, OP_EMBER_BROWSE_RES) => {
                                    let entries = parse_browse_response(&payload);
                                    let _ = session_ul_event_tx.send(UploadEvent {
                                        transfer_id: String::new(),
                                        kind: UploadEventKind::EmberBrowseResponse {
                                            ember_hash: peer_ember_hash,
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
                            debug!("Friend session read error from {addr}: {e}");
                            break;
                        }
                    }
                }
                Some(outbound_data) = outbound_rx.recv() => {
                    last_activity = tokio::time::Instant::now();
                    if writer.write_all(&outbound_data).await.is_err() {
                        debug!("Friend session write error to {addr}");
                        break;
                    }
                    if writer.flush().await.is_err() {
                        debug!("Friend session flush error to {addr}");
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
                        debug!("Friend session keepalive to {addr} failed");
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
            sessions.remove(&peer_ember_hash);
        }
        let _ = session_ul_event_tx
            .send(UploadEvent {
                transfer_id: String::new(),
                kind: UploadEventKind::EmberFriendDisconnected {
                    ember_hash: peer_ember_hash,
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

/// Number of `/punch/{id}` polls to make after registering, and the delay
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
/// `rendezvous_url` empty or `quic_endpoint` absent degrade gracefully to
/// TCP-only, matching the previous behaviour exactly.
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
    our_nat_type: crate::network::ember::nat::NatType,
    our_external_addr: Option<SocketAddr>,
    quic_endpoint: Option<Arc<quinn::Endpoint>>,
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

    if let (Some(endpoint), Some(ext_addr)) = (quic_endpoint.as_ref(), our_external_addr) {
        if our_nat_type != crate::network::ember::nat::NatType::Symmetric {
            match punch_friend(
                &rendezvous_url,
                endpoint,
                our_ember_hash,
                expected_ember_hash,
                ext_addr,
                our_nat_type,
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

    match relay_friend(&rendezvous_url, our_ember_hash, expected_ember_hash, addr).await {
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
) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
    let our_id = format!("{:0>64}", hex::encode(our_ember_hash));
    let target_id = format!("{:0>64}", hex::encode(friend_ember_hash));

    // Register the port our QUIC endpoint is actually bound to, not
    // `our_external_addr.port()` — that address comes from the KAD UDP
    // STUN probe (a *different* socket than the QUIC endpoint the friend
    // will actually dial), so advertising it here would misdirect the
    // friend's `punch_quic` connect at a socket we're not listening on.
    let advertise_port = endpoint
        .local_addr()
        .map(|a| a.port())
        .unwrap_or_else(|_| our_external_addr.port());
    crate::network::ember::relay::register_punch(
        rendezvous_url,
        &our_id,
        &target_id,
        advertise_port,
        our_nat_type.as_u8(),
    )
    .await?;

    for _ in 0..FRIEND_PUNCH_POLL_ATTEMPTS {
        tokio::time::sleep(FRIEND_PUNCH_POLL_INTERVAL).await;
        match crate::network::ember::relay::poll_punch(rendezvous_url, &our_id).await {
            Ok(Some(info)) => {
                let Ok(ip) = info.ip.parse::<std::net::IpAddr>() else {
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
                    continue;
                }
                let peer_addr = SocketAddr::new(ip, info.port);
                return super::super::ember::broker::punch_quic(endpoint, peer_addr, None)
                    .await
                    .map_err(|e| format!("QUIC punch to {peer_addr} failed: {e}"));
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
/// Addressed by `(ip, port)` — the same synthetic id scheme the download
/// broker uses for LowID sources, and the *only* scheme the existing
/// relay-invite responder (`network/mod.rs`'s "poll for incoming
/// server-relay invitations" task, which every rendezvous-registered node
/// already runs unconditionally) knows how to answer. `friend_addr` is
/// the friend's last rendezvous-registered `(ip, tcp_port)` — the exact
/// value that responder independently recomputes from its own
/// `state.external_ip` / `state.quic_port`, so no new responder-side code
/// is needed: the friend's own client picks this invitation up the next
/// time its existing poller runs.
async fn relay_friend(
    rendezvous_url: &str,
    our_ember_hash: [u8; 16],
    friend_ember_hash: [u8; 16],
    friend_addr: SocketAddr,
) -> Result<crate::network::ember::relay::WsStream, String> {
    let target_id = match friend_addr.ip() {
        std::net::IpAddr::V4(v4) => format!(
            "{:0>64}",
            format!("{:08x}{:04x}", u32::from(v4), friend_addr.port())
        ),
        std::net::IpAddr::V6(_) => {
            return Err("friend relay requires an IPv4 rendezvous address".to_string())
        }
    };
    let nonce = {
        use rand::RngCore;
        let mut n = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut n);
        hex::encode(n)
    };
    let session_id = format!(
        "friend-{}-{}-{}",
        hex::encode(our_ember_hash),
        hex::encode(friend_ember_hash),
        nonce
    );

    crate::network::ember::relay::post_relay_invite(rendezvous_url, &target_id, &session_id)
        .await?;
    crate::network::ember::relay::connect_server_relay(rendezvous_url, &session_id).await
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
                crate::network::ember::nat::NatType::Unknown,
                None,
                None,
            ),
        )
        .await
        .expect("connect_friend_with_fallback must not hang with no rendezvous URL");

        assert!(result.is_err());
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
const EMBER_HELLO_TIMEOUT_SECS: u64 = 5;
/// Cap on the number of unrelated packets we'll consume while looking
/// for the peer's Ember hello. A well-behaved Ember peer sends its
/// hello immediately after the EmuleInfo exchange, so 0–1 unrelated
/// packets are normal (e.g. `OP_SECIDENTSTATE`); a higher count may
/// indicate the peer is racing in unrelated traffic. Bounded so a
/// chatty peer can't pin us in this loop.
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
/// Verification checks:
///   1. `BLAKE3(peer_pubkey)[0..16] == peer_ember_hash` (identity binding)
///   2. The signature over our nonce is valid under the peer's public key
///
/// Exposed as `pub(crate)` so the regular download/upload TCP loops in
/// `upload.rs` and `multi_source.rs` can run the same authoritative
/// challenge-response immediately after an `OP_EMBER_HELLO` /
/// `OP_EMBER_HELLOANSWER` exchange reveals the peer's pubkey — without
/// waiting for a dedicated friend-connect session. Reader/writer are
/// generic so callers pass whatever stream pair they already have
/// (RC4-wrapped or plain, buffered or not).
pub(crate) async fn perform_ember_auth<R, W>(
    reader: &mut R,
    writer: &mut W,
    our_pubkey: &[u8; 32],
    our_secret_key: &[u8; 32],
    peer_pubkey: &[u8; 32],
    peer_ember_hash: Option<&[u8; 16]>,
    addr: SocketAddr,
) -> anyhow::Result<()>
where
    // `?Sized` lets the multi_source download loop pass a
    // `&mut dyn AsyncRead/AsyncWrite` (from a `Box<dyn ...>`) without
    // having to unbox first. Concrete-type callers (friend_connect,
    // buffered readers) still work unchanged.
    R: AsyncReadExt + Unpin + ?Sized,
    W: AsyncWriteExt + Unpin + ?Sized,
{
    // Verify peer pubkey matches their advertised ember_hash
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

    // Generate and send our challenge nonce
    let mut our_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut our_nonce);
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_CHALLENGE, &our_nonce).await?;

    // Read peer's challenge nonce, tolerating interleaved packets.
    //
    // The peer (typically `upload.rs`) emits proactive opcodes
    // immediately after its OP_EMBER_HELLO — most notably
    // `OP_SECIDENTSTATE` from `maybe_send_secident_challenge`,
    // which sits in the TCP stream ahead of the peer's CHALLENGE
    // response. A strict "next packet must be CHALLENGE" read
    // would consume + reject that SecIdent frame and abort
    // friend-connect for every Ember-to-Ember dial. We instead
    // read up to a small bounded number of packets and accept
    // the first one that's actually our CHALLENGE; non-matching
    // packets are logged and dropped (acceptable here because
    // friend-connect is short-lived and doesn't process SecIdent
    // or other peer-initiated opcodes itself — multi_source uses
    // `perform_ember_auth_buffered` instead).
    let peer_nonce_payload = read_specific_auth_packet(
        reader,
        OP_EMBER_AUTH_CHALLENGE,
        32,
        addr,
        "AUTH_CHALLENGE",
        |_, _, _| {},
    )
    .await?;

    // Sign the peer's nonce with our key and send response (pubkey + signature)
    let signing_key = SigningKey::from_bytes(our_secret_key);
    let signature = signing_key.sign(&peer_nonce_payload);
    let mut response = Vec::with_capacity(96);
    response.extend_from_slice(our_pubkey);
    response.extend_from_slice(&signature.to_bytes());
    write_packet(writer, OP_EMULEPROT, OP_EMBER_AUTH_RESPONSE, &response).await?;

    // Read peer's response (32-byte pubkey + 64-byte signature),
    // again tolerating intervening unrelated packets per the
    // same rationale as the CHALLENGE read above.
    let peer_response = read_specific_auth_packet(
        reader,
        OP_EMBER_AUTH_RESPONSE,
        96,
        addr,
        "AUTH_RESPONSE",
        |_, _, _| {},
    )
    .await?;

    let resp_pubkey: [u8; 32] = peer_response[..32].try_into().unwrap();
    if resp_pubkey != *peer_pubkey {
        anyhow::bail!("Ember auth: response pubkey doesn't match EmuleInfo pubkey from {addr}");
    }

    let peer_vk = VerifyingKey::from_bytes(peer_pubkey)
        .map_err(|e| anyhow::anyhow!("invalid peer Ed25519 pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = peer_response[32..96].try_into().unwrap();
    let peer_sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    peer_vk.verify_strict(&our_nonce, &peer_sig).map_err(|e| {
        anyhow::anyhow!("Ember auth: signature verification failed for {addr}: {e}")
    })?;

    info!(
        "Ember auth: verified peer {} at {}",
        hex::encode(&peer_pubkey[..8]),
        addr
    );
    Ok(())
}

/// Buffered variant of [`perform_ember_auth`] for callers that cannot
/// safely drop intervening non-AUTH packets.
///
/// Identical to `perform_ember_auth` except that any packet read off
/// the stream while waiting for `OP_EMBER_AUTH_CHALLENGE` /
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
    let signature = signing_key.sign(&peer_nonce_payload);
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
    peer_vk.verify_strict(&our_nonce, &peer_sig).map_err(|e| {
        anyhow::anyhow!("Ember auth: signature verification failed for {addr}: {e}")
    })?;

    info!(
        "Ember auth (buffered): verified peer {} at {} ({} deferred packet(s) captured)",
        hex::encode(&peer_pubkey[..8]),
        addr,
        deferred_packets.len(),
    );
    Ok(())
}
