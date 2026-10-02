use std::io::{self, Cursor, Read};
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use byteorder::{LittleEndian, ReadBytesExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::messages::*;

/// Longest silence tolerated at any single point inside a packet body, on a
/// plain or an obfuscated connection.
///
/// This, rather than the total below, is what detects a dead connection. A
/// large `OP_SEARCHRESULT` or `OP_SERVERLIST` over a slow link keeps delivering
/// bytes, so it never trips an idle deadline however long it takes overall,
/// while a server that stops mid-packet is caught in seconds instead of
/// holding the caller for the whole total budget.
const SERVER_PACKET_IDLE_TIMEOUT_SECS: u64 = 10;

/// Hard cap on one packet body once its first byte is consumed.
///
/// There is no safe way to abandon this read, so expiry is treated as a
/// corrupt stream and drops the session. The idle deadline above covers honest
/// slowness; this only bounds a server that trickles just fast enough to keep
/// resetting it. The read runs in the session's reader task, so waiting it out
/// holds up that session and nothing else.
const SERVER_PACKET_BODY_TIMEOUT_SECS: u64 = 120;

/// Bound on any single write to the server socket, in the session's writer
/// task. A server that stops draining its receive buffer — congested,
/// overloaded, or simply hostile — fails the write here rather than after
/// however long the OS TCP stack allows, and a failed write ends the session
/// (see [`ServerLink`]). 30s mirrors the read-side timeout used for the login
/// exchange (`Ed2kServerConnection::login`).
const SERVER_WRITE_TIMEOUT_SECS: u64 = 30;

/// Packets the network loop may queue ahead of the writer task.
///
/// Every producer is paced: `OP_GETSOURCES` leaves only in frames of at most
/// 15 that every asking path shares (`SERVER_TCP_SRCREQ_MAX_PER_FRAME`), LowID
/// callbacks at 4 a second, one `OP_OFFERFILES` chunk and one keep-alive a
/// minute, and a search's follow-up requests seconds apart. Even a frame
/// landing on top of a callback burst is a fraction of this, so a full queue
/// means the writer is stuck behind a server that has stopped reading. Sends
/// then fail at once instead of waiting, the caller keeps what it meant to
/// send exactly as it does for a failed write, and the stuck write ends the
/// session within `SERVER_WRITE_TIMEOUT_SECS`.
const SERVER_WRITE_QUEUE: usize = 64;

/// Decoded server events the reader task may hold for the network loop, which
/// is also the most one server tick takes. While it is full the reader stops
/// reading and TCP flow control pushes back on the server.
pub const SERVER_EVENT_QUEUE: usize = 64;

/// Overall deadline for one `Ed2kServerConnection::login` exchange.
///
/// The per-packet reads are bounded, but nothing bounded the whole sequence:
/// the loop accepts up to 50 packets and only `OP_IDCHANGE` ends it, so a
/// server that drip-feeds a tiny `OP_SERVERMESSAGE` just inside the 30s
/// per-packet budget holds login for ~25 minutes — doubled by the
/// encrypted-then-plain retry in `network/mod.rs`. That all happens in the
/// single `pending_server_connect` slot, which gates auto-reconnect *and*
/// initial auto-connect, so eD2k connectivity sits on "Connecting…" with no
/// fallback for the duration. A real server completes the exchange in well
/// under a second; 45s leaves room for a slow link and a long MOTD.
const SERVER_LOGIN_TIMEOUT_SECS: u64 = 45;

// Server protocol opcodes (OP_EDONKEYHEADER)
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_SERVERLIST: u8 = 0x32;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_IDCHANGE: u8 = 0x40;
pub const OP_SERVERIDENT: u8 = 0x41;
pub const OP_SEARCHREQUEST: u8 = 0x16;
pub const OP_SEARCHRESULT: u8 = 0x33;
pub const OP_GETSOURCES: u8 = 0x19;
pub const OP_FOUNDSOURCES: u8 = 0x42;
pub const OP_GETSERVERLIST: u8 = 0x14;
pub const OP_REJECT: u8 = 0x05;
pub const OP_OFFERFILES: u8 = 0x15;
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
pub const OP_CALLBACK_FAIL: u8 = 0x36;
pub const OP_GETSOURCES_OBFU: u8 = 0x23;
pub const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
pub const OP_QUERY_MORE_RESULT: u8 = 0x21;

/// SRV_TCPFLG constants: server capability flags from OP_IDCHANGE (eMule Server.h)
pub const SRV_TCPFLG_COMPRESSION: u32 = 0x0001;
pub const SRV_TCPFLG_NEWTAGS: u32 = 0x0008;
pub const SRV_TCPFLG_UNICODE: u32 = 0x0010;
pub const SRV_TCPFLG_RELATEDSEARCH: u32 = 0x0040;
pub const SRV_TCPFLG_TYPETAGINTEGER: u32 = 0x0080;
pub const SRV_TCPFLG_LARGEFILES: u32 = 0x0100;
pub const SRV_TCPFLG_TCPOBFUSCATION: u32 = 0x0400;

/// LowID threshold: client_id < this means LowID
pub const LOWID_THRESHOLD: u32 = 0x0100_0000;

/// Process-wide mirror of whether the connected server advertises
/// [`SRV_TCPFLG_RELATEDSEARCH`].
///
/// The authoritative value lives in [`ServerSession::server_flags`], which only
/// the network task can reach. The "find related files" planner runs in a Tauri
/// command and has to know, before any search starts, whether eMule's native
/// co-share request is available — that decides both what the UI tells the user
/// and whether seed hashes are worth sending at all. Following
/// `SHARE_BROWSING_ALLOWED` in `messages.rs`, one atomic is cheaper than
/// threading a server snapshot into the command layer, and there is nothing
/// per-caller about the answer.
static RELATED_SEARCH_SUPPORTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Mirror the connected server's co-share capability. Called with the server's
/// TCP flags on login and on every `OP_IDCHANGE`, and with `0` on disconnect.
pub fn set_server_flags_mirror(server_flags: u32) {
    RELATED_SEARCH_SUPPORTED.store(
        server_flags & SRV_TCPFLG_RELATEDSEARCH != 0,
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Whether the connected server can answer eMule's `related::<HASH>` co-share
/// request. False when no server is connected.
pub fn related_search_supported() -> bool {
    RELATED_SEARCH_SUPPORTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// A file to offer to the ed2k server via OP_OFFERFILES.
pub struct OfferFile {
    pub hash: [u8; 16],
    pub name: String,
    pub size: u64,
    pub is_complete: bool,
    pub file_type: String,
}

#[derive(Debug, Clone)]
pub struct ServerSearchResult {
    pub file_hash: [u8; 16],
    pub client_id: u32,
    pub client_port: u16,
    pub file_name: String,
    pub file_size: u64,
    pub source_count: u32,
    pub complete_source_count: u32,
    pub rating: Option<u8>,
    pub comment: Option<String>,
    pub media: crate::types::MediaMetadata,
}

#[derive(Debug, Clone)]
pub struct ServerSource {
    pub ip: String,
    pub port: u16,
    /// LowID client_id from the server (0 = HighID, use ip:port directly)
    pub client_id: u32,
    pub crypt_options: Option<u8>,
    pub user_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct ServerSession {
    pub client_id: u32,
    pub server_flags: u32,
    pub server_name: String,
    pub user_count: u32,
    pub file_count: u32,
    /// Raw OP_SERVERLIST payload received during login (if any)
    pub server_list_data: Option<Vec<u8>>,
    /// MOTD messages received during login (for frontend display)
    pub motd_messages: Vec<String>,
    /// Server-reported public IP from OP_IDCHANGE (offset 12, if present).
    pub server_reported_ip: u32,
}

/// One per server connection, held for its lifetime. Same reasoning as the
/// upload stream enums: the size difference is a single move at connect time,
/// and boxing would add an indirection to every server packet.
#[allow(clippy::large_enum_variant)]
enum ServerTransport {
    Plain {
        reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
        writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    },
    Encrypted(super::server_crypt::ObfuscatedServerStream),
}

impl ServerTransport {
    fn into_halves(self) -> (ServerReadHalf, ServerWriteHalf) {
        match self {
            ServerTransport::Plain { reader, writer } => {
                (ServerReadHalf::Plain(reader), ServerWriteHalf::Plain(writer))
            }
            ServerTransport::Encrypted(stream) => {
                let (reader, writer) = stream.into_split();
                (
                    ServerReadHalf::Encrypted(reader),
                    ServerWriteHalf::Encrypted(writer),
                )
            }
        }
    }
}

// The encrypted arm carries its RC4 state inline. The half is built once per
// server session and then read in place by its task, so the size difference
// is a single move at login, while a box would add a pointer chase to every
// read. Same trade as `StreamReader` in `upload.rs`.
#[allow(clippy::large_enum_variant)]
enum ServerReadHalf {
    Plain(tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>),
    Encrypted(super::server_crypt::ObfuscatedReadHalf),
}

impl ServerReadHalf {
    /// The next whole packet.
    ///
    /// Waits as long as it takes for the first byte — an idle server is not a
    /// dead one; the keep-alive and the network loop's watchdog decide that —
    /// then gives the rest `SERVER_PACKET_BODY_TIMEOUT_SECS`.
    async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let body_budget = std::time::Duration::from_secs(SERVER_PACKET_BODY_TIMEOUT_SECS);
        let body = match self {
            ServerReadHalf::Plain(reader) => {
                let protocol = reader.read_u8().await?;
                tokio::time::timeout(
                    body_budget,
                    read_server_packet_after_protocol(reader, protocol),
                )
                .await
            }
            ServerReadHalf::Encrypted(stream) => {
                let first = stream.read_packet_first_byte().await?;
                tokio::time::timeout(body_budget, stream.read_packet_after_first_byte(first)).await
            }
        };
        body.unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server packet body did not arrive in time, stream is corrupt",
            ))
        })
    }
}

#[allow(clippy::large_enum_variant)] // Same as `ServerReadHalf` above.
enum ServerWriteHalf {
    Plain(tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>),
    Encrypted(super::server_crypt::ObfuscatedWriteHalf),
}

impl ServerWriteHalf {
    /// Send one complete wire packet under `SERVER_WRITE_TIMEOUT_SECS`.
    async fn write_packet(&mut self, wire: &[u8]) -> io::Result<()> {
        let write = async {
            match self {
                ServerWriteHalf::Plain(writer) => {
                    writer.write_all(wire).await?;
                    writer.flush().await
                }
                ServerWriteHalf::Encrypted(stream) => stream.write_packet(wire).await,
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(SERVER_WRITE_TIMEOUT_SECS), write)
            .await
            .unwrap_or_else(|_| {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "server write timed out",
                ))
            })
    }
}

/// `[protocol][length u32 LE][opcode][payload]`, the framing of every server
/// packet in both directions.
fn server_wire_packet(protocol: u8, opcode: u8, payload: &[u8]) -> io::Result<Vec<u8>> {
    let wire_len = u32::try_from(1 + payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "packet payload too large for u32 length field",
        )
    })?;
    let mut wire = Vec::with_capacity(6 + payload.len());
    wire.push(protocol);
    wire.extend_from_slice(&wire_len.to_le_bytes());
    wire.push(opcode);
    wire.extend_from_slice(payload);
    Ok(wire)
}

/// A server connection from TCP connect through login. Once logged in it is
/// handed to [`Ed2kServerConnection::into_link`], which gives the socket to
/// the tasks that carry the session.
pub struct Ed2kServerConnection {
    transport: ServerTransport,
}

impl Ed2kServerConnection {
    pub async fn connect(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream =
            tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
                .await??;
        let _ = stream.set_nodelay(true);

        let (reader, writer) = stream.into_split();
        Ok(Self {
            transport: ServerTransport::Plain {
                reader: tokio::io::BufReader::new(reader),
                writer: tokio::io::BufWriter::new(writer),
            },
        })
    }

    pub async fn connect_encrypted(addr: SocketAddr) -> anyhow::Result<Self> {
        let stream = super::server_crypt::connect_obfuscated(addr).await?;
        Ok(Self {
            transport: ServerTransport::Encrypted(stream),
        })
    }

    /// Hand the logged-in socket to the session's reader and writer tasks.
    pub fn into_link(self, session: ServerSession) -> ServerLink {
        ServerLink::spawn(self.transport, session, SERVER_WRITE_QUEUE, SERVER_EVENT_QUEUE)
    }

    pub async fn login(
        &mut self,
        user_hash: &[u8; 16],
        nickname: &str,
        tcp_port: u16,
    ) -> anyhow::Result<ServerSession> {
        let is_encrypted = matches!(self.transport, ServerTransport::Encrypted(_));
        let mut flags: u32 = SRVCAP_ZLIB | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES;
        // Only advertise crypto preference when we're actually on an encrypted connection.
        // Lugdunum servers close plain connections from clients that claim SRVCAP_REQUESTCRYPT,
        // expecting them to reconnect on the obfuscation port.
        //
        // Match eMule's default crypt prefs here: SUPPORT + REQUEST, but NOT
        // REQUIRE. Stock eMule sets SRVCAP_REQUIRECRYPT only when the user opts
        // into "require obfuscated" (off by default), so advertising it
        // unconditionally was more aggressive than any vanilla client. These
        // bits are relayed to peers (they describe how others should connect to
        // *us*), so dropping REQUIRE doesn't reduce the sources we receive — it
        // just stops us from looking like a require-only client to strict
        // lugdunum servers (e.g. eMule Security) that have been observed
        // dropping the obfuscated login after a valid DH handshake.
        if is_encrypted {
            flags |= SRVCAP_SUPPORTCRYPT | SRVCAP_REQUESTCRYPT;
        }
        let payload = build_login_request(user_hash, tcp_port, nickname, flags);
        info!(
            "Sending OP_LOGINREQUEST ({} bytes, encrypted={}): port={}, flags=0x{:04X}",
            payload.len(),
            is_encrypted,
            tcp_port,
            flags
        );

        let wire_packet = server_wire_packet(OP_EDONKEYHEADER, OP_LOGINREQUEST, &payload)?;

        // Absolute, so it covers the request write and every response read
        // together rather than resetting per packet.
        let login_deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(SERVER_LOGIN_TIMEOUT_SECS);

        tokio::time::timeout(
            std::time::Duration::from_secs(SERVER_WRITE_TIMEOUT_SECS),
            async {
                match &mut self.transport {
                    ServerTransport::Plain { writer, .. } => {
                        writer.write_all(&wire_packet).await?;
                        writer.flush().await
                    }
                    ServerTransport::Encrypted(stream) => stream.write_login(&wire_packet).await,
                }
            },
        )
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "server login write timed out",
            ))
        })?;

        let mut session = ServerSession {
            client_id: 0,
            server_flags: 0,
            server_name: String::new(),
            user_count: 0,
            file_count: 0,
            server_list_data: None,
            motd_messages: Vec::new(),
            server_reported_ip: 0,
        };

        let mut packets_read = 0u32;
        let mut last_error: Option<String> = None;

        for i in 0..50 {
            let (opcode, payload) =
                match tokio::time::timeout_at(login_deadline, self.read_packet()).await {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        info!(
                            "Server read error on packet {i}: kind={:?} msg={e}",
                            e.kind()
                        );
                        last_error = Some(format!("{} ({})", e, e.kind()));
                        break;
                    }
                    Err(_) => {
                        anyhow::bail!(
                            "Login did not complete within {SERVER_LOGIN_TIMEOUT_SECS}s \
                         ({packets_read} packet(s) received, no IDCHANGE)"
                        );
                    }
                };
            packets_read += 1;

            match opcode {
                OP_SERVERMESSAGE => {
                    if payload.len() >= 2 {
                        let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                        if payload.len() >= 2 + len {
                            let msg = crate::security::sanitize_remote_text(
                                &String::from_utf8_lossy(&payload[2..2 + len]),
                                4096,
                            );
                            info!("Server MOTD: {msg}");
                            session.motd_messages.push(msg);
                        }
                    }
                }
                OP_IDCHANGE => {
                    if payload.len() >= 4 {
                        session.client_id =
                            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        if session.client_id == 0 {
                            return Err(anyhow::anyhow!("server rejected login (client_id=0)"));
                        }
                        if payload.len() >= 8 {
                            session.server_flags = u32::from_le_bytes([
                                payload[4], payload[5], payload[6], payload[7],
                            ]);
                            let f = session.server_flags;
                            info!(
                                "Server TCP flags: 0x{f:04X} [{}{}{}{}{}{}{}]",
                                if f & SRV_TCPFLG_COMPRESSION != 0 {
                                    "zlib "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_NEWTAGS != 0 {
                                    "newtags "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_UNICODE != 0 {
                                    "unicode "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_RELATEDSEARCH != 0 {
                                    "relsearch "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_TYPETAGINTEGER != 0 {
                                    "typeint "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_LARGEFILES != 0 {
                                    "large "
                                } else {
                                    ""
                                },
                                if f & SRV_TCPFLG_TCPOBFUSCATION != 0 {
                                    "obfu "
                                } else {
                                    ""
                                },
                            );
                        }
                        if payload.len() >= 16 {
                            let reported_ip = u32::from_le_bytes([
                                payload[12],
                                payload[13],
                                payload[14],
                                payload[15],
                            ]);
                            if reported_ip >= LOWID_THRESHOLD {
                                session.server_reported_ip = reported_ip;
                            }
                        }
                        info!("Server assigned client ID: {}", session.client_id);
                    }
                    return Ok(session);
                }
                OP_SERVERSTATUS => {
                    if payload.len() >= 8 {
                        session.user_count =
                            u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        session.file_count =
                            u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                        debug!(
                            "Server status: {} users, {} files",
                            session.user_count, session.file_count
                        );
                    }
                }
                OP_SERVERIDENT => {
                    if let Some(name) = parse_server_ident_name(&payload) {
                        session.server_name = name;
                        debug!("Server name: {}", session.server_name);
                    }
                }
                OP_SERVERLIST => {
                    debug!("Got server list from server ({} bytes)", payload.len());
                    session.server_list_data = Some(payload);
                }
                OP_REJECT => {
                    anyhow::bail!("Server rejected login");
                }
                _ => {
                    debug!("Login phase: ignoring opcode 0x{opcode:02X}");
                }
            }
        }

        match last_error {
            Some(err) => anyhow::bail!(
                "Server closed connection after {packets_read} packet(s): {err}"
            ),
            None => anyhow::bail!(
                "Login sequence did not complete after {packets_read} packets (no IDCHANGE received)"
            ),
        }
    }

    async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        match &mut self.transport {
            ServerTransport::Plain { reader, .. } => read_server_packet_timeout(reader).await,
            ServerTransport::Encrypted(stream) => {
                tokio::time::timeout(std::time::Duration::from_secs(30), stream.read_packet())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "encrypted server read timed out")
                    })?
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.transport, ServerTransport::Encrypted(_))
    }
}

/// What the reader task hands the network loop.
enum ServerInbound {
    Event(ServerEvent),
    /// The reader has stopped, and why. Nothing follows it.
    Closed(String),
}

/// The network loop's handle on a logged-in server session.
///
/// The socket belongs to two tasks: a reader that decodes packets into
/// [`ServerEvent`]s, and a writer that sends queued packets one at a time,
/// each under `SERVER_WRITE_TIMEOUT_SECS`. Both talk to the loop through
/// bounded queues and nothing on this handle awaits, so a slow or hostile
/// server can stall its own session but not UDP, KAD, the Ember DHT, timers
/// or IPC. Dropping the handle stops both tasks and closes the socket.
///
/// A send returning `Ok` means the packet is queued, not that it reached the
/// server; a write that later fails ends the session through
/// [`ServerLink::write_failure`], which the server tick checks.
pub struct ServerLink {
    pub session: ServerSession,
    /// Connected server's soft per-client file limit (`GetSoftFiles()` in
    /// eMule). 0 = unknown. Used to cap `OP_OFFERFILES` like eMule does.
    soft_files: u32,
    encrypted: bool,
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: mpsc::Receiver<ServerInbound>,
    /// Set by the first failed or timed-out write and never cleared. A write
    /// abandoned part-way leaves a partial frame on the wire and, on an
    /// obfuscated connection, an RC4 send keystream the server no longer
    /// agrees with, so nothing written afterwards can be parsed.
    write_failure: Arc<OnceLock<String>>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl Drop for ServerLink {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

async fn run_server_reader(mut half: ServerReadHalf, inbound: mpsc::Sender<ServerInbound>) {
    loop {
        let (opcode, payload) = match half.read_packet().await {
            Ok(packet) => packet,
            Err(e) => {
                debug!("Server packet read error: {e}");
                let _ = inbound.send(ServerInbound::Closed(e.to_string())).await;
                return;
            }
        };
        info!(
            "Server packet: opcode=0x{opcode:02X}, {} bytes",
            payload.len()
        );
        // Caught so the session ends with the reason attached; an uncaught
        // panic would only show up as the reader having gone away.
        let events = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            parse_server_event(opcode, &payload)
        })) {
            Ok(events) => events,
            Err(panic) => {
                let what = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic payload".to_string());
                let _ = inbound
                    .send(ServerInbound::Closed(format!(
                        "server packet 0x{opcode:02X} parse panicked: {what}"
                    )))
                    .await;
                return;
            }
        };
        for event in events {
            if inbound.send(ServerInbound::Event(event)).await.is_err() {
                return;
            }
        }
    }
}

async fn run_server_writer(
    mut half: ServerWriteHalf,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    write_failure: Arc<OnceLock<String>>,
) {
    while let Some(wire) = outbound.recv().await {
        if let Some(opcode) = wire.get(5) {
            debug!("Server write: opcode=0x{opcode:02X}, wire={} bytes", wire.len());
        }
        if let Err(e) = half.write_packet(&wire).await {
            warn!("Server write failed ({e}); connection marked unusable");
            let _ = write_failure.set(e.to_string());
            return;
        }
    }
}

impl ServerLink {
    fn spawn(
        transport: ServerTransport,
        session: ServerSession,
        write_queue: usize,
        event_queue: usize,
    ) -> Self {
        let encrypted = matches!(transport, ServerTransport::Encrypted(_));
        let (read_half, write_half) = transport.into_halves();
        let (outbound, outbound_rx) = mpsc::channel(write_queue);
        let (inbound_tx, inbound) = mpsc::channel(event_queue);
        let write_failure = Arc::new(OnceLock::new());
        let reader = tokio::spawn(run_server_reader(read_half, inbound_tx));
        let writer = tokio::spawn(run_server_writer(
            write_half,
            outbound_rx,
            write_failure.clone(),
        ));
        Self {
            session,
            soft_files: 0,
            encrypted,
            outbound,
            inbound,
            write_failure,
            reader,
            writer,
        }
    }

    /// Why this session can no longer be written to, if a write has failed or
    /// timed out. Once set the session is unusable and should be dropped.
    pub fn write_failure(&self) -> Option<&str> {
        self.write_failure.get().map(String::as_str)
    }

    /// Up to `max` events the reader has decoded since the last call, in
    /// arrival order, and — if the reader has stopped — why. Never waits.
    pub fn drain_events(&mut self, max: usize) -> (Vec<ServerEvent>, Option<String>) {
        let mut events = Vec::new();
        while events.len() < max {
            match self.inbound.try_recv() {
                Ok(ServerInbound::Event(event)) => events.push(event),
                Ok(ServerInbound::Closed(reason)) => return (events, Some(reason)),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    return (events, Some("server reader stopped".to_string()));
                }
            }
        }
        (events, None)
    }

    /// Queue one packet for the writer. Fails at once, without waiting, when
    /// the session is already broken or the queue is full.
    fn queue_packet(&mut self, protocol: u8, opcode: u8, payload: &[u8]) -> io::Result<()> {
        if let Some(reason) = self.write_failure() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("server connection unusable after earlier write failure: {reason}"),
            ));
        }
        let wire = server_wire_packet(protocol, opcode, payload)?;
        match self.outbound.try_send(wire) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "server write queue full",
            )),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let _ = self.write_failure.set("server writer stopped".to_string());
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "server writer stopped",
                ))
            }
        }
    }

    fn queue(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        self.queue_packet(OP_EDONKEYHEADER, opcode, payload)
    }

    /// Record the connected server's soft per-client file limit so
    /// `offer_files_chunk_limit` can cap each OP_OFFERFILES the way eMule does.
    pub fn set_soft_files(&mut self, soft_files: u32) {
        self.soft_files = soft_files;
    }

    /// Send a pre-built search expression (AND tree or single keyword) as
    /// `OP_SEARCHREQUEST`. Multi-word queries MUST use the AND-tree wire
    /// format for reliable results across all eD2K servers.
    ///
    /// The result arrives later as `ServerEvent::SearchResult`.
    pub fn send_search_expr_bytes(&mut self, expr: &[u8]) -> anyhow::Result<()> {
        // A server without large-file support cannot parse a 64-bit size
        // leaf; the UDP sweep leaves such servers out for the same reason.
        if self.session.server_flags & SRV_TCPFLG_LARGEFILES == 0
            && crate::network::kad::messages::search_expression_uses_64bit(expr)
        {
            anyhow::bail!("server lacks large-file support for a size limit past 4 GiB");
        }
        info!(
            "Queuing OP_SEARCHREQUEST expression ({} bytes payload)",
            expr.len(),
        );
        self.queue(OP_SEARCHREQUEST, expr)?;
        Ok(())
    }

    /// Send a source request to the server (eMule DownloadQueue.cpp format).
    /// Uses OP_GETSOURCES_OBFU only when our connection is encrypted (so our
    /// login advertised crypt) AND the server supports it; otherwise plain
    /// OP_GETSOURCES — see the opcode selection below for why.
    /// Returns the number of bytes sent on the wire (header + opcode +
    /// payload) so callers can attribute the cost to source-exchange
    /// overhead in the Statistics panel. Returns 0 when the request was
    /// silently skipped (e.g. the server lacks LARGEFILES support).
    pub fn send_get_sources(&mut self, file_hash: &[u8; 16], file_size: u64) -> anyhow::Result<u64> {
        let mut payload = Vec::with_capacity(28);
        payload.extend_from_slice(file_hash);
        let srv_flags = self.session.server_flags;
        let supports_large = (srv_flags & SRV_TCPFLG_LARGEFILES) != 0;
        // Match eMule's `CPartFile::IsLargeFile()` boundary (OLD_MAX_EMULE_FILE_SIZE),
        // NOT u32::MAX. Files in the (OLD_MAX_EMULE_FILE_SIZE, u32::MAX] window are
        // large on the wire (uploaders offer them with the 64-bit encoding), so a
        // 32-bit source request won't match the server's large-file index.
        let is_large = file_size > OLD_MAX_EMULE_FILE_SIZE;
        if is_large && !supports_large {
            debug!("Skipping source query for large file — server does not support LARGEFILES");
            return Ok(0);
        }
        if is_large {
            payload.extend_from_slice(&0u32.to_le_bytes());
            payload.extend_from_slice(&file_size.to_le_bytes());
        } else {
            payload.extend_from_slice(&(file_size as u32).to_le_bytes());
        }
        // Only request the *obfuscated* source variant when our login actually
        // advertised crypt support to this server. `login()` only sets
        // SRVCAP_SUPPORTCRYPT/REQUESTCRYPT on an encrypted connection (plain
        // Lugdunum connections that claim crypt get dropped), so on a plain
        // connection we announced "no crypt". Sending OP_GETSOURCES_OBFU there
        // is inconsistent with that login — the server sees a non-crypt client
        // asking for obfuscated sources and silently ignores the request,
        // returning no OP_FOUNDSOURCES at all. eMule keeps these in lockstep
        // (it only emits OP_GETSOURCES_OBFU when its crypt layer is enabled,
        // which is also when its login advertises crypt). Mirror that: use the
        // OBFU opcode only when this connection is encrypted AND the server
        // supports it; otherwise send the plain OP_GETSOURCES.
        let is_encrypted = self.encrypted;
        let opcode = if is_encrypted && (srv_flags & SRV_TCPFLG_TCPOBFUSCATION) != 0 {
            OP_GETSOURCES_OBFU
        } else {
            OP_GETSOURCES
        };
        debug!(
            "OP_GETSOURCES: opcode={} (0x{:02X}), file_size={}, conn_encrypted={}, srv_obfu={}",
            if opcode == OP_GETSOURCES_OBFU {
                "OBFU"
            } else {
                "PLAIN"
            },
            opcode,
            file_size,
            is_encrypted,
            (srv_flags & SRV_TCPFLG_TCPOBFUSCATION) != 0,
        );
        self.queue(opcode, &payload)?;
        // Wire framing: 1 protocol + 4 length + 1 opcode + payload.
        Ok(6 + payload.len() as u64)
    }

    /// eMule keep-alive: send empty OP_OFFERFILES (file count = 0). The only
    /// empty offer that is ever sent; servers read it as nothing else.
    pub fn keep_alive(&mut self) -> anyhow::Result<()> {
        self.queue(OP_OFFERFILES, &0u32.to_le_bytes())?;
        Ok(())
    }

    /// Send eMule's `OP_GETSERVERLIST` to ask the server for its known
    /// peer servers. The response arrives later as `OP_SERVERLIST` and
    /// is parsed by `ServerList::add_from_server_list_packet`. Called
    /// after login when `add_servers_from_server` is enabled.
    pub fn request_server_list(&mut self) -> anyhow::Result<()> {
        self.queue(OP_GETSERVERLIST, &[])?;
        debug!("Queued OP_GETSERVERLIST request to server");
        Ok(())
    }

    /// Ask for the next page of the current search (eMule `SearchMore`).
    pub fn request_more_results(&mut self) -> anyhow::Result<()> {
        self.queue(OP_QUERY_MORE_RESULT, &[])?;
        debug!("Queued OP_QUERY_MORE_RESULT to server");
        Ok(())
    }

    pub fn request_callback(&mut self, client_id: u32) -> anyhow::Result<()> {
        self.queue(OP_CALLBACKREQUEST, &client_id.to_le_bytes())?;
        info!("Queued callback request for LowID client {client_id}");
        Ok(())
    }

    /// Soft per-packet file cap, exactly like eMule's
    /// `CSharedFileList::SendListToServer`:
    ///
    /// ```text
    /// limit = GetSoftFiles(); if (limit == 0 || limit > 200) limit = 200;
    /// ```
    ///
    /// eMule truncates to that many files in a single packet. Sending the
    /// rest as extra `OP_OFFERFILES` packets at once looks like republishing
    /// to Lugdunum, which answers "Too many files republished by your client
    /// software. Please upgrade it." and can blacklist the client.
    pub fn offer_files_chunk_limit(&self) -> usize {
        if self.soft_files == 0 || self.soft_files > 200 {
            200
        } else {
            self.soft_files as usize
        }
    }

    /// Send a single OP_OFFERFILES packet (one chunk), compressed when the
    /// server supports SRV_TCPFLG_COMPRESSION and that makes it smaller.
    ///
    /// Refuses a chunk with nothing this server can index rather than send it
    /// empty: a zero-file OP_OFFERFILES is the keep-alive, not an offer.
    pub fn offer_files_chunk(&mut self, files: &[OfferFile], tcp_port: u16) -> anyhow::Result<()> {
        let srv_flags = self.session.server_flags;
        if !files
            .iter()
            .any(|file| server_indexes_file_size(file.size, srv_flags))
        {
            anyhow::bail!("OP_OFFERFILES chunk has no file this server can index");
        }
        let payload = build_offer_files_payload(files, srv_flags, self.session.client_id, tcp_port);
        // Compress payload if server supports compression (eMule SharedFileList.cpp)
        if (srv_flags & SRV_TCPFLG_COMPRESSION) != 0 && payload.len() > 100 {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write as _;
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
            match encoder.write_all(&payload).and_then(|_| encoder.finish()) {
                Ok(compressed) if compressed.len() < payload.len() => {
                    debug!(
                        "Compressed OP_OFFERFILES: {} -> {} bytes",
                        payload.len(),
                        compressed.len()
                    );
                    self.queue_packet(OP_PACKEDPROT, OP_OFFERFILES, &compressed)?;
                    info!(
                        "Queued compressed OP_OFFERFILES with {} shared files to server",
                        files.len()
                    );
                    return Ok(());
                }
                Ok(_) => debug!("OP_OFFERFILES compression not smaller, sending uncompressed"),
                Err(e) => debug!("OP_OFFERFILES compression failed: {e}, sending uncompressed"),
            }
        }
        self.queue(OP_OFFERFILES, &payload)?;
        info!(
            "Queued OP_OFFERFILES with {} shared files to server",
            files.len()
        );
        Ok(())
    }

    pub fn is_low_id(&self) -> bool {
        self.session.client_id > 0 && self.session.client_id < LOWID_THRESHOLD
    }

    pub fn our_client_id(&self) -> u32 {
        self.session.client_id
    }
}

/// eMule's `EED2KFileType` protocol value (`OtherFunctions.h`, "eserver
/// 17.6+") for an offer's file-type string, when it has one. Archives and CD
/// images are already folded into "Pro" by [`offer_file_type`], matching
/// `GetED2KFileTypeSearchID`; "EmuleCollection" has no integer form.
fn ed2k_file_type_id(file_type: &str) -> Option<u32> {
    match file_type {
        "Audio" => Some(1),
        "Video" => Some(2),
        "Image" => Some(3),
        "Pro" => Some(4),
        "Doc" => Some(5),
        _ => None,
    }
}

/// The `FT_FILETYPE` string eMule publishes for `file_name`:
/// `GetED2KFileTypeSearchTerm(GetED2KFileTypeID(name))`, which files archives
/// and CD images under "Pro" (`OtherFunctions.cpp:1528-1533`). Empty when the
/// extension maps to no type, in which case no tag is sent.
pub fn offer_file_type(file_name: &str) -> String {
    let extension = file_name
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .unwrap_or_default();
    match crate::search::index::infer_file_type(extension).as_str() {
        "Arc" | "Iso" => "Pro".to_string(),
        other => other.to_string(),
    }
}

/// Whether a server with `server_flags` can index a file of `file_size`:
/// past eMule's old 4 GiB limit only with SRV_TCPFLG_LARGEFILES.
pub fn server_indexes_file_size(file_size: u64, server_flags: u32) -> bool {
    file_size <= OLD_MAX_EMULE_FILE_SIZE || server_flags & SRV_TCPFLG_LARGEFILES != 0
}

/// The OP_OFFERFILES body for `files`, using eMule SharedFileList.cpp's
/// per-file encoding; magic client ID/port values stand in for our address
/// when the server supports SRV_TCPFLG_COMPRESSION.
fn build_offer_files_payload(
    files: &[OfferFile],
    srv_flags: u32,
    client_id: u32,
    tcp_port: u16,
) -> Vec<u8> {
    let use_magic_ids = (srv_flags & SRV_TCPFLG_COMPRESSION) != 0;
    // Our address only means something to a peer when we hold a HighID;
    // otherwise eMule offers 0/0 (`SharedFileList.cpp:907-913`).
    let (offered_id, offered_port) = if client_id >= LOWID_THRESHOLD {
        (client_id, tcp_port)
    } else {
        (0, 0)
    };

    let filtered_files: Vec<&OfferFile> = files
        .iter()
        .filter(|file| server_indexes_file_size(file.size, srv_flags))
        .collect();
    if filtered_files.len() != files.len() {
        debug!(
            "OP_OFFERFILES: omitted {} large file(s) because server lacks LARGEFILES",
            files.len() - filtered_files.len()
        );
    }

    let mut payload = Vec::with_capacity(4 + filtered_files.len() * 64);
    payload.extend_from_slice(&(filtered_files.len() as u32).to_le_bytes());
    for file in filtered_files {
        payload.extend_from_slice(&file.hash);

        if use_magic_ids {
            if file.is_complete {
                payload.extend_from_slice(&0xFBFBFBFBu32.to_le_bytes());
                payload.extend_from_slice(&0xFBFBu16.to_le_bytes());
            } else {
                payload.extend_from_slice(&0xFCFCFCFCu32.to_le_bytes());
                payload.extend_from_slice(&0xFCFCu16.to_le_bytes());
            }
        } else {
            payload.extend_from_slice(&offered_id.to_le_bytes());
            payload.extend_from_slice(&offered_port.to_le_bytes());
        }

        let mut tag_count: u32 = 0;
        let mut tags = Vec::new();
        write_string_tag(&mut tags, 0x01, &file.name); // FT_FILENAME
        tag_count += 1;
        // eMule offers files above OLD_MAX_EMULE_FILE_SIZE (not u32::MAX) as
        // large: FT_FILESIZE (low 32) + FT_FILESIZE_HI (high 32, may be 0).
        // Using the same boundary keeps the server's large-file index aligned
        // with our later OP_GETSOURCES so source lookups for ~4 GiB files match.
        if file.size > OLD_MAX_EMULE_FILE_SIZE {
            write_uint32_tag(&mut tags, 0x02, file.size as u32);
            tag_count += 1;
            write_uint32_tag(&mut tags, 0x3A, (file.size >> 32) as u32);
            tag_count += 1;
        } else {
            write_uint32_tag(&mut tags, 0x02, file.size as u32);
            tag_count += 1;
        }
        // FT_FILETYPE (0x03): the integer form for servers that take it and
        // a type that has one, the string otherwise (SharedFileList.cpp:965-983).
        match ed2k_file_type_id(&file.file_type)
            .filter(|_| srv_flags & SRV_TCPFLG_TYPETAGINTEGER != 0)
        {
            Some(type_id) => {
                write_uint32_tag(&mut tags, 0x03, type_id);
                tag_count += 1;
            }
            None if !file.file_type.is_empty() => {
                write_string_tag(&mut tags, 0x03, &file.file_type);
                tag_count += 1;
            }
            None => {}
        }
        payload.extend_from_slice(&tag_count.to_le_bytes());
        payload.extend_from_slice(&tags);
    }
    payload
}

#[derive(Debug, Clone)]
pub enum ServerEvent {
    CallbackRequested {
        ip: String,
        port: u16,
        crypt_options: Option<u8>,
        user_hash: Option<[u8; 16]>,
    },
    CallbackFailed,
    Message(String),
    StatusUpdate {
        users: u32,
        files: u32,
    },
    ServerIdent {
        name: String,
    },
    ServerList {
        data: Vec<u8>,
    },
    SearchResult {
        results: Vec<ServerSearchResult>,
        /// The server's trailing "more results available" byte.
        more: bool,
    },
    FoundSources {
        file_hash: [u8; 16],
        sources: Vec<ServerSource>,
    },
    /// Mid-session `OP_IDCHANGE` — server reassigned our client ID (e.g. after
    /// a successful port-forward retest promotes LowID → HighID).
    IdChange {
        client_id: u32,
        server_flags: u32,
        server_reported_ip: u32,
    },
}

fn parse_server_event(opcode: u8, payload: &[u8]) -> Vec<ServerEvent> {
    let mut events = Vec::new();
    match opcode {
        OP_CALLBACKREQUESTED => {
            if payload.len() >= 6 {
                let ip = std::net::Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let port = u16::from_le_bytes([payload[4], payload[5]]);
                let crypt_options = payload.get(6).copied();
                let user_hash = if payload.len() >= 23 {
                    let mut hash = [0u8; 16];
                    hash.copy_from_slice(&payload[7..23]);
                    Some(hash)
                } else {
                    None
                };
                info!("Callback requested: connect to {ip}:{port}");
                events.push(ServerEvent::CallbackRequested {
                    ip: ip.to_string(),
                    port,
                    crypt_options,
                    user_hash,
                });
            }
        }
        OP_CALLBACK_FAIL => {
            debug!("Server reported callback failure");
            events.push(ServerEvent::CallbackFailed);
        }
        OP_SERVERMESSAGE => {
            if payload.len() >= 2 {
                let len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
                if payload.len() >= 2 + len {
                    let msg = crate::security::sanitize_remote_text(
                        &String::from_utf8_lossy(&payload[2..2 + len]),
                        4096,
                    );
                    events.push(ServerEvent::Message(msg));
                }
            }
        }
        OP_SERVERSTATUS => {
            if payload.len() >= 8 {
                let users = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let files = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                events.push(ServerEvent::StatusUpdate { users, files });
            }
        }
        OP_SERVERIDENT => {
            if let Some(name) = parse_server_ident_name(payload) {
                events.push(ServerEvent::ServerIdent { name });
            }
        }
        OP_SERVERLIST => {
            debug!("Got server list from server ({} bytes)", payload.len());
            events.push(ServerEvent::ServerList {
                data: payload.to_vec(),
            });
        }
        OP_SEARCHRESULT => match parse_search_result(payload) {
            Ok((results, more)) => {
                debug!("Server search result: {} files (more={more})", results.len());
                events.push(ServerEvent::SearchResult { results, more });
            }
            Err(e) => {
                debug!("Failed to parse search result: {e}");
            }
        },
        OP_FOUNDSOURCES | OP_FOUNDSOURCES_OBFU => {
            match parse_found_sources(payload, opcode == OP_FOUNDSOURCES_OBFU) {
                Ok((file_hash, sources)) => {
                    debug!(
                        "Server found {} sources for file {}",
                        sources.len(),
                        hex::encode(file_hash)
                    );
                    events.push(ServerEvent::FoundSources { file_hash, sources });
                }
                Err(e) => {
                    debug!("Failed to parse found sources: {e}");
                }
            }
        }
        OP_IDCHANGE => {
            if payload.len() >= 4 {
                let client_id =
                    u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let server_flags = if payload.len() >= 8 {
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
                } else {
                    0
                };
                let server_reported_ip = if payload.len() >= 16 {
                    let reported =
                        u32::from_le_bytes([payload[12], payload[13], payload[14], payload[15]]);
                    if reported >= LOWID_THRESHOLD {
                        reported
                    } else {
                        0
                    }
                } else {
                    0
                };
                events.push(ServerEvent::IdChange {
                    client_id,
                    server_flags,
                    server_reported_ip,
                });
            }
        }
        _ => {
            debug!("Ignoring server opcode 0x{opcode:02X}");
        }
    }
    events
}

fn parse_server_ident_name(payload: &[u8]) -> Option<String> {
    // eMule: server_hash(16) + server_ip(4) + server_port(2) + tag_count(4) + tags
    if payload.len() < 26 {
        return None;
    }
    let tag_count =
        u32::from_le_bytes([payload[22], payload[23], payload[24], payload[25]]) as usize;
    let mut offset = 26;
    for _ in 0..tag_count.min(32) {
        if offset >= payload.len() {
            break;
        }
        let raw_tag_type = payload[offset];
        offset += 1;
        // eD2K tags have two encodings on the wire. eMule builds network-packet
        // tags with `CTag::WriteNewEd2kTag`, which uses the compact form —
        // `type | 0x80` followed by a single name-id byte instead of a
        // length-prefixed name — whenever the tag has a numeric id, and accepts
        // both forms when parsing. We advertise `SRVCAP_NEWTAGS`, so a server may
        // answer `OP_SERVERIDENT` compactly; handling only the old form meant the
        // first such tag fell through to the catch-all `break` below and the
        // server name was dropped, leaving the list showing a dotted quad for any
        // server learned from an `OP_SERVERLIST` push. The `.met` *file* parsers
        // are correct to reject `0x80`: `CTag::WriteTagToFile` always writes the
        // old form to disk, so the two cases genuinely differ.
        let compact = raw_tag_type & 0x80 != 0;
        let tag_type = raw_tag_type & 0x7F;
        let name_id = if compact {
            if offset >= payload.len() {
                break;
            }
            let id = payload[offset];
            offset += 1;
            Some(id)
        } else {
            if offset + 3 > payload.len() {
                break;
            }
            let name_len = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            if offset + name_len > payload.len() {
                break;
            }
            let id = if name_len == 1 {
                Some(payload[offset])
            } else {
                None
            };
            offset += name_len;
            id
        };

        match tag_type {
            0x02 => {
                if offset + 2 > payload.len() {
                    break;
                }
                let slen = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                if offset + slen > payload.len() {
                    break;
                }
                if name_id == Some(0x01) {
                    if let Ok(s) = std::str::from_utf8(&payload[offset..offset + slen]) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            return Some(crate::security::sanitize_remote_text(trimmed, 256));
                        }
                    }
                }
                offset += slen;
            }
            0x01 => offset = offset.saturating_add(16), // HASH
            0x03 | 0x04 => offset = offset.saturating_add(4), // UINT32/FLOAT32
            0x05 | 0x09 => offset = offset.saturating_add(1), // BOOL/UINT8
            0x06 => {
                if offset + 2 > payload.len() {
                    break;
                }
                let bits = u16::from_le_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset = offset.saturating_add(2 + bits.div_ceil(8));
            }
            0x07 => {
                if offset + 4 > payload.len() {
                    break;
                }
                let len = u32::from_le_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]) as usize;
                offset = offset.saturating_add(4 + len);
            }
            0x08 => offset = offset.saturating_add(2), // UINT16
            0x0A => {
                if offset >= payload.len() {
                    break;
                }
                let len = payload[offset] as usize;
                offset = offset.saturating_add(1 + len);
            }
            0x0B => offset = offset.saturating_add(8), // UINT64
            0x11..=0x20 => {
                let len = (tag_type - 0x10) as usize;
                if offset + len > payload.len() {
                    break;
                }
                if name_id == Some(0x01) {
                    if let Ok(s) = std::str::from_utf8(&payload[offset..offset + len]) {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() {
                            return Some(crate::security::sanitize_remote_text(trimmed, 256));
                        }
                    }
                }
                offset += len;
            }
            _ => break,
        }
        if offset > payload.len() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;

    #[test]
    fn server_ident_skips_standard_unknown_tag_before_name() {
        let mut payload = vec![0u8; 26];
        payload[22..26].copy_from_slice(&2u32.to_le_bytes());
        payload.push(0x07); // TAGTYPE_BLOB
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0x99);
        payload.extend_from_slice(&3u32.to_le_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        payload.push(0x02); // TAGTYPE_STRING
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0x01); // server-name tag id
        payload.extend_from_slice(&8u16.to_le_bytes());
        payload.extend_from_slice(b"MyServer");

        assert_eq!(
            parse_server_ident_name(&payload).as_deref(),
            Some("MyServer")
        );
    }

    /// eMule writes network-packet tags with `WriteNewEd2kTag`, which uses the
    /// compact `type | 0x80` + name-id form for any tag with a numeric id. Only
    /// handling the old form meant the first compact tag hit the catch-all `break`
    /// and the server name was dropped, leaving a dotted quad in the server list.
    #[test]
    fn server_ident_reads_a_compact_name_tag() {
        let mut payload = vec![0u8; 26];
        payload[22..26].copy_from_slice(&1u32.to_le_bytes());
        payload.push(0x02 | 0x80); // compact TAGTYPE_STRING
        payload.push(0x01); // server-name tag id, no length prefix
        payload.extend_from_slice(&8u16.to_le_bytes());
        payload.extend_from_slice(b"Compact!");

        assert_eq!(
            parse_server_ident_name(&payload).as_deref(),
            Some("Compact!")
        );
    }

    /// A compact tag ahead of the name must be skipped correctly rather than
    /// desynchronising the loop or aborting it.
    #[test]
    fn server_ident_skips_a_compact_tag_before_the_name() {
        let mut payload = vec![0u8; 26];
        payload[22..26].copy_from_slice(&2u32.to_le_bytes());
        payload.push(0x03 | 0x80); // compact TAGTYPE_UINT32
        payload.push(0x99);
        payload.extend_from_slice(&7u32.to_le_bytes());
        payload.push(0x02 | 0x80); // compact TAGTYPE_STRING
        payload.push(0x01);
        payload.extend_from_slice(&6u16.to_le_bytes());
        payload.extend_from_slice(b"Second");

        assert_eq!(parse_server_ident_name(&payload).as_deref(), Some("Second"));
    }

    #[tokio::test]
    async fn read_packet_reads_loopback_server_message() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let payload = {
                let mut p = Vec::new();
                p.extend_from_slice(&2u16.to_le_bytes());
                p.extend_from_slice(b"hi");
                p
            };
            let mut packet = Vec::new();
            packet.push(OP_EDONKEYHEADER);
            packet.extend_from_slice(&((1 + payload.len()) as u32).to_le_bytes());
            packet.push(OP_SERVERMESSAGE);
            packet.extend_from_slice(&payload);
            socket.write_all(&packet).await.unwrap();
            socket.flush().await.unwrap();
            let _ = shutdown_rx.await;
        });

        let mut conn = Ed2kServerConnection::connect(addr).await.unwrap();
        let (opcode, payload) = conn.read_packet().await.unwrap();
        let _ = shutdown_tx.send(());
        let events = parse_server_event(opcode, &payload);

        assert!(matches!(
            events.as_slice(),
            [ServerEvent::Message(msg)] if msg == "hi"
        ));
    }

    async fn loopback_connection() -> (Ed2kServerConnection, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap().0 });
        let conn = Ed2kServerConnection::connect(addr).await.unwrap();
        (conn, accept.await.unwrap())
    }

    fn test_session(server_flags: u32) -> ServerSession {
        ServerSession {
            client_id: 0x0102_0304,
            server_flags,
            server_name: String::new(),
            user_count: 0,
            file_count: 0,
            server_list_data: None,
            motd_messages: Vec::new(),
            server_reported_ip: 0,
        }
    }

    async fn loopback_link(write_queue: usize) -> (ServerLink, TcpStream) {
        let (conn, peer) = loopback_connection().await;
        let link = ServerLink::spawn(conn.transport, test_session(0), write_queue, SERVER_EVENT_QUEUE);
        (link, peer)
    }

    fn server_message(text: &str) -> Vec<u8> {
        let mut payload = (text.len() as u16).to_le_bytes().to_vec();
        payload.extend_from_slice(text.as_bytes());
        server_wire_packet(OP_EDONKEYHEADER, OP_SERVERMESSAGE, &payload).unwrap()
    }

    /// Drain the link until `done` holds for everything collected so far, or
    /// five seconds pass.
    async fn drain_until(
        link: &mut ServerLink,
        done: impl Fn(&[ServerEvent], &Option<String>) -> bool,
    ) -> (Vec<ServerEvent>, Option<String>) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut events = Vec::new();
        let mut closed = None;
        while !done(&events, &closed) && std::time::Instant::now() < deadline {
            let (more, reason) = link.drain_events(SERVER_EVENT_QUEUE);
            events.extend(more);
            closed = closed.or(reason);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        (events, closed)
    }

    #[tokio::test]
    async fn the_link_frames_queued_writes_and_delivers_decoded_events() {
        let (mut link, mut peer) = loopback_link(SERVER_WRITE_QUEUE).await;

        link.keep_alive().unwrap();
        let mut wire = [0u8; 10];
        tokio::time::timeout(std::time::Duration::from_secs(5), peer.read_exact(&mut wire))
            .await
            .expect("keep-alive never reached the server")
            .unwrap();
        assert_eq!(
            wire.to_vec(),
            server_wire_packet(OP_EDONKEYHEADER, OP_OFFERFILES, &0u32.to_le_bytes()).unwrap()
        );

        peer.write_all(&server_message("hi")).await.unwrap();
        let (events, closed) = drain_until(&mut link, |events, _| !events.is_empty()).await;
        assert!(matches!(events.as_slice(), [ServerEvent::Message(msg)] if msg == "hi"));
        assert!(closed.is_none());
    }

    /// The whole point of the link: a server that stops reading may stall its
    /// own writer, but every send on the network loop returns at once, and a
    /// full queue is reported as back-pressure rather than a broken session.
    #[tokio::test]
    async fn a_server_that_stops_reading_never_blocks_a_send() {
        let (mut link, _peer) = loopback_link(2).await;
        let payload = vec![0x5Au8; 256 * 1024];

        let mut spent = std::time::Duration::ZERO;
        let mut refused = None;
        for _ in 0..4096 {
            let started = std::time::Instant::now();
            let result = link.send_search_expr_bytes(&payload);
            spent += started.elapsed();
            if let Err(e) = result {
                refused = Some(e);
                break;
            }
            tokio::task::yield_now().await;
        }

        let err = refused.expect("the queue never filled against a server that does not read");
        assert_eq!(
            err.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::WouldBlock)
        );
        assert!(link.write_failure().is_none());
        assert!(spent < std::time::Duration::from_secs(1), "sends took {spent:?}");
    }

    #[tokio::test]
    async fn a_closed_server_is_reported_after_what_it_sent_first() {
        let (mut link, mut peer) = loopback_link(SERVER_WRITE_QUEUE).await;
        peer.write_all(&server_message("bye")).await.unwrap();
        drop(peer);

        let (events, closed) = drain_until(&mut link, |_, closed| closed.is_some()).await;
        assert!(matches!(events.as_slice(), [ServerEvent::Message(msg)] if msg == "bye"));
        assert!(closed.is_some(), "the reader must report the close");
    }

    #[tokio::test]
    async fn dropping_the_link_closes_the_socket() {
        let (link, mut peer) = loopback_link(SERVER_WRITE_QUEUE).await;
        drop(link);

        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), peer.read(&mut buf))
            .await
            .expect("the socket stayed open after the link was dropped")
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn failed_write_makes_every_later_write_fail_fast_without_touching_the_wire() {
        let (mut link, mut peer) = loopback_link(SERVER_WRITE_QUEUE).await;
        assert!(link.write_failure().is_none());

        link.write_failure.set("server write timed out".to_string()).unwrap();

        let err = link.keep_alive().unwrap_err();
        assert_eq!(
            err.downcast_ref::<io::Error>().map(io::Error::kind),
            Some(io::ErrorKind::BrokenPipe)
        );
        assert!(link.request_callback(0x00AB_CDEF).is_err());
        assert!(link.request_more_results().is_err());
        assert!(link.send_get_sources(&[7u8; 16], 1024).is_err());
        assert!(link.offer_files_chunk(&[offer("movie.avi")], 4662).is_err());
        assert!(link.send_search_expr_bytes(b"x").is_err());
        // A later failure does not overwrite the first, root-cause reason.
        assert_eq!(link.write_failure(), Some("server write timed out"));

        drop(link);
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), peer.read(&mut buf))
            .await
            .expect("peer read timed out")
            .unwrap();
        assert_eq!(n, 0, "a broken connection must not put further frames on the wire");
    }

    #[tokio::test]
    async fn socket_write_error_marks_connection_unusable() {
        let (mut link, peer) = loopback_link(SERVER_WRITE_QUEUE).await;
        drop(peer);

        for _ in 0..200 {
            if link.write_failure().is_some() {
                break;
            }
            let _ = link.keep_alive();
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let reason = link
            .write_failure()
            .expect("writes to a closed peer never failed")
            .to_string();
        assert!(!reason.contains("earlier write failure"));

        let err = link.keep_alive().unwrap_err();
        assert!(err.to_string().contains("earlier write failure"));
    }

    fn offer(name: &str) -> OfferFile {
        OfferFile {
            hash: [1u8; 16],
            name: name.to_string(),
            size: 1000,
            is_complete: true,
            file_type: offer_file_type(name),
        }
    }

    /// FT_FILETYPE of the one file in an OP_OFFERFILES body, as
    /// `(tag type, value bytes)`. Every tag the builder writes uses the old
    /// one-byte-name form.
    fn offered_file_type(payload: &[u8]) -> Option<(u8, Vec<u8>)> {
        let mut pos = 4 + 16 + 4 + 2;
        let tag_count = u32::from_le_bytes(payload[pos..pos + 4].try_into().unwrap());
        pos += 4;
        for _ in 0..tag_count {
            let tag_type = payload[pos];
            assert_eq!(u16::from_le_bytes([payload[pos + 1], payload[pos + 2]]), 1);
            let name_id = payload[pos + 3];
            pos += 4;
            let len = match tag_type {
                0x02 => {
                    let len = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
                    pos += 2;
                    len
                }
                0x03 => 4,
                other => panic!("unexpected tag type 0x{other:02X}"),
            };
            let value = payload[pos..pos + len].to_vec();
            pos += len;
            if name_id == 0x03 {
                return Some((tag_type, value));
            }
        }
        None
    }

    #[test]
    fn offer_file_type_follows_emules_search_terms() {
        assert_eq!(offer_file_type("movie.AVI"), "Video");
        assert_eq!(offer_file_type("song.mp3"), "Audio");
        assert_eq!(offer_file_type("photo.jpg"), "Image");
        assert_eq!(offer_file_type("setup.exe"), "Pro");
        assert_eq!(offer_file_type("book.pdf"), "Doc");
        assert_eq!(offer_file_type("backup.tar.gz"), "Pro", "archives publish as Pro");
        assert_eq!(offer_file_type("disc.iso"), "Pro", "CD images publish as Pro");
        assert_eq!(offer_file_type("set.emulecollection"), "EmuleCollection");
        assert_eq!(offer_file_type("README"), "");
        assert_eq!(offer_file_type("odd.unknownext"), "");
    }

    #[test]
    fn offers_carry_the_integer_file_type_to_servers_that_take_it() {
        let flags = SRV_TCPFLG_TYPETAGINTEGER;
        for (name, id) in [("movie.avi", 2u32), ("song.mp3", 1), ("pack.zip", 4), ("book.pdf", 5)] {
            let payload = build_offer_files_payload(&[offer(name)], flags, 0, 4662);
            assert_eq!(
                offered_file_type(&payload),
                Some((0x03, id.to_le_bytes().to_vec())),
                "{name}"
            );
        }
    }

    #[test]
    fn offers_fall_back_to_the_file_type_string() {
        let payload = build_offer_files_payload(&[offer("movie.avi")], 0, 0, 4662);
        assert_eq!(offered_file_type(&payload), Some((0x02, b"Video".to_vec())));

        // No integer form exists for a collection, even on a server that
        // takes integers (`SharedFileList.cpp:975-982`).
        let payload = build_offer_files_payload(
            &[offer("set.emulecollection")],
            SRV_TCPFLG_TYPETAGINTEGER,
            0,
            4662,
        );
        assert_eq!(
            offered_file_type(&payload),
            Some((0x02, b"EmuleCollection".to_vec()))
        );

        let payload = build_offer_files_payload(&[offer("README")], SRV_TCPFLG_TYPETAGINTEGER, 0, 4662);
        assert_eq!(offered_file_type(&payload), None);
    }

    /// `(client id, port)` the first file in an OP_OFFERFILES body is offered
    /// under.
    fn offered_address(payload: &[u8]) -> (u32, u16) {
        let at = 4 + 16;
        (
            u32::from_le_bytes(payload[at..at + 4].try_into().unwrap()),
            u16::from_le_bytes([payload[at + 4], payload[at + 5]]),
        )
    }

    #[test]
    fn only_a_highid_offers_its_address() {
        let highid = 0x0102_0304;
        let lowid = 0x00AB_CDEF;
        let files = [offer("movie.avi")];
        assert_eq!(
            offered_address(&build_offer_files_payload(&files, 0, highid, 4662)),
            (highid, 4662)
        );
        assert_eq!(
            offered_address(&build_offer_files_payload(&files, 0, lowid, 4662)),
            (0, 0)
        );
        assert_eq!(
            offered_address(&build_offer_files_payload(&files, SRV_TCPFLG_COMPRESSION, lowid, 4662)),
            (0xFBFB_FBFB, 0xFBFB),
            "the status markers do not depend on our ID"
        );
    }

    #[tokio::test]
    async fn a_chunk_the_server_cannot_index_is_refused_rather_than_sent_empty() {
        let (mut link, _peer) = loopback_link(SERVER_WRITE_QUEUE).await;
        assert_eq!(link.session.server_flags & SRV_TCPFLG_LARGEFILES, 0);

        assert!(link.offer_files_chunk(&[], 4662).is_err());
        let mut huge = offer("disc.iso");
        huge.size = OLD_MAX_EMULE_FILE_SIZE + 1;
        assert!(link.offer_files_chunk(&[huge], 4662).is_err());
        assert!(link.offer_files_chunk(&[offer("disc.iso")], 4662).is_ok());
        assert!(!server_indexes_file_size(OLD_MAX_EMULE_FILE_SIZE + 1, 0));
        assert!(server_indexes_file_size(OLD_MAX_EMULE_FILE_SIZE + 1, SRV_TCPFLG_LARGEFILES));
    }

    fn search_result_payload(declared: u32, records: u32, trailing: &[u8]) -> Vec<u8> {
        let mut payload = declared.to_le_bytes().to_vec();
        for n in 0..records {
            payload.extend_from_slice(&[n as u8; 16]);
            payload.extend_from_slice(&0x0102_0304u32.to_le_bytes());
            payload.extend_from_slice(&4662u16.to_le_bytes());
            payload.extend_from_slice(&0u32.to_le_bytes());
        }
        payload.extend_from_slice(trailing);
        payload
    }

    #[test]
    fn search_result_reads_the_more_results_byte() {
        let more = |payload: Vec<u8>| parse_search_result(&payload).unwrap().1;
        assert!(more(search_result_payload(2, 2, &[0x01])));
        assert!(more(search_result_payload(0, 0, &[0x01])));
        assert!(!more(search_result_payload(2, 2, &[0x00])));
        assert!(!more(search_result_payload(2, 2, &[])));
        assert!(!more(search_result_payload(2, 2, &[0x02])), "only 0x01 means more");
        assert!(!more(search_result_payload(2, 2, &[0x01, 0x01])), "extra data is not a flag");
    }

    #[test]
    fn a_truncated_search_result_never_asks_for_more() {
        let (results, more) = parse_search_result(&search_result_payload(3, 2, &[0x01])).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!more);
    }

    // ---- Boolean search tree tests (L12) ----

    #[test]
    fn search_tree_simple_string() {
        let expr = SearchExpression::String("test".into());
        let buf = build_search_tree(&expr);
        // SEARCH_LEAF_STRING(0x01) + len(u16 LE) + "test"
        assert_eq!(buf, vec![0x01, 0x04, 0x00, b't', b'e', b's', b't']);
    }

    #[test]
    fn search_tree_and_two_strings() {
        let expr = SearchExpression::And(
            Box::new(SearchExpression::String("hello".into())),
            Box::new(SearchExpression::String("world".into())),
        );
        let buf = build_search_tree(&expr);
        assert_eq!(&buf[0..2], &[0x00, 0x00]); // operator, AND
                                               // left leaf
        assert_eq!(buf[2], 0x01); // STRING
        assert_eq!(u16::from_le_bytes([buf[3], buf[4]]), 5);
        assert_eq!(&buf[5..10], b"hello");
        // right leaf
        assert_eq!(buf[10], 0x01); // STRING
        assert_eq!(u16::from_le_bytes([buf[11], buf[12]]), 5);
        assert_eq!(&buf[13..18], b"world");
    }

    #[test]
    fn search_tree_or_not() {
        // OR("a", NOT("b", "c"))
        //  [0]  operator, OR
        //  [2]  STRING leaf "a": 0x01, len_lo, len_hi, 'a'
        //  [6]  operator, NOT
        //  [8]  STRING leaf "b": 0x01, len_lo, len_hi, 'b'
        // [12]  STRING leaf "c": 0x01, len_lo, len_hi, 'c'
        let expr = SearchExpression::Or(
            Box::new(SearchExpression::String("a".into())),
            Box::new(SearchExpression::Not(
                Box::new(SearchExpression::String("b".into())),
                Box::new(SearchExpression::String("c".into())),
            )),
        );
        let buf = build_search_tree(&expr);
        assert_eq!(&buf[0..2], &[0x00, 0x01]); // OR
        assert_eq!(buf[2], 0x01); // STRING leaf "a"
        assert_eq!(&buf[6..8], &[0x00, 0x02]); // NOT
        assert_eq!(buf[8], 0x01); // STRING "b"
        assert_eq!(buf[12], 0x01); // STRING "c"
        assert_eq!(buf.len(), 16);
    }

    /// The reference tree exists to catch the live encoder drifting, so the
    /// two must agree on every boolean shape.
    #[test]
    fn search_tree_matches_the_live_query_encoder() {
        use crate::search::query::QueryExpr;
        let term = |s: &str| QueryExpr::Term(s.to_string());
        let live = QueryExpr::Or(
            Box::new(term("aaa")),
            Box::new(QueryExpr::Not(
                Box::new(QueryExpr::And(Box::new(term("bbb")), Box::new(term("ccc")))),
                Box::new(term("ddd")),
            )),
        )
        .to_wire_bytes();
        let string = |s: &str| Box::new(SearchExpression::String(s.to_string()));
        let reference = SearchExpression::Or(
            string("aaa"),
            Box::new(SearchExpression::Not(
                Box::new(SearchExpression::And(string("bbb"), string("ccc"))),
                string("ddd"),
            )),
        );
        assert_eq!(build_search_tree(&reference), live);
    }

    #[test]
    fn search_tree_min_size() {
        let expr = SearchExpression::MinSize(1_048_576);
        let buf = build_search_tree(&expr);
        assert_eq!(buf[0], 0x03); // META_UINT32
        assert_eq!(
            u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            1_048_576
        );
        assert_eq!(buf[5], 0x03); // GREATER_EQUAL
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 1);
        assert_eq!(buf[8], 0x02); // FT_FILESIZE
    }

    #[test]
    fn search_tree_max_size() {
        let expr = SearchExpression::MaxSize(500_000);
        let buf = build_search_tree(&expr);
        assert_eq!(buf[0], 0x03);
        assert_eq!(
            u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]),
            500_000
        );
        assert_eq!(buf[5], 0x04); // LESS_EQUAL
        assert_eq!(buf[8], 0x02); // FT_FILESIZE
    }

    #[test]
    fn search_tree_file_type() {
        let expr = SearchExpression::FileType("Audio".into());
        let buf = build_search_tree(&expr);
        assert_eq!(buf[0], 0x02); // META_STRING
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 5);
        assert_eq!(&buf[3..8], b"Audio");
        assert_eq!(u16::from_le_bytes([buf[8], buf[9]]), 1);
        assert_eq!(buf[10], 0x03); // FT_FILETYPE
    }

    #[test]
    fn search_tree_file_extension() {
        let expr = SearchExpression::FileExtension("mp3".into());
        let buf = build_search_tree(&expr);
        assert_eq!(buf[0], 0x02); // META_STRING
        assert_eq!(u16::from_le_bytes([buf[1], buf[2]]), 3);
        assert_eq!(&buf[3..6], b"mp3");
        assert_eq!(u16::from_le_bytes([buf[6], buf[7]]), 1);
        assert_eq!(buf[8], 0x04); // FT_FILEFORMAT
    }

    #[test]
    fn search_tree_min_availability() {
        let expr = SearchExpression::MinAvailability(5);
        let buf = build_search_tree(&expr);
        assert_eq!(buf[0], 0x03);
        assert_eq!(u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]), 5);
        assert_eq!(buf[5], 0x03); // GREATER_EQUAL
        assert_eq!(buf[8], 0x15); // FT_SOURCES
    }

    #[test]
    fn search_tree_compound_expression() {
        // "linux" AND FileType("Archive") AND MinSize(1MB)
        let expr = SearchExpression::And(
            Box::new(SearchExpression::And(
                Box::new(SearchExpression::String("linux".into())),
                Box::new(SearchExpression::FileType("Archive".into())),
            )),
            Box::new(SearchExpression::MinSize(1_048_576)),
        );
        let buf = build_search_tree(&expr);
        // Outer AND
        assert_eq!(&buf[0..2], &[0x00, 0x00]);
        // Inner AND
        assert_eq!(&buf[2..4], &[0x00, 0x00]);
        // "linux" string leaf
        assert_eq!(buf[4], 0x01);
        assert!(buf.len() > 25);
    }

    #[test]
    fn existing_simple_search_unchanged() {
        let buf = build_search_request("test");
        assert_eq!(buf, vec![0x01, 0x04, 0x00, b't', b'e', b's', b't']);
    }

    #[test]
    fn search_result_extracts_media_rating_and_comment() {
        fn put_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u16).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        fn old_name(buf: &mut Vec<u8>, tag_type: u8, name: &str) {
            buf.push(tag_type); // no high bit => old format
            buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
            buf.extend_from_slice(name.as_bytes());
        }

        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_le_bytes()); // result count
        payload.extend_from_slice(&[0u8; 16]); // file hash
        payload.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // HighID client id
        payload.extend_from_slice(&4662u16.to_le_bytes()); // client port
        payload.extend_from_slice(&7u32.to_le_bytes()); // tag count

        // FT_FILENAME (new-format string, name id 0x01)
        payload.push(0x02 | 0x80);
        payload.push(0x01);
        put_str(&mut payload, "song.mp3");
        // FT_FILESIZE (new-format uint32, name id 0x02)
        payload.push(0x03 | 0x80);
        payload.push(0x02);
        payload.extend_from_slice(&5_000_000u32.to_le_bytes());
        // media length as old-format string "length" = "3:45"
        old_name(&mut payload, 0x02, "length");
        put_str(&mut payload, "3:45");
        // bitrate as old-format uint32 "bitrate" = 192
        old_name(&mut payload, 0x03, "bitrate");
        payload.extend_from_slice(&192u32.to_le_bytes());
        // codec as old-format string "codec" = "mp3"
        old_name(&mut payload, 0x02, "codec");
        put_str(&mut payload, "mp3");
        // FT_FILERATING (new-format uint32, name id 0xF7) = 4
        payload.push(0x03 | 0x80);
        payload.push(0xF7);
        payload.extend_from_slice(&4u32.to_le_bytes());
        // FT_FILECOMMENT (new-format string, name id 0xF6)
        payload.push(0x02 | 0x80);
        payload.push(0xF6);
        put_str(&mut payload, "great rip");

        let (results, more) = parse_search_result(&payload).expect("parse");
        assert!(!more);
        assert_eq!(results.len(), 1);
        let r = &results[0];
        assert_eq!(r.file_name, "song.mp3");
        assert_eq!(r.file_size, 5_000_000);
        assert_eq!(r.media.duration, Some(3 * 60 + 45));
        assert_eq!(r.media.bitrate, Some(192));
        assert_eq!(r.media.codec.as_deref(), Some("mp3"));
        assert_eq!(r.rating, Some(4));
        assert_eq!(r.comment.as_deref(), Some("great rip"));
    }
}

// CT_SERVER_FLAGS capability bits (from eMule Opcodes.h)
const SRVCAP_ZLIB: u32 = 0x0001;
const SRVCAP_NEWTAGS: u32 = 0x0008;
const SRVCAP_UNICODE: u32 = 0x0010;
const SRVCAP_LARGEFILES: u32 = 0x0100;
const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
// Documented for completeness but intentionally never advertised: stock eMule
// only sets this when the user enables "require obfuscated server connection"
// (off by default), and advertising it unconditionally made strict lugdunum
// servers drop our obfuscated login. See `login()`.
#[allow(dead_code)]
const SRVCAP_REQUIRECRYPT: u32 = 0x0800;

const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

fn build_login_request(user_hash: &[u8; 16], tcp_port: u16, nickname: &str, flags: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    // eMule: WriteHash16 + WriteUInt32(clientID) + WriteUInt16(port)
    buf.extend_from_slice(user_hash);
    buf.extend_from_slice(&0u32.to_le_bytes()); // client ID 0 = request new
    buf.extend_from_slice(&tcp_port.to_le_bytes());

    // eMule sends exactly 4 tags
    let tag_count: u32 = 4;
    buf.extend_from_slice(&tag_count.to_le_bytes());

    // Tag 1: CT_NAME (0x01) - nickname string
    write_string_tag(&mut buf, CT_NAME, nickname);

    // Tag 2: CT_VERSION (0x11) - EDONKEYVERSION = 0x3C
    write_uint32_tag(&mut buf, CT_VERSION, 0x3C);

    // Tag 3: CT_SERVER_FLAGS (0x20) - capability flags
    write_uint32_tag(&mut buf, CT_SERVER_FLAGS, flags);

    // Tag 4: CT_EMULE_VERSION (0xFB) - (compat << 24) | (major << 17) | (minor << 10) | (update << 7)
    // Claim 0.50a (last official eMule release) — must match build_hello_inner.
    // The update field is the letter's offset from 'a' (`Emule.cpp:316`), so
    // 'a' is 0.
    let emule_version: u32 = 50u32 << 10;
    write_uint32_tag(&mut buf, CT_EMULE_VERSION, emule_version);

    buf
}

fn write_string_tag(buf: &mut Vec<u8>, name_id: u8, value: &str) {
    buf.push(0x02); // TAGTYPE_STRING
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    // Truncate at a UTF-8 char boundary rather than an arbitrary byte
    // offset, so an overlong value never splits a multi-byte codepoint
    // (the receiving peer decodes this as UTF-8 and would otherwise show
    // a mangled/replacement-character tail).
    let max_len = u16::MAX as usize;
    let clamped = if value.len() <= max_len {
        value
    } else {
        let mut end = max_len;
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        &value[..end]
    };
    let clamped = clamped.as_bytes();
    buf.extend_from_slice(&(clamped.len() as u16).to_le_bytes());
    buf.extend_from_slice(clamped);
}

fn write_uint32_tag(buf: &mut Vec<u8>, name_id: u8, value: u32) {
    buf.push(0x03); // TAGTYPE_UINT32
    buf.extend_from_slice(&1u16.to_le_bytes()); // name length = 1
    buf.push(name_id);
    buf.extend_from_slice(&value.to_le_bytes());
}

// The plain single-keyword OP_SEARCHREQUEST payload. Kept because
// `existing_simple_search_unchanged` pins these bytes: live searches always
// send the AND-tree form, so nothing outside the tests builds one.
#[allow(dead_code)]
fn build_search_request(query: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x01); // Search type: string
    let clamped = &query.as_bytes()[..query.len().min(u16::MAX as usize)];
    buf.extend_from_slice(&(clamped.len() as u16).to_le_bytes());
    buf.extend_from_slice(clamped);
    buf
}

// ---------------------------------------------------------------------------
// Boolean search tree support (L12)
// ---------------------------------------------------------------------------

// ED2K search comparison operators (SearchFile.h). `write_search_node` emits
// only the two `_EQUAL` bounds; the rest complete the operator space so a new
// `SearchExpression` variant does not have to re-derive the numbering from
// eMule. Dead outside `cargo test` for the reason given on `SearchExpression`.
#[allow(dead_code)]
const ED2K_SEARCH_OP_EQUAL: u8 = 0x00;
#[allow(dead_code)]
const ED2K_SEARCH_OP_GREATER: u8 = 0x01;
#[allow(dead_code)]
const ED2K_SEARCH_OP_LESS: u8 = 0x02;
#[allow(dead_code)]
const ED2K_SEARCH_OP_GREATER_EQUAL: u8 = 0x03;
#[allow(dead_code)]
const ED2K_SEARCH_OP_LESS_EQUAL: u8 = 0x04;
#[allow(dead_code)]
const ED2K_SEARCH_OP_NOTEQUAL: u8 = 0x05;

// Wire-format node type bytes for the search tree. All read by
// `write_search_node`, so they are dead only because it is. An operator node
// is `SEARCH_NODE_OPERATOR` followed by one of the `SEARCH_BOOL_*` bytes.
#[allow(dead_code)]
const SEARCH_NODE_OPERATOR: u8 = 0x00;
#[allow(dead_code)]
const SEARCH_BOOL_AND: u8 = 0x00;
#[allow(dead_code)]
const SEARCH_BOOL_OR: u8 = 0x01;
#[allow(dead_code)]
const SEARCH_BOOL_NOT: u8 = 0x02;
#[allow(dead_code)]
const SEARCH_LEAF_STRING: u8 = 0x01;
#[allow(dead_code)]
const SEARCH_LEAF_META_STRING: u8 = 0x02;
#[allow(dead_code)]
const SEARCH_LEAF_META_UINT32: u8 = 0x03;

// Single-byte tag-name IDs used inside search meta constraints. Read only by
// `write_search_node`, same as the node bytes above.
#[allow(dead_code)]
const FT_FILESIZE_TAG: u8 = 0x02;
#[allow(dead_code)]
const FT_FILETYPE_TAG: u8 = 0x03;
#[allow(dead_code)]
const FT_FILEFORMAT_TAG: u8 = 0x04;
#[allow(dead_code)]
const FT_SOURCES_TAG: u8 = 0x15;

/// A boolean search expression tree matching eMule's OP_SEARCHREQUEST wire format.
///
/// Operators carry two children (prefix notation on the wire: operator byte,
/// then left subtree, then right subtree).  Leaf nodes encode either a plain
/// search string or a typed meta-constraint (size, type, extension, sources).
///
/// Nothing in a release build constructs one: live searches serialize through
/// [`crate::network::kad::messages::build_search_expression_with_node`], which
/// also covers Kad and 64-bit size leaves, and go out via
/// [`ServerLink::send_search_expr_bytes`]. This tree and its helpers
/// are kept because the `search_tree_*` tests pin the eD2K search wire format
/// byte for byte, independently of that shared builder — which is what would
/// catch the shared builder drifting away from what eD2K servers accept.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum SearchExpression {
    String(String),
    And(Box<SearchExpression>, Box<SearchExpression>),
    Or(Box<SearchExpression>, Box<SearchExpression>),
    Not(Box<SearchExpression>, Box<SearchExpression>),
    MinSize(u64),
    MaxSize(u64),
    FileType(String),
    FileExtension(String),
    MinAvailability(u32),
}

/// Serialize a [`SearchExpression`] tree into the eMule search-request wire
/// format suitable for use as the payload of an `OP_SEARCHREQUEST` packet.
///
/// Called by the `search_tree_*` tests only — see [`SearchExpression`].
#[allow(dead_code)]
pub fn build_search_tree(expr: &SearchExpression) -> Vec<u8> {
    let mut buf = Vec::new();
    write_search_node(&mut buf, expr);
    buf
}

// Reached only through `build_search_tree`, and recursively from itself.
#[allow(dead_code)]
fn write_search_node(buf: &mut Vec<u8>, expr: &SearchExpression) {
    match expr {
        SearchExpression::String(s) => {
            buf.push(SEARCH_LEAF_STRING);
            let bytes = s.as_bytes();
            let max_len = bytes.len().min(u16::MAX as usize);
            let clamped_len = truncate_utf8_safe(bytes, max_len);
            buf.extend_from_slice(&(clamped_len as u16).to_le_bytes());
            buf.extend_from_slice(&bytes[..clamped_len]);
        }
        SearchExpression::And(left, right) => {
            buf.extend([SEARCH_NODE_OPERATOR, SEARCH_BOOL_AND]);
            write_search_node(buf, left);
            write_search_node(buf, right);
        }
        SearchExpression::Or(left, right) => {
            buf.extend([SEARCH_NODE_OPERATOR, SEARCH_BOOL_OR]);
            write_search_node(buf, left);
            write_search_node(buf, right);
        }
        SearchExpression::Not(left, right) => {
            buf.extend([SEARCH_NODE_OPERATOR, SEARCH_BOOL_NOT]);
            write_search_node(buf, left);
            write_search_node(buf, right);
        }
        SearchExpression::MinSize(size) => {
            let clamped = (*size).min(u32::MAX as u64) as u32;
            write_search_meta_uint32(buf, clamped, ED2K_SEARCH_OP_GREATER_EQUAL, FT_FILESIZE_TAG);
        }
        SearchExpression::MaxSize(size) => {
            let clamped = (*size).min(u32::MAX as u64) as u32;
            write_search_meta_uint32(buf, clamped, ED2K_SEARCH_OP_LESS_EQUAL, FT_FILESIZE_TAG);
        }
        SearchExpression::FileType(t) => {
            write_search_meta_string(buf, t, FT_FILETYPE_TAG);
        }
        SearchExpression::FileExtension(ext) => {
            write_search_meta_string(buf, ext, FT_FILEFORMAT_TAG);
        }
        SearchExpression::MinAvailability(avail) => {
            write_search_meta_uint32(buf, *avail, ED2K_SEARCH_OP_GREATER_EQUAL, FT_SOURCES_TAG);
        }
    }
}

/// Find the largest byte index <= max_len that doesn't split a multi-byte UTF-8 codepoint.
///
/// Only `write_search_node` calls it.
#[allow(dead_code)]
fn truncate_utf8_safe(bytes: &[u8], max_len: usize) -> usize {
    let mut len = max_len.min(bytes.len());
    while len > 0 && (bytes[len - 1] & 0xC0) == 0x80 {
        len -= 1;
    }
    if len > 0 && bytes[len - 1] >= 0xC0 {
        let start = len - 1;
        let expected = if bytes[start] < 0xE0 {
            2
        } else if bytes[start] < 0xF0 {
            3
        } else {
            4
        };
        if start + expected > max_len {
            len = start;
        }
    }
    len
}

/// Wire format: `0x03 | value(u32 LE) | comparison_op(u8) | tag_name_len(u16 LE) | tag_name`
///
/// Only `write_search_node` calls it.
#[allow(dead_code)]
fn write_search_meta_uint32(buf: &mut Vec<u8>, value: u32, op: u8, tag_name_id: u8) {
    buf.push(SEARCH_LEAF_META_UINT32);
    buf.extend_from_slice(&value.to_le_bytes());
    buf.push(op);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.push(tag_name_id);
}

/// Wire format: `0x02 | value_len(u16 LE) | value | tag_name_len(u16 LE) | tag_name`
///
/// Only `write_search_node` calls it.
#[allow(dead_code)]
fn write_search_meta_string(buf: &mut Vec<u8>, value: &str, tag_name_id: u8) {
    buf.push(SEARCH_LEAF_META_STRING);
    let bytes = value.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf.extend_from_slice(&1u16.to_le_bytes());
    buf.push(tag_name_id);
}

/// Read one eMule-style tag (supports both old and "new tags" compressed format).
/// Returns (name_id, tag_type, was read successfully).
fn read_tag_header(cursor: &mut Cursor<&[u8]>) -> Option<(u8, u8, Option<String>)> {
    let raw_type = ReadBytesExt::read_u8(cursor).ok()?;

    if raw_type & 0x80 != 0 {
        // New tag format: high bit set → single-byte name follows, type is low 7 bits
        let tag_type = raw_type & 0x7F;
        let name_id = ReadBytesExt::read_u8(cursor).ok()?;
        Some((name_id, tag_type, None))
    } else {
        // Old format: u16 name length + name bytes
        let name_len = ReadBytesExt::read_u16::<LittleEndian>(cursor).ok()? as usize;
        // Cap the name length before allocating: a hostile/buggy server can
        // advertise name_len up to 65535 on every tag (256 tags/result), and
        // `vec![0u8; name_len]` is allocated before the read can fail. eMule
        // tag names are tiny; 256 matches `messages.rs` MAX_TAG_NAME_LEN.
        const MAX_TAG_NAME_LEN: usize = 256;
        if name_len > MAX_TAG_NAME_LEN {
            return None;
        }
        if name_len == 1 {
            let name_id = ReadBytesExt::read_u8(cursor).ok()?;
            Some((name_id, raw_type, None))
        } else {
            // Preserve the string name: ED2K servers send media metadata under
            // string tag names ("Artist"/"length"/"bitrate"/"codec"/...), which
            // map to no single-byte id. Lowercased so the caller can match
            // case-insensitively.
            let mut name_buf = vec![0u8; name_len];
            Read::read_exact(cursor, &mut name_buf).ok()?;
            let name = String::from_utf8_lossy(&name_buf).to_ascii_lowercase();
            Some((0u8, raw_type, Some(name)))
        }
    }
}

/// Accumulator for the per-result tags we care about (filled across the tag
/// loop, then moved into a [`ServerSearchResult`]).
#[derive(Default)]
struct ServerResultTags {
    file_name: String,
    file_size: u64,
    source_count: u32,
    complete_sources: u32,
    rating: Option<u8>,
    comment: Option<String>,
    media: crate::types::MediaMetadata,
}

/// Parse an eMule media-length string ("h:mm:ss" / "mm:ss" / "ss") into whole
/// seconds (matches `ConvertED2KTag` in eMule's SearchFile.cpp).
fn parse_media_length_str(s: &str) -> Option<u32> {
    let parts: Vec<u32> = s
        .split(':')
        .map(|p| p.trim().parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()?;
    match parts.as_slice() {
        // Saturating: a garbage wire string ("99999:99999:99999") would
        // otherwise wrap in release and report a nonsense duration.
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

impl ServerResultTags {
    /// Route a decoded string value to the right field by tag id (KAD-style
    /// byte ids) or, for old-format tags, by lowercased name.
    fn apply_string(&mut self, name_id: u8, name: Option<&str>, value: String) {
        let value = crate::security::sanitize_remote_text(&value, 8192);
        if name_id == 0x01 {
            self.file_name = value;
            return;
        }
        if value.is_empty() {
            return;
        }
        let is = |n: &str| name == Some(n);
        match name_id {
            0xF6 => self.comment = Some(value),
            0xD0 => self.media.artist = Some(value),
            0xD1 => self.media.album = Some(value),
            0xD2 => self.media.title = Some(value),
            0xD5 => self.media.codec = Some(value),
            0xD3 => self.media.duration = parse_media_length_str(&value),
            _ if is("comment") || is("description") => self.comment = Some(value),
            _ if is("artist") => self.media.artist = Some(value),
            _ if is("album") => self.media.album = Some(value),
            _ if is("title") => self.media.title = Some(value),
            _ if is("codec") => self.media.codec = Some(value),
            _ if is("length") => self.media.duration = parse_media_length_str(&value),
            _ => {}
        }
    }

    /// Route a decoded unsigned-int value to the right field by tag id or name.
    fn apply_uint(&mut self, name_id: u8, name: Option<&str>, value: u64) {
        let is = |n: &str| name == Some(n);
        // Clamp rather than `as`-truncate, exactly as the UDP parser for these
        // same tag ids does (`server_udp.rs::apply_udp_uint_tag`), so an
        // oversized wire value lands somewhere predictable instead of wrapping
        // into an arbitrary one (a truncated 256 reads as 0 stars, 261 as 5).
        // FT_FILERATING is the low byte (`1..=5`); packed DWORDs also carry a
        // vote count in the upper bytes, so clamping the whole integer with
        // `min(5)` used to map those to five stars.
        match name_id {
            0x15 => self.source_count = value.min(u32::MAX as u64) as u32,
            0x30 => self.complete_sources = value.min(u32::MAX as u64) as u32,
            0xD3 if value > 0 => self.media.duration = Some(value as u32),
            0xD4 if value > 0 => self.media.bitrate = Some(value as u32),
            0xF7 => self.rating = super::comments::unpack_file_rating(value),
            _ if is("bitrate") && value > 0 => self.media.bitrate = Some(value as u32),
            _ if is("length") && value > 0 => self.media.duration = Some(value as u32),
            _ if (is("filerating") || is("rating")) => {
                self.rating = super::comments::unpack_file_rating(value)
            }
            _ => {}
        }
    }
}

/// Read and skip a tag value, extracting file metadata we care about.
/// Handles all eMule tag types including TAGTYPE_STR1..STR16 (0x11..0x20).
fn read_tag_value(
    cursor: &mut Cursor<&[u8]>,
    tag_type: u8,
    name_id: u8,
    name: Option<&str>,
    sink: &mut ServerResultTags,
) -> bool {
    match tag_type {
        // TAGTYPE_HASH (0x01)
        0x01 => {
            let mut buf = [0u8; 16];
            Read::read_exact(cursor, &mut buf).is_ok()
        }
        // TAGTYPE_STRING (0x02)
        0x02 => {
            let slen = match ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                Ok(v) => v as usize,
                Err(_) => return false,
            };
            let start = cursor.position() as usize;
            let end = start.saturating_add(slen);
            if end > cursor.get_ref().len() {
                return false;
            }
            let bytes = cursor.get_ref().get(start..end).unwrap_or(&[]);
            cursor.set_position(end as u64);
            let keep = &bytes[..bytes.len().min(8192)];
            sink.apply_string(name_id, name, String::from_utf8_lossy(keep).to_string());
            true
        }
        // TAGTYPE_UINT32 (0x03)
        0x03 => {
            let v = match ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                Ok(v) => v,
                Err(_) => return false,
            };
            match name_id {
                0x02 => sink.file_size = (sink.file_size & 0xFFFF_FFFF_0000_0000) | v as u64,
                0x3A => {
                    sink.file_size = (sink.file_size & 0x0000_0000_FFFF_FFFF) | ((v as u64) << 32)
                }
                _ => sink.apply_uint(name_id, name, v as u64),
            }
            true
        }
        // TAGTYPE_FLOAT32 (0x04)
        0x04 => {
            let mut buf = [0u8; 4];
            Read::read_exact(cursor, &mut buf).is_ok()
        }
        // TAGTYPE_BOOL (0x05)
        0x05 => {
            let _ = ReadBytesExt::read_u8(cursor);
            true
        }
        // TAGTYPE_BOOLARRAY (0x06): u16 bit count followed by ceil(count/8)
        // bytes. We don't consume the bits, but we MUST advance past them —
        // returning `false` here (as the previous `_ => false` did) aborted
        // the whole tag loop for the result, dropping the file_size/file_name
        // tags that follow. Matches `server_udp.rs`.
        0x06 => {
            if let Ok(count) = ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                let skip = (count as usize + 7) / 8;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_BLOB (0x07)
        0x07 => {
            if let Ok(blob_len) = ReadBytesExt::read_u32::<LittleEndian>(cursor) {
                let skip = blob_len as usize;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                // checked_add: avoid pos+skip wrapping on 32-bit usize, which
                // could let a bogus length pass the `<= len` gate.
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_UINT16 (0x08)
        0x08 => {
            if let Ok(v) = ReadBytesExt::read_u16::<LittleEndian>(cursor) {
                if name_id == 0x02 {
                    sink.file_size = v as u64;
                } else {
                    sink.apply_uint(name_id, name, v as u64);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_UINT8 (0x09)
        0x09 => {
            if let Ok(v) = ReadBytesExt::read_u8(cursor) {
                if name_id == 0x02 {
                    sink.file_size = v as u64;
                } else {
                    sink.apply_uint(name_id, name, v as u64);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_BSOB (0x0A)
        0x0A => {
            if let Ok(bsob_len) = ReadBytesExt::read_u8(cursor) {
                let skip = bsob_len as usize;
                let pos = cursor.position() as usize;
                let len = cursor.get_ref().len();
                if let Some(end) = pos.checked_add(skip) {
                    if end <= len {
                        cursor.set_position(end as u64);
                        return true;
                    }
                }
            }
            false
        }
        // TAGTYPE_UINT64 (0x0B)
        0x0B => {
            if let Ok(v) = ReadBytesExt::read_u64::<LittleEndian>(cursor) {
                if name_id == 0x02 {
                    // FT_FILESIZE
                    sink.file_size = v;
                } else {
                    sink.apply_uint(name_id, name, v);
                }
                true
            } else {
                false
            }
        }
        // TAGTYPE_STR1..TAGTYPE_STR16 (0x11..0x20) — string with length embedded in type
        t if (0x11..=0x20).contains(&t) => {
            let slen = (t - 0x11 + 1) as usize;
            let mut sbuf = vec![0u8; slen];
            if Read::read_exact(cursor, &mut sbuf).is_err() {
                return false;
            }
            sink.apply_string(name_id, name, String::from_utf8_lossy(&sbuf).to_string());
            true
        }
        _ => false,
    }
}

/// The results in one `OP_SEARCHRESULT`, and whether the server says it has
/// more to give.
///
/// The flag is the single byte eMule reads after the last record
/// (`SearchList.cpp:264-281`): 0x01 means more, 0x00 or anything else does
/// not. It is only meaningful if every declared record was read in step, so a
/// truncated or desynchronised answer never asks for another page.
fn parse_search_result(payload: &[u8]) -> anyhow::Result<(Vec<ServerSearchResult>, bool)> {
    let mut cursor = Cursor::new(payload);
    let count = ReadBytesExt::read_u32::<LittleEndian>(&mut cursor)? as usize;
    let mut results = Vec::with_capacity(count.min(1000));
    let mut last_in_sync = true;

    for _ in 0..count.min(1000) {
        let mut file_hash = [0u8; 16];
        if Read::read_exact(&mut cursor, &mut file_hash).is_err() {
            break;
        }
        let client_id = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let client_port = match ReadBytesExt::read_u16::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };

        let tag_count = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        const MAX_DECLARED_RESULT_TAGS: u32 = 4096;
        if tag_count > MAX_DECLARED_RESULT_TAGS {
            debug!(
                "Dropping search-result record with excessive tag count {tag_count} (cap {MAX_DECLARED_RESULT_TAGS})"
            );
            break;
        }
        let mut tags = ServerResultTags::default();

        let tag_limit = tag_count.min(256);
        let mut in_sync = true;
        for _ in 0..tag_limit {
            let (name_id, tag_type, name) = match read_tag_header(&mut cursor) {
                Some(v) => v,
                None => {
                    in_sync = false;
                    break;
                }
            };
            if !read_tag_value(&mut cursor, tag_type, name_id, name.as_deref(), &mut tags) {
                in_sync = false;
                break;
            }
        }
        // A result may legitimately carry more than the cap; consume (and
        // discard) the surplus tags so the cursor stays aligned for the next
        // result record. Without this, tag_count > 256 desyncs the parser and
        // every subsequent result decodes from the wrong offset (garbage
        // hashes/names). Only safe to skip when the capped loop stayed in sync.
        if in_sync && tag_count > tag_limit {
            let mut discard = ServerResultTags::default();
            for _ in tag_limit..tag_count {
                let (name_id, tag_type, name) = match read_tag_header(&mut cursor) {
                    Some(v) => v,
                    None => {
                        in_sync = false;
                        break;
                    }
                };
                if !read_tag_value(
                    &mut cursor,
                    tag_type,
                    name_id,
                    name.as_deref(),
                    &mut discard,
                ) {
                    in_sync = false;
                    break;
                }
            }
        }

        results.push(ServerSearchResult {
            file_hash,
            client_id,
            client_port,
            file_name: tags.file_name,
            file_size: tags.file_size,
            source_count: tags.source_count,
            complete_source_count: tags.complete_sources,
            rating: tags.rating,
            comment: tags.comment,
            media: tags.media,
        });

        // If a tag failed to decode mid-record the cursor is no longer aligned
        // to the next result; stop rather than decoding subsequent entries from
        // a mid-tag offset (which would emit garbage rows). The surplus-tag
        // path above keeps us aligned on success, so only a desync forces the
        // break. Mirrors the UDP sibling in `server_udp.rs`.
        last_in_sync = in_sync;
        if !in_sync {
            break;
        }
    }

    let aligned = results.len() == count && last_in_sync;
    let trailing = payload.len().saturating_sub(cursor.position() as usize);
    let more = aligned && trailing == 1 && payload.last() == Some(&0x01);
    Ok((results, more))
}

fn parse_found_sources(
    payload: &[u8],
    obfuscated: bool,
) -> anyhow::Result<([u8; 16], Vec<ServerSource>)> {
    if payload.len() < 17 {
        anyhow::bail!(
            "found_sources payload too short ({} bytes, need at least 17)",
            payload.len()
        );
    }
    let mut cursor = Cursor::new(payload);
    let mut file_hash = [0u8; 16];
    Read::read_exact(&mut cursor, &mut file_hash)?;
    let count = ReadBytesExt::read_u8(&mut cursor)? as usize;
    let mut sources = Vec::with_capacity(count);

    for _ in 0..count {
        // A truncated tail must not discard the sources we already parsed
        // successfully: a short/garbled final record should still leave the
        // earlier (valid) sources usable, matching eMule's tolerant parsing.
        let id = match ReadBytesExt::read_u32::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let port = match ReadBytesExt::read_u16::<LittleEndian>(&mut cursor) {
            Ok(v) => v,
            Err(_) => break,
        };
        let crypt_options = if obfuscated {
            match ReadBytesExt::read_u8(&mut cursor) {
                Ok(v) => Some(v),
                Err(_) => break,
            }
        } else {
            None
        };
        let user_hash = if crypt_options.is_some_and(|opts| (opts & 0x80) != 0) {
            let mut hash = [0u8; 16];
            if Read::read_exact(&mut cursor, &mut hash).is_err() {
                break;
            }
            Some(hash)
        } else {
            None
        };
        // Strip the 0x80 "hash follows" flag — only bits 0-2 are peer connect options
        let connect_opts = crypt_options.map(|opts| opts & 0x7F);
        if id < LOWID_THRESHOLD {
            sources.push(ServerSource {
                ip: String::new(),
                port,
                client_id: id,
                crypt_options: connect_opts,
                user_hash,
            });
        } else {
            let ip = std::net::Ipv4Addr::from(id.to_le_bytes());
            sources.push(ServerSource {
                ip: ip.to_string(),
                port,
                client_id: 0,
                crypt_options: connect_opts,
                user_hash,
            });
        }
    }

    Ok((file_hash, sources))
}

async fn read_server_packet_timeout<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<(u8, Vec<u8>)> {
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        read_server_packet(reader),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server read timed out"))?
}

const OP_PACKEDPROT: u8 = 0xD4;
const MAX_UNCOMPRESSED_SERVER_PACKET: usize = 300_000;

async fn read_server_packet<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<(u8, Vec<u8>)> {
    let protocol = reader.read_u8().await?;
    read_server_packet_after_protocol(reader, protocol).await
}

/// Await `read`, failing with `TimedOut` if it delivers nothing for
/// [`SERVER_PACKET_IDLE_TIMEOUT_SECS`].
///
/// Applied per step rather than once around the whole body so that progress
/// resets the clock: a slow but live transfer is never cut off, while a server
/// that goes quiet mid-packet is detected without waiting out the total budget.
pub(super) async fn read_step<T>(
    read: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    match tokio::time::timeout(
        std::time::Duration::from_secs(SERVER_PACKET_IDLE_TIMEOUT_SECS),
        read,
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "server stopped sending mid-packet",
        )),
    }
}

/// The rest of a server packet, once its protocol byte has been consumed.
///
/// Split out so the reader can wait indefinitely for the *first* byte — where
/// giving up provably consumed nothing — and read the remainder under a long,
/// fatal budget. `read_exact` is not cancel-safe, so a deadline that fires
/// anywhere after the first byte leaves the reader parked mid-payload with no
/// way to resynchronize.
async fn read_server_packet_after_protocol<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    protocol: u8,
) -> io::Result<(u8, Vec<u8>)> {
    if protocol != OP_EDONKEYHEADER && protocol != OP_PACKEDPROT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected server protocol byte: 0x{protocol:02X}"),
        ));
    }
    let length = read_step(reader.read_u32_le()).await? as usize;
    if length == 0 || length > 5 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid server packet length",
        ));
    }
    let opcode = read_step(reader.read_u8()).await?;
    let payload_len = length - 1;
    let mut payload = Vec::new();
    if payload_len > 0 {
        // Grow the buffer as bytes actually arrive rather than eagerly
        // allocating the full declared length (up to 5 MiB). A slow/hostile
        // server would otherwise pin that memory for the whole read window
        // before sending a single byte.
        payload.reserve(payload_len.min(64 * 1024));
        let mut remaining = payload_len;
        let mut chunk = [0u8; 32 * 1024];
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            read_step(reader.read_exact(&mut chunk[..want])).await?;
            payload.extend_from_slice(&chunk[..want]);
            remaining -= want;
        }
    }

    if protocol == OP_PACKEDPROT {
        let decompressed = decompress_server_payload(&payload)?;
        debug!(
            "Decompressed server packet: opcode=0x{opcode:02X}, {payload_len} -> {} bytes",
            decompressed.len()
        );
        Ok((opcode, decompressed))
    } else {
        Ok((opcode, payload))
    }
}

fn decompress_server_payload(compressed: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;

    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        decompressed.extend_from_slice(&buf[..n]);
        if decompressed.len() > MAX_UNCOMPRESSED_SERVER_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed server packet exceeds size limit",
            ));
        }
    }
    Ok(decompressed)
}
