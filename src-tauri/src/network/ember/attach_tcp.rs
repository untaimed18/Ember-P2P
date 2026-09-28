//! File streams over a secure TCP connection, for when QUIC cannot connect.
//!
//! A chat attachment or room transfer normally crosses a QUIC stream, but the
//! QUIC endpoint listens on a UDP port of its own, and many setups forward only
//! the eD2K ports — a VPN that forwards a single port always does. The upload
//! listener's TCP port is the one that is reachable there, so the recipient
//! dials it, runs the same Noise handshake a friend session does, and then the
//! same request, header and verified chunks as on QUIC.
//!
//! The listener tells such a stream from an eD2K session by its first byte
//! after the handshake: eD2K framing starts with a protocol marker, never with
//! [`super::attach::ATTACH_STREAM_MSG_TYPE`] or
//! [`super::attach::ROOM_XFER_STREAM_MSG_TYPE`].

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::attach_stream::{FetchError, FetchOutcome, FetchProgress};
use crate::network::ed2k::secure_stream::{self, SecureStreamParts};

/// The byte a recipient writes once every chunk has arrived and verified.
///
/// QUIC says this with a close reason; TCP has none, and a bare close cannot
/// tell "I have it all" from "I gave up".
pub const TCP_STREAM_RECEIVED: u8 = 0x01;

/// How long one TCP connect may take.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long the sender waits after the last chunk for the recipient to say it
/// has everything.
const TCP_DELIVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a QUIC dial runs alone before the TCP fallback is dialled beside
/// it. A reachable QUIC port answers within a round trip, and a punched one
/// within a handshake retransmit or two. A port nothing forwards never
/// answers, and waiting out the whole dial timeout for it held every file
/// from such a sender back by that long before its first byte.
pub const TCP_HEAD_START: Duration = Duration::from_secs(3);

/// Which carrier [`dial_quic_or_tcp`] connected.
pub enum Dialled<Q, T, E> {
    Quic(Q),
    Tcp(T),
    /// Neither connected; the QUIC dial's failure.
    Neither(E),
}

/// Dial QUIC, and once it has had [`TCP_HEAD_START`] without connecting,
/// dial TCP beside it. The first to connect is used and the other is dropped
/// mid-dial, before either has sent a request, so the sender never serves the
/// file twice. A QUIC dial that fails inside the head start starts TCP at once.
pub async fn dial_quic_or_tcp<Q, T, E, FQ, FT>(
    quic: FQ,
    tcp: impl FnOnce() -> FT,
) -> Dialled<Q, T, E>
where
    FQ: std::future::Future<Output = Result<Q, E>>,
    FT: std::future::Future<Output = Option<T>>,
{
    dial_quic_or_tcp_after(TCP_HEAD_START, quic, tcp).await
}

async fn dial_quic_or_tcp_after<Q, T, E, FQ, FT>(
    head_start: Duration,
    quic: FQ,
    tcp: impl FnOnce() -> FT,
) -> Dialled<Q, T, E>
where
    FQ: std::future::Future<Output = Result<Q, E>>,
    FT: std::future::Future<Output = Option<T>>,
{
    tokio::pin!(quic);
    let early = tokio::select! {
        dialled = &mut quic => Some(dialled),
        () = tokio::time::sleep(head_start) => None,
    };
    let mut quic_failed = match early {
        Some(Ok(conn)) => return Dialled::Quic(conn),
        Some(Err(e)) => Some(e),
        None => None,
    };
    let tcp = tcp();
    tokio::pin!(tcp);
    let mut tcp_failed = false;
    loop {
        tokio::select! {
            dialled = &mut quic, if quic_failed.is_none() => match dialled {
                Ok(conn) => return Dialled::Quic(conn),
                Err(e) => quic_failed = Some(e),
            },
            dialled = &mut tcp, if !tcp_failed => match dialled {
                Some(parts) => return Dialled::Tcp(parts),
                None => tcp_failed = true,
            },
        }
        if tcp_failed {
            if let Some(e) = quic_failed.take() {
                return Dialled::Neither(e);
            }
        }
    }
}

/// Connect to `addr` and run the secure-stream handshake, requiring the peer
/// to prove it is `peer_hash`.
pub async fn dial_secure(
    addr: SocketAddr,
    our_hash: [u8; 16],
    our_ed25519_public_key: [u8; 32],
    our_ed25519_secret_key: [u8; 32],
    peer_hash: [u8; 16],
) -> anyhow::Result<SecureStreamParts> {
    let stream = tokio::time::timeout(TCP_CONNECT_TIMEOUT, tokio::net::TcpStream::connect(addr))
        .await
        .map_err(|_| anyhow::anyhow!("TCP connect timed out"))??;
    crate::network::ed2k::multi_source::tune_peer_stream(&stream);
    let (reader, writer) = stream.into_split();
    secure_stream::initiate(
        Box::new(tokio::io::BufReader::new(reader)),
        Box::new(writer),
        our_hash,
        peer_hash,
        our_ed25519_public_key,
        our_ed25519_secret_key,
    )
    .await
}

/// [`super::attach_stream::fetch_stream_waiting`] over a secure TCP stream,
/// saying [`TCP_STREAM_RECEIVED`] once the file is complete.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_over_tcp<P>(
    parts: &mut SecureStreamParts,
    stream_type: u8,
    xfer_id: &[u8; 16],
    capability: &[u8; 32],
    size: u64,
    root: &[u8; 32],
    part: std::fs::File,
    on_progress: P,
    status_wait: Duration,
    status_waited: &mut Duration,
) -> Result<FetchOutcome, FetchError>
where
    P: FnMut(FetchProgress),
{
    let outcome = super::attach_stream::fetch_stream_waiting(
        stream_type,
        &mut parts.reader,
        &mut parts.writer,
        xfer_id,
        capability,
        size,
        root,
        part,
        on_progress,
        status_wait,
        status_waited,
    )
    .await?;
    if outcome.complete {
        // Best effort: the file is ours either way, and the sender only uses
        // this to mark its side finished.
        let _ = parts.writer.write_all(&[TCP_STREAM_RECEIVED]).await;
        let _ = parts.writer.flush().await;
    }
    Ok(outcome)
}

/// After the last chunk: whether the recipient said it received everything.
pub async fn tcp_stream_delivered<R, W>(recv: &mut R, send: &mut W) -> bool
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    if send.flush().await.is_err() {
        return false;
    }
    matches!(
        tokio::time::timeout(TCP_DELIVERY_TIMEOUT, recv.read_u8()).await,
        Ok(Ok(TCP_STREAM_RECEIVED))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::attach::ROOM_XFER_STREAM_MSG_TYPE;
    use crate::network::ember::crypto::node_id_from_public_key;
    use crate::network::ember::transfer::HashTree;
    use ed25519_dalek::SigningKey;

    fn temp_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ember-attach-tcp-{tag}-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    /// The whole fallback over a real socket: the secure handshake the upload
    /// listener runs, the stream type it dispatches on, the verified chunks,
    /// and the byte that tells the sender the file arrived.
    #[tokio::test]
    async fn a_file_crosses_a_secure_tcp_stream_and_is_acknowledged() {
        let sender = SigningKey::from_bytes(&[51u8; 32]);
        let receiver = SigningKey::from_bytes(&[52u8; 32]);
        let sender_pub = sender.verifying_key().to_bytes();
        let receiver_pub = receiver.verifying_key().to_bytes();
        let sender_hash = node_id_from_public_key(&sender.verifying_key());
        let receiver_hash = node_id_from_public_key(&receiver.verifying_key());

        let data: Vec<u8> = (0..super::super::attach::ATTACH_CHUNK_SIZE * 2 + 321)
            .map(|i| (i % 233) as u8)
            .collect();
        let source = temp_path("src");
        std::fs::write(&source, &data).expect("write source");
        let root = HashTree::from_data(&data).root_hash;
        let size = data.len() as u64;
        let (xfer_id, capability) = ([61u8; 16], [62u8; 32]);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = source.clone();
        let sender_seed = sender.to_bytes();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, writer) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(reader);
            let first = reader.read_u8().await.expect("preamble byte");
            let mut parts = secure_stream::accept_after_first(
                Box::new(reader),
                Box::new(writer),
                first,
                sender_hash,
                sender_pub,
                sender_seed,
            )
            .await
            .expect("secure accept");
            assert_eq!(parts.peer.ed25519_public_key, receiver_pub);
            let mut header = [0u8; 7];
            parts.reader.read_exact(&mut header).await.expect("header");
            assert_eq!(header[0], ROOM_XFER_STREAM_MSG_TYPE);
            super::super::attach_stream::serve_stream(
                ROOM_XFER_STREAM_MSG_TYPE,
                &mut parts.reader,
                &mut parts.writer,
                &header,
                |id| (*id == xfer_id).then(|| (served.clone(), size, root, capability)),
                |_, _, _| true,
                None,
            )
            .await
            .expect("serve");
            tcp_stream_delivered(&mut parts.reader, &mut parts.writer).await
        });

        let mut parts = dial_secure(addr, receiver_hash, receiver_pub, receiver.to_bytes(), sender_hash)
            .await
            .expect("secure dial");
        let part_path = temp_path("part");
        let part = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&part_path)
            .expect("part");
        let outcome = fetch_over_tcp(
            &mut parts,
            ROOM_XFER_STREAM_MSG_TYPE,
            &xfer_id,
            &capability,
            size,
            &root,
            part,
            |_| {},
            Duration::from_secs(30),
            &mut Duration::default(),
        )
        .await
        .expect("fetch");
        assert!(outcome.complete);
        assert_eq!(std::fs::read(&part_path).expect("read part"), data);
        assert!(server.await.expect("server task"), "the sender heard the file arrived");
        let _ = std::fs::remove_file(&source);
        let _ = std::fs::remove_file(&part_path);
    }

    const HEAD_START: Duration = Duration::from_millis(100);

    /// A QUIC port that answers inside the head start is used, and TCP is
    /// never dialled.
    #[tokio::test]
    async fn a_quic_dial_that_answers_in_time_never_dials_tcp() {
        let tcp_dialled = std::sync::atomic::AtomicBool::new(false);
        let won = dial_quic_or_tcp_after(HEAD_START, async { Ok::<_, ()>("quic") }, || async {
            tcp_dialled.store(true, std::sync::atomic::Ordering::Relaxed);
            Some("tcp")
        })
        .await;
        assert!(matches!(won, Dialled::Quic("quic")));
        assert!(!tcp_dialled.load(std::sync::atomic::Ordering::Relaxed));
    }

    /// A QUIC port nothing answers on costs the head start, not the whole
    /// dial timeout.
    #[tokio::test]
    async fn a_silent_quic_port_hands_over_to_tcp_after_the_head_start() {
        let started = std::time::Instant::now();
        let won = dial_quic_or_tcp_after(
            HEAD_START,
            std::future::pending::<Result<&str, ()>>(),
            || async { Some("tcp") },
        )
        .await;
        assert!(matches!(won, Dialled::Tcp("tcp")));
        let took = started.elapsed();
        assert!(took >= HEAD_START && took < HEAD_START * 20, "took {took:?}");
    }

    /// A QUIC dial that fails outright does not wait out the head start.
    #[tokio::test]
    async fn a_failed_quic_dial_starts_tcp_at_once() {
        let started = std::time::Instant::now();
        let won = dial_quic_or_tcp_after(
            Duration::from_secs(30),
            async { Err::<&str, _>("refused") },
            || async { Some("tcp") },
        )
        .await;
        assert!(matches!(won, Dialled::Tcp("tcp")));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// TCP starting does not end the QUIC dial: a slow QUIC answer still
    /// wins over a TCP port that refused.
    #[tokio::test]
    async fn a_slow_quic_dial_still_wins_after_tcp_missed() {
        let won = dial_quic_or_tcp_after(
            HEAD_START,
            async {
                tokio::time::sleep(HEAD_START * 3).await;
                Ok::<_, ()>("quic")
            },
            || async { None::<&str> },
        )
        .await;
        assert!(matches!(won, Dialled::Quic("quic")));
    }

    #[tokio::test]
    async fn neither_connecting_reports_the_quic_failure() {
        let won = dial_quic_or_tcp_after(
            HEAD_START,
            async {
                tokio::time::sleep(HEAD_START * 2).await;
                Err::<&str, _>("timed out")
            },
            || async { None::<&str> },
        )
        .await;
        assert!(matches!(won, Dialled::Neither("timed out")));
    }

    /// The dialer's claim about who it is reaching is checked: a listener that
    /// is not the expected identity is refused before any file byte moves.
    #[tokio::test]
    async fn a_dial_to_the_wrong_identity_is_refused() {
        let impostor = SigningKey::from_bytes(&[53u8; 32]);
        let receiver = SigningKey::from_bytes(&[54u8; 32]);
        let expected = SigningKey::from_bytes(&[55u8; 32]);
        let impostor_pub = impostor.verifying_key().to_bytes();
        let impostor_hash = node_id_from_public_key(&impostor.verifying_key());
        let impostor_seed = impostor.to_bytes();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            let (reader, writer) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(reader);
            let Ok(first) = reader.read_u8().await else {
                return;
            };
            let _ = secure_stream::accept_after_first(
                Box::new(reader),
                Box::new(writer),
                first,
                impostor_hash,
                impostor_pub,
                impostor_seed,
            )
            .await;
        });

        let result = dial_secure(
            addr,
            node_id_from_public_key(&receiver.verifying_key()),
            receiver.verifying_key().to_bytes(),
            receiver.to_bytes(),
            node_id_from_public_key(&expected.verifying_key()),
        )
        .await;
        assert!(result.is_err(), "a listener that is not the expected peer must not be accepted");
    }
}
