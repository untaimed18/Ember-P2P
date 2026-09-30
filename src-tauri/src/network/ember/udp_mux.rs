//! One UDP socket for KAD, eD2K UDP, Ember DHT and QUIC.
//!
//! Setups that forward a single port (a VPN, many routers) left a separate
//! QUIC socket unreachable. Here one task owns `recv_from` on the KAD socket
//! and hands each datagram to one of two places: QUIC straight to quinn, and
//! everything else to the network loop, which then routes STUN, Ember and
//! KAD/eD2K exactly as it did when it read the socket itself. QUIC must not go
//! through that loop: relayed transfers, attachments and room streams all
//! ride it, and the loop awaits inside its handlers.
//!
//! The first byte alone decides nothing. Plain KAD and eD2K begin `0xE3`,
//! `0xE4`, `0xE5`, `0xC5` or `0xD4`, all of them valid QUIC long-header first
//! bytes, and obfuscated eMule packets begin with random bytes. So:
//!
//! - a long header (first bit set) is QUIC only when bytes 1 to 4 are a version
//!   we speak and the connection-id lengths that follow fit the datagram;
//! - a short header is QUIC only when its destination connection id is one we
//!   issued: [`EmberCidGenerator`] tags every id with a keyed hash, which a
//!   random packet matches one time in 2^64. Our endpoint does not offer QUIC
//!   bit greasing, so every short header sent to us keeps the fixed bit set.
//!
//! A misrouted packet costs only itself. QUIC handed to the KAD handler fails
//! to parse and is dropped; obfuscated KAD handed to quinn fails connection-id
//! validation, so quinn neither answers it nor sends a stateless reset. A
//! stateless reset sent *to* us looks random and is dropped the same way, so
//! such a connection ends by idle timeout instead of at once.

use std::future::Future;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, ConnectionId, ConnectionIdGenerator, UdpPoller};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

/// Length of the connection ids our endpoint issues.
pub const CID_LEN: usize = 16;
const CID_NONCE_LEN: usize = 8;
/// QUIC version 1 (RFC 9000), the one version every build negotiates.
const QUIC_VERSION_1: u32 = 1;
/// A long header with version 0 is version negotiation.
const QUIC_VERSION_NEGOTIATION: u32 = 0;
const MAX_CID_LEN: usize = 20;
/// Datagrams waiting for the network loop. Replaces the kernel buffer as the
/// queue the loop drains, so it is sized like that buffer rather than small.
const OTHER_QUEUE: usize = 8192;
const QUIC_QUEUE: usize = 4096;
/// Bytes either queue may hold. The counts above alone would let a flood of
/// 64 KiB datagrams hold half a gigabyte; the kernel buffer this replaces was
/// bounded in bytes, and so is this.
const QUEUE_BYTES: usize = 16 * 1024 * 1024;
const MAX_DATAGRAM: usize = 65_535;
/// Consecutive receive errors before the reader backs off. Windows reports an
/// ICMP port-unreachable on a UDP socket as an error on the next receive, which
/// is routine and must not slow reception; a socket that errors every time
/// must not spin a core.
const RECV_ERROR_BACKOFF_AFTER: u32 = 64;

/// One datagram off the shared socket. Holds its share of its queue's byte
/// budget until it is dropped.
pub struct Datagram {
    pub data: Vec<u8>,
    pub from: SocketAddr,
    budget: Arc<AtomicUsize>,
}

impl Drop for Datagram {
    fn drop(&mut self) {
        self.budget.fetch_sub(self.data.len(), Ordering::Relaxed);
    }
}

/// Take `len` bytes of `budget`, or `None` if the queue is already that full.
fn charge(budget: &Arc<AtomicUsize>, data: &[u8], from: SocketAddr) -> Option<Datagram> {
    let queued = budget.fetch_add(data.len(), Ordering::Relaxed);
    if queued + data.len() > QUEUE_BYTES {
        budget.fetch_sub(data.len(), Ordering::Relaxed);
        return None;
    }
    Some(Datagram {
        data: data.to_vec(),
        from,
        budget: budget.clone(),
    })
}

/// The key our connection ids are tagged under. Random per process: nothing
/// outside this endpoint ever needs to recognise its ids.
#[derive(Clone)]
pub struct CidKey(Arc<[u8; 32]>);

impl std::fmt::Debug for CidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CidKey(..)")
    }
}

impl CidKey {
    pub fn random() -> Self {
        Self(Arc::new(rand::random()))
    }

    fn tag(&self, nonce: &[u8]) -> [u8; CID_LEN - CID_NONCE_LEN] {
        let hash = blake3::keyed_hash(&self.0, nonce);
        let mut tag = [0u8; CID_LEN - CID_NONCE_LEN];
        tag.copy_from_slice(&hash.as_bytes()[..CID_LEN - CID_NONCE_LEN]);
        tag
    }

    fn generate(&self) -> [u8; CID_LEN] {
        let nonce: [u8; CID_NONCE_LEN] = rand::random();
        let mut cid = [0u8; CID_LEN];
        cid[..CID_NONCE_LEN].copy_from_slice(&nonce);
        cid[CID_NONCE_LEN..].copy_from_slice(&self.tag(&nonce));
        cid
    }

    /// Whether `cid` is one this key issued.
    pub fn issued(&self, cid: &[u8]) -> bool {
        cid.len() == CID_LEN && self.tag(&cid[..CID_NONCE_LEN]) == cid[CID_NONCE_LEN..]
    }
}

/// Connection ids that say which endpoint issued them. quinn's own
/// `HashedConnectionIdGenerator` validates too, but on a five-byte FxHash tag
/// and a three-byte nonce, which is too thin to tell our packets from random
/// ones on a socket that also carries obfuscated eMule traffic.
pub struct EmberCidGenerator {
    key: CidKey,
}

impl ConnectionIdGenerator for EmberCidGenerator {
    fn generate_cid(&mut self) -> ConnectionId {
        ConnectionId::new(&self.key.generate())
    }

    fn validate(&self, cid: &ConnectionId) -> Result<(), quinn_proto::InvalidCid> {
        if self.key.issued(cid) {
            Ok(())
        } else {
            Err(quinn_proto::InvalidCid)
        }
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// The endpoint configuration the shared socket depends on.
pub fn endpoint_config(key: &CidKey) -> quinn::EndpointConfig {
    let mut config = quinn::EndpointConfig::default();
    let key = key.clone();
    config.cid_generator(move || Box::new(EmberCidGenerator { key: key.clone() }));
    // Not offered, so peers keep the fixed bit set on everything they send us,
    // which the short-header test relies on.
    config.grease_quic_bit(false);
    config
}

/// Whether a datagram off the shared socket is QUIC for our endpoint.
pub fn is_quic(data: &[u8], key: &CidKey) -> bool {
    let Some(&first) = data.first() else {
        return false;
    };
    if first & 0x80 != 0 {
        if data.len() < 7 {
            return false;
        }
        let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
        // The fixed bit is random in version negotiation, and set otherwise.
        let fixed_ok = first & 0x40 != 0 || version == QUIC_VERSION_NEGOTIATION;
        if !fixed_ok || (version != QUIC_VERSION_1 && version != QUIC_VERSION_NEGOTIATION) {
            return false;
        }
        let dcid_len = data[5] as usize;
        if dcid_len > MAX_CID_LEN || data.len() < 7 + dcid_len {
            return false;
        }
        let scid_len = data[6 + dcid_len] as usize;
        scid_len <= MAX_CID_LEN && data.len() >= 7 + dcid_len + scid_len
    } else {
        first & 0x40 != 0 && data.len() > CID_LEN && key.issued(&data[1..1 + CID_LEN])
    }
}

/// Start the reader for `socket`.
///
/// Returns the datagrams the network loop handles, and the QUIC half as a
/// socket quinn can drive — `None` when `cid_key` is, which is the fallback to
/// a separate QUIC socket: then everything goes to the loop, as before.
///
/// The reader stops once the loop drops its receiver.
pub fn start(
    socket: Arc<UdpSocket>,
    cid_key: Option<CidKey>,
) -> (mpsc::Receiver<Datagram>, Option<SharedQuicSocket>) {
    let (other_tx, other_rx) = mpsc::channel(OTHER_QUEUE);
    let (quic_route, quic) = match &cid_key {
        Some(_) => {
            let (tx, rx) = mpsc::channel(QUIC_QUEUE);
            let claimed = Arc::new(AtomicBool::new(false));
            let shared = SharedQuicSocket {
                socket: socket.clone(),
                rx: parking_lot::Mutex::new(rx),
                claimed: claimed.clone(),
                last_send_error_log: parking_lot::Mutex::new(None),
            };
            (Some(QuicRoute { tx, claimed }), Some(shared))
        }
        None => (None, None),
    };
    tokio::spawn(read_loop(socket, cid_key, other_tx, quic_route));
    (other_rx, quic)
}

/// Where the reader sends QUIC.
struct QuicRoute {
    tx: mpsc::Sender<Datagram>,
    /// Set by [`SharedQuicSocket`] once quinn first polls it. The endpoint is
    /// built only once our external address is known, and possibly never, so
    /// until then nothing drains the queue: QUIC would fill it and then warn,
    /// and whatever did fit would reach quinn as Initials long since given up
    /// on. Until then QUIC is dropped, as a socket nobody listens on would.
    claimed: Arc<AtomicBool>,
}

/// Says so if the reader ends while the loop still wants datagrams: nothing
/// else would, since the loop's receive arm just goes quiet.
struct ReaderExitNotice(mpsc::Sender<Datagram>);

impl Drop for ReaderExitNotice {
    fn drop(&mut self) {
        if !self.0.is_closed() {
            error!("UDP reader stopped while the network runs; KAD, Ember and QUIC reception has ended");
        }
    }
}

async fn read_loop(
    socket: Arc<UdpSocket>,
    cid_key: Option<CidKey>,
    other_tx: mpsc::Sender<Datagram>,
    mut quic_route: Option<QuicRoute>,
) {
    let _exit_notice = ReaderExitNotice(other_tx.clone());
    let mut buf = vec![0u8; MAX_DATAGRAM];
    let other_budget = Arc::new(AtomicUsize::new(0));
    let quic_budget = Arc::new(AtomicUsize::new(0));
    let mut dropped_other = 0u64;
    let mut dropped_quic = 0u64;
    let mut consecutive_errors = 0u32;
    loop {
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            // Otherwise a quiet socket would outlive the loop, and a network
            // restart would find its port still bound.
            () = other_tx.closed() => return,
        };
        let (len, from) = match received {
            Ok(received) => {
                consecutive_errors = 0;
                received
            }
            // Windows reports each ICMP port-unreachable as a reset on the next
            // receive, and pings to dead KAD contacts produce them in runs, so
            // resets never count toward the backoff.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {
                debug!("UDP recv reset: {e}");
                continue;
            }
            Err(e) => {
                debug!("UDP recv error: {e}");
                consecutive_errors = consecutive_errors.saturating_add(1);
                if consecutive_errors >= RECV_ERROR_BACKOFF_AFTER {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                continue;
            }
        };
        let data = &buf[..len];
        if let (Some(key), Some(route)) = (&cid_key, &quic_route) {
            if is_quic(data, key) {
                if !route.claimed.load(Ordering::Acquire) {
                    // The endpoint was never built (QUIC fell back to a socket
                    // of its own), so there is nothing left to classify for.
                    if route.tx.is_closed() {
                        quic_route = None;
                    }
                    continue;
                }
                match charge(&quic_budget, data, from).map(|datagram| route.tx.try_send(datagram)) {
                    Some(Ok(())) => {}
                    // The endpoint is gone (QUIC fell back to a socket of its
                    // own), so there is nothing left to classify for.
                    Some(Err(mpsc::error::TrySendError::Closed(_))) => quic_route = None,
                    Some(Err(mpsc::error::TrySendError::Full(_))) | None => {
                        dropped_quic += 1;
                        note_drop("QUIC", dropped_quic);
                    }
                }
                continue;
            }
        }
        match charge(&other_budget, data, from).map(|datagram| other_tx.try_send(datagram)) {
            Some(Ok(())) => {}
            Some(Err(mpsc::error::TrySendError::Closed(_))) => return,
            Some(Err(mpsc::error::TrySendError::Full(_))) | None => {
                dropped_other += 1;
                note_drop("KAD/Ember", dropped_other);
            }
        }
    }
}

/// The first drop and every thousandth after, so an overloaded queue is visible
/// without a line per datagram.
fn note_drop(queue: &str, total: u64) {
    if total == 1 || total.is_multiple_of(1000) {
        warn!("UDP reader: {queue} queue full, {total} datagram(s) dropped so far");
    }
}

/// The QUIC half of the shared socket, as quinn drives it: datagrams from the
/// reader, and sends straight to the socket.
///
/// One datagram per transmit and per receive: the segmentation offloads quinn
/// would otherwise use need a socket configured for them, and GRO in
/// particular coalesces datagrams, which would break the KAD reader.
pub struct SharedQuicSocket {
    socket: Arc<UdpSocket>,
    rx: parking_lot::Mutex<mpsc::Receiver<Datagram>>,
    /// See [`QuicRoute::claimed`].
    claimed: Arc<AtomicBool>,
    last_send_error_log: parking_lot::Mutex<Option<std::time::Instant>>,
}

impl SharedQuicSocket {
    /// At most one line a minute, as quinn's own socket does.
    fn note_send_error(&self, e: &io::Error) {
        let mut last = self.last_send_error_log.lock();
        if last.is_none_or(|at| at.elapsed() >= Duration::from_secs(60)) {
            *last = Some(std::time::Instant::now());
            warn!("QUIC send on the shared UDP socket failed: {e}");
        }
    }
}

impl std::fmt::Debug for SharedQuicSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedQuicSocket")
            .field("local", &self.socket.local_addr().ok())
            .finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for SharedQuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(WritablePoller {
            socket: self.socket.clone(),
            waiting: None,
        })
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // `max_transmit_segments` is 1, so quinn hands over one datagram.
        debug_assert!(transmit
            .segment_size
            .is_none_or(|size| size >= transmit.contents.len()));
        match self.socket.try_send_to(transmit.contents, transmit.destination) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            // Any other error ends the connection driver that asked, leaving the
            // connection hung with its timers stopped. quinn's own socket logs
            // and drops the datagram instead, which loss recovery then covers:
            // an unreachable host after a Wi-Fi drop, a full send buffer.
            Err(e) => {
                self.note_send_error(&e);
                Ok(())
            }
        }
    }

    /// Shared sockets carry no don't-fragment flag: setting one would also
    /// apply to KAD and Ember frames, which rely on fragmentation. So quinn keeps
    /// to its 1200-byte initial MTU and skips path-MTU discovery, costing bulk
    /// transfers about one packet in six over the separate socket.
    fn may_fragment(&self) -> bool {
        true
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if !self.claimed.load(Ordering::Relaxed) {
            self.claimed.store(true, Ordering::Release);
        }
        let mut rx = self.rx.lock();
        let slots = bufs.len().min(meta.len());
        if slots == 0 {
            return Poll::Ready(Ok(0));
        }
        let first = match rx.poll_recv(cx) {
            Poll::Ready(Some(datagram)) => datagram,
            // The reader is gone, which only happens as the network loop ends.
            Poll::Ready(None) | Poll::Pending => return Poll::Pending,
        };
        let mut filled = 0;
        let mut next = Some(first);
        while let Some(datagram) = next {
            let buf = &mut bufs[filled];
            let len = datagram.data.len().min(buf.len());
            buf[..len].copy_from_slice(&datagram.data[..len]);
            meta[filled] = RecvMeta {
                addr: datagram.from,
                len,
                stride: len,
                ecn: None,
                dst_ip: None,
            };
            filled += 1;
            if filled == slots {
                break;
            }
            next = rx.try_recv().ok();
        }
        Poll::Ready(Ok(filled))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

type WritableFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

/// Wakes one task when the shared socket can take a send. Built on
/// `writable()` rather than `poll_send_ready`, which keeps only the most recent
/// waker, because quinn gives each connection a poller of its own.
struct WritablePoller {
    socket: Arc<UdpSocket>,
    waiting: Option<WritableFuture>,
}

impl std::fmt::Debug for WritablePoller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WritablePoller").finish_non_exhaustive()
    }
}

impl UdpPoller for WritablePoller {
    fn poll_writable(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let socket = &this.socket;
        let waiting = this.waiting.get_or_insert_with(|| {
            let socket = socket.clone();
            Box::pin(async move { socket.writable().await })
        });
        let result = waiting.as_mut().poll(cx);
        if result.is_ready() {
            this.waiting = None;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::ember::quic;
    use rand::{Rng, RngCore, SeedableRng};

    fn long_header(version: u32, first: u8) -> Vec<u8> {
        let mut p = vec![first];
        p.extend_from_slice(&version.to_be_bytes());
        p.push(8);
        p.extend_from_slice(&[0x11; 8]);
        p.push(8);
        p.extend_from_slice(&[0x22; 8]);
        p.resize(1200, 0);
        p
    }

    fn short_header(cid: &[u8]) -> Vec<u8> {
        let mut p = vec![0x41];
        p.extend_from_slice(cid);
        p.extend_from_slice(&[0x33; 40]);
        p
    }

    #[test]
    fn our_connection_ids_validate_and_others_do_not() {
        let key = CidKey::random();
        let other = CidKey::random();
        for _ in 0..1000 {
            let cid = key.generate();
            assert!(key.issued(&cid));
            assert!(!other.issued(&cid));
        }
        assert!(!key.issued(&[0u8; CID_LEN]));
        assert!(!key.issued(&key.generate()[..CID_LEN - 1]));
    }

    #[test]
    fn quic_headers_are_recognised() {
        let key = CidKey::random();
        assert!(is_quic(&long_header(QUIC_VERSION_1, 0xC3), &key), "an Initial");
        assert!(is_quic(&long_header(QUIC_VERSION_1, 0xE0), &key), "a Handshake");
        assert!(
            is_quic(&long_header(QUIC_VERSION_NEGOTIATION, 0x80), &key),
            "version negotiation, whose fixed bit is random"
        );
        assert!(is_quic(&short_header(&key.generate()), &key), "a 1-RTT packet for us");

        assert!(!is_quic(&long_header(0x6b33_43cf, 0xC3), &key), "a version we do not speak");
        assert!(!is_quic(&long_header(QUIC_VERSION_1, 0x83), &key), "fixed bit clear");
        assert!(!is_quic(&short_header(&CidKey::random().generate()), &key), "another endpoint's id");
        let mut unfixed = short_header(&key.generate());
        unfixed[0] = 0x01;
        assert!(!is_quic(&unfixed, &key), "a short header with the fixed bit clear");
        let mut overlong = long_header(QUIC_VERSION_1, 0xC3);
        overlong[5] = 21;
        assert!(!is_quic(&overlong, &key), "a connection id longer than QUIC allows");
        assert!(!is_quic(&[0xC3, 0, 0, 0, 1, 8], &key), "truncated");
        assert!(!is_quic(&[], &key));
    }

    #[test]
    fn plain_kad_ed2k_ember_and_stun_are_not_quic() {
        let key = CidKey::random();
        let ember = [
            crate::network::ember::transport::EMBER_MAGIC[0],
            crate::network::ember::transport::EMBER_MAGIC[1],
            0x01,
            0,
            0,
            0,
            1,
            8,
        ];
        let stun = crate::network::ember::nat::build_binding_request(&[7u8; 12]);
        let mut cases: Vec<Vec<u8>> = vec![ember.to_vec(), stun];
        // Every plain protocol byte, with every opcode. Opcode 0 followed by
        // `00 00 01` would read as version 1 and go to quinn; only the retired
        // KAD1 bootstrap starts that way, so that loss is accepted.
        for proto in [0xE3u8, 0xE4, 0xE5, 0xC5, 0xD4] {
            for opcode in 0..=255u8 {
                cases.push(vec![proto, opcode, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60]);
            }
        }
        for case in &cases {
            assert!(!is_quic(case, &key), "{:02x?}", &case[..case.len().min(8)]);
        }
    }

    /// The loss the test above accepts, pinned: a plain datagram with opcode 0
    /// whose next bytes read as version 1 and whose connection-id lengths fit
    /// is handed to quinn, whichever plain protocol byte it starts with.
    #[test]
    fn a_plain_datagram_reading_as_version_1_goes_to_quic() {
        let key = CidKey::random();
        for proto in [0xE3u8, 0xE4, 0xE5, 0xC5, 0xD4] {
            let mut datagram = vec![proto, 0x00, 0x00, 0x00, 0x01, 8];
            datagram.extend_from_slice(&[0x11; 8]);
            datagram.push(0);
            datagram.extend_from_slice(&[0x55; 16]);
            assert!(is_quic(&datagram, &key), "{proto:02x} 00 00 00 01");
            assert!(is_quic(&[proto, 0, 0, 0, 1, 0, 0], &key), "{proto:02x} with empty ids");

            datagram[5] = 30;
            assert!(!is_quic(&datagram, &key), "{proto:02x} with an id that does not fit");
        }
    }

    /// Until quinn first polls the shared socket nothing drains its queue, so
    /// QUIC that arrives before the endpoint exists is dropped, neither held
    /// for quinn nor passed to the loop, and reaches quinn once it polls.
    #[tokio::test]
    async fn quic_is_dropped_until_the_endpoint_polls() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = socket.local_addr().unwrap();
        let (mut other, quic_half) = start(socket.clone(), Some(CidKey::random()));
        let quic_half = quic_half.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let initial = long_header(QUIC_VERSION_1, 0xC3);
        // Yielding lets the reader drain as they arrive, since a send does not
        // yield on its own and the kernel buffer would otherwise overflow.
        for _ in 0..64 {
            sender.send_to(&initial, addr).await.unwrap();
            tokio::task::yield_now().await;
        }
        sender.send_to(&[0xE4, 0x21, 1, 2], addr).await.unwrap();
        let kad = tokio::time::timeout(Duration::from_secs(5), other.recv())
            .await
            .expect("the KAD datagram arrives")
            .unwrap();
        assert_eq!(&kad.data[..2], &[0xE4, 0x21], "only KAD reaches the loop");
        assert!(quic_half.rx.lock().try_recv().is_err(), "nothing is held for quinn");

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let mut meta = [RecvMeta::default()];
        std::future::poll_fn(|cx| {
            let mut bufs = [IoSliceMut::new(&mut buf)];
            let _ = quic_half.poll_recv(cx, &mut bufs, &mut meta);
            Poll::Ready(())
        })
        .await;
        sender.send_to(&initial, addr).await.unwrap();
        let received = tokio::time::timeout(
            Duration::from_secs(5),
            std::future::poll_fn(|cx| {
                let mut bufs = [IoSliceMut::new(&mut buf)];
                quic_half.poll_recv(cx, &mut bufs, &mut meta)
            }),
        )
        .await
        .expect("QUIC reaches quinn once it polls")
        .unwrap();
        assert_eq!(received, 1);
        assert_eq!(meta[0].len, initial.len());
    }

    /// Obfuscated eMule packets begin with random bytes, so they are the traffic
    /// the classifier has to be right about. Tens of thousands of them, plus
    /// plain random datagrams, and not one reads as ours.
    #[test]
    fn obfuscated_and_random_traffic_is_never_quic() {
        let key = CidKey::random();
        let mut rng = rand::rngs::StdRng::seed_from_u64(0x5AFE_0DD5);
        let mut misread = 0usize;
        for i in 0..20_000u32 {
            let mut plain = vec![0xE4, (i % 256) as u8];
            let mut body = vec![0u8; rng.gen_range(0..600)];
            rng.fill_bytes(&mut body);
            plain.extend_from_slice(&body);
            let kad = crate::network::kad::obfuscation::encrypt_kad_packet(
                &plain,
                &crate::network::kad::types::KadId(rng.gen()),
                rng.gen(),
                rng.gen(),
            );
            let mut ed2k_plain = vec![0xC5, 0x90];
            ed2k_plain.extend_from_slice(&body);
            let ed2k = crate::network::kad::obfuscation::encrypt_client_ed2k_packet(
                &ed2k_plain,
                &rng.gen(),
                rng.gen(),
            );
            misread += usize::from(is_quic(&kad, &key)) + usize::from(is_quic(&ed2k, &key));
        }
        for _ in 0..200_000 {
            let mut datagram = vec![0u8; rng.gen_range(1..1500)];
            rng.fill_bytes(&mut datagram);
            misread += usize::from(is_quic(&datagram, &key));
        }
        assert_eq!(misread, 0);
    }

    fn endpoint_identity() -> (Vec<u8>, Vec<u8>) {
        quic::generate_self_signed_cert(&rand::random()).unwrap()
    }

    async fn shared_endpoint() -> (quinn::Endpoint, Arc<UdpSocket>, mpsc::Receiver<Datagram>) {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let key = CidKey::random();
        let (other, quic_half) = start(socket.clone(), Some(key.clone()));
        let (cert, pkey) = endpoint_identity();
        let endpoint = quic::build_shared_endpoint(&cert, &pkey, quic_half.unwrap(), &key).unwrap();
        (endpoint, socket, other)
    }

    /// Echo every stream on `endpoint` back to its sender.
    fn serve_echo(endpoint: quinn::Endpoint) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let Ok(conn) = incoming.await else { return };
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let Ok(data) = recv.read_to_end(16 << 20).await else { return };
                        let _ = send.write_all(&data).await;
                        let _ = send.finish();
                    }
                });
            }
        })
    }

    async fn round_trip(client: &quinn::Endpoint, server: SocketAddr, len: usize) {
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            client.connect(server, "ember-relay").unwrap(),
        )
        .await
        .expect("handshake timed out")
        .expect("handshake failed");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let payload: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(20), recv.read_to_end(16 << 20))
            .await
            .expect("transfer timed out")
            .unwrap();
        assert_eq!(echoed, payload);
        conn.close(0u32.into(), b"done");
    }

    /// A bulk QUIC transfer and a stream of KAD datagrams on the same pair of
    /// sockets at once: the transfer completes byte for byte, the KAD side gets
    /// its datagrams, and not one QUIC packet reaches it.
    #[tokio::test]
    async fn quic_and_kad_share_one_socket() {
        let (client, client_socket, mut client_other) = shared_endpoint().await;
        let (server, server_socket, mut server_other) = shared_endpoint().await;
        let server_addr = server_socket.local_addr().unwrap();
        let echo = serve_echo(server);

        const KAD_DATAGRAMS: u16 = 200;
        let kad = {
            let socket = client_socket.clone();
            tokio::spawn(async move {
                for i in 0..KAD_DATAGRAMS {
                    let mut packet = vec![0xE4, 0x21];
                    packet.extend_from_slice(&i.to_le_bytes());
                    socket.send_to(&packet, server_addr).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
        };
        round_trip(&client, server_addr, 2 << 20).await;
        kad.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut kad_seen = 0usize;
        while let Ok(datagram) = server_other.try_recv() {
            assert_eq!(&datagram.data[..2], &[0xE4, 0x21], "only KAD reaches the loop");
            kad_seen += 1;
        }
        // Loopback can still drop a datagram under a bulk transfer.
        assert!(kad_seen >= usize::from(KAD_DATAGRAMS) * 9 / 10, "{kad_seen} KAD datagrams");
        assert!(client_other.try_recv().is_err(), "no QUIC reached the client's loop");
        echo.abort();
    }

    /// A 1.7.x peer runs QUIC on a socket of its own with quinn's defaults. It
    /// reaches a shared endpoint, and a shared endpoint reaches it.
    #[tokio::test]
    async fn a_shared_endpoint_interoperates_with_a_separate_one() {
        let (shared, shared_socket, _other) = shared_endpoint().await;
        let (cert, key) = endpoint_identity();
        let (separate, _) = quic::build_server_client_endpoint(&cert, &key, 0, false)
            .await
            .unwrap();
        let separate_addr = SocketAddr::from(([127, 0, 0, 1], separate.local_addr().unwrap().port()));
        let shared_addr = shared_socket.local_addr().unwrap();

        let echo_shared = serve_echo(shared.clone());
        round_trip(&separate, shared_addr, 256 << 10).await;
        echo_shared.abort();

        let echo_separate = serve_echo(separate.clone());
        round_trip(&shared, separate_addr, 256 << 10).await;
        echo_separate.abort();
    }

    /// Queued datagrams are bounded in bytes, and a datagram hands its bytes
    /// back when it is dropped, whether it was consumed or refused.
    #[test]
    fn the_queue_budget_is_bytes_and_comes_back() {
        let budget = Arc::new(AtomicUsize::new(0));
        let from = SocketAddr::from(([127, 0, 0, 1], 4672));
        let big = vec![0u8; MAX_DATAGRAM];
        let mut held = Vec::new();
        while let Some(datagram) = charge(&budget, &big, from) {
            held.push(datagram);
        }
        assert_eq!(held.len(), QUEUE_BYTES / MAX_DATAGRAM);
        assert_eq!(budget.load(Ordering::Relaxed), held.len() * MAX_DATAGRAM, "the refusal gave its bytes back");
        assert!(charge(&budget, &[0u8; 64], from).is_some(), "small datagrams still fit the remainder");
        drop(held);
        assert_eq!(budget.load(Ordering::Relaxed), 0);
    }

    /// The reader lets go of the socket once the loop is gone, so a network
    /// restart can bind the port again.
    #[tokio::test]
    async fn the_reader_releases_the_socket_with_the_loop() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (other, quic_half) = start(socket.clone(), None);
        assert!(quic_half.is_none(), "no QUIC half with sharing off");
        drop(other);
        for _ in 0..50 {
            if Arc::strong_count(&socket) == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the reader still holds the socket");
    }
}
