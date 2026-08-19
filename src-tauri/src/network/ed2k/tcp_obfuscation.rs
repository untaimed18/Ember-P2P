use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use digest::Digest;
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, info};

use crate::network::kad::obfuscation::Rc4State;

const MAGICVALUE_REQUESTER: u8 = 0x22; // 34
const MAGICVALUE_SERVER: u8 = 0xCB; // 203
const MAGICVALUE_SYNC: u32 = 0x835E6FC4;
const ENM_OBFUSCATION: u8 = 0x00;
const RC4_DROP_BYTES: usize = 1024;

const PLAIN_PROTOCOL_MARKERS: [u8; 5] = [
    0xE3, // OP_EDONKEYHEADER
    0xC5, // OP_EMULEPROT
    0xD4, // OP_PACKEDPROT
    0xF4, // OP_ED2KV2HEADER
    0xF5, // OP_ED2KV2PACKEDPROT
];

/// RC4 obfuscation key material needs to be unpredictable to peers observing
/// the handshake. `rand::random` delegates to a thread-local PRNG that *is*
/// seeded from the OS, but being explicit about using `OsRng` makes the
/// security property locally reviewable and avoids a future reseed-from-time
/// regression.
fn rand_u32_os() -> u32 {
    OsRng.next_u32()
}

fn rand_u8_os() -> u8 {
    (OsRng.next_u32() & 0xFF) as u8
}

fn fill_random_os(buf: &mut [u8]) {
    OsRng.fill_bytes(buf);
}

fn semi_random_not_protocol_marker() -> u8 {
    for _ in 0..256 {
        let b = rand_u8_os();
        if !PLAIN_PROTOCOL_MARKERS.contains(&b) && b != 0 {
            return b;
        }
    }
    0x01
}

pub enum NegotiationResult {
    Plain {
        first_byte: u8,
    },
    Obfuscated {
        recv_key: Rc4State,
        send_key: Rc4State,
    },
}

/// Negotiate an incoming TCP connection. Reads the first byte to determine
/// if the connection is plain text or obfuscated.
///
/// - Plain: returns `NegotiationResult::Plain` with the first byte (the caller
///   must prepend it when parsing the first packet).
/// - Obfuscated: performs the RC4 handshake matching eMule's
///   `EncryptedStreamSocket` receiver side, then returns the RC4 keys.
///
/// If `send_response` is false, the receive side of the handshake is verified
/// but no response is sent. This is used for server port test probes where
/// the server's simple test code doesn't expect a response.
#[allow(dead_code)]
pub async fn negotiate_incoming<R, W>(
    reader: &mut R,
    writer: &mut W,
    user_hash: &[u8; 16],
    send_response: bool,
) -> io::Result<NegotiationResult>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let first_byte = reader.read_u8().await?;
    negotiate_incoming_with_first_byte(reader, writer, user_hash, send_response, first_byte).await
}

/// Continue incoming obfuscation negotiation after a caller has inspected the
/// first byte.  The upload listener uses this to detect Ember's private v2
/// preamble without changing the byte sequence fed to the standard eMule
/// plain/RC4 negotiator when the discriminator is absent.
pub async fn negotiate_incoming_with_first_byte<R, W>(
    reader: &mut R,
    writer: &mut W,
    user_hash: &[u8; 16],
    send_response: bool,
    first_byte: u8,
) -> io::Result<NegotiationResult>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    if PLAIN_PROTOCOL_MARKERS.contains(&first_byte) {
        debug!("TCP negotiation: plain text (protocol 0x{first_byte:02X})");
        return Ok(NegotiationResult::Plain { first_byte });
    }

    // --- Obfuscated connection ---
    debug!("TCP negotiation: obfuscated (first byte 0x{first_byte:02X})");

    // Step 1: Read the 4-byte random key part (unencrypted)
    let random_key_part_bytes = reader.read_u32_le().await?;
    let rkp = random_key_part_bytes.to_le_bytes();
    debug!("TCP obfuscation: negotiating keys");

    // Step 2: Derive RC4 keys using MD5(userHash[16] || magicByte[1] || randomKeyPart[4])
    let mut key_buf = [0u8; 21];
    key_buf[..16].copy_from_slice(user_hash);

    // ReceiveKey: magic = MAGICVALUE_REQUESTER (0x22)
    key_buf[16] = MAGICVALUE_REQUESTER;
    key_buf[17..21].copy_from_slice(&rkp);
    let recv_md5 = md5::Md5::digest(key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    // SendKey: magic = MAGICVALUE_SERVER (0xCB)
    key_buf[16] = MAGICVALUE_SERVER;
    let send_md5 = md5::Md5::digest(key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    // Step 3: Read and decrypt MAGICVALUE_SYNC (4 bytes)
    let mut enc_magic = [0u8; 4];
    reader.read_exact(&mut enc_magic).await?;
    let mut dec_magic = [0u8; 4];
    recv_key.process(&enc_magic, &mut dec_magic);
    let magic = u32::from_le_bytes(dec_magic);

    if magic != MAGICVALUE_SYNC {
        info!(
            "TCP obfuscation: magic MISMATCH: got 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}"
        );
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "obfuscation handshake: bad magic 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}"
            ),
        ));
    }
    info!("TCP obfuscation: magic verified OK");

    // Step 4: Read and decrypt method tags + padding length (3 bytes)
    let mut enc_tags = [0u8; 3];
    reader.read_exact(&mut enc_tags).await?;
    let mut dec_tags = [0u8; 3];
    recv_key.process(&enc_tags, &mut dec_tags);
    let _supported_method = dec_tags[0];
    let _preferred_method = dec_tags[1];
    let padding_len = dec_tags[2] as usize;

    // Step 5: Read and decrypt padding (discard)
    if padding_len > 0 {
        let mut enc_pad = vec![0u8; padding_len];
        reader.read_exact(&mut enc_pad).await?;
        let mut dec_pad = vec![0u8; padding_len];
        recv_key.process(&enc_pad, &mut dec_pad);
    }

    // Step 6: Send our response (encrypted with send_key)
    if send_response {
        // eMule default: CryptTCPPaddingLength=128, so % (128+1) = 0..128
        let response_pad_len = (rand_u8_os() % 129) as usize;
        let resp_len = 4 + 1 + 1 + response_pad_len;
        let mut resp_plain = Vec::with_capacity(resp_len);
        resp_plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        resp_plain.push(ENM_OBFUSCATION);
        resp_plain.push(response_pad_len as u8);
        let pad_start = resp_plain.len();
        resp_plain.resize(pad_start + response_pad_len, 0);
        fill_random_os(&mut resp_plain[pad_start..]);

        let mut resp_encrypted = vec![0u8; resp_plain.len()];
        send_key.process(&resp_plain, &mut resp_encrypted);
        writer.write_all(&resp_encrypted).await?;
        writer.flush().await?;

        info!("TCP obfuscation handshake complete (padding_in={padding_len}, padding_out={response_pad_len})");
    } else {
        info!("TCP obfuscation verified (no response sent, padding_in={padding_len})");
    }

    Ok(NegotiationResult::Obfuscated { recv_key, send_key })
}

/// I/O under the same deadline the rest of this handshake uses.
///
/// One shared bound, not a fresh timeout per read: a peer that drip-feeds a
/// byte at a time would otherwise stall for `N * timeout`. The handshake sits
/// in the single `pending_outgoing_buddy` slot and in a
/// `firewall_connect_semaphore` permit, and this crate never sets a TCP
/// keepalive or `SO_RCVTIMEO`, so one unbounded `read_exact` parks those
/// scarce resources indefinitely.
async fn io_at_deadline<F, T>(
    deadline: tokio::time::Instant,
    fut: F,
    what: &str,
) -> io::Result<T>
where
    F: std::future::Future<Output = io::Result<T>>,
{
    tokio::time::timeout_at(deadline, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out")))?
}

/// Wall-clock budget for the entire outgoing TCP obfuscation handshake.
const OUTGOING_HANDSHAKE_TIMEOUT_SECS: u64 = 15;

pub async fn negotiate_outgoing<R, W>(
    reader: &mut R,
    writer: &mut W,
    peer_user_hash: &[u8; 16],
) -> io::Result<(Rc4State, Rc4State)>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let random_key_part = rand_u32_os();
    let rkp = random_key_part.to_le_bytes();

    let mut key_buf = [0u8; 21];
    key_buf[..16].copy_from_slice(peer_user_hash);
    key_buf[16] = MAGICVALUE_REQUESTER;
    key_buf[17..21].copy_from_slice(&rkp);
    let send_md5 = md5::Md5::digest(key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    key_buf[16] = MAGICVALUE_SERVER;
    let recv_md5 = md5::Md5::digest(key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    let pad_len = (rand_u8_os() % 129) as usize;
    let mut plain = Vec::with_capacity(7 + pad_len);
    plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    plain.push(ENM_OBFUSCATION);
    plain.push(ENM_OBFUSCATION);
    plain.push(pad_len as u8);
    let pad_start = plain.len();
    plain.resize(pad_start + pad_len, 0);
    fill_random_os(&mut plain[pad_start..]);
    let mut encrypted = vec![0u8; plain.len()];
    send_key.process(&plain, &mut encrypted);

    let deadline = tokio::time::Instant::now()
        + std::time::Duration::from_secs(OUTGOING_HANDSHAKE_TIMEOUT_SECS);

    io_at_deadline(
        deadline,
        writer.write_u8(semi_random_not_protocol_marker()),
        "outgoing obfuscation marker",
    )
    .await?;
    io_at_deadline(
        deadline,
        writer.write_u32_le(random_key_part),
        "outgoing obfuscation key part",
    )
    .await?;
    io_at_deadline(
        deadline,
        writer.write_all(&encrypted),
        "outgoing obfuscation handshake",
    )
    .await?;
    io_at_deadline(deadline, writer.flush(), "outgoing obfuscation flush").await?;

    let mut enc_magic = [0u8; 4];
    io_at_deadline(
        deadline,
        reader.read_exact(&mut enc_magic),
        "outgoing obfuscation magic",
    )
    .await?;
    let mut dec_magic = [0u8; 4];
    recv_key.process(&enc_magic, &mut dec_magic);
    if u32::from_le_bytes(dec_magic) != MAGICVALUE_SYNC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad obfuscated peer magic",
        ));
    }

    let mut enc_tags = [0u8; 2];
    io_at_deadline(
        deadline,
        reader.read_exact(&mut enc_tags),
        "outgoing obfuscation tags",
    )
    .await?;
    let mut dec_tags = [0u8; 2];
    recv_key.process(&enc_tags, &mut dec_tags);
    if dec_tags[0] != ENM_OBFUSCATION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported obfuscation method",
        ));
    }
    let response_pad_len = dec_tags[1] as usize;
    if response_pad_len > 0 {
        let mut enc_pad = vec![0u8; response_pad_len];
        io_at_deadline(
            deadline,
            reader.read_exact(&mut enc_pad),
            "outgoing obfuscation padding",
        )
        .await?;
        let mut dec_pad = vec![0u8; response_pad_len];
        recv_key.process(&enc_pad, &mut dec_pad);
    }

    Ok((recv_key, send_key))
}

/// Wraps a tokio AsyncRead with transparent RC4 decryption.
pub struct Rc4Reader<R> {
    inner: R,
    rc4: Rc4State,
}

impl<R> Rc4Reader<R> {
    pub fn new(inner: R, rc4: Rc4State) -> Self {
        Self { inner, rc4 }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Rc4Reader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &result {
            let after = buf.filled().len();
            let new_bytes = after - before;
            if new_bytes > 0 {
                let filled = buf.filled_mut();
                let data = &mut filled[before..after];
                let mut decrypted = vec![0u8; new_bytes];
                self.rc4.process(data, &mut decrypted);
                data.copy_from_slice(&decrypted);
            }
        }

        result
    }
}

/// Wraps a tokio AsyncWrite with transparent RC4 encryption.
///
/// Buffers encrypted data internally so that partial writes from the inner
/// transport don't desynchronize the RC4 keystream. Data is encrypted once
/// and retried until fully sent.
pub struct Rc4Writer<W> {
    inner: W,
    rc4: Rc4State,
    pending: Vec<u8>,
    pending_offset: usize,
    /// The plaintext `pending` was encrypted from, retained only while the
    /// caller has not been told those bytes were consumed.
    ///
    /// The bytes themselves, not just a length: once the ciphertext is flushed we
    /// have to decide whether the buffer now offered *is* that same plaintext
    /// (its prefix, re-presented by a `BufWriter` whose flush was cancelled) or
    /// an unrelated one from another call site. A length comparison cannot tell
    /// those apart, and getting it wrong either resends the prefix or claims
    /// bytes that were never encrypted — both desynchronise eD2K framing at the
    /// peer, which decrypts the stream cleanly either way.
    pending_plaintext: Vec<u8>,
}

impl<W> Rc4Writer<W> {
    pub fn new(inner: W, rc4: Rc4State) -> Self {
        Self {
            inner,
            rc4,
            pending: Vec::new(),
            pending_offset: 0,
            pending_plaintext: Vec::new(),
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Rc4Writer<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Flush any pending encrypted data before encrypting new data.
        // Encrypting new data while pending exists would advance the RC4
        // keystream; if the caller retries with the same plaintext the
        // keystream would be out of sync.
        if self.pending_offset < self.pending.len() {
            let chunk = self.pending[self.pending_offset..].to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(n)) => {
                    self.pending_offset += n;
                    if self.pending_offset >= self.pending.len() {
                        self.pending.clear();
                        self.pending_offset = 0;
                        let pending_plaintext = std::mem::take(&mut self.pending_plaintext);
                        // The `Poll::Pending` arm below advances the keystream but
                        // reports nothing consumed, so the caller keeps that slice
                        // and re-presents it — every caller wraps this in a
                        // `BufWriter`, whose cancelled `flush_buf` leaves its
                        // buffer intact and later offers the same prefix plus
                        // newly appended bytes. Its ciphertext is on the wire now,
                        // so report exactly those bytes consumed; re-encrypting
                        // them would send the prefix twice, and because the
                        // keystream stays aligned the peer would decrypt the
                        // duplicate cleanly and desynchronise its eD2K framing.
                        //
                        // Match on the plaintext rather than its length: a longer
                        // buffer from an unrelated call site is not this prefix,
                        // and claiming bytes of it that were never encrypted
                        // leaves a hole with the same consequence.
                        if !pending_plaintext.is_empty() && buf.starts_with(&pending_plaintext) {
                            return Poll::Ready(Ok(pending_plaintext.len()));
                        }
                        // Not that plaintext, so none of `buf` is on the wire yet:
                        // fall through and encrypt all of it.
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        let plaintext_len = buf.len();
        let mut encrypted = vec![0u8; plaintext_len];
        self.rc4.process(buf, &mut encrypted);

        match Pin::new(&mut self.inner).poll_write(cx, &encrypted) {
            Poll::Ready(Ok(n)) => {
                if n < encrypted.len() {
                    self.pending = encrypted;
                    self.pending_offset = n;
                    // Reported consumed, so the caller will not offer these bytes
                    // again and there is no prefix left to recognise.
                    self.pending_plaintext.clear();
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(plaintext_len))
            }
            Poll::Pending => {
                self.pending = encrypted;
                self.pending_offset = 0;
                self.pending_plaintext = buf.to_vec();
                Poll::Pending
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_offset < self.pending.len() {
            let chunk = self.pending[self.pending_offset..].to_vec();
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(n)) => {
                    self.pending_offset += n;
                    if self.pending_offset >= self.pending.len() {
                        self.pending.clear();
                        self.pending_offset = 0;
                        // `pending_plaintext` describes the ciphertext in
                        // `pending` and must not outlive it. The retry
                        // reconciliation in `poll_write` is gated on `pending`
                        // being non-empty, so a stale prefix left here can never
                        // be recognised again: a caller that retries the buffer
                        // whose write returned `Pending` — which the `AsyncWrite`
                        // contract entitles it to do, since those bytes were
                        // never reported consumed — would have it encrypted a
                        // second time and put on the wire twice, with the
                        // keystream advanced. That decrypts cleanly at the peer,
                        // so nothing looks wrong until the eD2K framing has
                        // drifted and the connection is finished.
                        self.pending_plaintext.clear();
                    } else {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Waker;

    /// Inner writer that refuses the very first `poll_write` (accepting
    /// nothing) and then takes everything it is offered.
    struct PendingThenAccept {
        polls: usize,
        written: Vec<u8>,
    }

    impl AsyncWrite for PendingThenAccept {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.polls += 1;
            if self.polls == 1 {
                return Poll::Pending;
            }
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Decrypt an observed ciphertext stream with a fresh keystream, which
    /// only reproduces the plaintext if every byte was encrypted exactly
    /// once and the ciphertext went out in order.
    fn decrypt_stream(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let mut rc4 = Rc4State::new(key);
        let mut plaintext = vec![0u8; ciphertext.len()];
        rc4.process(ciphertext, &mut plaintext);
        plaintext
    }

    /// A `write_all` future dropped on a write timeout leaves the whole
    /// plaintext queued as pending ciphertext with nobody waiting for its
    /// byte count. The next packet comes from a different call site with a
    /// different slice, so that orphaned count says nothing about it:
    /// reporting it consumed would satisfy `AsyncWrite`'s `n <= buf.len()`
    /// while never encrypting those bytes, leaving a hole that decrypts
    /// cleanly at the peer and desynchronises eD2K framing from there on.
    #[test]
    fn an_orphaned_pending_count_does_not_swallow_the_next_packet() {
        let key = [0x11u8; 16];
        let mut cx = Context::from_waker(Waker::noop());
        let mut writer = Rc4Writer::new(
            PendingThenAccept {
                polls: 0,
                written: Vec::new(),
            },
            Rc4State::new(&key),
        );

        let queued = vec![0xAAu8; 64];
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &queued),
            Poll::Pending
        ));

        // Drains the orphaned ciphertext and then encrypts this shorter slice
        // for real, rather than claiming bytes it has not encrypted.
        let next_packet = [0xBBu8; 4];
        match Pin::new(&mut writer).poll_write(&mut cx, &next_packet) {
            Poll::Ready(Ok(n)) => assert_eq!(
                n,
                next_packet.len(),
                "the shorter slice must be encrypted, not swallowed"
            ),
            other => panic!("expected a completed write, got {other:?}"),
        }

        let mut expected = queued.clone();
        expected.extend_from_slice(&next_packet);
        assert_eq!(
            decrypt_stream(&key, &writer.inner.written),
            expected,
            "both packets must reach the wire once, in order",
        );
    }

    /// Every caller wraps this writer in a `tokio::io::BufWriter`, and a
    /// `flush_buf` cancelled by a write timeout leaves that buffer intact: the
    /// next packet appends to it, so the retry presents the same prefix *plus*
    /// new bytes. Only the prefix is already on the wire, so re-encrypting the
    /// whole slice would send it twice — and because the keystream stays
    /// aligned the peer decrypts the duplicate cleanly and its eD2K framing
    /// desynchronises from there on.
    #[test]
    fn a_superset_retry_does_not_resend_the_prefix() {
        let key = [0x33u8; 16];
        let mut cx = Context::from_waker(Waker::noop());
        let mut writer = Rc4Writer::new(
            PendingThenAccept {
                polls: 0,
                written: Vec::new(),
            },
            Rc4State::new(&key),
        );

        let first = vec![0xAAu8; 64];
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &first),
            Poll::Pending
        ));

        // What a `BufWriter` re-presents: the un-drained prefix plus 16 newly
        // appended bytes.
        let mut superset = first.clone();
        superset.extend_from_slice(&[0xCCu8; 16]);
        match Pin::new(&mut writer).poll_write(&mut cx, &superset) {
            Poll::Ready(Ok(n)) => assert_eq!(
                n, 64,
                "only the prefix whose ciphertext is already out counts as consumed"
            ),
            other => panic!("expected the prefix to be reported consumed, got {other:?}"),
        }

        let tail = [0xCCu8; 16];
        match Pin::new(&mut writer).poll_write(&mut cx, &tail) {
            Poll::Ready(Ok(n)) => assert_eq!(n, tail.len()),
            other => panic!("expected the tail to be written, got {other:?}"),
        }

        assert_eq!(
            decrypt_stream(&key, &writer.inner.written),
            superset,
            "every byte must reach the wire exactly once, in order",
        );
    }

    /// A longer buffer is not automatically the `BufWriter` prefix retry: a
    /// timed-out `write_all` can be followed by an unrelated, larger packet from
    /// another call site. Deciding on length alone claimed that packet's leading
    /// bytes as written without ever encrypting them, leaving a hole the peer
    /// decrypts cleanly — the same framing desync as sending them twice.
    #[test]
    fn a_longer_unrelated_buffer_is_encrypted_rather_than_claimed() {
        let key = [0x44u8; 16];
        let mut cx = Context::from_waker(Waker::noop());
        let mut writer = Rc4Writer::new(
            PendingThenAccept {
                polls: 0,
                written: Vec::new(),
            },
            Rc4State::new(&key),
        );

        let orphaned = vec![0xAAu8; 8];
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &orphaned),
            Poll::Pending
        ));

        // Longer than the orphaned count, but a different payload entirely.
        let unrelated = vec![0xDDu8; 32];
        match Pin::new(&mut writer).poll_write(&mut cx, &unrelated) {
            Poll::Ready(Ok(n)) => assert_eq!(
                n,
                unrelated.len(),
                "an unrelated packet must be encrypted in full, not partly claimed"
            ),
            other => panic!("expected the unrelated packet to be written, got {other:?}"),
        }

        let mut expected = orphaned.clone();
        expected.extend_from_slice(&unrelated);
        assert_eq!(
            decrypt_stream(&key, &writer.inner.written),
            expected,
            "every byte reaches the wire exactly once, in order",
        );
    }

    /// The fast path: a `write_all` that was interrupted mid-write retries
    /// with the identical buffer, whose ciphertext is already queued. It must
    /// be reported consumed without re-encrypting it — a second pass over the
    /// same plaintext would emit it twice and desynchronise the keystream.
    #[test]
    fn a_retry_with_the_same_buffer_is_reported_consumed_once() {
        let key = [0x22u8; 16];
        let mut cx = Context::from_waker(Waker::noop());
        let mut writer = Rc4Writer::new(
            PendingThenAccept {
                polls: 0,
                written: Vec::new(),
            },
            Rc4State::new(&key),
        );

        let packet = vec![0xCCu8; 64];
        assert!(matches!(
            Pin::new(&mut writer).poll_write(&mut cx, &packet),
            Poll::Pending
        ));
        match Pin::new(&mut writer).poll_write(&mut cx, &packet) {
            Poll::Ready(Ok(n)) => assert_eq!(n, packet.len()),
            other => panic!("expected a completed write, got {other:?}"),
        }
        assert_eq!(
            writer.inner.written.len(),
            packet.len(),
            "the queued ciphertext must be delivered exactly once",
        );

        // A following packet has to pick up the keystream where the first one
        // left off, which only holds if the retry did not re-encrypt.
        let followup = [0xDDu8; 8];
        match Pin::new(&mut writer).poll_write(&mut cx, &followup) {
            Poll::Ready(Ok(n)) => assert_eq!(n, followup.len()),
            other => panic!("expected a completed write, got {other:?}"),
        }
        let mut expected = packet.clone();
        expected.extend_from_slice(&followup);
        assert_eq!(decrypt_stream(&key, &writer.inner.written), expected);
    }
}
