use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use digest::Digest;
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

fn semi_random_not_protocol_marker() -> u8 {
    for _ in 0..256 {
        let b = rand::random::<u8>();
        if !PLAIN_PROTOCOL_MARKERS.contains(&b) && b != 0 {
            return b;
        }
    }
    0x01
}

pub enum NegotiationResult {
    Plain { first_byte: u8 },
    Obfuscated { recv_key: Rc4State, send_key: Rc4State },
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
    let recv_md5 = md5::Md5::digest(&key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    // SendKey: magic = MAGICVALUE_SERVER (0xCB)
    key_buf[16] = MAGICVALUE_SERVER;
    let send_md5 = md5::Md5::digest(&key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    // Step 3: Read and decrypt MAGICVALUE_SYNC (4 bytes)
    let mut enc_magic = [0u8; 4];
    reader.read_exact(&mut enc_magic).await?;
    let mut dec_magic = [0u8; 4];
    recv_key.process(&enc_magic, &mut dec_magic);
    let magic = u32::from_le_bytes(dec_magic);

    if magic != MAGICVALUE_SYNC {
        info!("TCP obfuscation: magic MISMATCH: got 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}");
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("obfuscation handshake: bad magic 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}"),
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
        let response_pad_len = (rand::random::<u8>() % 129) as usize;
        let resp_len = 4 + 1 + 1 + response_pad_len;
        let mut resp_plain = Vec::with_capacity(resp_len);
        resp_plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        resp_plain.push(ENM_OBFUSCATION);
        resp_plain.push(response_pad_len as u8);
        for _ in 0..response_pad_len {
            resp_plain.push(rand::random::<u8>());
        }

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

pub async fn negotiate_outgoing<R, W>(
    reader: &mut R,
    writer: &mut W,
    peer_user_hash: &[u8; 16],
) -> io::Result<(Rc4State, Rc4State)>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let random_key_part = rand::random::<u32>();
    let rkp = random_key_part.to_le_bytes();

    let mut key_buf = [0u8; 21];
    key_buf[..16].copy_from_slice(peer_user_hash);
    key_buf[16] = MAGICVALUE_REQUESTER;
    key_buf[17..21].copy_from_slice(&rkp);
    let send_md5 = md5::Md5::digest(&key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    key_buf[16] = MAGICVALUE_SERVER;
    let recv_md5 = md5::Md5::digest(&key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    let pad_len = (rand::random::<u8>() % 129) as usize;
    let mut plain = Vec::with_capacity(7 + pad_len);
    plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    plain.push(ENM_OBFUSCATION);
    plain.push(ENM_OBFUSCATION);
    plain.push(pad_len as u8);
    for _ in 0..pad_len {
        plain.push(rand::random::<u8>());
    }
    let mut encrypted = vec![0u8; plain.len()];
    send_key.process(&plain, &mut encrypted);

    writer.write_u8(semi_random_not_protocol_marker()).await?;
    writer.write_u32_le(random_key_part).await?;
    writer.write_all(&encrypted).await?;
    writer.flush().await?;

    let mut enc_magic = [0u8; 4];
    reader.read_exact(&mut enc_magic).await?;
    let mut dec_magic = [0u8; 4];
    recv_key.process(&enc_magic, &mut dec_magic);
    if u32::from_le_bytes(dec_magic) != MAGICVALUE_SYNC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad obfuscated peer magic"));
    }

    let mut enc_tags = [0u8; 2];
    reader.read_exact(&mut enc_tags).await?;
    let mut dec_tags = [0u8; 2];
    recv_key.process(&enc_tags, &mut dec_tags);
    if dec_tags[0] != ENM_OBFUSCATION {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported obfuscation method"));
    }
    let response_pad_len = dec_tags[1] as usize;
    if response_pad_len > 0 {
        let mut enc_pad = vec![0u8; response_pad_len];
        reader.read_exact(&mut enc_pad).await?;
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
    pending_plaintext_len: usize,
}

impl<W> Rc4Writer<W> {
    pub fn new(inner: W, rc4: Rc4State) -> Self {
        Self { inner, rc4, pending: Vec::new(), pending_offset: 0, pending_plaintext_len: 0 }
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
                        let consumed = self.pending_plaintext_len;
                        self.pending_plaintext_len = 0;
                        if consumed > 0 {
                            return Poll::Ready(Ok(consumed));
                        }
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
                    self.pending_plaintext_len = 0;
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Ok(plaintext_len))
            }
            Poll::Pending => {
                self.pending = encrypted;
                self.pending_offset = 0;
                self.pending_plaintext_len = plaintext_len;
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
