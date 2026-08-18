use std::io;
use std::net::SocketAddr;

use digest::Digest;
use num_bigint_dig::BigUint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::info;

use crate::network::kad::obfuscation::Rc4State;

const MAGICVALUE_REQUESTER: u8 = 0x22;
const MAGICVALUE_SERVER: u8 = 0xCB;
const MAGICVALUE_SYNC: u32 = 0x835E6FC4;
const ENM_OBFUSCATION: u8 = 0x00;
const RC4_DROP_BYTES: usize = 1024;
const PRIMESIZE_BYTES: usize = 96;
const DH_A_BITS: usize = 128;

#[rustfmt::skip]
const DH768_P: [u8; PRIMESIZE_BYTES] = [
    0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36, 0xE8, 0x86, 0xEB, 0x3C,
    0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D, 0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7,
    0x21, 0xFC, 0x28, 0x63, 0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
    0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4, 0x5A, 0xD5, 0xE0, 0x74,
    0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34, 0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91,
    0x42, 0xFB, 0x42, 0x68, 0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
];

const PLAIN_MARKERS: [u8; 5] = [0xE3, 0xC5, 0xD4, 0xF4, 0xF5];

fn semi_random_marker() -> u8 {
    for _ in 0..32 {
        let b: u8 = rand::random();
        if !PLAIN_MARKERS.contains(&b) {
            return b;
        }
    }
    0x01
}

/// Encode a BigUint as exactly `size` big-endian bytes, zero-padded on the left.
fn biguint_to_be_padded(val: &BigUint, size: usize) -> Vec<u8> {
    let raw = val.to_bytes_be();
    if raw.len() >= size {
        raw[raw.len() - size..].to_vec()
    } else {
        let mut padded = vec![0u8; size - raw.len()];
        padded.extend_from_slice(&raw);
        padded
    }
}

/// Result of the server DH handshake.
pub struct ObfuscatedServerStream {
    pub(crate) reader: tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    pub(crate) writer: tokio::io::BufWriter<tokio::net::tcp::OwnedWriteHalf>,
    pub(crate) recv_key: Rc4State,
    pub(crate) send_key: Rc4State,
    pending_handshake: Vec<u8>,
}

impl ObfuscatedServerStream {
    /// Write the login request, prepending the buffered handshake response (Message 3).
    /// This matches eMule's delayed-sending behavior: the handshake response and the
    /// first payload go out as a single TCP frame.
    pub async fn write_login(&mut self, login_payload: &[u8]) -> io::Result<()> {
        let mut encrypted_payload = vec![0u8; login_payload.len()];
        self.send_key.process(login_payload, &mut encrypted_payload);

        let mut combined =
            Vec::with_capacity(self.pending_handshake.len() + encrypted_payload.len());
        combined.extend_from_slice(&self.pending_handshake);
        combined.extend_from_slice(&encrypted_payload);
        self.pending_handshake.clear();

        self.writer.write_all(&combined).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Read and decrypt a server packet. Returns (opcode, payload).
    /// Consume just the first ciphertext byte of a packet header.
    ///
    /// The poll loop deadlines this alone so an expiry provably leaves the
    /// stream on a packet boundary; everything after it is read under a long
    /// fatal budget, because RC4 is a stream cipher and an abandoned read
    /// desynchronizes the keystream as well as the framing.
    pub async fn read_packet_first_byte(&mut self) -> io::Result<u8> {
        let mut first = [0u8; 1];
        self.reader.read_exact(&mut first).await?;
        Ok(first[0])
    }

    pub async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let first = self.read_packet_first_byte().await?;
        self.read_packet_after_first_byte(first).await
    }

    /// The rest of a packet, given its already-consumed first ciphertext byte.
    ///
    /// The byte is re-joined with the remaining five before decryption, so the
    /// RC4 keystream advances over exactly the same six bytes as a single
    /// read would have.
    pub async fn read_packet_after_first_byte(&mut self, first: u8) -> io::Result<(u8, Vec<u8>)> {
        let mut enc_header = [0u8; 6];
        enc_header[0] = first;
        self.reader.read_exact(&mut enc_header[1..]).await?;
        let mut dec_header = [0u8; 6];
        self.recv_key.process(&enc_header, &mut dec_header);

        let protocol = dec_header[0];
        if protocol != 0xE3 && protocol != 0xC5 && protocol != 0xD4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected encrypted server protocol byte: 0x{protocol:02X} (dec_header={:02X?})", dec_header),
            ));
        }
        let length =
            u32::from_le_bytes([dec_header[1], dec_header[2], dec_header[3], dec_header[4]])
                as usize;
        if length == 0 || length > 5 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid encrypted server packet length",
            ));
        }
        let opcode = dec_header[5];
        let payload_len = length - 1;

        // Grow + decrypt as bytes actually arrive rather than allocating the
        // full declared length (up to ~5 MiB) twice (cipher input + output)
        // up front. A slow/hostile server (or MITM on this connection) could
        // otherwise pin ~10 MiB per session by announcing a large length then
        // stalling. RC4 is a stateful stream cipher, so chunked `process`
        // produces byte-identical output to a single call. The encrypted
        // chunk lives on the heap (not the stack) since this read runs inside
        // the server connection future.
        let mut payload = Vec::new();
        if payload_len > 0 {
            payload.reserve(payload_len.min(64 * 1024));
            let mut remaining = payload_len;
            let mut enc_chunk = vec![0u8; payload_len.min(32 * 1024)];
            while remaining > 0 {
                let want = remaining.min(enc_chunk.len());
                self.reader.read_exact(&mut enc_chunk[..want]).await?;
                let start = payload.len();
                payload.resize(start + want, 0);
                self.recv_key
                    .process(&enc_chunk[..want], &mut payload[start..start + want]);
                remaining -= want;
            }
        }

        if protocol == 0xD4 {
            let decompressed = decompress_payload(&payload)?;
            Ok((opcode, decompressed))
        } else {
            Ok((opcode, payload))
        }
    }
}

fn decompress_payload(compressed: &[u8]) -> io::Result<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    const MAX_DECOMPRESSED: usize = 300_000;
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if out.len() + n > MAX_DECOMPRESSED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decompressed packet too large",
            ));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

/// `read_exact` under the same deadline the rest of this handshake uses.
///
/// Each step of the DH exchange needs its own bound: the handshake sits in
/// the single `pending_server_connect` slot, and that slot gating eD2K
/// auto-reconnect means one unbounded read takes the whole server subsystem
/// down until the user reconnects by hand.
async fn read_exact_bounded<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    what: &str,
) -> io::Result<()> {
    tokio::time::timeout(
        std::time::Duration::from_secs(DH_STEP_TIMEOUT_SECS),
        reader.read_exact(buf),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("{what} timed out")))??;
    Ok(())
}

/// Per-step deadline for the obfuscated server handshake.
const DH_STEP_TIMEOUT_SECS: u64 = 10;

/// Perform the full DH handshake with a server's obfuscation port.
pub async fn connect_obfuscated(addr: SocketAddr) -> io::Result<ObfuscatedServerStream> {
    info!("Connecting to server obfuscation port {addr}");

    let stream = tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect(addr))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "server obfuscation connect timed out",
            )
        })??;
    let _ = stream.set_nodelay(true);

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    // --- Message 1: Client -> Server (all plaintext) ---
    let p = BigUint::from_bytes_be(&DH768_P);
    let g = BigUint::from(2u32);

    // Generate 128-bit random private key from a CSPRNG (OsRng): this is the
    // DH secret exponent, so it must be cryptographically unpredictable.
    let mut a_bytes = [0u8; DH_A_BITS / 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut a_bytes);
    let a = BigUint::from_bytes_be(&a_bytes);

    let g_a_mod_p = g.modpow(&a, &p);
    let g_a_bytes = biguint_to_be_padded(&g_a_mod_p, PRIMESIZE_BYTES);

    let pad_len = (rand::random::<u8>() % 16) as usize;
    let mut msg1 = Vec::with_capacity(1 + PRIMESIZE_BYTES + 1 + pad_len);
    msg1.push(semi_random_marker());
    msg1.extend_from_slice(&g_a_bytes);
    msg1.push(pad_len as u8);
    for _ in 0..pad_len {
        msg1.push(rand::random());
    }

    writer.write_all(&msg1).await?;
    writer.flush().await?;
    info!(
        "Server DH: sent g^a ({} bytes + {} padding)",
        PRIMESIZE_BYTES, pad_len
    );

    // --- Message 2: Server -> Client ---
    // Step 1: Read g^b (96 bytes, plaintext)
    let mut g_b_bytes = [0u8; PRIMESIZE_BYTES];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        reader.read_exact(&mut g_b_bytes),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server DH answer timed out"))??;

    let g_b = BigUint::from_bytes_be(&g_b_bytes);

    let one = BigUint::from(1u32);
    if g_b <= one || g_b >= (&p - &one) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "server DH: invalid g^b value (small subgroup)",
        ));
    }

    // Step 2: Compute shared secret S = (g^b)^a mod p
    let shared_secret = g_b.modpow(&a, &p);
    let s_bytes = biguint_to_be_padded(&shared_secret, PRIMESIZE_BYTES);

    // Step 3: Derive RC4 keys from MD5(S[96] || magic_byte)
    let mut key_buf = [0u8; PRIMESIZE_BYTES + 1];
    key_buf[..PRIMESIZE_BYTES].copy_from_slice(&s_bytes);

    key_buf[PRIMESIZE_BYTES] = MAGICVALUE_REQUESTER;
    let send_md5 = md5::Md5::digest(key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    key_buf[PRIMESIZE_BYTES] = MAGICVALUE_SERVER;
    let recv_md5 = md5::Md5::digest(key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    info!("Server DH: shared secret computed, RC4 keys derived");

    // Step 4: Read + decrypt: magic(4) + methods(1) + preferred(1) + padLen(1) + padding
    //
    // Every read from here on is bounded. Without a timeout, a server that
    // accepted the connection and sent its 96-byte g^b and then went quiet
    // parked this future forever — and because it runs inside the
    // `pending_server_connect` task, whose slot must be empty for eD2K
    // auto-reconnect to fire again, the whole server subsystem stayed wedged
    // on "Connecting…" for the rest of the session with nothing to recover it.
    let mut enc_magic = [0u8; 4];
    read_exact_bounded(&mut reader, &mut enc_magic, "server DH sync magic").await?;
    let mut dec_magic = [0u8; 4];
    recv_key.process(&enc_magic, &mut dec_magic);
    let magic = u32::from_le_bytes(dec_magic);

    if magic != MAGICVALUE_SYNC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("server DH: bad magic 0x{magic:08X}, expected 0x{MAGICVALUE_SYNC:08X}"),
        ));
    }
    info!("Server DH: magic verified OK");

    let mut enc_tags = [0u8; 3];
    read_exact_bounded(&mut reader, &mut enc_tags, "server DH method tags").await?;
    let mut dec_tags = [0u8; 3];
    recv_key.process(&enc_tags, &mut dec_tags);
    let _methods_supported = dec_tags[0];
    let _method_preferred = dec_tags[1];
    let server_pad_len = dec_tags[2] as usize;

    if server_pad_len > 0 {
        let mut enc_pad = vec![0u8; server_pad_len];
        read_exact_bounded(&mut reader, &mut enc_pad, "server DH padding").await?;
        let mut dec_pad = vec![0u8; server_pad_len];
        recv_key.process(&enc_pad, &mut dec_pad);
    }

    // --- Build Message 3 (buffered, sent with first write) ---
    let resp_pad_len = (rand::random::<u8>() % 16) as usize;
    let mut resp_plain = Vec::with_capacity(6 + resp_pad_len);
    resp_plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    resp_plain.push(ENM_OBFUSCATION);
    resp_plain.push(resp_pad_len as u8);
    for _ in 0..resp_pad_len {
        resp_plain.push(rand::random());
    }

    let mut resp_encrypted = vec![0u8; resp_plain.len()];
    send_key.process(&resp_plain, &mut resp_encrypted);

    info!("Server DH: handshake complete, encrypted stream ready");

    Ok(ObfuscatedServerStream {
        reader,
        writer,
        recv_key,
        send_key,
        pending_handshake: resp_encrypted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// Padding the server side sends inside Message 2, so the test drives the
    /// `server_pad_len > 0` branch rather than only the zero-padding case a
    /// hand-written stub would default to.
    const SERVER_PAD_LEN: usize = 5;

    /// The two RC4 keystreams the handshake derives from a shared secret,
    /// returned as `(requester, server)` — the pair `connect_obfuscated` calls
    /// `send_key` and `recv_key`, from the far side's point of view.
    ///
    /// Both come from the same MD5 over the same 96-byte secret and differ only
    /// in the trailing magic byte, which is what makes the direction separation
    /// worth a test of its own.
    fn derive_keys(shared: &BigUint) -> (Rc4State, Rc4State) {
        let mut key_buf = [0u8; PRIMESIZE_BYTES + 1];
        key_buf[..PRIMESIZE_BYTES].copy_from_slice(&biguint_to_be_padded(shared, PRIMESIZE_BYTES));
        let [requester, server] = [MAGICVALUE_REQUESTER, MAGICVALUE_SERVER].map(|magic| {
            key_buf[PRIMESIZE_BYTES] = magic;
            let mut key = Rc4State::new(&md5::Md5::digest(&key_buf));
            key.skip(RC4_DROP_BYTES);
            key
        });
        (requester, server)
    }

    /// What the far side managed to read out of the client's first write.
    /// Returned to the test rather than asserted inside the spawned task, so a
    /// mismatch fails the test instead of hanging it on a dead peer.
    struct ServerObserved {
        sync_magic: u32,
        method: u8,
        login: Vec<u8>,
    }

    /// Play the server half of the obfuscation handshake, then send one
    /// encrypted packet back.
    ///
    /// Deliberately written against the wire format rather than against the
    /// helpers in this module: a test that reuses the same code for both sides
    /// would still pass if the recipe drifted away from what eMule's servers do.
    async fn run_server_half(
        mut socket: TcpStream,
        login_len: usize,
        packet: (u8, &[u8]),
    ) -> ServerObserved {
        // Message 1: semi-random marker, g^a, then a length-prefixed pad.
        let mut head = [0u8; 1 + PRIMESIZE_BYTES + 1];
        socket.read_exact(&mut head).await.unwrap();
        let client_pad = head[1 + PRIMESIZE_BYTES] as usize;
        if client_pad > 0 {
            let mut discarded = vec![0u8; client_pad];
            socket.read_exact(&mut discarded).await.unwrap();
        }
        let g_a = BigUint::from_bytes_be(&head[1..=PRIMESIZE_BYTES]);

        let p = BigUint::from_bytes_be(&DH768_P);
        // Fixed exponent: the client's is drawn from OsRng, so one deterministic
        // side is enough and keeps a failure reproducible.
        let b = BigUint::from_bytes_be(&[0x5Au8; DH_A_BITS / 8]);
        let g_b = BigUint::from(2u32).modpow(&b, &p);
        socket
            .write_all(&biguint_to_be_padded(&g_b, PRIMESIZE_BYTES))
            .await
            .unwrap();

        let (mut client_to_server, mut server_to_client) = derive_keys(&g_a.modpow(&b, &p));

        // Message 2 tail: sync magic, the method tags, and padding, encrypted.
        let mut tail = Vec::new();
        tail.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
        tail.push(ENM_OBFUSCATION);
        tail.push(ENM_OBFUSCATION);
        tail.push(SERVER_PAD_LEN as u8);
        tail.extend(std::iter::repeat(0xABu8).take(SERVER_PAD_LEN));
        let mut encrypted = vec![0u8; tail.len()];
        server_to_client.process(&tail, &mut encrypted);
        socket.write_all(&encrypted).await.unwrap();

        // Message 3 arrives glued to the first login write, which is the whole
        // point of `pending_handshake`.
        let mut encrypted_response = [0u8; 6];
        socket.read_exact(&mut encrypted_response).await.unwrap();
        let mut response = [0u8; 6];
        client_to_server.process(&encrypted_response, &mut response);
        let response_pad = response[5] as usize;
        if response_pad > 0 {
            let mut encrypted_pad = vec![0u8; response_pad];
            socket.read_exact(&mut encrypted_pad).await.unwrap();
            let mut discarded = vec![0u8; response_pad];
            client_to_server.process(&encrypted_pad, &mut discarded);
        }
        let mut encrypted_login = vec![0u8; login_len];
        socket.read_exact(&mut encrypted_login).await.unwrap();
        let mut login = vec![0u8; login_len];
        client_to_server.process(&encrypted_login, &mut login);

        let (opcode, payload) = packet;
        let mut plain = Vec::with_capacity(6 + payload.len());
        plain.push(0xE3);
        plain.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
        plain.push(opcode);
        plain.extend_from_slice(payload);
        let mut encrypted_packet = vec![0u8; plain.len()];
        server_to_client.process(&plain, &mut encrypted_packet);
        socket.write_all(&encrypted_packet).await.unwrap();

        ServerObserved {
            sync_magic: u32::from_le_bytes([response[0], response[1], response[2], response[3]]),
            method: response[4],
            login,
        }
    }

    /// Both sides reach the same secret from their own private exponent, and
    /// each direction's keystream is readable by exactly the other end. The
    /// login write also has to carry the buffered Message 3 in front of it: the
    /// server reads them as one stream, so a client that sent the payload first
    /// would desynchronize the RC4 keystream for the rest of the session.
    #[tokio::test]
    async fn the_dh_handshake_keys_both_directions_of_the_stream() {
        const LOGIN: &[u8] = b"\xE3\x0B\x00\x00\x00\x01login-body";
        const OPCODE: u8 = 0x38;
        const PAYLOAD: &[u8] = b"server-said-this";

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            run_server_half(socket, LOGIN.len(), (OPCODE, PAYLOAD)).await
        });

        let mut stream = connect_obfuscated(addr).await.unwrap();
        stream.write_login(LOGIN).await.unwrap();
        let (opcode, payload) = stream.read_packet().await.unwrap();
        let observed = server.await.unwrap();

        assert_eq!(
            observed.sync_magic, MAGICVALUE_SYNC,
            "the server must decrypt our Message 3 to the sync magic"
        );
        assert_eq!(observed.method, ENM_OBFUSCATION);
        assert_eq!(
            observed.login, LOGIN,
            "the login payload must survive the client-to-server keystream"
        );
        assert_eq!(opcode, OPCODE);
        assert_eq!(
            payload, PAYLOAD,
            "and the server-to-client keystream must be the one we derived"
        );
    }

    /// The two directions are separated only by the trailing magic byte. If that
    /// byte were dropped, or the roles swapped, both ends would still derive a
    /// key and the handshake would still "succeed" — every packet after it would
    /// simply be garbage, which is far harder to diagnose than a failed connect.
    #[test]
    fn a_key_from_the_other_direction_or_another_secret_reads_garbage() {
        let shared = BigUint::from_bytes_be(&[0x7Cu8; PRIMESIZE_BYTES]);
        let plain = b"OP_LOGINREQUEST body";

        let (mut requester, _) = derive_keys(&shared);
        let mut cipher = vec![0u8; plain.len()];
        requester.process(plain, &mut cipher);

        let (mut same_key, mut wrong_direction) = derive_keys(&shared);
        let mut decrypted = vec![0u8; plain.len()];
        same_key.process(&cipher, &mut decrypted);
        assert_eq!(
            decrypted.as_slice(),
            plain.as_slice(),
            "the derivation must be reproducible from the shared secret alone"
        );

        wrong_direction.process(&cipher, &mut decrypted);
        assert_ne!(
            decrypted.as_slice(),
            plain.as_slice(),
            "the server-direction key must not read the requester's stream"
        );

        let other_shared = BigUint::from_bytes_be(&[0x7Du8; PRIMESIZE_BYTES]);
        let (mut other_secret, _) = derive_keys(&other_shared);
        other_secret.process(&cipher, &mut decrypted);
        assert_ne!(
            decrypted.as_slice(),
            plain.as_slice(),
            "a secret that differs in one byte must not read the stream either"
        );
    }

    /// The common case: a secret with leading zero bytes. `to_bytes_be` drops
    /// them, and eMule's MD5 is taken over the full 96 bytes, so a secret that
    /// happens to start with a zero byte would key a different stream on each
    /// side if the padding were lost.
    #[test]
    fn a_short_value_is_left_padded_to_the_full_wire_width() {
        let value = BigUint::from(0x0102_0304u32);
        let padded = biguint_to_be_padded(&value, PRIMESIZE_BYTES);

        assert_eq!(padded.len(), PRIMESIZE_BYTES);
        assert!(
            padded[..PRIMESIZE_BYTES - 4].iter().all(|byte| *byte == 0),
            "the pad must go on the left"
        );
        assert_eq!(&padded[PRIMESIZE_BYTES - 4..], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(
            BigUint::from_bytes_be(&padded),
            value,
            "padding must not change the value"
        );
    }

    #[test]
    fn a_value_exactly_the_wire_width_is_passed_through_unchanged() {
        // Top bit set so the big-endian encoding cannot shrink below 96 bytes
        // and quietly take the padding branch instead.
        let bytes: Vec<u8> = (0..PRIMESIZE_BYTES).map(|i| i as u8 | 0x80).collect();
        let value = BigUint::from_bytes_be(&bytes);

        assert_eq!(biguint_to_be_padded(&value, PRIMESIZE_BYTES), bytes);
    }

    /// Both branches subtract lengths, on opposite sides of the same
    /// comparison. With `overflow-checks` on, an off-by-one there is an
    /// unsigned underflow panic mid-handshake rather than a wrong key, so the
    /// equal-length and zero-width edges are worth pinning.
    #[test]
    fn an_oversized_value_keeps_its_low_bytes_and_stays_in_bounds() {
        let mut bytes = vec![0xEEu8; PRIMESIZE_BYTES + 2];
        bytes[0] = 0x01;
        let oversized = BigUint::from_bytes_be(&bytes);

        assert_eq!(
            biguint_to_be_padded(&oversized, PRIMESIZE_BYTES),
            &bytes[2..],
            "the most significant bytes are the ones dropped"
        );
        assert_eq!(
            biguint_to_be_padded(&BigUint::from(0u32), PRIMESIZE_BYTES),
            vec![0u8; PRIMESIZE_BYTES],
            "zero must still occupy the full width"
        );
        assert!(biguint_to_be_padded(&oversized, 0).is_empty());
    }
}
