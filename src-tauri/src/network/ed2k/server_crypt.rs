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

const PLAIN_MARKERS: [u8; 3] = [0xE3, 0xC5, 0xD4];

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

        let mut combined = Vec::with_capacity(self.pending_handshake.len() + encrypted_payload.len());
        combined.extend_from_slice(&self.pending_handshake);
        combined.extend_from_slice(&encrypted_payload);
        self.pending_handshake.clear();

        self.writer.write_all(&combined).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Read and decrypt a server packet. Returns (opcode, payload).
    pub async fn read_packet(&mut self) -> io::Result<(u8, Vec<u8>)> {
        let mut enc_header = [0u8; 6];
        self.reader.read_exact(&mut enc_header).await?;
        let mut dec_header = [0u8; 6];
        self.recv_key.process(&enc_header, &mut dec_header);

        let protocol = dec_header[0];
        if protocol != 0xE3 && protocol != 0xD4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected encrypted server protocol byte: 0x{protocol:02X} (dec_header={:02X?})", dec_header),
            ));
        }
        let length = u32::from_le_bytes([dec_header[1], dec_header[2], dec_header[3], dec_header[4]]) as usize;
        if length == 0 || length > 50 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid encrypted server packet length",
            ));
        }
        let opcode = dec_header[5];
        let payload_len = length - 1;

        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            let mut enc_payload = vec![0u8; payload_len];
            self.reader.read_exact(&mut enc_payload).await?;
            self.recv_key.process(&enc_payload, &mut payload);
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
    let mut decoder = ZlibDecoder::new(compressed);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf)?;
        if n == 0 { break; }
        out.extend_from_slice(&buf[..n]);
        if out.len() > 300_000 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "decompressed packet too large"));
        }
    }
    Ok(out)
}

/// Perform the full DH handshake with a server's obfuscation port.
pub async fn connect_obfuscated(addr: SocketAddr) -> io::Result<ObfuscatedServerStream> {
    info!("Connecting to server obfuscation port {addr}");

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(addr),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server obfuscation connect timed out"))?
    ?;

    let (reader, writer) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);
    let mut writer = tokio::io::BufWriter::new(writer);

    // --- Message 1: Client -> Server (all plaintext) ---
    let p = BigUint::from_bytes_be(&DH768_P);
    let g = BigUint::from(2u32);

    // Generate 128-bit random private key
    let mut a_bytes = [0u8; DH_A_BITS / 8];
    for b in &mut a_bytes { *b = rand::random(); }
    let a = BigUint::from_bytes_be(&a_bytes);

    let g_a_mod_p = g.modpow(&a, &p);
    let g_a_bytes = biguint_to_be_padded(&g_a_mod_p, PRIMESIZE_BYTES);

    let pad_len = (rand::random::<u8>() % 16) as usize;
    let mut msg1 = Vec::with_capacity(1 + PRIMESIZE_BYTES + 1 + pad_len);
    msg1.push(semi_random_marker());
    msg1.extend_from_slice(&g_a_bytes);
    msg1.push(pad_len as u8);
    for _ in 0..pad_len { msg1.push(rand::random()); }

    writer.write_all(&msg1).await?;
    writer.flush().await?;
    info!("Server DH: sent g^a ({} bytes + {} padding)", PRIMESIZE_BYTES, pad_len);

    // --- Message 2: Server -> Client ---
    // Step 1: Read g^b (96 bytes, plaintext)
    let mut g_b_bytes = [0u8; PRIMESIZE_BYTES];
    tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_exact(&mut g_b_bytes),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server DH answer timed out"))?
    ?;

    let g_b = BigUint::from_bytes_be(&g_b_bytes);

    // Step 2: Compute shared secret S = (g^b)^a mod p
    let shared_secret = g_b.modpow(&a, &p);
    let s_bytes = biguint_to_be_padded(&shared_secret, PRIMESIZE_BYTES);

    // Step 3: Derive RC4 keys from MD5(S[96] || magic_byte)
    let mut key_buf = [0u8; PRIMESIZE_BYTES + 1];
    key_buf[..PRIMESIZE_BYTES].copy_from_slice(&s_bytes);

    key_buf[PRIMESIZE_BYTES] = MAGICVALUE_REQUESTER;
    let send_md5 = md5::Md5::digest(&key_buf);
    let mut send_key = Rc4State::new(&send_md5);
    send_key.skip(RC4_DROP_BYTES);

    key_buf[PRIMESIZE_BYTES] = MAGICVALUE_SERVER;
    let recv_md5 = md5::Md5::digest(&key_buf);
    let mut recv_key = Rc4State::new(&recv_md5);
    recv_key.skip(RC4_DROP_BYTES);

    info!("Server DH: shared secret computed, RC4 keys derived");

    // Step 4: Read + decrypt: magic(4) + methods(1) + preferred(1) + padLen(1) + padding
    let mut enc_magic = [0u8; 4];
    reader.read_exact(&mut enc_magic).await?;
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
    reader.read_exact(&mut enc_tags).await?;
    let mut dec_tags = [0u8; 3];
    recv_key.process(&enc_tags, &mut dec_tags);
    let _methods_supported = dec_tags[0];
    let _method_preferred = dec_tags[1];
    let server_pad_len = dec_tags[2] as usize;

    if server_pad_len > 0 {
        let mut enc_pad = vec![0u8; server_pad_len];
        reader.read_exact(&mut enc_pad).await?;
        let mut dec_pad = vec![0u8; server_pad_len];
        recv_key.process(&enc_pad, &mut dec_pad);
    }

    // --- Build Message 3 (buffered, sent with first write) ---
    let resp_pad_len = (rand::random::<u8>() % 16) as usize;
    let mut resp_plain = Vec::with_capacity(6 + resp_pad_len);
    resp_plain.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    resp_plain.push(ENM_OBFUSCATION);
    resp_plain.push(resp_pad_len as u8);
    for _ in 0..resp_pad_len { resp_plain.push(rand::random()); }

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
