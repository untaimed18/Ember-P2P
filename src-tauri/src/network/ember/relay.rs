use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use tracing::{debug, info};

const MSG_RELAY_REQUEST: u8 = 0x01;
const MSG_RELAY_ACCEPT: u8 = 0x02;
const MSG_RELAY_CONNECT: u8 = 0x03;
const MSG_RELAY_DATA: u8 = 0x04;
const MSG_RELAY_CLOSE: u8 = 0x05;
const MSG_RELAY_REJECT: u8 = 0x06;

const MAX_RELAY_DATA_SIZE: usize = 16384;
const RELAY_BANDWIDTH_LIMIT: usize = 512 * 1024;
const MAX_CONCURRENT_RELAY_SESSIONS: usize = 4;
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const RELAY_MAX_DURATION: Duration = Duration::from_secs(7200);

/// A relay session between two LowID peers through an intermediary.
#[derive(Debug)]
pub struct RelaySession {
    pub session_id: u32,
    pub initiator_ip: Ipv4Addr,
    pub initiator_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
    pub file_hash: [u8; 16],
    pub state: RelaySessionState,
    pub created: Instant,
    pub last_activity: Instant,
    pub bytes_relayed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RelaySessionState {
    /// Waiting for target peer to connect to the relay.
    WaitingForTarget,
    /// Both peers connected; actively relaying data.
    Active,
    /// Session is closing down.
    Closing,
}

impl RelaySession {
    pub fn new(
        session_id: u32,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            initiator_ip,
            initiator_port,
            target_ip,
            target_port,
            file_hash,
            state: RelaySessionState::WaitingForTarget,
            created: now,
            last_activity: now,
            bytes_relayed: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.last_activity.elapsed() > RELAY_IDLE_TIMEOUT
            || self.created.elapsed() > RELAY_MAX_DURATION
    }

    pub fn mark_active(&mut self) {
        self.state = RelaySessionState::Active;
        self.last_activity = Instant::now();
    }

    pub fn add_relayed_bytes(&mut self, count: usize) {
        self.bytes_relayed += count as u64;
        self.last_activity = Instant::now();
    }
}

/// Manages relay sessions when this node acts as a relay for others.
pub struct RelayManager {
    sessions: HashMap<u32, RelaySession>,
    next_session_id: u32,
    total_bytes_relayed: u64,
}

impl RelayManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 1,
            total_bytes_relayed: 0,
        }
    }

    /// Create a new relay session if capacity allows.
    pub fn create_session(
        &mut self,
        initiator_ip: Ipv4Addr,
        initiator_port: u16,
        target_ip: Ipv4Addr,
        target_port: u16,
        file_hash: [u8; 16],
    ) -> Option<u32> {
        if self.sessions.len() >= MAX_CONCURRENT_RELAY_SESSIONS {
            debug!("RelayManager: at capacity ({} sessions)", self.sessions.len());
            return None;
        }

        let id = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1);

        self.sessions.insert(id, RelaySession::new(
            id, initiator_ip, initiator_port, target_ip, target_port, file_hash,
        ));
        info!("RelayManager: created session {} ({} -> {}:{})", id, initiator_ip, target_ip, target_port);
        Some(id)
    }

    pub fn get_session(&self, id: u32) -> Option<&RelaySession> {
        self.sessions.get(&id)
    }

    pub fn get_session_mut(&mut self, id: u32) -> Option<&mut RelaySession> {
        self.sessions.get_mut(&id)
    }

    pub fn remove_session(&mut self, id: u32) -> Option<RelaySession> {
        self.sessions.remove(&id)
    }

    /// Clean up expired sessions.
    pub fn cleanup(&mut self) -> Vec<u32> {
        let expired: Vec<u32> = self.sessions.iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(session) = self.sessions.remove(id) {
                info!("RelayManager: expired session {} ({} bytes relayed)", id, session.bytes_relayed);
                self.total_bytes_relayed += session.bytes_relayed;
            }
        }
        expired
    }

    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn total_bytes_relayed(&self) -> u64 {
        self.total_bytes_relayed + self.sessions.values().map(|s| s.bytes_relayed).sum::<u64>()
    }
}

/// Encode a relay protocol message.
pub fn encode_relay_message(msg_type: u8, session_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u16;
    let mut buf = Vec::with_capacity(7 + payload.len());
    buf.push(msg_type);
    buf.extend_from_slice(&session_id.to_le_bytes());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a relay protocol message header. Returns (msg_type, session_id, payload).
pub fn decode_relay_message(data: &[u8]) -> Option<(u8, u32, &[u8])> {
    if data.len() < 7 {
        return None;
    }
    let msg_type = data[0];
    let session_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
    let payload_len = u16::from_le_bytes([data[5], data[6]]) as usize;
    if data.len() < 7 + payload_len {
        return None;
    }
    Some((msg_type, session_id, &data[7..7 + payload_len]))
}

/// Build a RELAY_REQUEST message.
pub fn build_relay_request(session_id: u32, target_ip: Ipv4Addr, target_port: u16, file_hash: &[u8; 16]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(22);
    payload.extend_from_slice(&target_ip.octets());
    payload.extend_from_slice(&target_port.to_le_bytes());
    payload.extend_from_slice(file_hash);
    encode_relay_message(MSG_RELAY_REQUEST, session_id, &payload)
}

/// Build a RELAY_ACCEPT message.
pub fn build_relay_accept(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_ACCEPT, session_id, &[])
}

/// Build a RELAY_REJECT message.
pub fn build_relay_reject(session_id: u32, reason: u8) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_REJECT, session_id, &[reason])
}

/// Build a RELAY_CONNECT message (target peer joining).
pub fn build_relay_connect(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CONNECT, session_id, &[])
}

/// Build a RELAY_DATA message.
pub fn build_relay_data(session_id: u32, data: &[u8]) -> Vec<u8> {
    let chunk = &data[..data.len().min(MAX_RELAY_DATA_SIZE)];
    encode_relay_message(MSG_RELAY_DATA, session_id, chunk)
}

/// Build a RELAY_CLOSE message.
pub fn build_relay_close(session_id: u32) -> Vec<u8> {
    encode_relay_message(MSG_RELAY_CLOSE, session_id, &[])
}

/// Parse a RELAY_REQUEST payload.
pub fn parse_relay_request(payload: &[u8]) -> Option<(Ipv4Addr, u16, [u8; 16])> {
    if payload.len() < 22 {
        return None;
    }
    let ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
    let port = u16::from_le_bytes([payload[4], payload[5]]);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&payload[6..22]);
    Some((ip, port, hash))
}

/// Client-side helper: coordinate with the rendezvous server for a relay session.
pub async fn request_server_relay(
    rendezvous_url: &str,
    session_id: &str,
) -> Result<String, String> {
    let ws_url = format!(
        "{}/relay/{}",
        rendezvous_url.replace("https://", "wss://").replace("http://", "ws://"),
        session_id
    );
    Ok(ws_url)
}

/// Client-side helper: register a hole-punch coordination request.
pub async fn register_punch(
    rendezvous_url: &str,
    from_id: &str,
    target_id: &str,
    port: u16,
    nat_type: u8,
) -> Result<(), String> {
    let url = format!("{}/punch", rendezvous_url);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "from_id": from_id,
            "target_id": target_id,
            "port": port,
            "nat_type": nat_type,
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch register: {e}"))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("punch register: status {}", resp.status()))
    }
}

/// Client-side helper: poll for incoming punch requests.
pub async fn poll_punch(
    rendezvous_url: &str,
    our_id: &str,
) -> Result<Option<PunchInfo>, String> {
    let url = format!("{}/punch/{}", rendezvous_url, our_id);
    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("punch poll: {e}"))?;

    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(format!("punch poll: status {}", resp.status()));
    }

    let body: serde_json::Value = resp.json().await.map_err(|e| format!("punch poll parse: {e}"))?;
    Ok(Some(PunchInfo {
        from_id: body["from_id"].as_str().unwrap_or("").to_string(),
        ip: body["ip"].as_str().unwrap_or("").to_string(),
        port: body["port"].as_u64().unwrap_or(0) as u16,
        nat_type: body["nat_type"].as_u64().unwrap_or(5) as u8,
    }))
}

#[derive(Debug, Clone)]
pub struct PunchInfo {
    pub from_id: String,
    pub ip: String,
    pub port: u16,
    pub nat_type: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_message_round_trip() {
        let original = encode_relay_message(MSG_RELAY_DATA, 42, b"hello world");
        let (msg_type, session_id, payload) = decode_relay_message(&original).unwrap();
        assert_eq!(msg_type, MSG_RELAY_DATA);
        assert_eq!(session_id, 42);
        assert_eq!(payload, b"hello world");
    }

    #[test]
    fn relay_request_round_trip() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let port = 4662u16;
        let hash = [0xAA; 16];
        let msg = build_relay_request(1, ip, port, &hash);
        let (msg_type, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(msg_type, MSG_RELAY_REQUEST);
        assert_eq!(sid, 1);
        let (parsed_ip, parsed_port, parsed_hash) = parse_relay_request(payload).unwrap();
        assert_eq!(parsed_ip, ip);
        assert_eq!(parsed_port, port);
        assert_eq!(parsed_hash, hash);
    }

    #[test]
    fn relay_accept_decode() {
        let msg = build_relay_accept(99);
        let (t, sid, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(t, MSG_RELAY_ACCEPT);
        assert_eq!(sid, 99);
        assert!(payload.is_empty());
    }

    #[test]
    fn relay_manager_session_lifecycle() {
        let mut mgr = RelayManager::new();
        assert_eq!(mgr.active_count(), 0);

        let sid = mgr.create_session(
            Ipv4Addr::new(1, 2, 3, 4), 4662,
            Ipv4Addr::new(5, 6, 7, 8), 4663,
            [1u8; 16],
        ).unwrap();

        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get_session(sid).is_some());

        mgr.get_session_mut(sid).unwrap().mark_active();
        mgr.get_session_mut(sid).unwrap().add_relayed_bytes(1000);
        assert_eq!(mgr.get_session(sid).unwrap().bytes_relayed, 1000);

        mgr.remove_session(sid);
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn relay_manager_capacity_limit() {
        let mut mgr = RelayManager::new();
        for i in 0..MAX_CONCURRENT_RELAY_SESSIONS {
            let mut ip_bytes = [0u8; 4];
            ip_bytes[3] = (i + 1) as u8;
            assert!(mgr.create_session(
                Ipv4Addr::from(ip_bytes), 4662,
                Ipv4Addr::new(10, 10, 10, 10), 4663,
                [i as u8; 16],
            ).is_some());
        }
        // Next one should fail
        assert!(mgr.create_session(
            Ipv4Addr::new(99, 99, 99, 99), 4662,
            Ipv4Addr::new(10, 10, 10, 10), 4663,
            [0xFF; 16],
        ).is_none());
    }

    #[test]
    fn relay_data_capped() {
        let big = vec![0u8; MAX_RELAY_DATA_SIZE + 100];
        let msg = build_relay_data(1, &big);
        let (_, _, payload) = decode_relay_message(&msg).unwrap();
        assert_eq!(payload.len(), MAX_RELAY_DATA_SIZE);
    }
}
