use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use tracing::{debug, info, warn};

/// Maximum concurrent friend sessions.
const MAX_FRIEND_SESSIONS: usize = 64;

/// How often to send keep-alive pings to friend sessions.
const FRIEND_KEEPALIVE_SECS: u64 = 30;

/// Session idle timeout (no messages exchanged).
const FRIEND_SESSION_TIMEOUT_SECS: u64 = 300;

/// Friend session state.
#[derive(Debug, Clone, PartialEq)]
pub enum FriendSessionState {
    /// QUIC connection is being established.
    Connecting,
    /// Connected and authenticated (verified Ember node ID).
    Connected,
    /// Disconnected (can attempt reconnect).
    Disconnected,
}

/// Stream protocol message types for friend communication.
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FriendMessageType {
    /// Text chat message.
    Chat = 0x01,
    /// File browse request: peer wants to see our shared files.
    BrowseRequest = 0x02,
    /// File browse response: list of shared files.
    BrowseResponse = 0x03,
    /// Presence update (online status, display name, etc.).
    Presence = 0x04,
    /// Keep-alive ping.
    Ping = 0x05,
    /// Keep-alive pong.
    Pong = 0x06,
}

impl FriendMessageType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Chat),
            0x02 => Some(Self::BrowseRequest),
            0x03 => Some(Self::BrowseResponse),
            0x04 => Some(Self::Presence),
            0x05 => Some(Self::Ping),
            0x06 => Some(Self::Pong),
            _ => None,
        }
    }
}

/// A friend session over QUIC.
#[derive(Debug)]
pub struct FriendSession {
    /// The friend's Ember node ID.
    pub node_id: [u8; 16],
    /// The friend's Ed25519 public key.
    pub ed25519_pub: [u8; 32],
    /// Current session state.
    pub state: FriendSessionState,
    /// Remote address (may change due to QUIC connection migration).
    pub remote_addr: Option<SocketAddr>,
    /// When the session was established.
    pub connected_at: Option<Instant>,
    /// Last message exchanged (sent or received).
    pub last_activity: Instant,
    /// Display name of the friend (from presence updates).
    pub display_name: Option<String>,
}

impl FriendSession {
    pub fn new(node_id: [u8; 16], ed25519_pub: [u8; 32]) -> Self {
        Self {
            node_id,
            ed25519_pub,
            state: FriendSessionState::Disconnected,
            remote_addr: None,
            connected_at: None,
            last_activity: Instant::now(),
            display_name: None,
        }
    }

    pub fn is_connected(&self) -> bool {
        self.state == FriendSessionState::Connected
    }

    pub fn is_idle(&self) -> bool {
        self.last_activity.elapsed().as_secs() > FRIEND_SESSION_TIMEOUT_SECS
    }

    pub fn needs_keepalive(&self) -> bool {
        self.state == FriendSessionState::Connected
            && self.last_activity.elapsed().as_secs() > FRIEND_KEEPALIVE_SECS
    }

    pub fn mark_activity(&mut self) {
        self.last_activity = Instant::now();
    }
}

/// Manages friend sessions over QUIC.
pub struct FriendManager {
    sessions: HashMap<[u8; 16], FriendSession>,
}

impl FriendManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Register a friend for session management.
    pub fn add_friend(&mut self, node_id: [u8; 16], ed25519_pub: [u8; 32]) {
        if self.sessions.len() >= MAX_FRIEND_SESSIONS && !self.sessions.contains_key(&node_id) {
            warn!("Friend session limit reached ({MAX_FRIEND_SESSIONS})");
            return;
        }
        self.sessions
            .entry(node_id)
            .or_insert_with(|| FriendSession::new(node_id, ed25519_pub));
    }

    /// Remove a friend.
    pub fn remove_friend(&mut self, node_id: &[u8; 16]) {
        self.sessions.remove(node_id);
    }

    /// Mark a friend session as connected.
    pub fn mark_connected(&mut self, node_id: &[u8; 16], addr: SocketAddr) {
        if let Some(session) = self.sessions.get_mut(node_id) {
            session.state = FriendSessionState::Connected;
            session.remote_addr = Some(addr);
            session.connected_at = Some(Instant::now());
            session.mark_activity();
            info!("Friend {} connected via QUIC from {addr}", hex::encode(node_id));
        }
    }

    /// Mark a friend session as disconnected.
    pub fn mark_disconnected(&mut self, node_id: &[u8; 16]) {
        if let Some(session) = self.sessions.get_mut(node_id) {
            session.state = FriendSessionState::Disconnected;
            debug!("Friend {} disconnected", hex::encode(node_id));
        }
    }

    /// Get a friend session by node ID.
    pub fn get(&self, node_id: &[u8; 16]) -> Option<&FriendSession> {
        self.sessions.get(node_id)
    }

    /// Get a mutable friend session by node ID.
    pub fn get_mut(&mut self, node_id: &[u8; 16]) -> Option<&mut FriendSession> {
        self.sessions.get_mut(node_id)
    }

    /// Return friends that need a keep-alive ping.
    pub fn needs_keepalive(&self) -> Vec<[u8; 16]> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.needs_keepalive())
            .map(|(id, _)| *id)
            .collect()
    }

    /// Return friends that are connected.
    pub fn connected_friends(&self) -> Vec<&FriendSession> {
        self.sessions
            .values()
            .filter(|s| s.is_connected())
            .collect()
    }

    /// Total number of registered friends.
    pub fn total_friends(&self) -> usize {
        self.sessions.len()
    }

    /// Number of currently connected friends.
    pub fn connected_count(&self) -> usize {
        self.sessions.values().filter(|s| s.is_connected()).count()
    }

    /// Clean up idle connected sessions.
    pub fn cleanup_idle(&mut self) -> Vec<[u8; 16]> {
        let idle: Vec<[u8; 16]> = self
            .sessions
            .iter()
            .filter(|(_, s)| s.is_connected() && s.is_idle())
            .map(|(id, _)| *id)
            .collect();

        for id in &idle {
            if let Some(session) = self.sessions.get_mut(id) {
                session.state = FriendSessionState::Disconnected;
                debug!("Friend {} session timed out (idle)", hex::encode(id));
            }
        }
        idle
    }
}

/// Encode a friend chat message for sending over a QUIC stream.
pub fn encode_chat_message(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut buf = Vec::with_capacity(1 + 2 + bytes.len());
    buf.push(FriendMessageType::Chat as u8);
    buf.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(bytes);
    buf
}

/// Decode a friend message type and payload from raw data.
pub fn decode_friend_message(data: &[u8]) -> Option<(FriendMessageType, &[u8])> {
    if data.is_empty() {
        return None;
    }
    let msg_type = FriendMessageType::from_u8(data[0])?;
    Some((msg_type, &data[1..]))
}

/// Encode a presence update message.
pub fn encode_presence(display_name: &str, online: bool) -> Vec<u8> {
    let name_bytes = display_name.as_bytes();
    let mut buf = Vec::with_capacity(1 + 1 + 2 + name_bytes.len());
    buf.push(FriendMessageType::Presence as u8);
    buf.push(if online { 1 } else { 0 });
    buf.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(name_bytes);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn friend_session_lifecycle() {
        let mut fm = FriendManager::new();
        let node_id = [1u8; 16];
        let ed_pub = [2u8; 32];

        fm.add_friend(node_id, ed_pub);
        assert_eq!(fm.total_friends(), 1);
        assert_eq!(fm.connected_count(), 0);

        fm.mark_connected(&node_id, "1.2.3.4:4662".parse().unwrap());
        assert_eq!(fm.connected_count(), 1);
        assert!(fm.get(&node_id).unwrap().is_connected());

        fm.mark_disconnected(&node_id);
        assert_eq!(fm.connected_count(), 0);
    }

    #[test]
    fn encode_decode_chat() {
        let encoded = encode_chat_message("hello friend!");
        let (msg_type, payload) = decode_friend_message(&encoded).unwrap();
        assert_eq!(msg_type, FriendMessageType::Chat);

        let text_len = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        let text = std::str::from_utf8(&payload[2..2 + text_len]).unwrap();
        assert_eq!(text, "hello friend!");
    }

    #[test]
    fn encode_decode_presence() {
        let encoded = encode_presence("Alice", true);
        let (msg_type, payload) = decode_friend_message(&encoded).unwrap();
        assert_eq!(msg_type, FriendMessageType::Presence);
        assert_eq!(payload[0], 1); // online
    }

    #[test]
    fn remove_friend() {
        let mut fm = FriendManager::new();
        fm.add_friend([1u8; 16], [2u8; 32]);
        fm.add_friend([3u8; 16], [4u8; 32]);
        assert_eq!(fm.total_friends(), 2);

        fm.remove_friend(&[1u8; 16]);
        assert_eq!(fm.total_friends(), 1);
        assert!(fm.get(&[1u8; 16]).is_none());
    }
}
