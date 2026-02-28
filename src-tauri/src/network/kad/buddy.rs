use std::net::SocketAddr;
use tracing::{debug, info, warn};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

use super::types::KadId;

const OP_EMULEPROT: u8 = 0xC5;
const OP_BUDDYPING: u8 = 0x9F;
#[allow(dead_code)]
const OP_BUDDYPONG: u8 = 0xA0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuddyState {
    NoBuddy,
    FindingBuddy,
    Connected,
}

pub struct BuddyManager {
    local_id: KadId,
    tcp_port: u16,
    state: BuddyState,
    buddy_id: Option<KadId>,
    buddy_addr: Option<SocketAddr>,
    buddy_stream: Option<TcpStream>,
    last_find_attempt: i64,
    /// If we're acting as a buddy for another firewalled node
    serving_buddy_for: Option<KadId>,
    serving_stream: Option<TcpStream>,
}

impl BuddyManager {
    pub fn new(local_id: KadId, tcp_port: u16) -> Self {
        BuddyManager {
            local_id,
            tcp_port,
            state: BuddyState::NoBuddy,
            buddy_id: None,
            buddy_addr: None,
            buddy_stream: None,
            last_find_attempt: 0,
            serving_buddy_for: None,
            serving_stream: None,
        }
    }

    pub fn reset(&mut self) {
        self.state = BuddyState::NoBuddy;
        self.buddy_id = None;
        self.buddy_addr = None;
        self.buddy_stream = None;
        self.last_find_attempt = 0;
        self.serving_buddy_for = None;
        self.serving_stream = None;
    }

    pub fn state(&self) -> BuddyState {
        self.state
    }

    pub fn local_id(&self) -> &KadId {
        &self.local_id
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    pub fn buddy_id(&self) -> Option<&KadId> {
        self.buddy_id.as_ref()
    }

    /// Compute the target for FindBuddy search (our_id XOR buddy_mask).
    pub fn find_buddy_target(&self) -> KadId {
        let mut target = self.local_id.0;
        // XOR with a mask that has high bits set to search in a different part of the space
        target[0] ^= 0xFF;
        target[1] ^= 0xFF;
        KadId(target)
    }

    /// Should we attempt to find a buddy? (firewalled, no current buddy, enough time passed)
    pub fn should_find_buddy(&self, firewalled: bool) -> bool {
        if !firewalled {
            return false;
        }
        if self.state == BuddyState::Connected {
            return false;
        }
        if self.state == BuddyState::FindingBuddy {
            return false;
        }
        let now = chrono::Utc::now().timestamp();
        now - self.last_find_attempt > 1200 // Every 20 minutes (eMule: MIN2S(20))
    }

    pub fn start_finding(&mut self) {
        self.state = BuddyState::FindingBuddy;
        self.last_find_attempt = chrono::Utc::now().timestamp();
        info!("Starting buddy search");
    }

    pub fn find_failed(&mut self) {
        self.state = BuddyState::NoBuddy;
        debug!("Buddy search failed, will retry later");
    }

    /// Handle a FindBuddyRes: connect to the buddy via TCP.
    pub async fn handle_findbuddy_response(
        &mut self,
        buddy_id: KadId,
        buddy_ip: std::net::Ipv4Addr,
        tcp_port: u16,
    ) -> bool {
        let addr = SocketAddr::new(buddy_ip.into(), tcp_port);
        info!("Attempting to connect to buddy {} at {}", buddy_id, addr);

        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            TcpStream::connect(addr),
        ).await {
            Ok(Ok(stream)) => {
                info!("Connected to buddy {} at {}", buddy_id, addr);
                self.buddy_id = Some(buddy_id);
                self.buddy_addr = Some(addr);
                self.buddy_stream = Some(stream);
                self.state = BuddyState::Connected;
                true
            }
            Ok(Err(e)) => {
                warn!("Failed to connect to buddy {}: {}", buddy_id, e);
                self.find_failed();
                false
            }
            Err(_) => {
                warn!("Timeout connecting to buddy {}", buddy_id);
                self.find_failed();
                false
            }
        }
    }

    /// Send OP_BUDDYPING to verify the buddy connection (eMule keepalive).
    pub async fn check_buddy_alive(&mut self) {
        if self.state == BuddyState::Connected {
            if let Some(ref mut stream) = self.buddy_stream {
                let ping = build_emule_packet(OP_BUDDYPING, &[]);
                match tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    stream.write_all(&ping),
                ).await {
                    Ok(Ok(())) => {}
                    _ => {
                        info!("Buddy connection lost (ping failed)");
                        self.buddy_stream = None;
                        self.buddy_id = None;
                        self.buddy_addr = None;
                        self.state = BuddyState::NoBuddy;
                    }
                }
            } else {
                self.state = BuddyState::NoBuddy;
            }
        }
    }

    /// Accept serving as a buddy for a firewalled client (if we're not firewalled).
    pub fn accept_buddy_request(
        &mut self,
        requester_id: KadId,
        stream: TcpStream,
    ) -> bool {
        if self.serving_buddy_for.is_some() {
            debug!("Already serving as buddy, rejecting request from {}", requester_id);
            return false;
        }
        info!("Accepting buddy request from {}", requester_id);
        self.serving_buddy_for = Some(requester_id);
        self.serving_stream = Some(stream);
        true
    }

    /// Forward a callback request to our buddy using ed2k packet framing.
    pub async fn relay_callback(&mut self, data: &[u8]) -> bool {
        if let Some(ref mut stream) = self.serving_stream {
            // eMule ed2k framing: [protocol(1)][length(4)][payload]
            let mut packet = Vec::with_capacity(5 + data.len());
            packet.push(OP_EMULEPROT);
            packet.extend_from_slice(&(data.len() as u32).to_le_bytes());
            packet.extend_from_slice(data);
            match stream.write_all(&packet).await {
                Ok(()) => true,
                Err(e) => {
                    warn!("Failed to relay callback: {}", e);
                    self.serving_buddy_for = None;
                    self.serving_stream = None;
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn is_serving(&self) -> bool {
        self.serving_buddy_for.is_some()
    }

    pub fn serving_for(&self) -> Option<&KadId> {
        self.serving_buddy_for.as_ref()
    }
}

fn build_emule_packet(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let len = (1 + payload.len()) as u32;
    let mut pkt = Vec::with_capacity(6 + payload.len());
    pkt.push(OP_EMULEPROT);
    pkt.extend_from_slice(&len.to_le_bytes());
    pkt.push(opcode);
    pkt.extend_from_slice(payload);
    pkt
}
