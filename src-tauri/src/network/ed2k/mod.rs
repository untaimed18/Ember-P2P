pub mod a4af;
pub mod aich;
pub mod archive_recovery;
pub mod chunk_selection;
pub mod collection;
pub mod comments;
pub mod corruption_blackbox;
pub mod credits;
pub mod dead_sources;
pub mod ember_auth;
pub mod friend_connect;
pub mod hash;
pub mod messages;
pub mod multi_source;
pub mod part_tracker;
pub mod preview;
pub mod secure_stream;
pub mod server;
pub mod server_crypt;
pub mod server_list;
pub mod server_obfuscation;
pub mod server_udp;
pub mod sources;
pub mod tcp_obfuscation;
pub mod transfer;
pub mod upload;
pub mod write_coordinator;

/// Legacy Ember PoP/friend opcodes remain parseable for compatibility tests,
/// but are never a live authorization or signing path.
pub(crate) const LEGACY_FRIEND_AUTH_ENABLED: bool = false;

/// Prefer the listen port advertised in Hello/EmuleInfo over the TCP
/// source port. Inbound `peer_addr.port()` is the client's ephemeral
/// source port and is not a usable dial-back address.
#[inline]
pub fn advertised_listen_port(hello_tcp_port: u16, socket_port: u16) -> u16 {
    if hello_tcp_port > 0 {
        hello_tcp_port
    } else {
        socket_port
    }
}

#[cfg(test)]
mod advertised_listen_port_tests {
    use super::advertised_listen_port;

    #[test]
    fn prefers_hello_listen_port_over_ephemeral_source() {
        assert_eq!(advertised_listen_port(4662, 54_321), 4662);
        assert_eq!(advertised_listen_port(0, 54_321), 54_321);
    }
}
