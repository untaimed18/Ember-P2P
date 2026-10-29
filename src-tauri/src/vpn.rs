//! Whether this computer's internet traffic leaves through a VPN, so the
//! connection doctor does not send someone to their router's UPnP settings
//! when the router never carries Ember's traffic.

/// IANA interface types a VPN client's adapter reports: PPP (23) for PPTP and
/// L2TP, `IF_TYPE_PROP_VIRTUAL` (53) for WireGuard and Wintun, and
/// `IF_TYPE_TUNNEL` (131) for IKEv2 and SSTP. Ethernet (6), which Hyper-V's
/// and most other virtual switches report, and Wi-Fi (71) are not among them.
const VPN_INTERFACE_TYPES: [u32; 3] = [23, 53, 131];

/// Words in the description of an adapter that reports Ethernet but belongs
/// to a VPN: OpenVPN's TAP driver, and the ones VPN clients ship under their
/// own names.
const VPN_DESCRIPTION_WORDS: [&str; 4] = ["tap-", "vpn", "wireguard", "wintun"];

/// Whether the route to the internet runs over a VPN's adapter, or `None`
/// where that cannot be read.
pub fn default_route_is_vpn() -> Option<bool> {
    imp::default_route_interface().map(|(if_type, description)| is_vpn_interface(if_type, &description))
}

fn is_vpn_interface(if_type: u32, description: &str) -> bool {
    let description = description.to_lowercase();
    VPN_INTERFACE_TYPES.contains(&if_type) || VPN_DESCRIPTION_WORDS.iter().any(|word| description.contains(word))
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetBestInterface, GetIfEntry2, MIB_IF_ROW2};

    /// A documentation address (TEST-NET-1): only the route to it is looked
    /// up, so it stands for the internet as a whole.
    const INTERNET: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 1);

    /// The type and description of the interface the route to the internet
    /// leaves through.
    pub fn default_route_interface() -> Option<(u32, String)> {
        let mut index = 0u32;
        // SAFETY: `index` is a valid, writable u32, and the address is passed
        // by value in network byte order, as GetBestInterface takes it.
        if unsafe { GetBestInterface(u32::from_ne_bytes(INTERNET.octets()), &mut index) } != 0 {
            return None;
        }
        // SAFETY: MIB_IF_ROW2 is plain data, for which all zeroes is valid.
        let mut row: MIB_IF_ROW2 = unsafe { std::mem::zeroed() };
        row.InterfaceIndex = index;
        // SAFETY: `row` is a valid, writable MIB_IF_ROW2 whose zero
        // InterfaceLuid tells GetIfEntry2 to find the interface by index.
        if unsafe { GetIfEntry2(&mut row) } != 0 {
            return None;
        }
        let len = row.Description.iter().position(|&c| c == 0).unwrap_or(row.Description.len());
        Some((row.Type, String::from_utf16_lossy(&row.Description[..len])))
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn default_route_interface() -> Option<(u32, String)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::is_vpn_interface;

    #[test]
    fn tunnels_and_vpn_adapters_are_told_from_lan_adapters() {
        assert!(is_vpn_interface(53, "WireGuard Tunnel"));
        assert!(is_vpn_interface(131, "WAN Miniport (IKEv2)"));
        assert!(is_vpn_interface(23, "WAN Miniport (L2TP)"));
        assert!(is_vpn_interface(6, "TAP-Windows Adapter V9"), "OpenVPN's TAP reports Ethernet");
        assert!(is_vpn_interface(6, "NordLynx VPN Adapter"));
        assert!(!is_vpn_interface(6, "Intel(R) Ethernet Controller I226-LMvP"));
        assert!(!is_vpn_interface(6, "Hyper-V Virtual Ethernet Adapter #2"));
        assert!(!is_vpn_interface(71, "Intel(R) Wi-Fi 6E AX211 160MHz"));
    }

    /// Reads this machine's route, so it can only say the call works.
    #[cfg(windows)]
    #[test]
    fn the_route_to_the_internet_can_be_read() {
        if let Some((if_type, description)) = super::imp::default_route_interface() {
            eprintln!("default route: type {if_type}, {description}");
            assert!(if_type > 0);
        }
    }
}
