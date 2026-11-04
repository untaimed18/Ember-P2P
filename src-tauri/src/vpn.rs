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
    let (if_type, description) = imp::default_route_interface()?;
    if if_type == PPP_INTERFACE_TYPE {
        if let Some(vpn) = ras_says_vpn(&description, &imp::active_ras_connections()) {
            return Some(vpn);
        }
    }
    Some(is_vpn_interface(if_type, &description))
}

/// PPP (23) is also what a PPPoE broadband or dial-up connection made on this
/// computer reports. That one is the internet connection itself, with no router
/// in between, so it must not read as a VPN.
const PPP_INTERFACE_TYPE: u32 = 23;

/// What Windows' own record of the connection says, for a PPP interface: its
/// description is the connection's name ("Broadband Connection", "Work"), the
/// same as the RAS entry it was dialled from, whose device type is `vpn` for
/// PPTP, L2TP, SSTP and IKEv2 and `PPPoE` for broadband. `None` when no active
/// connection carries that name, to fall back on the interface alone.
fn ras_says_vpn(description: &str, connections: &[(String, String)]) -> Option<bool> {
    let (_, device_type) = connections
        .iter()
        .find(|(entry, _)| entry.eq_ignore_ascii_case(description))?;
    if device_type.eq_ignore_ascii_case("vpn") {
        Some(true)
    } else if device_type.eq_ignore_ascii_case("pppoe") {
        Some(false)
    } else {
        None
    }
}

fn is_vpn_interface(if_type: u32, description: &str) -> bool {
    let description = description.to_lowercase();
    if if_type == PPP_INTERFACE_TYPE && description.contains("pppoe") {
        return false;
    }
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

    fn wide(text: &[u16]) -> String {
        let len = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        String::from_utf16_lossy(&text[..len])
    }

    /// Each dialled-up connection's entry name and device type, empty when
    /// there are none or they cannot be read.
    pub fn active_ras_connections() -> Vec<(String, String)> {
        use windows_sys::Win32::NetworkManagement::Rras::{RasEnumConnectionsW, RASCONNW};
        const ERROR_BUFFER_TOO_SMALL: u32 = 603;
        let entry_size = std::mem::size_of::<RASCONNW>() as u32;
        // SAFETY: RASCONNW is plain data, for which all zeroes is valid.
        let mut conns: Vec<RASCONNW> = vec![unsafe { std::mem::zeroed() }];
        conns[0].dwSize = entry_size;
        let mut bytes = entry_size;
        let mut count = 0u32;
        // SAFETY: `conns` holds `bytes` bytes of RASCONNW, the first one's
        // dwSize set as the call requires; `bytes` and `count` are writable.
        let mut status = unsafe { RasEnumConnectionsW(conns.as_mut_ptr(), &mut bytes, &mut count) };
        if status == ERROR_BUFFER_TOO_SMALL {
            let needed = (bytes / entry_size).max(1) as usize;
            // SAFETY: as above.
            conns = vec![unsafe { std::mem::zeroed() }; needed];
            conns[0].dwSize = entry_size;
            bytes = entry_size * needed as u32;
            // SAFETY: as above, with room for `needed` entries.
            status = unsafe { RasEnumConnectionsW(conns.as_mut_ptr(), &mut bytes, &mut count) };
        }
        if status != 0 {
            return Vec::new();
        }
        conns
            .iter()
            .take(count as usize)
            .map(|c| (wide(&c.szEntryName), wide(&c.szDeviceType)))
            .collect()
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn default_route_interface() -> Option<(u32, String)> {
        None
    }

    pub fn active_ras_connections() -> Vec<(String, String)> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_vpn_interface, ras_says_vpn};

    /// A PPP interface is described by its connection's own name, so the RAS
    /// entry of that name decides: a PPPoE broadband connection is not a VPN.
    #[test]
    fn a_ppp_connection_is_judged_by_its_ras_entry() {
        let conns = vec![
            ("Broadband Connection".to_string(), "PPPoE".to_string()),
            ("Work".to_string(), "vpn".to_string()),
        ];
        assert_eq!(ras_says_vpn("Broadband Connection", &conns), Some(false));
        assert_eq!(ras_says_vpn("broadband connection", &conns), Some(false));
        assert_eq!(ras_says_vpn("Work", &conns), Some(true));
        assert_eq!(ras_says_vpn("Elsewhere", &conns), None, "falls back on the interface");
        assert_eq!(ras_says_vpn("Modem", &[("Modem".to_string(), "modem".to_string())]), None);
    }

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

    #[test]
    fn a_pppoe_connection_on_this_computer_is_not_a_vpn() {
        assert!(!is_vpn_interface(23, "WAN Miniport (PPPOE)"));
        assert!(is_vpn_interface(23, "WAN Miniport (PPTP)"));
        assert!(is_vpn_interface(23, "WAN Miniport (SSTP)"));
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
