//! Keeping every connection Ember makes on one network interface, so traffic
//! meant for a VPN cannot leave by the ordinary connection (eMule's
//! `BindAddr`).
//!
//! Each socket Ember opens is made here. `clippy.toml` refuses the raw
//! constructors everywhere else, so a path around the binding fails the build
//! instead of quietly using another interface. With no interface chosen,
//! everything binds as it always has, to any address. With one chosen and not
//! there, nothing opens at all: it fails closed.
//!
//! Bound to an address rather than to a device: Windows sends from an address
//! only through its interface, and on Linux an address that has gone with its
//! VPN cannot be sent from at all, so a socket opened before the VPN went
//! sends nothing after it either. Host names are looked up only while
//! connections may go out, and then by the system's resolver.
#![allow(clippy::disallowed_methods)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use parking_lot::RwLock;

/// Where connections may go out from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// No interface chosen: any, as before.
    Any,
    /// The chosen interface, at this address.
    Bound(Ipv4Addr),
    /// The chosen interface is not connected, or is no longer at the address
    /// the network started on: nothing may be opened.
    Unavailable,
}

struct Chosen {
    id: String,
    name: String,
}

struct State {
    binding: Binding,
    chosen: Option<Chosen>,
    /// The address the network's sockets were bound to, once they are. Those
    /// sockets keep it, so a different one later takes a restart.
    started_on: Option<Ipv4Addr>,
    /// The chosen interface's address at the last look, if it had one.
    seen: Option<Ipv4Addr>,
}

static STATE: RwLock<State> =
    RwLock::new(State { binding: Binding::Any, chosen: None, started_on: None, seen: None });

/// The binding a look at the interface comes to: `seen` is its usable address
/// now, `started_on` the one the network's sockets hold.
fn decide(chosen: bool, seen: Option<Ipv4Addr>, started_on: Option<Ipv4Addr>) -> Binding {
    match (chosen, seen, started_on) {
        (false, _, _) => Binding::Any,
        (true, Some(ip), None) => Binding::Bound(ip),
        (true, Some(ip), Some(started)) if ip == started => Binding::Bound(ip),
        _ => Binding::Unavailable,
    }
}

/// Take the interface the settings name, at startup. An empty `id` is any.
pub fn configure(id: &str, name: &str) {
    {
        let mut state = STATE.write();
        state.chosen = (!id.trim().is_empty()).then(|| Chosen { id: id.to_string(), name: name.to_string() });
        state.started_on = None;
        state.seen = None;
        state.binding = if state.chosen.is_some() { Binding::Unavailable } else { Binding::Any };
    }
    refresh();
}

/// Look at the chosen interface again, and return the binding that leaves.
pub fn refresh() -> Binding {
    let id = match &STATE.read().chosen {
        None => return Binding::Any,
        Some(chosen) => chosen.id.clone(),
    };
    let seen = usable_address(&list_raw(), &id);
    let mut state = STATE.write();
    if state.chosen.as_ref().is_none_or(|chosen| chosen.id != id) {
        return state.binding;
    }
    state.seen = seen;
    state.binding = decide(true, seen, state.started_on);
    state.binding
}

/// The binding now.
pub fn binding() -> Binding {
    STATE.read().binding
}

/// An interface is chosen, connected or not.
pub fn is_configured() -> bool {
    STATE.read().chosen.is_some()
}

/// The network is about to bind its sockets: from here, only the address it
/// binds them to counts as the interface being there.
pub fn hold_address() {
    let mut state = STATE.write();
    if let Binding::Bound(ip) = state.binding {
        state.started_on = Some(ip);
    }
}

/// What the main window says about the binding.
#[derive(Clone, Debug, serde::Serialize)]
pub struct BindingStatus {
    /// `any`; `bound`; `waiting`, not there yet, and the network goes online
    /// once it is; `lost`, gone since the network started; or `changed`, back
    /// at another address, which takes a restart.
    pub state: &'static str,
    /// The interface as it was named when chosen.
    pub name: String,
    pub address: Option<String>,
}

pub fn status() -> BindingStatus {
    let state = STATE.read();
    let Some(chosen) = &state.chosen else {
        return BindingStatus { state: "any", name: String::new(), address: None };
    };
    let (label, address) = match (state.binding, state.started_on, state.seen) {
        (Binding::Bound(ip), _, _) => ("bound", Some(ip)),
        (_, None, _) => ("waiting", None),
        (_, Some(_), None) => ("lost", None),
        (_, Some(_), Some(other)) => ("changed", Some(other)),
    };
    BindingStatus {
        state: label,
        name: if chosen.name.is_empty() { chosen.id.clone() } else { chosen.name.clone() },
        address: address.map(|ip| ip.to_string()),
    }
}

fn interface_away_for(configured: bool, error: &io::Error) -> bool {
    configured && error.kind() == io::ErrorKind::AddrNotAvailable
}

/// A bind that failed because the chosen interface is away, not because of
/// its port: one that went between the network's wait for it and the bind.
/// Worth trying again once the watch in `lib.rs` sees it back.
pub fn interface_away(error: &io::Error) -> bool {
    interface_away_for(is_configured(), error)
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "the network interface Ember is set to use is not connected",
    )
}

fn local_ip_for(binding: Binding) -> io::Result<Option<Ipv4Addr>> {
    match binding {
        Binding::Any => Ok(None),
        Binding::Bound(ip) => Ok(Some(ip)),
        Binding::Unavailable => Err(unavailable()),
    }
}

fn local_addr_for(binding: Binding, port: u16) -> io::Result<SocketAddr> {
    Ok(SocketAddr::from((local_ip_for(binding)?.unwrap_or(Ipv4Addr::UNSPECIFIED), port)))
}

/// Where a socket on `port` binds: the chosen interface's address, or any.
pub fn local_addr(port: u16) -> io::Result<SocketAddr> {
    local_addr_for(binding(), port)
}

async fn tcp_connect_for(binding: Binding, addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let Some(ip) = local_ip_for(binding)? else {
        return tokio::net::TcpStream::connect(addr).await;
    };
    if !addr.is_ipv4() {
        return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "the chosen interface has no IPv6 address"));
    }
    let socket = tokio::net::TcpSocket::new_v4()?;
    socket.bind(SocketAddr::from((ip, 0)))?;
    socket.connect(addr).await
}

/// A TCP connection to `addr`, from the chosen interface.
pub async fn tcp_connect(addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    tcp_connect_for(binding(), addr).await
}

/// [`tcp_connect`] out from a fixed local `port`, which other sockets may
/// share (the NAT-mapping hold on the listen port).
pub async fn tcp_connect_from(port: u16, addr: SocketAddr) -> io::Result<tokio::net::TcpStream> {
    tcp_socket(port, true)?.connect(addr).await
}

/// A TCP socket bound to `port` on the chosen interface, to listen on.
pub fn tcp_socket(port: u16, reuse_address: bool) -> io::Result<tokio::net::TcpSocket> {
    let addr = local_addr(port)?;
    let socket = tokio::net::TcpSocket::new_v4()?;
    if reuse_address {
        socket.set_reuseaddr(true)?;
    }
    socket.bind(addr)?;
    Ok(socket)
}

/// A UDP socket on `port`, `0` for any, on the chosen interface.
pub fn std_udp(port: u16) -> io::Result<std::net::UdpSocket> {
    std::net::UdpSocket::bind(local_addr(port)?)
}

/// [`std_udp`] for the async runtime.
pub async fn udp(port: u16) -> io::Result<tokio::net::UdpSocket> {
    tokio::net::UdpSocket::bind(local_addr(port)?).await
}

/// Bind a socket made with options of its own to `port` on the chosen
/// interface.
pub fn bind_socket(socket: &socket2::Socket, port: u16) -> io::Result<()> {
    socket.bind(&socket2::SockAddr::from(local_addr(port)?))
}

async fn lookup_host_for<T: tokio::net::ToSocketAddrs>(
    binding: Binding,
    host: T,
) -> io::Result<impl Iterator<Item = SocketAddr>> {
    local_ip_for(binding)?;
    tokio::net::lookup_host(host).await
}

/// Look `host` up, by the system's resolver. Refused while the chosen
/// interface is not there, so not even the query goes out another way.
pub async fn lookup_host<T: tokio::net::ToSocketAddrs>(host: T) -> io::Result<impl Iterator<Item = SocketAddr>> {
    lookup_host_for(binding(), host).await
}

/// An HTTP client builder whose connections leave from the chosen interface.
pub fn http_client() -> io::Result<reqwest::ClientBuilder> {
    bind_http(reqwest::Client::builder())
}

/// Put a builder made elsewhere (the updater plugin's) on the chosen interface.
pub fn bind_http(builder: reqwest::ClientBuilder) -> io::Result<reqwest::ClientBuilder> {
    Ok(match local_ip_for(binding())? {
        None => builder,
        Some(ip) => builder.local_address(IpAddr::V4(ip)),
    })
}

/// One of this computer's network interfaces, for the picker in Settings.
#[derive(Clone, Debug, serde::Serialize)]
pub struct NetworkInterface {
    /// What Settings keeps: the adapter's GUID on Windows, which a rename does
    /// not change, and its name on Linux.
    pub id: String,
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
    /// Up, with an address connections can leave from.
    pub connected: bool,
    pub vpn: bool,
}

/// An interface as the system reports it.
#[derive(Clone, Debug, Default)]
struct RawInterface {
    id: String,
    name: String,
    description: String,
    if_type: u32,
    up: bool,
    loopback: bool,
    ipv4: Vec<Ipv4Addr>,
}

/// An address connections can leave from: not the link-local one Windows gives
/// a disconnected VPN adapter, nor an unspecified one.
fn is_usable(ip: &Ipv4Addr) -> bool {
    !ip.is_link_local() && !ip.is_unspecified() && !ip.is_loopback()
}

fn usable_address(interfaces: &[RawInterface], id: &str) -> Option<Ipv4Addr> {
    let iface = interfaces.iter().find(|iface| iface.id == id && iface.up)?;
    iface.ipv4.iter().copied().find(is_usable)
}

/// Names a Linux VPN client gives its device.
const LINUX_VPN_PREFIXES: [&str; 10] =
    ["tun", "tap", "wg", "ppp", "ipsec", "vti", "nordlynx", "proton", "mullvad", "tailscale"];

fn looks_like_vpn(iface: &RawInterface) -> bool {
    if cfg!(windows) {
        crate::vpn::is_vpn_interface(iface.if_type, &iface.description)
    } else {
        let name = iface.name.to_lowercase();
        LINUX_VPN_PREFIXES.iter().any(|prefix| name.starts_with(prefix))
    }
}

/// This computer's interfaces, loopback left out, the connected first.
pub fn list() -> Vec<NetworkInterface> {
    let mut out: Vec<NetworkInterface> = list_raw()
        .into_iter()
        .filter(|iface| !iface.loopback)
        .map(|iface| NetworkInterface {
            connected: iface.up && iface.ipv4.iter().any(is_usable),
            vpn: looks_like_vpn(&iface),
            addresses: iface.ipv4.iter().map(|ip| ip.to_string()).collect(),
            id: iface.id,
            name: iface.name,
            description: iface.description,
        })
        .collect();
    out.sort_by(|a, b| b.connected.cmp(&a.connected).then_with(|| a.name.cmp(&b.name)));
    out
}

fn list_raw() -> Vec<RawInterface> {
    imp::list()
}

#[cfg(windows)]
mod imp {
    use super::RawInterface;
    use std::net::Ipv4Addr;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows_sys::Win32::Networking::WinSock::{AF_INET, SOCKADDR_IN};

    const ERROR_BUFFER_OVERFLOW: u32 = 111;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

    /// A NUL-terminated UTF-16 string the call returned.
    ///
    /// # Safety
    /// `text` is null or points at a NUL-terminated UTF-16 string.
    unsafe fn wide(text: *const u16) -> String {
        if text.is_null() {
            return String::new();
        }
        let mut len = 0;
        // SAFETY: the string is NUL-terminated, so every unit up to the NUL
        // is in bounds.
        while unsafe { *text.add(len) } != 0 {
            len += 1;
        }
        // SAFETY: the `len` units before the NUL were just read.
        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
    }

    pub fn list() -> Vec<RawInterface> {
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 16 * 1024;
        // u64s, for the alignment the structures it is filled with want.
        let mut buffer: Vec<u64> = Vec::new();
        let mut filled = false;
        for _ in 0..4 {
            buffer.resize((size as usize).div_ceil(8), 0);
            // SAFETY: `buffer` holds `size` writable bytes, aligned for
            // IP_ADAPTER_ADDRESSES_LH, and `size` is writable.
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_INET as u32,
                    flags,
                    std::ptr::null(),
                    buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                    &mut size,
                )
            };
            match status {
                0 => {
                    filled = true;
                    break;
                }
                ERROR_BUFFER_OVERFLOW => continue,
                _ => return Vec::new(),
            }
        }
        if !filled {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            // SAFETY: a node of the list the call wrote into `buffer`, which
            // outlives this loop.
            let a = unsafe { &*adapter };
            let id = if a.AdapterName.is_null() {
                String::new()
            } else {
                // SAFETY: AdapterName is a NUL-terminated ANSI string.
                unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast_const().cast::<std::ffi::c_char>()) }
                    .to_string_lossy()
                    .into_owned()
            };
            let mut ipv4 = Vec::new();
            let mut unicast = a.FirstUnicastAddress;
            while !unicast.is_null() {
                // SAFETY: a node of the same list.
                let u = unsafe { &*unicast };
                let sockaddr = u.Address.lpSockaddr;
                // SAFETY: a non-null lpSockaddr points at a SOCKADDR, and one
                // whose family is AF_INET is a SOCKADDR_IN.
                if !sockaddr.is_null() && unsafe { (*sockaddr).sa_family } == AF_INET {
                    let sin = unsafe { &*sockaddr.cast::<SOCKADDR_IN>() };
                    // SAFETY: every view of the IN_ADDR union is the same four
                    // bytes, in network order.
                    let raw = unsafe { sin.sin_addr.S_un.S_addr };
                    ipv4.push(Ipv4Addr::from(raw.to_ne_bytes()));
                }
                unicast = u.Next;
            }
            out.push(RawInterface {
                id,
                // SAFETY: both are NUL-terminated UTF-16 strings or null.
                name: unsafe { wide(a.FriendlyName) },
                description: unsafe { wide(a.Description) },
                if_type: a.IfType,
                up: a.OperStatus == IfOperStatusUp,
                loopback: a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                ipv4,
            });
            adapter = a.Next.cast_const();
        }
        out
    }
}

#[cfg(unix)]
mod imp {
    use super::RawInterface;
    use std::net::Ipv4Addr;

    pub fn list() -> Vec<RawInterface> {
        let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `head` is a valid place for the list's address.
        if unsafe { libc::getifaddrs(&mut head) } != 0 {
            return Vec::new();
        }
        let mut out: Vec<RawInterface> = Vec::new();
        let mut node = head;
        while !node.is_null() {
            // SAFETY: a node of the list getifaddrs returned, freed below.
            let ifa = unsafe { &*node };
            node = ifa.ifa_next;
            if ifa.ifa_name.is_null() {
                continue;
            }
            // SAFETY: ifa_name is a NUL-terminated C string.
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().into_owned();
            let flags = ifa.ifa_flags;
            let up = flags & libc::IFF_UP as u32 != 0 && flags & libc::IFF_RUNNING as u32 != 0;
            let loopback = flags & libc::IFF_LOOPBACK as u32 != 0;
            let at = match out.iter().position(|iface| iface.id == name) {
                Some(at) => at,
                None => {
                    out.push(RawInterface { id: name.clone(), name, up, loopback, ..Default::default() });
                    out.len() - 1
                }
            };
            // SAFETY: a non-null ifa_addr points at a sockaddr, and one whose
            // family is AF_INET is a sockaddr_in.
            if !ifa.ifa_addr.is_null() && i32::from(unsafe { (*ifa.ifa_addr).sa_family }) == libc::AF_INET {
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                out[at].ipv4.push(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
            }
        }
        // SAFETY: `head` came from getifaddrs and is freed once.
        unsafe { libc::freeifaddrs(head) };
        out
    }
}

#[cfg(not(any(windows, unix)))]
mod imp {
    pub fn list() -> Vec<super::RawInterface> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VPN: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);

    /// Chosen and not there is no connection at all, never a fallback to any
    /// interface; and once the network has bound its sockets, only the
    /// address they hold counts as there.
    #[test]
    fn a_chosen_interface_that_is_not_there_opens_nothing() {
        assert_eq!(decide(false, None, None), Binding::Any);
        assert_eq!(decide(true, None, None), Binding::Unavailable);
        assert_eq!(decide(true, Some(VPN), None), Binding::Bound(VPN));
        assert_eq!(decide(true, Some(VPN), Some(VPN)), Binding::Bound(VPN));
        assert_eq!(decide(true, None, Some(VPN)), Binding::Unavailable);
        assert_eq!(decide(true, Some(Ipv4Addr::new(10, 8, 0, 9)), Some(VPN)), Binding::Unavailable);
    }

    #[test]
    fn unavailable_refuses_every_socket() {
        assert!(local_addr_for(Binding::Unavailable, 4662).is_err());
        assert_eq!(local_addr_for(Binding::Any, 4662).unwrap(), "0.0.0.0:4662".parse().unwrap());
        assert_eq!(local_addr_for(Binding::Bound(VPN), 4662).unwrap(), "10.8.0.2:4662".parse().unwrap());
    }

    /// A connection made while bound leaves from the bound address; one made
    /// while the interface is gone is refused before anything is sent.
    #[tokio::test]
    async fn a_bound_connection_leaves_from_the_chosen_address() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = tcp_connect_for(Binding::Bound(Ipv4Addr::LOCALHOST), addr).await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let refused = tcp_connect_for(Binding::Unavailable, addr).await.unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::AddrNotAvailable);
        let v6 = tcp_connect_for(Binding::Bound(Ipv4Addr::LOCALHOST), "[::1]:1".parse().unwrap()).await;
        assert!(v6.is_err(), "no IPv6 route around the binding");
    }

    /// While the interface is gone, a name is not even looked up.
    #[tokio::test]
    async fn no_lookup_goes_out_while_the_interface_is_gone() {
        let refused = lookup_host_for(Binding::Unavailable, ("localhost", 80)).await.err().expect("refused");
        assert_eq!(refused.kind(), io::ErrorKind::AddrNotAvailable);
        let found: Vec<SocketAddr> = lookup_host_for(Binding::Bound(VPN), "127.0.0.1:80").await.unwrap().collect();
        assert_eq!(found, vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]);
    }

    /// A listener bound to an address this computer does not have fails as
    /// the interface being away, which is worth waiting out; a port in use,
    /// or no interface chosen, is not.
    #[test]
    fn a_bind_to_an_address_that_went_is_the_interface_away() {
        // TEST-NET-1, assigned to no interface anywhere.
        let gone = std::net::TcpListener::bind((Ipv4Addr::new(192, 0, 2, 1), 0)).unwrap_err();
        assert!(interface_away_for(true, &gone), "{gone:?}");
        assert!(!interface_away_for(false, &gone));
        assert!(interface_away_for(true, &unavailable()));
        assert!(!interface_away_for(true, &io::Error::from(io::ErrorKind::AddrInUse)));
    }

    /// The address a disconnected VPN adapter keeps is not one to bind to,
    /// and a down interface has none.
    #[test]
    fn only_an_up_interface_with_a_routable_address_is_there() {
        let iface = |up: bool, ipv4: Vec<Ipv4Addr>| RawInterface { id: "vpn".into(), up, ipv4, ..Default::default() };
        let apipa = Ipv4Addr::new(169, 254, 3, 4);
        assert_eq!(usable_address(&[iface(true, vec![apipa, VPN])], "vpn"), Some(VPN));
        assert_eq!(usable_address(&[iface(true, vec![apipa])], "vpn"), None);
        assert_eq!(usable_address(&[iface(false, vec![VPN])], "vpn"), None);
        assert_eq!(usable_address(&[iface(true, vec![VPN])], "other"), None);
    }

    /// Reads this machine's interfaces, so it can only say the call works.
    #[test]
    fn this_computers_interfaces_can_be_listed() {
        for iface in list() {
            assert!(!iface.id.is_empty());
        }
    }

    /// The address a connected interface of this computer is found at is one
    /// a connection can leave from. Nothing to try on a machine with none.
    #[tokio::test]
    async fn a_connected_interface_here_can_be_bound() {
        let raw = list_raw();
        let Some(ip) = raw.iter().filter(|iface| !iface.loopback).find_map(|iface| usable_address(&raw, &iface.id))
        else {
            return;
        };
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
        let stream = tcp_connect_for(Binding::Bound(ip), listener.local_addr().unwrap()).await.unwrap();
        assert_eq!(stream.local_addr().unwrap().ip(), IpAddr::V4(ip));
        assert_eq!(local_addr_for(Binding::Bound(ip), 0).unwrap().ip(), IpAddr::V4(ip));
    }
}
