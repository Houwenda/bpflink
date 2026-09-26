use std::ffi::CString;
use std::fs;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::bpf::FrameIo;
use crate::{Error, Result};

pub(crate) const ETH_P_ALL: u16 = libc::ETH_P_ALL as u16;
const READ_BATCH_LIMIT: usize = 64;
const ETHERNET_FRAME_OVERHEAD: usize = 64;

pub(crate) struct BpfDevice {
    fd: Option<OwnedFd>,
    mtu: usize,
    filter_configured: bool,
}

impl BpfDevice {
    pub(crate) fn open(interface: &str) -> Result<Self> {
        Self::open_with_filter(interface, None)
    }

    pub(crate) fn open_filtered(interface: &str, service_ports: &[u16]) -> Result<Self> {
        let service_ports = crate::bpf::filter::normalize_service_ports(service_ports)?;
        Self::open_with_filter(interface, Some(&service_ports))
    }

    fn open_with_filter(interface: &str, service_ports: Option<&[u16]>) -> Result<Self> {
        let index = if_index(interface)?;
        let fd = packet_socket()?;
        let sockaddr = sockaddr_ll_for_interface_index(index);
        let result = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &sockaddr as *const libc::sockaddr_ll as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if result < 0 {
            return Err(io_context(
                "bind AF_PACKET",
                std::io::Error::last_os_error(),
            ));
        }

        let mtu = interface_mtu(interface)?;
        let mut filter_configured = false;
        if let Some(service_ports) = service_ports {
            attach_service_filter(fd.as_raw_fd(), service_ports)?;
            filter_configured = true;
        }

        Ok(Self::from_opened_socket(fd, mtu, filter_configured))
    }

    fn from_opened_socket(fd: OwnedFd, mtu: usize, filter_configured: bool) -> Self {
        Self {
            fd: Some(fd),
            mtu,
            filter_configured,
        }
    }

    #[cfg(test)]
    fn from_opened_socket_for_test(mtu: usize, filter_configured: bool) -> Self {
        Self {
            fd: None,
            mtu,
            filter_configured,
        }
    }
}

pub(crate) fn interface_ethernet_addr(interface: &str) -> Result<[u8; 6]> {
    let socket = control_socket()?;
    let mut ifreq = named_ifreq(interface)?;

    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFHWADDR, &mut ifreq) };
    if result < 0 {
        return Err(io_context("SIOCGIFHWADDR", std::io::Error::last_os_error()));
    }

    let sockaddr = unsafe { ifreq.ifr_ifru.ifru_hwaddr };
    sockaddr_hwaddr_to_ethernet_addr(&sockaddr)
}

fn sockaddr_hwaddr_to_ethernet_addr(sockaddr: &libc::sockaddr) -> Result<[u8; 6]> {
    if sockaddr.sa_family != libc::ARPHRD_ETHER {
        return Err(Error::Config("interface hardware address is not Ethernet"));
    }

    let mut addr = [0u8; 6];
    for (dst, src) in addr.iter_mut().zip(sockaddr.sa_data.iter()) {
        *dst = src.to_ne_bytes()[0];
    }
    Ok(addr)
}

pub(crate) fn interface_ip_prefix_len(interface: &str, local_ip: IpAddr) -> Result<u8> {
    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Err(io_context("getifaddrs", std::io::Error::last_os_error()));
    }

    let _guard = IfAddrsGuard(addrs);
    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifaddr = unsafe { &*cursor };
        if ifaddr.ifa_addr.is_null() || ifaddr.ifa_netmask.is_null() {
            cursor = ifaddr.ifa_next;
            continue;
        }
        if unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) }.to_bytes() != interface.as_bytes() {
            cursor = ifaddr.ifa_next;
            continue;
        }

        let family = unsafe { (*ifaddr.ifa_addr).sa_family as libc::c_int };
        let netmask_family = unsafe { (*ifaddr.ifa_netmask).sa_family as libc::c_int };
        let prefix_len = match (local_ip, family, netmask_family) {
            (IpAddr::V4(local_ipv4), libc::AF_INET, libc::AF_INET)
                if sockaddr_in_ipv4(ifaddr.ifa_addr) == local_ipv4 =>
            {
                let netmask = sockaddr_in_ipv4_netmask(ifaddr.ifa_netmask);
                prefix_len_from_netmask(netmask)
                    .ok_or(Error::Config("interface IPv4 netmask is not contiguous"))?
            }
            (IpAddr::V6(local_ipv6), libc::AF_INET6, libc::AF_INET6)
                if sockaddr_in6_ipv6(ifaddr.ifa_addr) == local_ipv6 =>
            {
                let netmask = sockaddr_in6_ipv6(ifaddr.ifa_netmask);
                prefix_len_from_netmask_bytes(&netmask.octets())
                    .ok_or(Error::Config("interface IPv6 netmask is not contiguous"))?
            }
            _ => {
                cursor = ifaddr.ifa_next;
                continue;
            }
        };

        return Ok(prefix_len);
    }

    Err(Error::Config("IP address/netmask not found for interface"))
}

pub(crate) fn interface_default_gateway(
    interface: &str,
    local_ip: IpAddr,
) -> Result<Option<IpAddr>> {
    match local_ip {
        IpAddr::V4(_) => default_ipv4_gateway_from_proc_route(interface),
        IpAddr::V6(_) => default_ipv6_gateway_from_proc_route(interface),
    }
}

fn default_ipv4_gateway_from_proc_route(interface: &str) -> Result<Option<IpAddr>> {
    let contents = fs::read_to_string("/proc/net/route")
        .map_err(|err| io_context("read /proc/net/route", err))?;
    Ok(parse_proc_net_route_default_gateway(&contents, interface).map(IpAddr::V4))
}

fn default_ipv6_gateway_from_proc_route(interface: &str) -> Result<Option<IpAddr>> {
    let contents = fs::read_to_string("/proc/net/ipv6_route")
        .map_err(|err| io_context("read /proc/net/ipv6_route", err))?;
    Ok(parse_proc_net_ipv6_route_default_gateway(&contents, interface).map(IpAddr::V6))
}

fn parse_proc_net_route_default_gateway(contents: &str, interface: &str) -> Option<Ipv4Addr> {
    contents.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let destination = fields.next()?;
        let gateway = fields.next()?;
        let flags = fields.next()?;
        let _refcnt = fields.next()?;
        let _use = fields.next()?;
        let _metric = fields.next()?;
        let mask = fields.next()?;
        if iface != interface || destination != "00000000" || mask != "00000000" {
            return None;
        }
        let flags = u16::from_str_radix(flags, 16).ok()?;
        if flags & libc::RTF_GATEWAY == 0 {
            return None;
        }
        let gateway = u32::from_str_radix(gateway, 16).ok()?;
        Some(Ipv4Addr::from(gateway.to_le_bytes()))
    })
}

fn parse_proc_net_ipv6_route_default_gateway(contents: &str, interface: &str) -> Option<Ipv6Addr> {
    contents.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let destination = fields.next()?;
        let destination_prefix = fields.next()?;
        let _source = fields.next()?;
        let _source_prefix = fields.next()?;
        let next_hop = fields.next()?;
        let _metric = fields.next()?;
        let _refcnt = fields.next()?;
        let _use = fields.next()?;
        let flags = fields.next()?;
        let iface = fields.next()?;
        if iface != interface || destination_prefix != "00" || !is_zero_hex_128(destination) {
            return None;
        }
        let flags = u32::from_str_radix(flags, 16).ok()?;
        if flags & u32::from(libc::RTF_GATEWAY) == 0 {
            return None;
        }
        let gateway = parse_proc_ipv6_hex_addr(next_hop)?;
        (!gateway.is_unspecified()).then_some(gateway)
    })
}

fn parse_proc_ipv6_hex_addr(value: &str) -> Option<Ipv6Addr> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut octets = [0u8; 16];
    for (index, slot) in octets.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(Ipv6Addr::from(octets))
}

fn is_zero_hex_128(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte == b'0')
}

fn if_index(interface: &str) -> Result<i32> {
    let interface = c_interface_name(interface)?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(Error::Config("interface index not found"));
    }
    i32::try_from(index).map_err(|_| Error::Config("interface index does not fit in i32"))
}

fn interface_mtu(interface: &str) -> Result<usize> {
    let socket = control_socket()?;
    let mut ifreq = named_ifreq(interface)?;

    let result = unsafe { libc::ioctl(socket.as_raw_fd(), libc::SIOCGIFMTU, &mut ifreq) };
    if result < 0 {
        return Err(io_context("SIOCGIFMTU", std::io::Error::last_os_error()));
    }
    let mtu = unsafe { ifreq.ifr_ifru.ifru_mtu };
    if mtu <= 0 {
        return Err(Error::Config("interface MTU is not positive"));
    }
    Ok(mtu as usize)
}

fn control_socket() -> Result<OwnedFd> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io_context(
            "socket AF_INET SOCK_DGRAM",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn packet_socket() -> Result<OwnedFd> {
    let protocol = ETH_P_ALL.to_be() as libc::c_int;
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            protocol,
        )
    };
    if fd < 0 {
        return Err(io_context(
            "socket AF_PACKET SOCK_RAW",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn sockaddr_ll_for_interface_index(index: i32) -> libc::sockaddr_ll {
    libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as libc::c_ushort,
        sll_protocol: ETH_P_ALL.to_be(),
        sll_ifindex: index,
        sll_hatype: 0,
        sll_pkttype: 0,
        sll_halen: 0,
        sll_addr: [0; 8],
    }
}

fn attach_service_filter(fd: libc::c_int, service_ports: &[u16]) -> Result<()> {
    let mut instructions = service_filter_program(service_ports)?;
    let program = libc::sock_fprog {
        len: instructions.len() as libc::c_ushort,
        filter: instructions.as_mut_ptr(),
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            &program as *const libc::sock_fprog as *const libc::c_void,
            mem::size_of::<libc::sock_fprog>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io_context(
            "SO_ATTACH_FILTER",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn service_filter_program(service_ports: &[u16]) -> Result<Vec<libc::sock_filter>> {
    crate::bpf::filter::service_filter_program(service_ports).map(|instructions| {
        instructions
            .into_iter()
            .map(|instruction| libc::sock_filter {
                code: instruction.code,
                jt: instruction.jt,
                jf: instruction.jf,
                k: instruction.k,
            })
            .collect()
    })
}

fn named_ifreq(interface: &str) -> Result<libc::ifreq> {
    if interface.is_empty() {
        return Err(Error::Config("interface name must not be empty"));
    }
    if interface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config("interface name is too long"));
    }
    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    for (slot, byte) in ifreq.ifr_name.iter_mut().zip(interface.as_bytes()) {
        *slot = *byte as libc::c_char;
    }
    Ok(ifreq)
}

fn c_interface_name(interface: &str) -> Result<CString> {
    if interface.is_empty() {
        return Err(Error::Config("interface name must not be empty"));
    }
    CString::new(interface).map_err(|_| Error::Config("interface name contains NUL"))
}

fn sockaddr_in_ipv4(sockaddr: *const libc::sockaddr) -> Ipv4Addr {
    let sockaddr = unsafe { &*(sockaddr as *const libc::sockaddr_in) };
    Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr))
}

fn sockaddr_in_ipv4_netmask(sockaddr: *const libc::sockaddr) -> u32 {
    let sockaddr = unsafe { &*(sockaddr as *const libc::sockaddr_in) };
    u32::from_be(sockaddr.sin_addr.s_addr)
}

fn sockaddr_in6_ipv6(sockaddr: *const libc::sockaddr) -> Ipv6Addr {
    let sockaddr = unsafe { &*(sockaddr as *const libc::sockaddr_in6) };
    normalize_ipv6_addr(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr))
}

fn normalize_ipv6_addr(addr: Ipv6Addr) -> Ipv6Addr {
    addr
}

fn prefix_len_from_netmask(netmask: u32) -> Option<u8> {
    let prefix_len = netmask.count_ones();
    let expected = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    (netmask == expected).then_some(prefix_len as u8)
}

fn prefix_len_from_netmask_bytes(netmask: &[u8; 16]) -> Option<u8> {
    let mut prefix_len = 0u8;
    let mut saw_zero = false;
    for byte in netmask {
        for bit in (0..8).rev() {
            let is_one = (byte & (1 << bit)) != 0;
            if is_one {
                if saw_zero {
                    return None;
                }
                prefix_len += 1;
            } else {
                saw_zero = true;
            }
        }
    }
    Some(prefix_len)
}

struct IfAddrsGuard(*mut libc::ifaddrs);

impl Drop for IfAddrsGuard {
    fn drop(&mut self) {
        unsafe {
            libc::freeifaddrs(self.0);
        }
    }
}

fn io_context(operation: &'static str, source: std::io::Error) -> Error {
    Error::IoContext { operation, source }
}

impl FrameIo for BpfDevice {
    fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> Result<usize> {
        let fd = self.fd.as_ref().ok_or(Error::DriverClosed)?.as_raw_fd();
        let mut count = 0;
        for _ in 0..READ_BATCH_LIMIT {
            let mut frame = vec![0u8; self.mtu + ETHERNET_FRAME_OVERHEAD];
            let len =
                unsafe { libc::recv(fd, frame.as_mut_ptr() as *mut libc::c_void, frame.len(), 0) };
            if len < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                return Err(io_context("recv AF_PACKET", err));
            }
            if len == 0 {
                break;
            }
            frame.truncate(len as usize);
            out.push(frame);
            count += 1;
        }
        Ok(count)
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        let fd = self.fd.as_ref().ok_or(Error::DriverClosed)?.as_raw_fd();
        let sent = unsafe { libc::send(fd, frame.as_ptr() as *const libc::c_void, frame.len(), 0) };
        if sent < 0 {
            return Err(io_context(
                "send AF_PACKET",
                std::io::Error::last_os_error(),
            ));
        }
        if sent as usize != frame.len() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short AF_PACKET send",
            )));
        }
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn sees_sent_configured(&self) -> Option<bool> {
        None
    }

    fn filter_configured(&self) -> Option<bool> {
        Some(self.filter_configured)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::bpf::FrameIo;
    use crate::Error;

    #[test]
    fn prefix_len_from_netmask_accepts_only_contiguous_masks() {
        assert_eq!(super::prefix_len_from_netmask(0xffff_ff00), Some(24));
        assert_eq!(super::prefix_len_from_netmask(0xffff_0000), Some(16));
        assert_eq!(super::prefix_len_from_netmask(0), Some(0));
        assert_eq!(super::prefix_len_from_netmask(0xffff_00ff), None);
    }

    #[test]
    fn ipv6_prefix_len_from_netmask_accepts_only_contiguous_masks() {
        assert_eq!(super::prefix_len_from_netmask_bytes(&[0xff; 16]), Some(128));
        assert_eq!(
            super::prefix_len_from_netmask_bytes(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0,
            ]),
            Some(64)
        );
        assert_eq!(
            super::prefix_len_from_netmask_bytes(&[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0xff, 0, 0, 0, 0, 0, 0, 0,
            ]),
            None
        );
    }

    #[test]
    fn linux_sockaddr_normalization_keeps_ipv6_addresses_plain() {
        let addr = Ipv6Addr::new(0xfe80, 0x1234, 0, 0, 0, 0, 0, 1);

        assert_eq!(super::normalize_ipv6_addr(addr), addr);
    }

    #[test]
    fn linux_hwaddr_accepts_only_ethernet_family() {
        let mut sockaddr = libc::sockaddr {
            sa_family: libc::ARPHRD_ETHER,
            sa_data: [0; 14],
        };
        for (slot, byte) in sockaddr
            .sa_data
            .iter_mut()
            .zip([0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee])
        {
            *slot = byte as libc::c_char;
        }

        assert_eq!(
            super::sockaddr_hwaddr_to_ethernet_addr(&sockaddr).unwrap(),
            [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        );

        sockaddr.sa_family = libc::ARPHRD_LOOPBACK;
        let err = super::sockaddr_hwaddr_to_ethernet_addr(&sockaddr).unwrap_err();
        assert!(matches!(
            err,
            Error::Config("interface hardware address is not Ethernet")
        ));
    }

    #[test]
    fn proc_net_route_default_gateway_uses_interface_and_little_endian_gateway() {
        let route = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
eth1\t00000000\t010200C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t00000000\t016433C6\t0003\t0\t0\t100\t00000000\t0\t0\t0\n";

        assert_eq!(
            super::parse_proc_net_route_default_gateway(route, "eth1"),
            Some("192.0.2.1".parse().unwrap())
        );
        assert_eq!(
            super::parse_proc_net_route_default_gateway(route, "eth2"),
            None
        );
    }

    #[test]
    fn proc_net_ipv6_route_default_gateway_uses_interface_and_gateway_flag() {
        let route = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000003 eth1\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000064 00000000 00000000 00000001 eth2\n\
20010db8000100000000000000000000 40 00000000000000000000000000000000 00 fe800000000000000000000000000003 00000064 00000000 00000000 00000003 eth1\n";

        assert_eq!(
            super::parse_proc_net_ipv6_route_default_gateway(route, "eth1"),
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(
            super::parse_proc_net_ipv6_route_default_gateway(route, "eth2"),
            None
        );
    }

    #[test]
    fn sockaddr_ll_uses_interface_index_and_eth_p_all() {
        let sockaddr = super::sockaddr_ll_for_interface_index(7);

        assert_eq!(sockaddr.sll_family, libc::AF_PACKET as libc::c_ushort);
        assert_eq!(u16::from_be(sockaddr.sll_protocol), super::ETH_P_ALL);
        assert_eq!(sockaddr.sll_ifindex, 7);
    }

    #[test]
    fn linux_attach_filter_rejects_zero_service_port() {
        let err = super::service_filter_program(&[0]).unwrap_err();

        assert!(matches!(
            err,
            Error::Config("service_ports must not contain zero")
        ));
    }

    #[test]
    fn linux_bpf_device_reports_filter_status_from_open_path() {
        let device = super::BpfDevice::from_opened_socket_for_test(1500, true);

        assert_eq!(device.mtu(), 1500);
        assert_eq!(device.filter_configured(), Some(true));
        assert_eq!(device.sees_sent_configured(), None);
    }
}
