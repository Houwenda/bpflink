// Portions adapted from libpnet/pnet_datalink, licensed MIT OR Apache-2.0.
// Copyright (c) 2014-2016 Robert Clipsham.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use crate::bpf::frame::iter_bpf_frames;
use crate::bpf::ioctl::macos::{
    BIOCGBLEN, BIOCIMMEDIATE, BIOCPROMISC, BIOCSETF, BIOCSETIF, BIOCSHDRCMPLT, BIOCSSEESENT,
};
use crate::bpf::FrameIo;
use crate::{Error, Result};

pub(crate) struct BpfDevice {
    file: File,
    buffer_len: usize,
    mtu: usize,
    sees_sent_configured: bool,
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
        let file = open_bpf()?;
        let config_status = configure_bpf(&file, interface, service_ports)?;
        let buffer_len = get_buffer_len(&file)?;
        let mtu = interface_mtu(interface)?;
        Ok(Self {
            file,
            buffer_len,
            mtu,
            sees_sent_configured: config_status.sees_sent_configured,
            filter_configured: config_status.filter_configured,
        })
    }
}

pub(crate) fn interface_ethernet_addr(interface: &str) -> Result<[u8; 6]> {
    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Err(io_context("getifaddrs", std::io::Error::last_os_error()));
    }

    let _guard = IfAddrsGuard(addrs);
    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifaddr = unsafe { &*cursor };
        if !ifaddr.ifa_addr.is_null()
            && unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) }.to_bytes()
                == interface.as_bytes()
            && unsafe { (*ifaddr.ifa_addr).sa_family as libc::c_int } == libc::AF_LINK
        {
            let sockaddr = unsafe { &*(ifaddr.ifa_addr as *const libc::sockaddr_dl) };
            if sockaddr.sdl_alen == 6 {
                let offset = usize::from(sockaddr.sdl_nlen);
                let base = sockaddr.sdl_data.as_ptr() as *const u8;
                let mut addr = [0; 6];
                unsafe {
                    ptr::copy_nonoverlapping(base.add(offset), addr.as_mut_ptr(), addr.len());
                }
                return Ok(addr);
            }
        }
        cursor = ifaddr.ifa_next;
    }

    Err(Error::Config("interface ethernet address not found"))
}

pub(crate) fn interface_ip_prefix_len(interface: &str, local_ip: IpAddr) -> Result<u8> {
    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Err(io_context("getifaddrs", std::io::Error::last_os_error()));
    }

    let _guard = IfAddrsGuard(addrs);
    let mut fallback = None;
    let mut cursor = addrs;
    while !cursor.is_null() {
        let ifaddr = unsafe { &*cursor };
        if ifaddr.ifa_addr.is_null() || ifaddr.ifa_netmask.is_null() {
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

        if unsafe { std::ffi::CStr::from_ptr(ifaddr.ifa_name) }.to_bytes() == interface.as_bytes() {
            return Ok(prefix_len);
        }
        fallback = Some(prefix_len);
        cursor = ifaddr.ifa_next;
    }

    fallback.ok_or(Error::Config("IP address/netmask not found for local_ip"))
}

pub(crate) fn interface_default_gateway(
    interface: &str,
    local_ip: IpAddr,
) -> Result<Option<IpAddr>> {
    match local_ip {
        IpAddr::V4(_) => {
            interface_default_ipv4_gateway(interface).map(|gateway| gateway.map(IpAddr::V4))
        }
        IpAddr::V6(_) => {
            interface_default_ipv6_gateway(interface).map(|gateway| gateway.map(IpAddr::V6))
        }
    }
}

fn interface_default_ipv4_gateway(interface: &str) -> Result<Option<Ipv4Addr>> {
    let if_index = interface_index(interface)?;
    let routes = ipv4_gateway_routes()?;
    Ok(parse_default_ipv4_gateway_routes(&routes, if_index))
}

fn interface_default_ipv6_gateway(interface: &str) -> Result<Option<Ipv6Addr>> {
    let if_index = interface_index(interface)?;
    let routes = ipv6_gateway_routes()?;
    Ok(parse_default_ipv6_gateway_routes(&routes, if_index))
}

fn interface_index(interface: &str) -> Result<u16> {
    let interface = std::ffi::CString::new(interface)
        .map_err(|_| Error::Config("interface name contains NUL"))?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    if index == 0 {
        return Err(Error::Config("interface index not found"));
    }
    u16::try_from(index).map_err(|_| Error::Config("interface index does not fit in u16"))
}

fn ipv4_gateway_routes() -> Result<Vec<u8>> {
    gateway_routes(libc::AF_INET)
}

fn ipv6_gateway_routes() -> Result<Vec<u8>> {
    gateway_routes(libc::AF_INET6)
}

fn gateway_routes(address_family: libc::c_int) -> Result<Vec<u8>> {
    let mut mib = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        address_family,
        libc::NET_RT_FLAGS,
        libc::RTF_GATEWAY,
    ];
    let mut len = 0usize;
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            ptr::null_mut(),
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if result < 0 {
        return Err(io_context(
            "sysctl NET_RT_FLAGS size",
            std::io::Error::last_os_error(),
        ));
    }
    let mut routes = vec![0u8; len];
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            routes.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            ptr::null_mut(),
            0,
        )
    };
    if result < 0 {
        return Err(io_context(
            "sysctl NET_RT_FLAGS",
            std::io::Error::last_os_error(),
        ));
    }
    routes.truncate(len);
    Ok(routes)
}

fn parse_default_ipv4_gateway_routes(routes: &[u8], if_index: u16) -> Option<Ipv4Addr> {
    let mut offset = 0usize;
    while offset + mem::size_of::<libc::rt_msghdr>() <= routes.len() {
        let header = unsafe { &*(routes[offset..].as_ptr() as *const libc::rt_msghdr) };
        let message_len = usize::from(header.rtm_msglen);
        if message_len == 0 || offset + message_len > routes.len() {
            break;
        }
        if let Some(gateway) = parse_default_ipv4_gateway_route_message(
            header,
            &routes[offset + mem::size_of::<libc::rt_msghdr>()..offset + message_len],
            if_index,
        ) {
            return Some(gateway);
        }
        offset += message_len;
    }
    None
}

fn parse_default_ipv6_gateway_routes(routes: &[u8], if_index: u16) -> Option<Ipv6Addr> {
    let mut offset = 0usize;
    while offset + mem::size_of::<libc::rt_msghdr>() <= routes.len() {
        let header = unsafe { &*(routes[offset..].as_ptr() as *const libc::rt_msghdr) };
        let message_len = usize::from(header.rtm_msglen);
        if message_len == 0 || offset + message_len > routes.len() {
            break;
        }
        if let Some(gateway) = parse_default_ipv6_gateway_route_message(
            header,
            &routes[offset + mem::size_of::<libc::rt_msghdr>()..offset + message_len],
            if_index,
        ) {
            return Some(gateway);
        }
        offset += message_len;
    }
    None
}

fn parse_default_ipv4_gateway_route_message(
    header: &libc::rt_msghdr,
    sockaddrs: &[u8],
    if_index: u16,
) -> Option<Ipv4Addr> {
    if header.rtm_index != if_index {
        return None;
    }
    let addrs = route_sockaddrs(header.rtm_addrs, sockaddrs);
    let dst = addrs.get(libc::RTAX_DST as usize).copied().flatten();
    let gateway = addrs.get(libc::RTAX_GATEWAY as usize).copied().flatten();
    let netmask = addrs.get(libc::RTAX_NETMASK as usize).copied().flatten();
    if !is_default_ipv4_destination(dst) || !is_default_ipv4_netmask(netmask) {
        return None;
    }
    sockaddr_ipv4(gateway)
}

fn parse_default_ipv6_gateway_route_message(
    header: &libc::rt_msghdr,
    sockaddrs: &[u8],
    if_index: u16,
) -> Option<Ipv6Addr> {
    if header.rtm_index != if_index {
        return None;
    }
    let addrs = route_sockaddrs(header.rtm_addrs, sockaddrs);
    let dst = addrs.get(libc::RTAX_DST as usize).copied().flatten();
    let gateway = addrs.get(libc::RTAX_GATEWAY as usize).copied().flatten();
    let netmask = addrs.get(libc::RTAX_NETMASK as usize).copied().flatten();
    if !is_default_ipv6_destination(dst) || !is_default_ipv6_netmask(netmask) {
        return None;
    }
    sockaddr_ipv6(gateway).filter(|gateway| !gateway.is_unspecified())
}

fn route_sockaddrs(
    addrs_mask: libc::c_int,
    mut bytes: &[u8],
) -> [Option<*const libc::sockaddr>; 8] {
    let mut addrs = [None; 8];
    for (index, slot) in addrs.iter_mut().enumerate() {
        if addrs_mask & (1 << index) == 0 {
            continue;
        }
        if bytes.is_empty() {
            break;
        }
        let sockaddr = bytes.as_ptr() as *const libc::sockaddr;
        let len = sockaddr_route_len(sockaddr);
        if len == 0 || len > bytes.len() {
            break;
        }
        *slot = Some(sockaddr);
        bytes = &bytes[len..];
    }
    addrs
}

fn sockaddr_route_len(sockaddr: *const libc::sockaddr) -> usize {
    let len = unsafe { (*sockaddr).sa_len as usize };
    if len == 0 {
        mem::size_of::<libc::c_long>()
    } else {
        let align = mem::size_of::<libc::c_long>();
        (len + align - 1) & !(align - 1)
    }
}

fn is_default_ipv4_destination(sockaddr: Option<*const libc::sockaddr>) -> bool {
    sockaddr_ipv4(sockaddr) == Some(Ipv4Addr::UNSPECIFIED)
}

fn is_default_ipv4_netmask(sockaddr: Option<*const libc::sockaddr>) -> bool {
    match sockaddr {
        None => true,
        Some(sockaddr) if unsafe { (*sockaddr).sa_len } == 0 => true,
        Some(sockaddr) => sockaddr_ipv4(Some(sockaddr)) == Some(Ipv4Addr::UNSPECIFIED),
    }
}

fn sockaddr_ipv4(sockaddr: Option<*const libc::sockaddr>) -> Option<Ipv4Addr> {
    let sockaddr = sockaddr?;
    if unsafe { (*sockaddr).sa_family as libc::c_int } != libc::AF_INET {
        return None;
    }
    Some(sockaddr_in_ipv4(sockaddr))
}

fn is_default_ipv6_destination(sockaddr: Option<*const libc::sockaddr>) -> bool {
    sockaddr_ipv6(sockaddr) == Some(Ipv6Addr::UNSPECIFIED)
}

fn is_default_ipv6_netmask(sockaddr: Option<*const libc::sockaddr>) -> bool {
    match sockaddr {
        None => true,
        Some(sockaddr) if unsafe { (*sockaddr).sa_len } == 0 => true,
        Some(sockaddr) => sockaddr_ipv6(Some(sockaddr)) == Some(Ipv6Addr::UNSPECIFIED),
    }
}

fn sockaddr_ipv6(sockaddr: Option<*const libc::sockaddr>) -> Option<Ipv6Addr> {
    let sockaddr = sockaddr?;
    if unsafe { (*sockaddr).sa_family as libc::c_int } != libc::AF_INET6 {
        return None;
    }
    Some(sockaddr_in6_ipv6(sockaddr))
}

fn interface_mtu(interface: &str) -> Result<usize> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io_context(
            "socket AF_INET SOCK_DGRAM",
            std::io::Error::last_os_error(),
        ));
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
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
    normalize_ipv6_scope_embedding(Ipv6Addr::from(sockaddr.sin6_addr.s6_addr))
}

fn normalize_ipv6_scope_embedding(addr: Ipv6Addr) -> Ipv6Addr {
    let mut octets = addr.octets();
    if octets[0] == 0xfe && octets[1] == 0x80 {
        octets[2] = 0;
        octets[3] = 0;
    }
    Ipv6Addr::from(octets)
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

impl FrameIo for BpfDevice {
    fn read_frames(&mut self, out: &mut Vec<Vec<u8>>) -> Result<usize> {
        let mut buf = vec![0u8; self.buffer_len];
        let read = match self.file.read(&mut buf) {
            Ok(read) => read,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(0),
            Err(err) => return Err(io_context("read /dev/bpf*", err)),
        };

        let mut count = 0;
        for frame in iter_bpf_frames(&buf[..read]) {
            out.push(frame?.to_vec());
            count += 1;
        }
        Ok(count)
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<()> {
        self.file
            .write_all(frame)
            .map_err(|err| io_context("write /dev/bpf*", err))?;
        Ok(())
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn sees_sent_configured(&self) -> Option<bool> {
        Some(self.sees_sent_configured)
    }

    fn filter_configured(&self) -> Option<bool> {
        Some(self.filter_configured)
    }
}

#[derive(Clone, Copy, Debug)]
struct BpfConfigStatus {
    sees_sent_configured: bool,
    filter_configured: bool,
}

fn open_bpf() -> Result<File> {
    for index in 0..255 {
        let path = format!("/dev/bpf{index}");
        match OpenOptions::new().read(true).write(true).open(&path) {
            Ok(file) => return Ok(file),
            Err(err)
                if matches!(
                    err.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                if err.kind() == std::io::ErrorKind::PermissionDenied {
                    return Err(io_context("open /dev/bpf*", err));
                }
            }
            Err(err) => {
                if err.raw_os_error() != Some(libc::EBUSY) {
                    return Err(io_context("open /dev/bpf*", err));
                }
            }
        }
    }
    Err(Error::Io(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no available /dev/bpf device",
    )))
}

fn configure_bpf(
    file: &File,
    interface: &str,
    service_ports: Option<&[u16]>,
) -> Result<BpfConfigStatus> {
    set_interface(file, interface)?;
    let filter_configured = if let Some(service_ports) = service_ports {
        set_service_filter(file, service_ports)?;
        true
    } else {
        false
    };
    ioctl_int(file, "BIOCIMMEDIATE", BIOCIMMEDIATE, 1)?;
    ioctl_no_arg(file, "BIOCPROMISC", BIOCPROMISC)?;
    ioctl_int(file, "BIOCSHDRCMPLT", BIOCSHDRCMPLT, 1)?;
    let sees_sent_configured = match ioctl_int(file, "BIOCSSEESENT", BIOCSSEESENT, 1) {
        Ok(()) => true,
        Err(Error::IoContext { source, .. }) if source.raw_os_error() == Some(libc::EINVAL) => {
            false
        }
        Err(err) => return Err(err),
    };
    set_nonblocking(file)?;
    Ok(BpfConfigStatus {
        sees_sent_configured,
        filter_configured,
    })
}

fn set_service_filter(file: &File, service_ports: &[u16]) -> Result<()> {
    let mut instructions = service_filter_program(service_ports)?;
    let mut program = libc::bpf_program {
        bf_len: instructions.len() as libc::c_uint,
        bf_insns: instructions.as_mut_ptr(),
    };
    let result = unsafe { libc::ioctl(file.as_raw_fd(), BIOCSETF, &mut program) };
    if result < 0 {
        return Err(io_context("BIOCSETF", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn service_filter_program(service_ports: &[u16]) -> Result<Vec<libc::bpf_insn>> {
    crate::bpf::filter::service_filter_program(service_ports).map(|instructions| {
        instructions
            .into_iter()
            .map(|instruction| libc::bpf_insn {
                code: instruction.code,
                jt: instruction.jt,
                jf: instruction.jf,
                k: instruction.k,
            })
            .collect()
    })
}

fn set_interface(file: &File, interface: &str) -> Result<()> {
    let ifreq = named_ifreq(interface)?;

    let result = unsafe { libc::ioctl(file.as_raw_fd(), BIOCSETIF, &ifreq) };
    if result < 0 {
        return Err(io_context("BIOCSETIF", std::io::Error::last_os_error()));
    }
    Ok(())
}

fn named_ifreq(interface: &str) -> Result<libc::ifreq> {
    if interface.len() >= libc::IFNAMSIZ {
        return Err(Error::Config("interface name is too long"));
    }

    let mut ifreq: libc::ifreq = unsafe { mem::zeroed() };
    for (slot, byte) in ifreq.ifr_name.iter_mut().zip(interface.as_bytes()) {
        *slot = *byte as libc::c_char;
    }
    Ok(ifreq)
}

fn ioctl_int(
    file: &File,
    operation: &'static str,
    request: libc::c_ulong,
    value: libc::c_int,
) -> Result<()> {
    let mut value = value;
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request, &mut value) };
    if result < 0 {
        return Err(io_context(operation, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn ioctl_no_arg(file: &File, operation: &'static str, request: libc::c_ulong) -> Result<()> {
    let result = unsafe { libc::ioctl(file.as_raw_fd(), request) };
    if result < 0 {
        return Err(io_context(operation, std::io::Error::last_os_error()));
    }
    Ok(())
}

fn get_buffer_len(file: &File) -> Result<usize> {
    let mut value: libc::c_uint = 0;
    let result = unsafe { libc::ioctl(file.as_raw_fd(), BIOCGBLEN, &mut value) };
    if result < 0 {
        return Err(io_context("BIOCGBLEN", std::io::Error::last_os_error()));
    }
    Ok(value as usize)
}

fn set_nonblocking(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io_context("fcntl F_GETFL", std::io::Error::last_os_error()));
    }
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result < 0 {
        return Err(io_context(
            "fcntl F_SETFL O_NONBLOCK",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn io_context(operation: &'static str, source: std::io::Error) -> Error {
    Error::IoContext { operation, source }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;

    use crate::bpf::filter::{
        BPF_ABS, BPF_B, BPF_H, BPF_JEQ, BPF_JMP, BPF_JSET, BPF_K, BPF_LD, BPF_RET,
    };

    const SERVICE_PORT: u16 = 40000;

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
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0
            ]),
            Some(64)
        );
        assert_eq!(
            super::prefix_len_from_netmask_bytes(&[
                0xff, 0xff, 0xff, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ]),
            None
        );
    }

    #[test]
    fn service_filter_accepts_control_and_matching_udp_only() {
        let program = super::service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_ne!(run_filter(&program, &ethernet_frame(0x0806)), 0);
        assert_ne!(run_filter(&program, &ipv4_frame(1, 12345, 54321)), 0);
        assert_ne!(
            run_filter(&program, &ipv4_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv4_frame(17, SERVICE_PORT, 50000)),
            0
        );
        assert_eq!(run_filter(&program, &ipv4_frame(17, 50000, 50001)), 0);
        assert_eq!(run_filter(&program, &ethernet_frame(0x86dd)), 0);
    }

    #[test]
    fn service_filter_accepts_ipv6_icmpv6_and_matching_udp_only() {
        let program = super::service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_ne!(run_filter(&program, &ipv6_frame(58, 12345, 54321)), 0);
        assert_ne!(
            run_filter(&program, &ipv6_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_ne!(
            run_filter(&program, &ipv6_frame(17, SERVICE_PORT, 50000)),
            0
        );
        assert_eq!(run_filter(&program, &ipv6_frame(17, 50000, 50001)), 0);
        assert_eq!(run_filter(&program, &ipv6_frame(6, SERVICE_PORT, 50000)), 0);
    }

    #[test]
    fn service_filter_accepts_ipv6_udp_behind_common_extension_headers() {
        let program = super::service_filter_program(&[SERVICE_PORT]).unwrap();

        for next_header in [0, 43, 60] {
            assert_ne!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, 50000, SERVICE_PORT)
                ),
                0
            );
            assert_ne!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, SERVICE_PORT, 50000)
                ),
                0
            );
            assert_eq!(
                run_filter(
                    &program,
                    &ipv6_extension_udp_frame(next_header, 50000, 50001)
                ),
                0
            );
        }

        assert_eq!(
            run_filter(&program, &ipv6_extension_udp_frame(44, 50000, SERVICE_PORT)),
            0
        );
    }

    #[test]
    fn service_filter_drops_fragmented_or_optioned_udp() {
        let program = super::service_filter_program(&[SERVICE_PORT]).unwrap();

        assert_eq!(
            run_filter(&program, &ipv4_fragment_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_eq!(
            run_filter(&program, &ipv4_options_frame(17, 50000, SERVICE_PORT)),
            0
        );
        assert_eq!(
            run_filter(
                &program,
                &ipv4_options_frame_with_fixed_offset_service_port(17, 50000, 50001)
            ),
            0
        );
        assert_eq!(run_filter(&program, &[0; 24]), 0);
    }

    #[test]
    fn link_local_ipv6_scope_embedding_is_normalized_for_address_matching() {
        let mut bytes = [0; 16];
        bytes[0] = 0xfe;
        bytes[1] = 0x80;
        bytes[2] = 0x00;
        bytes[3] = 0x15;
        bytes[8..16].copy_from_slice(&[0xb0, 0xbe, 0x83, 0xff, 0xfe, 0x36, 0x02, 0x64]);

        assert_eq!(
            super::normalize_ipv6_scope_embedding(Ipv6Addr::from(bytes)),
            "fe80::b0be:83ff:fe36:264".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn route_sysctl_default_ipv6_gateway_uses_interface_and_default_prefix() {
        let routes = route_message_with_ipv6_gateway(
            7,
            "::".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            Some("::".parse().unwrap()),
        );

        assert_eq!(
            super::parse_default_ipv6_gateway_routes(&routes, 7),
            Some("fe80::1".parse().unwrap())
        );
        assert_eq!(super::parse_default_ipv6_gateway_routes(&routes, 8), None);

        let non_default_routes = route_message_with_ipv6_gateway(
            7,
            "2001:db8:1::".parse().unwrap(),
            "fe80::1".parse().unwrap(),
            Some("ffff:ffff:ffff:ffff::".parse().unwrap()),
        );
        assert_eq!(
            super::parse_default_ipv6_gateway_routes(&non_default_routes, 7),
            None
        );
    }

    fn route_message_with_ipv6_gateway(
        if_index: u16,
        dst: Ipv6Addr,
        gateway: Ipv6Addr,
        netmask: Option<Ipv6Addr>,
    ) -> Vec<u8> {
        let mut sockaddrs = Vec::new();
        push_sockaddr_in6(&mut sockaddrs, dst);
        push_sockaddr_in6(&mut sockaddrs, gateway);
        if let Some(netmask) = netmask {
            push_sockaddr_in6(&mut sockaddrs, netmask);
        }

        let mut header: libc::rt_msghdr = unsafe { std::mem::zeroed() };
        header.rtm_msglen = (std::mem::size_of::<libc::rt_msghdr>() + sockaddrs.len()) as u16;
        header.rtm_index = if_index;
        header.rtm_addrs = libc::RTA_DST | libc::RTA_GATEWAY;
        if netmask.is_some() {
            header.rtm_addrs |= libc::RTA_NETMASK;
        }

        let mut out = bytes_of(&header);
        out.extend_from_slice(&sockaddrs);
        out
    }

    fn push_sockaddr_in6(out: &mut Vec<u8>, addr: Ipv6Addr) {
        let sockaddr = libc::sockaddr_in6 {
            sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
            sin6_family: libc::AF_INET6 as u8,
            sin6_port: 0,
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: addr.octets(),
            },
            sin6_scope_id: 0,
        };
        let before = out.len();
        out.extend_from_slice(&bytes_of(&sockaddr));
        let align = std::mem::size_of::<libc::c_long>();
        let padded_len = (out.len() + align - 1) & !(align - 1);
        out.resize(padded_len.max(before + align), 0);
    }

    fn bytes_of<T>(value: &T) -> Vec<u8> {
        unsafe {
            std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>())
                .to_vec()
        }
    }

    fn run_filter(program: &[libc::bpf_insn], frame: &[u8]) -> u32 {
        let mut accumulator = 0;
        let mut pc = 0usize;
        loop {
            let instruction = program[pc];
            match instruction.code {
                code if code == BPF_LD | BPF_H | BPF_ABS => {
                    let offset = instruction.k as usize;
                    let Some(bytes) = frame.get(offset..offset + 2) else {
                        return 0;
                    };
                    accumulator = u16::from_be_bytes([bytes[0], bytes[1]]) as u32;
                    pc += 1;
                }
                code if code == BPF_LD | BPF_B | BPF_ABS => {
                    let Some(byte) = frame.get(instruction.k as usize) else {
                        return 0;
                    };
                    accumulator = *byte as u32;
                    pc += 1;
                }
                code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                    pc += if accumulator == instruction.k {
                        1 + instruction.jt as usize
                    } else {
                        1 + instruction.jf as usize
                    };
                }
                code if code == BPF_JMP | BPF_JSET | BPF_K => {
                    pc += if accumulator & instruction.k != 0 {
                        1 + instruction.jt as usize
                    } else {
                        1 + instruction.jf as usize
                    };
                }
                code if code == BPF_RET | BPF_K => return instruction.k,
                code => panic!("unsupported test instruction code {code:#x}"),
            }
        }
    }

    fn ethernet_frame(ethertype: u16) -> Vec<u8> {
        let mut frame = vec![0; 64];
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
        frame
    }

    fn ipv4_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x0800);
        frame[14] = 0x45;
        frame[23] = protocol;
        frame[34..36].copy_from_slice(&src_port.to_be_bytes());
        frame[36..38].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv4_fragment_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ipv4_frame(protocol, src_port, dst_port);
        frame[20..22].copy_from_slice(&1u16.to_be_bytes());
        frame
    }

    fn ipv4_options_frame(protocol: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x0800);
        frame[14] = 0x46;
        frame[23] = protocol;
        frame[38..40].copy_from_slice(&src_port.to_be_bytes());
        frame[40..42].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv4_options_frame_with_fixed_offset_service_port(
        protocol: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = ipv4_options_frame(protocol, src_port, dst_port);
        frame[36..38].copy_from_slice(&SERVICE_PORT.to_be_bytes());
        frame
    }

    fn ipv6_frame(next_header: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x86dd);
        frame[14] = 0x60;
        frame[20] = next_header;
        frame[54..56].copy_from_slice(&src_port.to_be_bytes());
        frame[56..58].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ipv6_extension_udp_frame(next_header: u8, src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = ethernet_frame(0x86dd);
        frame.resize(14 + 40 + 8 + 8, 0);
        frame[14] = 0x60;
        frame[20] = next_header;
        frame[54] = 17;
        frame[62..64].copy_from_slice(&src_port.to_be_bytes());
        frame[64..66].copy_from_slice(&dst_port.to_be_bytes());
        frame
    }
}
