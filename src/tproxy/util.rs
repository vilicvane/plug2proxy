//! TPROXY utility functions.

use std::io;
use std::net::SocketAddr;

/// Get the original destination address from a TCP socket.
///
/// This uses `SO_ORIGINAL_DST` (IPv4) or `IP6T_SO_ORIGINAL_DST` (IPv6)
/// to retrieve the destination address before TPROXY redirection.
#[cfg(target_os = "linux")]
pub fn get_original_dst<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    is_ipv6: bool,
) -> io::Result<SocketAddr> {
    use std::mem;

    let fd = socket.as_raw_fd();

    if is_ipv6 {
        // IPv6: IP6T_SO_ORIGINAL_DST
        const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

        let mut addr: libc::sockaddr_in6 = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                IP6T_SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
        let port = u16::from_be(addr.sin6_port);
        Ok(SocketAddr::from((ip, port)))
    } else {
        // IPv4: SO_ORIGINAL_DST
        const SO_ORIGINAL_DST: libc::c_int = 80;

        let mut addr: libc::sockaddr_in = unsafe { mem::zeroed() };
        let mut len = mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_IP,
                SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
        let port = u16::from_be(addr.sin_port);
        Ok(SocketAddr::from((ip, port)))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn get_original_dst<S>(_socket: &S, _is_ipv6: bool) -> io::Result<SocketAddr> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY is only supported on Linux",
    ))
}

/// Set IP_TRANSPARENT socket option.
#[cfg(target_os = "linux")]
pub fn set_ip_transparent<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    is_ipv6: bool,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enable: libc::c_int = 1;

    let (level, optname) = if is_ipv6 {
        (libc::SOL_IPV6, libc::IPV6_TRANSPARENT)
    } else {
        (libc::SOL_IP, libc::IP_TRANSPARENT)
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_ip_transparent<S>(_socket: &S, _is_ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY is only supported on Linux",
    ))
}

/// Set IP_FREEBIND socket option (allows binding to non-local addresses).
#[cfg(target_os = "linux")]
pub fn set_ip_freebind<S: std::os::unix::io::AsRawFd>(socket: &S, is_ipv6: bool) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enable: libc::c_int = 1;

    let (level, optname) = if is_ipv6 {
        (libc::SOL_IPV6, libc::IPV6_FREEBIND)
    } else {
        (libc::SOL_IP, libc::IP_FREEBIND)
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_ip_freebind<S>(_socket: &S, _is_ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY is only supported on Linux",
    ))
}

/// Set IP_RECVORIGDSTADDR socket option (for UDP to receive original destination).
#[cfg(target_os = "linux")]
pub fn set_recv_original_dst<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    is_ipv6: bool,
) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    let enable: libc::c_int = 1;

    let (level, optname) = if is_ipv6 {
        (libc::SOL_IPV6, libc::IPV6_RECVORIGDSTADDR)
    } else {
        (libc::SOL_IP, libc::IP_RECVORIGDSTADDR)
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        )
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_recv_original_dst<S>(_socket: &S, _is_ipv6: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TPROXY is only supported on Linux",
    ))
}
