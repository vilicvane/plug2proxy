//! TPROXY UDP socket.

use std::io;
use std::net::SocketAddr;

use tokio::net::UdpSocket;

use super::util::{set_ip_freebind, set_ip_transparent, set_recv_original_dst};
use crate::util::set_socket_mark;

/// A UDP socket that can receive TPROXY-redirected datagrams.
///
/// This socket can retrieve the original destination address of
/// datagrams that were redirected via nftables TPROXY.
pub struct TProxyUdpSocket {
    inner: UdpSocket,
    is_ipv6: bool,
}

/// A received TPROXY UDP datagram with metadata.
pub struct TProxyDatagram {
    /// The datagram data.
    pub data: Vec<u8>,
    /// The client's source address.
    pub source: SocketAddr,
    /// The original destination (before TPROXY redirect).
    pub original_dst: SocketAddr,
}

impl TProxyUdpSocket {
    /// Create a new TPROXY UDP socket bound to the given address.
    ///
    /// # Arguments
    /// * `addr` - Address to bind to (usually 0.0.0.0:12345 or [::]:12345)
    /// * `mark` - Optional SO_MARK for outgoing packets (for policy routing)
    ///
    /// # Requirements
    /// - Must run as root or have CAP_NET_ADMIN capability
    /// - Requires nftables TPROXY rules to redirect traffic
    #[cfg(target_os = "linux")]
    pub async fn bind(addr: SocketAddr, mark: Option<u32>) -> io::Result<Self> {
        use std::os::unix::io::{AsRawFd, FromRawFd};

        let is_ipv6 = addr.is_ipv6();

        // Create socket using socket2 for more control
        // NOTE: Don't use SOCK_NONBLOCK here - let tokio set it up properly
        let domain = if is_ipv6 {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };

        let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Wrap in a std socket for cleanup on error
        let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

        // Enable IP_TRANSPARENT - required for TPROXY to work
        set_ip_transparent(&std_socket, is_ipv6)?;

        // Enable IP_FREEBIND - allows binding to non-local addresses
        set_ip_freebind(&std_socket, is_ipv6)?;

        // Enable IP_RECVORIGDSTADDR to receive original destination in control message
        set_recv_original_dst(&std_socket, is_ipv6)?;

        // Set SO_REUSEADDR
        let enable: libc::c_int = 1;
        unsafe {
            libc::setsockopt(
                std_socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            );
        }

        // Set SO_MARK if configured (for outgoing packets to bypass TPROXY)
        if let Some(mark) = mark {
            set_socket_mark(&std_socket, mark)?;
        }

        // Bind to address
        bind_socket(fd, addr)?;

        // Set nonblocking AFTER bind, then convert to tokio
        std_socket.set_nonblocking(true)?;
        let inner = UdpSocket::from_std(std_socket)?;

        tracing::info!("TPROXY UDP socket bound to {}", addr);

        Ok(Self { inner, is_ipv6 })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn bind(_addr: SocketAddr, _mark: Option<u32>) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is only supported on Linux",
        ))
    }

    /// Receive a TPROXY-redirected datagram.
    ///
    /// Returns the datagram data along with source and original destination.
    #[cfg(target_os = "linux")]
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<TProxyDatagram> {
        // We need to use recvmsg to get the original destination from the control message
        loop {
            // Use try_io to properly integrate with tokio's reactor
            let result = self.inner.try_io(tokio::io::Interest::READABLE, || {
                self.recv_with_original_dst_sync(buf)
            });

            match result {
                Ok(datagram) => return Ok(datagram),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // Wait for socket to become readable
                    self.inner.readable().await?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn recv_with_original_dst_sync(&self, buf: &mut [u8]) -> io::Result<TProxyDatagram> {
        use std::os::unix::io::AsRawFd;

        let fd = self.inner.as_raw_fd();

        // Prepare iovec for data
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        // Prepare control message buffer
        // Size for one cmsghdr + sockaddr_in6 (largest)
        const CMSG_SPACE: usize = 128;
        let mut cmsg_buf = [0u8; CMSG_SPACE];

        // Prepare source address buffer
        let mut src_addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };

        // Prepare msghdr
        let mut msg = libc::msghdr {
            msg_name: &mut src_addr_storage as *mut _ as *mut libc::c_void,
            msg_namelen: std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t,
            msg_iov: &mut iov,
            msg_iovlen: 1,
            msg_control: cmsg_buf.as_mut_ptr() as *mut libc::c_void,
            msg_controllen: CMSG_SPACE,
            msg_flags: 0,
        };

        // Receive
        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let data_len = n as usize;

        // Parse source address
        let source = sockaddr_to_socketaddr(&src_addr_storage)?;

        // Parse control message to get original destination
        let original_dst = parse_original_dst(&msg, self.is_ipv6).unwrap_or(source);

        Ok(TProxyDatagram {
            data: buf[..data_len].to_vec(),
            source,
            original_dst,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn recv(&self, _buf: &mut [u8]) -> io::Result<TProxyDatagram> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is only supported on Linux",
        ))
    }

    /// Send a datagram from a specific source address.
    ///
    /// This is used for sending responses that appear to come from the
    /// original destination address.
    #[cfg(target_os = "linux")]
    pub async fn send_from(
        &self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> io::Result<usize> {
        // For sending responses, we need a separate socket bound to the original destination
        // with IP_TRANSPARENT. This allows us to send packets with a source IP that isn't ours.
        let response_socket = create_transparent_response_socket(from, self.is_ipv6)?;
        response_socket.send_to(data, to).await
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn send_from(
        &self,
        _data: &[u8],
        _from: SocketAddr,
        _to: SocketAddr,
    ) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TPROXY is only supported on Linux",
        ))
    }

    /// Get the local address this socket is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Get a reference to the inner UdpSocket for direct operations.
    pub fn inner(&self) -> &UdpSocket {
        &self.inner
    }
}

/// Convert a sockaddr_storage to SocketAddr.
#[cfg(target_os = "linux")]
fn sockaddr_to_socketaddr(storage: &libc::sockaddr_storage) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in = unsafe { std::mem::transmute(storage) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 = unsafe { std::mem::transmute(storage) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::from((ip, port)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown address family",
        )),
    }
}

/// Parse original destination from control message.
#[cfg(target_os = "linux")]
fn parse_original_dst(msg: &libc::msghdr, is_ipv6: bool) -> Option<SocketAddr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };

    while !cmsg.is_null() {
        let cmsg_ref = unsafe { &*cmsg };

        if is_ipv6 {
            if cmsg_ref.cmsg_level == libc::SOL_IPV6 && cmsg_ref.cmsg_type == libc::IPV6_ORIGDSTADDR
            {
                let addr: &libc::sockaddr_in6 =
                    unsafe { &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in6) };
                let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                return Some(SocketAddr::from((ip, port)));
            }
        } else {
            if cmsg_ref.cmsg_level == libc::SOL_IP && cmsg_ref.cmsg_type == libc::IP_ORIGDSTADDR {
                let addr: &libc::sockaddr_in =
                    unsafe { &*(libc::CMSG_DATA(cmsg) as *const libc::sockaddr_in) };
                let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                return Some(SocketAddr::from((ip, port)));
            }
        }

        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }

    None
}

/// Create a transparent UDP socket for sending responses.
#[cfg(target_os = "linux")]
fn create_transparent_response_socket(
    bind_addr: SocketAddr,
    is_ipv6: bool,
) -> io::Result<UdpSocket> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    let domain = if is_ipv6 {
        libc::AF_INET6
    } else {
        libc::AF_INET
    };

    let fd = unsafe { libc::socket(domain, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let std_socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };

    // Enable IP_TRANSPARENT to bind to non-local address
    set_ip_transparent(&std_socket, is_ipv6)?;

    // Enable IP_FREEBIND
    set_ip_freebind(&std_socket, is_ipv6)?;

    // Set SO_REUSEPORT for multiple response sockets
    let enable: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            std_socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enable) as libc::socklen_t,
        );
    }

    // Bind to the original destination address
    bind_socket(fd, bind_addr)?;

    std_socket.set_nonblocking(true)?;
    UdpSocket::from_std(std_socket)
}

/// Bind a socket to an address using libc.
#[cfg(target_os = "linux")]
fn bind_socket(fd: libc::c_int, addr: SocketAddr) -> io::Result<()> {
    let ret = match addr {
        SocketAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
        }
        SocketAddr::V6(addr) => {
            let sin6 = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            unsafe {
                libc::bind(
                    fd,
                    &sin6 as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
