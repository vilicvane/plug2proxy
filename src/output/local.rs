//! Local output - connects with a specific bind address or interface.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, Type};
use tokio::net::TcpStream;

use super::{Output, OutputError};

/// Local output that binds to a specific address or interface.
pub struct LocalOutput {
    /// Bind address (IP or interface resolved to IP).
    bind_addr: Option<IpAddr>,
}

impl LocalOutput {
    pub fn new(bind: Option<LocalIpOrInterface>) -> Self {
        let bind_addr = bind.and_then(|b| b.resolve());
        Self { bind_addr }
    }
}

#[async_trait::async_trait]
impl Output for LocalOutput {
    async fn connect(&self, target: &str) -> Result<TcpStream, OutputError> {
        // Parse target to determine if IPv4 or IPv6
        let target_addr: SocketAddr = resolve_target(target).await?;

        if let Some(bind_addr) = self.bind_addr {
            // Create socket with same domain as target
            let domain = if target_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let socket = Socket::new(domain, Type::STREAM, None)?;

            // Bind to the specified address
            let bind_sockaddr = SocketAddr::new(bind_addr, 0);
            socket.bind(&bind_sockaddr.into())?;

            // Set non-blocking for async
            socket.set_nonblocking(true)?;

            // Connect
            match socket.connect(&target_addr.into()) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }

            // Convert to tokio TcpStream
            let std_stream: std::net::TcpStream = socket.into();
            let stream = TcpStream::from_std(std_stream)?;

            // Wait for connection to complete
            stream.writable().await?;

            // Check for connection errors
            if let Some(e) = stream.take_error()? {
                return Err(e.into());
            }

            stream.set_nodelay(true)?;
            Ok(stream)
        } else {
            // No bind address, just connect directly
            let stream = TcpStream::connect(target).await?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }
    }
}

/// IP address or network interface name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LocalIpOrInterface {
    Ip(IpAddr),
    Interface(String),
}

impl LocalIpOrInterface {
    /// Resolve to an IP address.
    pub fn resolve(&self) -> Option<IpAddr> {
        match self {
            LocalIpOrInterface::Ip(ip) => Some(*ip),
            LocalIpOrInterface::Interface(iface) => resolve_interface_ip(iface),
        }
    }
}

/// Resolve interface name to IP address.
fn resolve_interface_ip(iface: &str) -> Option<IpAddr> {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::net::Ipv4Addr;

        // Try to get interface addresses using getifaddrs
        let iface_cstr = CString::new(iface).ok()?;

        unsafe {
            let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut addrs) != 0 {
                return None;
            }

            let mut current = addrs;
            let mut result = None;

            while !current.is_null() {
                let ifa = &*current;
                let name = std::ffi::CStr::from_ptr(ifa.ifa_name);

                if name == iface_cstr.as_c_str() && !ifa.ifa_addr.is_null() {
                    let family = (*ifa.ifa_addr).sa_family as i32;

                    if family == libc::AF_INET {
                        let addr = ifa.ifa_addr as *const libc::sockaddr_in;
                        let ip = Ipv4Addr::from(u32::from_be((*addr).sin_addr.s_addr));
                        result = Some(IpAddr::V4(ip));
                        break;
                    }
                }

                current = ifa.ifa_next;
            }

            libc::freeifaddrs(addrs);
            result
        }
    }

    #[cfg(not(unix))]
    {
        let _ = iface;
        None
    }
}

/// Resolve target string to SocketAddr (handles both IP:port and domain:port).
async fn resolve_target(target: &str) -> Result<SocketAddr, OutputError> {
    // Try parsing as socket address first
    if let Ok(addr) = target.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Try DNS resolution
    let addrs: Vec<_> = tokio::net::lookup_host(target)
        .await
        .map_err(|e| OutputError::InvalidTarget(format!("{}: {}", target, e)))?
        .collect();

    addrs
        .into_iter()
        .next()
        .ok_or_else(|| OutputError::InvalidTarget(format!("no addresses found for {}", target)))
}
