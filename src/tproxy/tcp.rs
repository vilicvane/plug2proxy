//! TPROXY TCP listener.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpSocket, TcpStream};

use super::util::{get_original_dst, set_ip_freebind, set_ip_transparent};
use crate::util::set_socket_mark;

/// A TCP listener that accepts TPROXY-redirected connections.
///
/// This listener can retrieve the original destination address of
/// connections that were redirected via nftables TPROXY.
pub struct TProxyTcpListener {
    inner: TcpListener,
    is_ipv6: bool,
}

/// A TPROXY-accepted TCP connection with its original destination.
pub struct TProxyTcpStream {
    /// The TCP stream.
    pub stream: TcpStream,
    /// The client's source address.
    pub source: SocketAddr,
    /// The original destination (before TPROXY redirect).
    pub original_dst: SocketAddr,
}

impl TProxyTcpListener {
    /// Create a new TPROXY TCP listener bound to the given address.
    ///
    /// # Arguments
    /// * `addr` - Address to bind to (usually 0.0.0.0:12345 or [::]:12345)
    /// * `mark` - Optional SO_MARK for outgoing packets (for policy routing)
    ///
    /// # Requirements
    /// - Must run as root or have CAP_NET_ADMIN capability
    /// - Requires nftables TPROXY rules to redirect traffic
    pub async fn bind(addr: SocketAddr, mark: Option<u32>) -> io::Result<Self> {
        let is_ipv6 = addr.is_ipv6();

        let socket = if is_ipv6 {
            TcpSocket::new_v6()?
        } else {
            TcpSocket::new_v4()?
        };

        // Enable IP_TRANSPARENT to accept connections to any IP
        set_ip_transparent(&socket, is_ipv6)?;

        // Enable IP_FREEBIND to bind to non-local addresses
        set_ip_freebind(&socket, is_ipv6)?;

        // Set SO_MARK if configured
        if let Some(mark) = mark {
            set_socket_mark(&socket, mark)?;
        }

        socket.set_reuseaddr(true)?;

        socket.bind(addr)?;

        let listener = socket.listen(1024)?;

        tracing::info!("TPROXY TCP listener bound to {}", addr);

        Ok(Self {
            inner: listener,
            is_ipv6,
        })
    }

    /// Accept a new TPROXY-redirected connection.
    ///
    /// Returns the stream along with its source and original destination addresses.
    pub async fn accept(&self) -> io::Result<TProxyTcpStream> {
        let (stream, source) = self.inner.accept().await?;

        // Get the original destination (before TPROXY redirect)
        let original_dst = get_original_dst(&stream, self.is_ipv6)
            .unwrap_or_else(|_| stream.local_addr().unwrap_or(source));

        // Set TCP_NODELAY for low latency
        stream.set_nodelay(true)?;

        Ok(TProxyTcpStream {
            stream,
            source,
            original_dst,
        })
    }

    /// Get the local address this listener is bound to.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
