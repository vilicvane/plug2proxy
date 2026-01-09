use std::net::SocketAddr;

use tokio::net::TcpStream;

/// Set SO_MARK socket option (Linux-specific, for TPROXY).
///
/// This sets the traffic mark on a socket, which is used by Linux's TPROXY
/// to route packets based on their mark value.
///
/// # Arguments
/// * `socket` - The socket to mark
/// * `mark` - The mark value to set
///
/// # Returns
/// * `Ok(())` on success
/// * `Err` if setting the socket option fails
///
/// # Platform Support
/// * Linux: Fully supported
/// * Other platforms: No-op (returns `Ok(())`)
#[cfg(target_os = "linux")]
pub fn set_socket_mark<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    mark: u32,
) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if ret != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn set_socket_mark<S>(_: &S, _: u32) -> std::io::Result<()> {
    // SO_MARK is Linux-specific, no-op on other platforms
    Ok(())
}

/// Connect a TCP socket with optional traffic mark set BEFORE connecting.
///
/// This is critical for TPROXY: the mark must be set before the SYN packet
/// is sent, otherwise the outgoing connection will be intercepted again.
///
/// # Arguments
/// * `addr` - The address to connect to
/// * `mark` - Optional traffic mark to set before connecting
///
/// # Returns
/// * `Ok(TcpStream)` on successful connection
/// * `Err` on connection or socket error
pub async fn tcp_connect_with_mark(
    addr: SocketAddr,
    mark: Option<u32>,
) -> std::io::Result<TcpStream> {
    if let Some(mark) = mark {
        // Create socket with socket2 to set mark before connect
        let socket = match addr {
            SocketAddr::V4(_) => socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,
            SocketAddr::V6(_) => socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?,
        };

        // Set mark BEFORE connect so the SYN packet is marked
        set_socket_mark(&socket, mark)?;
        socket.set_nonblocking(true)?;

        // Start async connect
        match socket.connect(&addr.into()) {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
            Err(e) => return Err(e),
        }

        let std_stream: std::net::TcpStream = socket.into();
        let stream = TcpStream::from_std(std_stream)?;

        // Wait for connect to complete
        stream.writable().await?;

        // Check for connection error
        if let Some(e) = stream.take_error()? {
            return Err(e);
        }

        Ok(stream)
    } else {
        // No mark needed, use simple connect
        TcpStream::connect(addr).await
    }
}
