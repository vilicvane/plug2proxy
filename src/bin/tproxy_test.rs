//! TPROXY test binary.
//!
//! This binary tests the TPROXY implementation by:
//! 1. Starting TCP and UDP TPROXY listeners
//! 2. Accepting connections and printing original destinations
//! 3. Optionally forwarding to the real destination (--forward mode)
//!
//! Usage (in Multipass VM - recommended for safe testing):
//!   1. Create VM: multipass launch -n tproxy-test
//!   2. Copy binary and setup script to VM
//!   3. Run setup: sudo ./tproxy_vm_setup.sh setup
//!   4. Run test: sudo ./tproxy_test [--forward]
//!   5. Test: curl http://example.com/
//!
//! See res/in/tproxy_test_multipass.md for detailed instructions.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use plug2proxy::tproxy::{TProxyTcpListener, TProxyUdpSocket};
use plug2proxy::util::set_socket_mark;

const TPROXY_ADDR: &str = "127.0.0.1:12345";
const MARK: u32 = 0xff;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let forward = std::env::args().any(|arg| arg == "--forward");

    let addr: SocketAddr = TPROXY_ADDR.parse()?;

    println!("===========================================");
    println!("TPROXY Test");
    println!("===========================================");
    println!("Listening on: {}", addr);
    println!("Mark: 0x{:02x}", MARK);
    println!("Forward mode: {}", forward);
    println!("===========================================");
    println!();

    // Start TCP listener
    let tcp_listener = TProxyTcpListener::bind(addr, Some(MARK)).await?;
    tracing::info!("TCP TPROXY listener started on {}", addr);

    // Start UDP socket
    let udp_socket = Arc::new(TProxyUdpSocket::bind(addr, Some(MARK)).await?);
    tracing::info!("UDP TPROXY socket started on {}", addr);

    // Spawn UDP handler
    let udp_socket_clone = Arc::clone(&udp_socket);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match udp_socket_clone.recv(&mut buf).await {
                Ok(datagram) => {
                    tracing::info!(
                        "UDP: {} -> {} ({} bytes)",
                        datagram.source,
                        datagram.original_dst,
                        datagram.data.len()
                    );

                    // In forward mode, send to real destination and relay response
                    // For now, just log
                }
                Err(e) => {
                    tracing::error!("UDP recv error: {}", e);
                }
            }
        }
    });

    // Handle TCP connections
    loop {
        match tcp_listener.accept().await {
            Ok(conn) => {
                tracing::info!(
                    "TCP: {} -> {} (original destination)",
                    conn.source,
                    conn.original_dst
                );

                if forward {
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_forward(conn.stream, conn.original_dst).await {
                            tracing::error!("TCP forward error: {}", e);
                        }
                    });
                } else {
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_echo(conn.stream, conn.original_dst).await {
                            tracing::error!("TCP echo error: {}", e);
                        }
                    });
                }
            }
            Err(e) => {
                tracing::error!("TCP accept error: {}", e);
            }
        }
    }
}

/// Echo mode: respond with info about the connection
async fn handle_tcp_echo(
    mut stream: tokio::net::TcpStream,
    original_dst: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Read some data
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await?;

    if n > 0 {
        let request = String::from_utf8_lossy(&buf[..n]);
        tracing::debug!("Received request:\n{}", request);
    }

    // Send response with connection info
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/plain\r\n\
         Connection: close\r\n\
         \r\n\
         TPROXY Test Response\n\
         Original destination: {}\n\
         Your address: {}\n",
        original_dst,
        stream
            .peer_addr()
            .unwrap_or_else(|_| "unknown".parse().unwrap())
    );

    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await?;

    Ok(())
}

/// Forward mode: connect to real destination and relay
async fn handle_tcp_forward(
    mut client: tokio::net::TcpStream,
    original_dst: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing::info!("Forwarding to {}", original_dst);

    // Create socket and set mark BEFORE connecting (critical for TPROXY bypass)
    let socket = match original_dst {
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

    // Mark BEFORE connect so the SYN packet is marked
    set_socket_mark(&socket, MARK)?;
    socket.set_nonblocking(true)?;

    // Connect
    match socket.connect(&original_dst.into()) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e.into()),
    }

    let std_stream: std::net::TcpStream = socket.into();
    let mut target = TcpStream::from_std(std_stream)?;
    target.writable().await?; // Wait for connect to complete
    target.set_nodelay(true)?;

    // Relay bidirectionally
    let (mut client_read, mut client_write) = client.split();
    let (mut target_read, mut target_write) = target.split();

    let client_to_target = tokio::io::copy(&mut client_read, &mut target_write);
    let target_to_client = tokio::io::copy(&mut target_read, &mut client_write);

    tokio::select! {
        result = client_to_target => {
            if let Err(e) = result {
                tracing::debug!("client->target error: {}", e);
            }
        }
        result = target_to_client => {
            if let Err(e) = result {
                tracing::debug!("target->client error: {}", e);
            }
        }
    }

    Ok(())
}
