use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use socks5_server::{
    AssociatedUdpSocket, Command, IncomingConnection, Server,
    proto::{Address, Reply},
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::node::InNode;
use crate::tunnel::Stream;
use crate::udp_proxy::Datagram;

/// SOCKS5 server that accepts connections and proxies through InNode.
pub struct Socks5Server {
    in_node: Arc<InNode>,
    bind_addr: SocketAddr,
}

impl Socks5Server {
    pub fn new(in_node: Arc<InNode>, bind_addr: SocketAddr) -> Self {
        Self { in_node, bind_addr }
    }

    /// Run the SOCKS5 server.
    /// Returns when HUB connection is lost.
    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        let auth = Arc::new(socks5_server::auth::NoAuth);
        let server = Server::new(listener, auth);

        tracing::info!("SOCKS5 server listening on {}", self.bind_addr);

        // Spawn a task to check HUB connection health
        let in_node_health = Arc::clone(&self.in_node);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                if !in_node_health.is_hub_connected().await {
                    tracing::warn!("HUB connection lost, shutting down SOCKS5 server");
                    let _ = shutdown_tx.send(());
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                result = server.accept() => {
                    match result {
                        Ok((conn, addr)) => {
                            tracing::debug!("accepted SOCKS5 connection from {}", addr);

                            let in_node = Arc::clone(&self.in_node);
                            let bind_addr = self.bind_addr;

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(conn, in_node, bind_addr).await {
                                    tracing::error!("SOCKS5 client {} error: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("failed to accept connection: {}", e);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("SOCKS5 server shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single SOCKS5 connection.
async fn handle_connection<A>(
    conn: IncomingConnection<A, socks5_server::connection::state::NeedAuthenticate>,
    in_node: Arc<InNode>,
    bind_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Perform authentication
    let (conn, _auth_result) = conn.authenticate().await.map_err(|(e, _)| e)?;

    // Wait for command from client
    match conn.wait().await.map_err(|(e, _)| e)? {
        Command::Connect(connect, addr) => {
            let target = address_to_string(&addr);
            tracing::info!("SOCKS5 CONNECT to {}", target);
            handle_connect(connect, &target, in_node).await
        }
        Command::Bind(_bind, _addr) => {
            tracing::warn!("BIND command not supported");
            Err(Socks5Error::UnsupportedCommand)
        }
        Command::Associate(associate, addr) => {
            tracing::info!("SOCKS5 UDP ASSOCIATE from {}", addr);
            handle_udp_associate(associate, in_node, bind_addr).await
        }
    }
}

/// Handle TCP CONNECT command.
async fn handle_connect(
    connect: socks5_server::Connect<socks5_server::connection::connect::state::NeedReply>,
    target: &str,
    in_node: Arc<InNode>,
) -> Result<(), Socks5Error> {
    // Connect through InNode
    let mut proxy_stream = match in_node.connect(target).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!("failed to connect to {}: {}", target, e);
            let _ = connect
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await;
            return Err(Socks5Error::ConnectFailed(e.into()));
        }
    };

    let stream_id = proxy_stream.id();
    tracing::info!("connected to {} via stream {:?}", target, proxy_stream);

    // Send success reply
    let mut client = connect
        .reply(Reply::Succeeded, Address::unspecified())
        .await
        .map_err(|(e, _)| e)?;

    // Relay data bidirectionally
    let result = proxy_stream
        .relay_bidirectional(&mut client)
        .await
        .map_err(|e| Socks5Error::IoError(std::io::Error::other(e)));

    tracing::debug!("stream {}: relay completed", stream_id);
    result
}

/// Handle UDP ASSOCIATE command.
async fn handle_udp_associate(
    associate: socks5_server::Associate<socks5_server::connection::associate::state::NeedReply>,
    in_node: Arc<InNode>,
    server_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Bind UDP relay socket
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let relay_socket = UdpSocket::bind(bind_addr).await?;
    let relay_local_addr = relay_socket.local_addr()?;

    tracing::info!("UDP relay socket bound to {}", relay_local_addr);

    // Build reply address (use server IP with relay port)
    let reply_ip = if server_addr.ip().is_loopback() {
        if server_addr.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
    } else {
        server_addr.ip()
    };
    let reply_addr = SocketAddr::new(reply_ip, relay_local_addr.port());

    tracing::info!("UDP ASSOCIATE: relay address {} sent to client", reply_addr);

    // Send success reply with relay address
    let mut associate = associate
        .reply(Reply::Succeeded, Address::SocketAddress(reply_addr))
        .await
        .map_err(|(e, _)| e)?;

    // Wrap relay socket with SOCKS5 UDP handling
    let associated_socket = AssociatedUdpSocket::new(relay_socket, 65535);

    // Spawn UDP relay task
    let relay_task = tokio::spawn(async move {
        if let Err(e) = run_udp_relay(associated_socket, in_node).await {
            tracing::error!("UDP relay error: {}", e);
        }
    });

    // Wait for TCP control connection to close
    if let Err(e) = associate.wait_close().await {
        tracing::debug!("TCP control connection closed: {}", e);
    }

    tracing::info!("UDP ASSOCIATE: TCP control connection closed, stopping relay");
    relay_task.abort();

    Ok(())
}

/// Run the UDP relay between SOCKS5 client and tunnel.
async fn run_udp_relay(
    socket: AssociatedUdpSocket,
    in_node: Arc<InNode>,
) -> Result<(), Socks5Error> {
    // Open tunnel stream for UDP forwarding
    let tunnel_stream = match in_node.open_udp_forward().await {
        Ok(stream) => Arc::new(stream),
        Err(e) => {
            tracing::error!("failed to open UDP tunnel stream: {}", e);
            return Err(Socks5Error::ConnectFailed(e.into()));
        }
    };

    tracing::info!(
        "UDP tunnel stream {} opened for forwarding",
        tunnel_stream.id()
    );

    let socket = Arc::new(socket);

    // Channel to signal tunnel data availability
    let (tunnel_data_tx, mut tunnel_data_rx) = mpsc::channel::<Datagram>(256);

    // Task: Poll tunnel for incoming data and send to channel
    let tunnel_recv = Arc::clone(&tunnel_stream);
    let stream_id = tunnel_stream.id();
    let tunnel_poll_task = tokio::spawn(async move {
        tracing::info!("UDP tunnel poll task started for stream {}", stream_id);
        let mut len_buf = [0u8; 4];
        loop {
            // Read length prefix
            if read_exact_from_stream(&tunnel_recv, &mut len_buf)
                .await
                .is_err()
            {
                tracing::debug!("UDP tunnel: failed to read length prefix");
                break;
            }

            let datagram_len = u32::from_be_bytes(len_buf) as usize;
            if datagram_len == 0 || datagram_len > 65535 {
                tracing::error!("invalid UDP datagram length: {}", datagram_len);
                break;
            }

            tracing::info!(
                "📥 UDP tunnel: received length prefix, expecting {} bytes",
                datagram_len
            );

            // Read datagram data
            let mut datagram_buf = vec![0u8; datagram_len];
            if read_exact_from_stream(&tunnel_recv, &mut datagram_buf)
                .await
                .is_err()
            {
                tracing::debug!("UDP tunnel: failed to read datagram data");
                break;
            }

            // Deserialize and send to channel
            match Datagram::deserialize(Bytes::from(datagram_buf)) {
                Ok(datagram) => {
                    tracing::info!(
                        "📥 UDP tunnel: received datagram {} -> {} ({} bytes)",
                        datagram.source,
                        datagram.dest,
                        datagram.data.len()
                    );
                    if tunnel_data_tx.send(datagram).await.is_err() {
                        tracing::debug!("UDP tunnel: channel closed");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("failed to deserialize UDP datagram: {}", e);
                }
            }
        }
        tracing::info!("UDP tunnel poll task ended");
    });

    // Main loop: handle both directions
    let tunnel_send = Arc::clone(&tunnel_stream);
    let socket_send = Arc::clone(&socket);
    let socket_recv = socket;

    tracing::info!("UDP relay: starting main loop");

    loop {
        tokio::select! {
            // Client -> Tunnel
            result = socket_recv.recv_from() => {
                match result {
                    Ok((data, header, client_addr)) => {
                        let dest_addr = match header.address {
                            Address::SocketAddress(addr) => addr,
                            Address::DomainAddress(domain, port) => {
                                let domain_str = String::from_utf8_lossy(&domain);
                                tracing::warn!(
                                    "UDP domain addresses not supported: {}:{}",
                                    domain_str,
                                    port
                                );
                                continue;
                            }
                        };

                        tracing::info!(
                            "📤 UDP SOCKS5: {} -> {} ({} bytes)",
                            client_addr,
                            dest_addr,
                            data.len()
                        );

                        // Serialize datagram for tunnel transport
                        let datagram = Datagram::new(client_addr, dest_addr, data);
                        let serialized = datagram.serialize();
                        let len_bytes = (serialized.len() as u32).to_be_bytes();

                        if tunnel_send.send(&len_bytes).await.is_err() {
                            tracing::error!("UDP: failed to send length to tunnel");
                            break;
                        }
                        if tunnel_send.send(&serialized).await.is_err() {
                            tracing::error!("UDP: failed to send data to tunnel");
                            break;
                        }
                        tracing::info!("📤 UDP SOCKS5: sent {} bytes to tunnel", serialized.len());
                    }
                    Err((e, _)) => {
                        tracing::error!("UDP recv error: {:?}", e);
                        break;
                    }
                }
            }

            // Tunnel -> Client (from channel)
            Some(response) = tunnel_data_rx.recv() => {
                tracing::info!(
                    "📥 UDP SOCKS5: {} <- {} ({} bytes)",
                    response.dest,
                    response.source,
                    response.data.len()
                );

                let header = socks5_server::proto::UdpHeader {
                    frag: 0,
                    address: Address::SocketAddress(response.source),
                };

                if let Err(e) = socket_send
                    .send_to(&response.data, &header, response.dest)
                    .await
                {
                    tracing::warn!(
                        "failed to send UDP response to {}: {}",
                        response.dest,
                        e
                    );
                }
            }

            else => break,
        }
    }

    tunnel_poll_task.abort();

    // Close tunnel stream with FIN to properly return stream credits
    let _ = tunnel_stream.close().await;
    tracing::debug!("UDP relay: tunnel stream closed");

    Ok(())
}

/// Read exactly `buf.len()` bytes from a tunnel stream.
async fn read_exact_from_stream(stream: &Stream, buf: &mut [u8]) -> Result<(), ()> {
    let mut offset = 0;
    let len = buf.len();

    while offset < len {
        match stream.recv_wait(&mut buf[offset..]).await {
            Ok((0, true)) | Err(_) => {
                return Err(());
            }
            Ok((n, _)) => {
                offset += n;
            }
        }
    }

    Ok(())
}

/// Convert socks5_server Address to string target.
fn address_to_string(addr: &Address) -> String {
    match addr {
        Address::SocketAddress(addr) => addr.to_string(),
        Address::DomainAddress(domain, port) => {
            let domain_str = String::from_utf8_lossy(domain);
            format!("{}:{}", domain_str, port)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("SOCKS5 protocol error: {0}")]
    ProtocolError(#[from] socks5_server::proto::Error),

    #[error("unsupported SOCKS5 command")]
    UnsupportedCommand,

    #[error("connection failed: {0}")]
    ConnectFailed(Box<dyn std::error::Error + Send + Sync>),

    #[error("relay error: {0}")]
    RelayError(Box<dyn std::error::Error + Send + Sync>),
}
