//! TPROXY server for transparent proxying (TCP and UDP).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::fake_ip::FakeIpResolver;
use crate::node::{DirectUdpHandler, InNode, UdpForwardHandler};
use crate::tunnel::Stream;
use crate::udp_proxy::Datagram;

use super::tcp::{TProxyTcpListener, TProxyTcpStream};
use super::udp::TProxyUdpSocket;

/// TPROXY server that handles transparently proxied connections.
pub struct TProxyServer {
    in_node: Arc<InNode>,
    listen_addr: SocketAddr,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
}

impl TProxyServer {
    /// Create a new TPROXY server.
    pub fn new(in_node: Arc<InNode>, listen_addr: SocketAddr) -> Self {
        Self {
            in_node,
            listen_addr,
            fake_ip_resolver: None,
        }
    }

    /// Set the fake IP resolver for translating fake IPs back to hostnames.
    pub fn with_fake_ip_resolver(mut self, resolver: Arc<FakeIpResolver>) -> Self {
        self.fake_ip_resolver = Some(resolver);
        self
    }

    /// Run the TPROXY server (TCP and UDP).
    pub async fn run(&self) -> Result<(), TProxyServerError> {
        let mark = self.in_node.mark();

        // Start TCP listener
        let tcp_listener = TProxyTcpListener::bind(self.listen_addr, mark).await?;
        tracing::info!("TPROXY TCP server listening on {}", self.listen_addr);

        // Start UDP listener
        let udp_socket = TProxyUdpSocket::bind(self.listen_addr, mark).await?;
        tracing::info!("TPROXY UDP server listening on {}", self.listen_addr);

        let in_node_tcp = Arc::clone(&self.in_node);
        let fake_ip_resolver_tcp = self.fake_ip_resolver.clone();

        let in_node_udp = Arc::clone(&self.in_node);
        let fake_ip_resolver_udp = self.fake_ip_resolver.clone();

        // Run TCP and UDP handlers concurrently
        tokio::select! {
            result = Self::run_tcp_loop(tcp_listener, in_node_tcp, fake_ip_resolver_tcp) => {
                result?;
            }
            result = Self::run_udp_loop(udp_socket, in_node_udp, fake_ip_resolver_udp) => {
                result?;
            }
        }

        Ok(())
    }

    /// TCP accept loop.
    async fn run_tcp_loop(
        listener: TProxyTcpListener,
        in_node: Arc<InNode>,
        fake_ip_resolver: Option<Arc<FakeIpResolver>>,
    ) -> Result<(), TProxyServerError> {
        loop {
            match listener.accept().await {
                Ok(conn) => {
                    let in_node = Arc::clone(&in_node);
                    let fake_ip_resolver = fake_ip_resolver.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(conn, in_node, fake_ip_resolver).await
                        {
                            tracing::debug!("TPROXY TCP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("TPROXY TCP accept error: {}", e);
                }
            }
        }
    }

    /// UDP receive loop.
    async fn run_udp_loop(
        socket: TProxyUdpSocket,
        in_node: Arc<InNode>,
        fake_ip_resolver: Option<Arc<FakeIpResolver>>,
    ) -> Result<(), TProxyServerError> {
        let socket = Arc::new(socket);

        // Open UDP forwarder once - it's shared across all sessions
        let udp_handler = in_node
            .open_udp_forward()
            .await
            .map_err(|e| TProxyServerError::Connect(e.to_string()))?;

        match udp_handler {
            UdpForwardHandler::Tunnel(tunnel_stream) => {
                tracing::info!(
                    "TPROXY UDP using tunnel stream {} for forwarding",
                    tunnel_stream.id()
                );
                run_udp_tunnel_relay(socket, Arc::new(tunnel_stream), fake_ip_resolver).await
            }
            UdpForwardHandler::Direct(direct_handler) => {
                tracing::info!("TPROXY UDP using direct handler for forwarding");
                run_udp_direct_relay(socket, Arc::new(direct_handler), fake_ip_resolver).await
            }
        }
    }
}

/// Handle a single TPROXY TCP connection.
async fn handle_tcp_connection(
    mut conn: TProxyTcpStream,
    in_node: Arc<InNode>,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
) -> Result<(), TProxyServerError> {
    let original_dst = conn.original_dst;
    let source = conn.source;

    // Resolve fake IP to hostname if available
    let target = resolve_target(&fake_ip_resolver, original_dst);

    tracing::debug!(
        "TPROXY TCP: {} -> {} (target: {})",
        source,
        original_dst,
        target
    );

    // Connect through the tunnel
    let mut proxy_stream = in_node
        .connect(&target)
        .await
        .map_err(|e| TProxyServerError::Connect(e.to_string()))?;

    // Relay data between client and proxy
    proxy_stream
        .relay_bidirectional(&mut conn.stream)
        .await
        .map_err(|e| TProxyServerError::Relay(e.to_string()))?;

    Ok(())
}

/// Resolve the target address, translating fake IPs to hostnames if possible.
fn resolve_target(
    fake_ip_resolver: &Option<Arc<FakeIpResolver>>,
    original_dst: SocketAddr,
) -> String {
    if let Some(resolver) = fake_ip_resolver {
        if let Some((_, Some(hostname))) = resolver.resolve(&original_dst.ip()) {
            return format!("{}:{}", hostname, original_dst.port());
        }
    }
    original_dst.to_string()
}

/// Resolve destination address for UDP, translating fake IPs to hostnames.
fn resolve_dest(
    fake_ip_resolver: &Option<Arc<FakeIpResolver>>,
    original_dst: SocketAddr,
) -> SocketAddr {
    if let Some(resolver) = fake_ip_resolver {
        if let Some((real_ip, _)) = resolver.resolve(&original_dst.ip()) {
            return SocketAddr::new(real_ip, original_dst.port());
        }
    }
    original_dst
}

/// Run UDP relay through tunnel.
async fn run_udp_tunnel_relay(
    socket: Arc<TProxyUdpSocket>,
    tunnel_stream: Arc<Stream>,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
) -> Result<(), TProxyServerError> {
    // Channel to signal tunnel data availability
    let (tunnel_data_tx, mut tunnel_data_rx) = mpsc::channel::<Datagram>(256);

    // Session mapping: original_dst -> source (for responses)
    let sessions: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Task: Poll tunnel for incoming data
    let tunnel_recv = Arc::clone(&tunnel_stream);
    let tunnel_poll_task = tokio::spawn(async move {
        let mut len_buf = [0u8; 4];
        loop {
            // Read length prefix
            if read_exact_from_stream(&tunnel_recv, &mut len_buf)
                .await
                .is_err()
            {
                tracing::debug!("TPROXY UDP tunnel: failed to read length prefix");
                break;
            }

            let datagram_len = u32::from_be_bytes(len_buf) as usize;
            if datagram_len == 0 || datagram_len > 65535 {
                tracing::error!("TPROXY UDP: invalid datagram length: {}", datagram_len);
                break;
            }

            // Read datagram data
            let mut datagram_buf = vec![0u8; datagram_len];
            if read_exact_from_stream(&tunnel_recv, &mut datagram_buf)
                .await
                .is_err()
            {
                tracing::debug!("TPROXY UDP tunnel: failed to read datagram data");
                break;
            }

            // Deserialize and send to channel
            match Datagram::deserialize(Bytes::from(datagram_buf)) {
                Ok(datagram) => {
                    tracing::debug!(
                        "TPROXY UDP tunnel recv: {} <- {} ({} bytes)",
                        datagram.dest,
                        datagram.source,
                        datagram.data.len()
                    );
                    if tunnel_data_tx.send(datagram).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("TPROXY UDP: failed to deserialize datagram: {}", e);
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // Client -> Tunnel
            result = socket.recv(&mut buf) => {
                match result {
                    Ok(datagram) => {
                        let dest = resolve_dest(&fake_ip_resolver, datagram.original_dst);

                        tracing::debug!(
                            "TPROXY UDP send: {} -> {} ({} bytes)",
                            datagram.source,
                            dest,
                            datagram.data.len()
                        );

                        // Remember session for responses
                        {
                            let mut sessions_write = sessions.write().await;
                            sessions_write.insert(dest, datagram.source);
                        }

                        // Create datagram and send through tunnel
                        let dgram = Datagram::new(datagram.source, dest, Bytes::from(datagram.data));
                        let serialized = dgram.serialize();

                        // Write length prefix + data
                        let len_bytes = (serialized.len() as u32).to_be_bytes();
                        if tunnel_stream.send(&len_bytes).await.is_err() {
                            tracing::debug!("TPROXY UDP: failed to send length prefix");
                            break;
                        }
                        if tunnel_stream.send(&serialized).await.is_err() {
                            tracing::debug!("TPROXY UDP: failed to send datagram");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("TPROXY UDP recv error: {}", e);
                        break;
                    }
                }
            }

            // Tunnel -> Client
            Some(datagram) = tunnel_data_rx.recv() => {
                // Look up original client for this response
                let client_addr = {
                    let sessions_read = sessions.read().await;
                    sessions_read.get(&datagram.source).copied()
                };

                if let Some(client) = client_addr {
                    // Send response back to client, appearing to come from original destination
                    if let Err(e) = socket.send_from(&datagram.data, datagram.source, client).await {
                        tracing::debug!("TPROXY UDP send_from error: {}", e);
                    }
                } else {
                    tracing::debug!(
                        "TPROXY UDP: no session for response from {}",
                        datagram.source
                    );
                }
            }
        }
    }

    tunnel_poll_task.abort();
    Ok(())
}

/// Run UDP relay directly (bypasses tunnel).
async fn run_udp_direct_relay(
    socket: Arc<TProxyUdpSocket>,
    direct_handler: Arc<DirectUdpHandler>,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
) -> Result<(), TProxyServerError> {
    // Session mapping: dest -> source (for routing responses back)
    let sessions: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let sessions_clone = Arc::clone(&sessions);
    let socket_clone = Arc::clone(&socket);
    let direct_handler_clone = Arc::clone(&direct_handler);

    // Task: Receive from direct handler and forward to clients
    let recv_task = tokio::spawn(async move {
        loop {
            match direct_handler_clone.recv().await {
                Ok(datagram) => {
                    // Look up original client for this response
                    let client_addr = {
                        let sessions_read = sessions_clone.read().await;
                        sessions_read.get(&datagram.source).copied()
                    };

                    if let Some(client) = client_addr {
                        tracing::debug!(
                            "TPROXY UDP direct recv: {} <- {} ({} bytes)",
                            client,
                            datagram.source,
                            datagram.data.len()
                        );
                        if let Err(e) = socket_clone
                            .send_from(&datagram.data, datagram.source, client)
                            .await
                        {
                            tracing::debug!("TPROXY UDP send_from error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("TPROXY UDP direct recv error: {}", e);
                    break;
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];

    loop {
        match socket.recv(&mut buf).await {
            Ok(datagram) => {
                let dest = resolve_dest(&fake_ip_resolver, datagram.original_dst);

                tracing::debug!(
                    "TPROXY UDP direct send: {} -> {} ({} bytes)",
                    datagram.source,
                    dest,
                    datagram.data.len()
                );

                // Remember session for responses
                {
                    let mut sessions_write = sessions.write().await;
                    sessions_write.insert(dest, datagram.source);
                }

                // Send via direct handler
                let dgram = Datagram::new(datagram.source, dest, Bytes::from(datagram.data));
                if let Err(e) = direct_handler.send(dgram).await {
                    tracing::error!("TPROXY UDP direct send error: {}", e);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("TPROXY UDP recv error: {}", e);
                break;
            }
        }
    }

    recv_task.abort();
    Ok(())
}

/// Read exact bytes from a tunnel stream.
async fn read_exact_from_stream(stream: &Stream, buf: &mut [u8]) -> Result<(), TProxyServerError> {
    let mut filled = 0;
    while filled < buf.len() {
        let (n, _fin) = stream
            .recv_wait(&mut buf[filled..])
            .await
            .map_err(|e| TProxyServerError::Relay(e.to_string()))?;
        if n == 0 {
            return Err(TProxyServerError::Relay("stream closed".to_string()));
        }
        filled += n;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum TProxyServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("relay error: {0}")]
    Relay(String),
}
