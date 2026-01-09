//! Unified UDP relay logic for both SOCKS5 and TPROXY.
//!
//! This module provides a common abstraction for UDP relaying through either
//! tunnel streams or direct sockets. The only difference between SOCKS5 and
//! TPROXY is how they accept packets from clients - this is abstracted via
//! the `ClientSocket` trait.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

use crate::tunnel::Stream;
use crate::udp_proxy::{Datagram, NatMappingTable};

/// Abstraction over client-facing UDP sockets.
///
/// Different protocols (SOCKS5, TPROXY) have different ways of receiving
/// datagrams from clients and sending responses back. This trait provides
/// a unified interface for the relay logic.
#[async_trait::async_trait]
pub trait UdpClientSocket: Send + Sync + 'static {
    /// Receive a datagram from a client.
    ///
    /// Returns:
    /// - `source`: The client's address (where to send responses)
    /// - `dest`: The destination address (where the client wants to send)
    /// - `data`: The datagram payload
    async fn recv(&self, buf: &mut [u8]) -> Result<UdpClientDatagram, UdpRelayError>;

    /// Send a response datagram to a client.
    ///
    /// - `data`: The response payload
    /// - `from`: The address the response appears to come from (original destination)
    /// - `to`: The client address to send to
    async fn send(
        &self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), UdpRelayError>;
}

/// A datagram received from a client.
#[derive(Debug)]
pub struct UdpClientDatagram {
    /// The client's source address (for sending responses).
    pub source: SocketAddr,
    /// The destination the client wants to reach.
    pub dest: SocketAddr,
    /// The datagram payload.
    pub data: Vec<u8>,
}

impl UdpClientDatagram {
    pub fn new(source: SocketAddr, dest: SocketAddr, data: Vec<u8>) -> Self {
        Self { source, dest, data }
    }
}

/// Handler for direct UDP forwarding (bypasses tunnel).
///
/// This is shared between SOCKS5, TPROXY, and potentially other protocols.
pub struct DirectUdpForwarder {
    socket: Arc<tokio::net::UdpSocket>,
    mappings: NatMappingTable,
    /// Reverse index: external_addr -> client_addr
    reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
}

impl DirectUdpForwarder {
    /// Create a new direct forwarder with the given socket.
    pub fn new(socket: Arc<tokio::net::UdpSocket>) -> Self {
        Self {
            socket,
            mappings: NatMappingTable::default(),
            reverse_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Send a datagram to its destination.
    pub async fn send(&self, datagram: Datagram) -> Result<(), UdpRelayError> {
        // Create/refresh NAT mapping
        let _port = self
            .mappings
            .get_or_create(datagram.source, datagram.dest)
            .await
            .ok_or(UdpRelayError::NatExhausted)?;

        // Update reverse index for response routing
        {
            let mut index = self.reverse_index.write().await;
            index.insert(datagram.dest, datagram.source);
        }

        self.socket
            .send_to(&datagram.data, datagram.dest)
            .await
            .map_err(UdpRelayError::Io)?;

        Ok(())
    }

    /// Receive a response datagram.
    pub async fn recv(&self) -> Result<Datagram, UdpRelayError> {
        let mut buf = vec![0u8; 65535];
        let (len, src) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(UdpRelayError::Io)?;

        // Look up the original client
        let client_addr = {
            let index = self.reverse_index.read().await;
            index.get(&src).copied()
        };

        let dest = client_addr.unwrap_or(src);

        Ok(Datagram::new(src, dest, Bytes::copy_from_slice(&buf[..len])))
    }
}

/// Configuration for UDP relay logging.
#[derive(Debug, Clone, Copy)]
pub struct UdpRelayLogConfig {
    /// Log new sessions at debug level.
    pub log_sessions: bool,
    /// Log per-packet at trace level.
    pub log_packets: bool,
    /// Prefix for log messages.
    pub prefix: &'static str,
}

impl Default for UdpRelayLogConfig {
    fn default() -> Self {
        Self {
            log_sessions: true,
            log_packets: true,
            prefix: "UDP",
        }
    }
}

impl UdpRelayLogConfig {
    pub fn with_prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }
}

/// Session tracker for UDP relay.
///
/// Tracks active sessions and provides unified logging.
pub struct SessionTracker {
    /// Maps dest -> source (for routing responses back)
    sessions: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
    log_config: UdpRelayLogConfig,
}

impl SessionTracker {
    pub fn new(log_config: UdpRelayLogConfig) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            log_config,
        }
    }

    /// Track a new session or refresh existing one.
    /// Returns true if this is a new session.
    pub async fn track(&self, source: SocketAddr, dest: SocketAddr) -> bool {
        let mut sessions = self.sessions.write().await;
        let is_new = !sessions.contains_key(&dest);
        sessions.insert(dest, source);

        if is_new && self.log_config.log_sessions {
            tracing::debug!("{} session: {} -> {}", self.log_config.prefix, source, dest);
        }
        is_new
    }

    /// Look up the client address for a response.
    pub async fn lookup(&self, dest: &SocketAddr) -> Option<SocketAddr> {
        let sessions = self.sessions.read().await;
        sessions.get(dest).copied()
    }

    /// Log an outbound packet (client -> dest).
    pub fn log_send(&self, source: SocketAddr, dest: SocketAddr, len: usize) {
        if self.log_config.log_packets {
            tracing::trace!(
                "{} send: {} -> {} ({} bytes)",
                self.log_config.prefix,
                source,
                dest,
                len
            );
        }
    }

    /// Log an inbound packet (dest -> client).
    pub fn log_recv(&self, client: SocketAddr, from: SocketAddr, len: usize) {
        if self.log_config.log_packets {
            tracing::trace!(
                "{} recv: {} <- {} ({} bytes)",
                self.log_config.prefix,
                client,
                from,
                len
            );
        }
    }

    /// Get inner sessions map for cloning in tasks.
    pub fn sessions(&self) -> Arc<RwLock<HashMap<SocketAddr, SocketAddr>>> {
        Arc::clone(&self.sessions)
    }
}

/// Run UDP relay between a client socket and a tunnel stream.
pub async fn relay_udp_tunnel<S: UdpClientSocket>(
    client_socket: Arc<S>,
    tunnel_stream: Arc<Stream>,
    log_config: UdpRelayLogConfig,
) -> Result<(), UdpRelayError> {
    let tracker = SessionTracker::new(log_config);

    // Channel for receiving datagrams from tunnel
    let (tunnel_data_tx, mut tunnel_data_rx) = mpsc::channel::<Datagram>(256);

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
                tracing::trace!("UDP tunnel: connection closed");
                break;
            }

            let datagram_len = u32::from_be_bytes(len_buf) as usize;
            if datagram_len == 0 || datagram_len > 65535 {
                tracing::error!("UDP relay: invalid datagram length: {}", datagram_len);
                break;
            }

            // Read datagram data
            let mut datagram_buf = vec![0u8; datagram_len];
            if read_exact_from_stream(&tunnel_recv, &mut datagram_buf)
                .await
                .is_err()
            {
                tracing::trace!("UDP tunnel: connection closed while reading data");
                break;
            }

            // Deserialize and send to channel
            match Datagram::deserialize(Bytes::from(datagram_buf)) {
                Ok(datagram) => {
                    if tunnel_data_tx.send(datagram).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("UDP relay: failed to deserialize datagram: {}", e);
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];

    loop {
        tokio::select! {
            // Client -> Tunnel
            result = client_socket.recv(&mut buf) => {
                match result {
                    Ok(datagram) => {
                        let is_new = tracker.track(datagram.source, datagram.dest).await;
                        if !is_new {
                            tracker.log_send(datagram.source, datagram.dest, datagram.data.len());
                        }

                        // Create and serialize datagram
                        let dgram = Datagram::new(datagram.source, datagram.dest, Bytes::from(datagram.data));
                        let serialized = dgram.serialize();

                        // Write length prefix + data
                        let len_bytes = (serialized.len() as u32).to_be_bytes();
                        if tunnel_stream.send(&len_bytes).await.is_err() {
                            tracing::debug!("UDP relay: tunnel send failed");
                            break;
                        }
                        if tunnel_stream.send(&serialized).await.is_err() {
                            tracing::debug!("UDP relay: tunnel send failed");
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("UDP relay: client recv error: {}", e);
                        break;
                    }
                }
            }

            // Tunnel -> Client
            Some(datagram) = tunnel_data_rx.recv() => {
                // Look up original client for this response
                if let Some(client) = tracker.lookup(&datagram.source).await {
                    tracker.log_recv(client, datagram.source, datagram.data.len());

                    if let Err(e) = client_socket.send(&datagram.data, datagram.source, client).await {
                        tracing::trace!("UDP relay: send_from error: {}", e);
                    }
                } else {
                    tracing::trace!("UDP relay: no session for response from {}", datagram.source);
                }
            }
        }
    }

    tunnel_poll_task.abort();
    Ok(())
}

/// Run UDP relay between a client socket and a direct forwarder.
pub async fn relay_udp_direct<S: UdpClientSocket>(
    client_socket: Arc<S>,
    forwarder: Arc<DirectUdpForwarder>,
    log_config: UdpRelayLogConfig,
) -> Result<(), UdpRelayError> {
    let tracker = SessionTracker::new(log_config);
    let tracker_clone = SessionTracker {
        sessions: tracker.sessions(),
        log_config,
    };
    let socket_clone = Arc::clone(&client_socket);
    let forwarder_clone = Arc::clone(&forwarder);

    // Task: Receive from forwarder and send to clients
    let recv_task = tokio::spawn(async move {
        loop {
            match forwarder_clone.recv().await {
                Ok(datagram) => {
                    // Look up original client
                    if let Some(client) = tracker_clone.lookup(&datagram.source).await {
                        tracker_clone.log_recv(client, datagram.source, datagram.data.len());

                        if let Err(e) =
                            socket_clone.send(&datagram.data, datagram.source, client).await
                        {
                            tracing::trace!("UDP relay: send_from error: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("UDP relay: direct recv error: {}", e);
                    break;
                }
            }
        }
    });

    let mut buf = vec![0u8; 65535];

    loop {
        match client_socket.recv(&mut buf).await {
            Ok(datagram) => {
                let is_new = tracker.track(datagram.source, datagram.dest).await;
                if !is_new {
                    tracker.log_send(datagram.source, datagram.dest, datagram.data.len());
                }

                // Send via direct forwarder
                let dgram = Datagram::new(datagram.source, datagram.dest, Bytes::from(datagram.data));
                if let Err(e) = forwarder.send(dgram).await {
                    tracing::error!("UDP relay: direct send error: {}", e);
                    break;
                }
            }
            Err(e) => {
                tracing::error!("UDP relay: client recv error: {}", e);
                break;
            }
        }
    }

    recv_task.abort();
    Ok(())
}

/// Read exact bytes from a tunnel stream.
async fn read_exact_from_stream(stream: &Stream, buf: &mut [u8]) -> Result<(), UdpRelayError> {
    let mut filled = 0;
    while filled < buf.len() {
        let (n, _fin) = stream
            .recv_wait(&mut buf[filled..])
            .await
            .map_err(|e| UdpRelayError::Tunnel(e.to_string()))?;
        if n == 0 {
            return Err(UdpRelayError::Tunnel("stream closed".to_string()));
        }
        filled += n;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum UdpRelayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tunnel error: {0}")]
    Tunnel(String),
    #[error("NAT port range exhausted")]
    NatExhausted,
    #[error("protocol error: {0}")]
    Protocol(String),
}
