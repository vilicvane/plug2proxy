use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;

use super::{ChannelReceiver, ChannelSender, Datagram, NatMappingTable};

/// Default cleanup interval for expired NAT mappings.
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// The outbound side of the DNS transparent proxy.
///
/// Responsibilities:
/// - Receive queries from the channel (sent by inbound).
/// - Maintain NAT mappings for full-cone semantics.
/// - Forward queries to actual DNS servers.
/// - Receive responses and route them back through the channel.
pub struct Outbound {
    /// The UDP socket for sending queries to external servers.
    socket: Arc<UdpSocket>,
    /// Channel receiver for getting queries from inbound.
    channel_rx: ChannelReceiver,
    /// Channel sender for sending responses back to inbound.
    channel_tx: ChannelSender,
    /// NAT mapping table for tracking client addresses.
    mappings: NatMappingTable,
}

impl Outbound {
    /// Create a new outbound handler.
    ///
    /// # Arguments
    /// - `socket`: The UDP socket to send queries from.
    /// - `channel_rx`: Receiver to get queries from the inbound side.
    /// - `channel_tx`: Sender to return responses to the inbound side.
    /// - `mappings`: NAT mapping table for full-cone semantics.
    pub fn new(
        socket: UdpSocket,
        channel_rx: ChannelReceiver,
        channel_tx: ChannelSender,
        mappings: NatMappingTable,
    ) -> Self {
        Self {
            socket: Arc::new(socket),
            channel_rx,
            channel_tx,
            mappings,
        }
    }

    /// Bind to any available address and create an outbound handler.
    pub async fn bind(
        channel_rx: ChannelReceiver,
        channel_tx: ChannelSender,
        mappings: NatMappingTable,
    ) -> Result<Self, OutboundError> {
        // Bind to any available address (0.0.0.0:0)
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let local_addr = socket.local_addr()?;
        tracing::info!(addr = %local_addr, "outbound socket bound");
        Ok(Self::new(socket, channel_rx, channel_tx, mappings))
    }

    /// Bind to a specific address.
    pub async fn bind_addr(
        addr: SocketAddr,
        channel_rx: ChannelReceiver,
        channel_tx: ChannelSender,
        mappings: NatMappingTable,
    ) -> Result<Self, OutboundError> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(addr = %addr, "outbound socket bound");
        Ok(Self::new(socket, channel_rx, channel_tx, mappings))
    }

    /// Get the local address this outbound is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, OutboundError> {
        self.socket.local_addr().map_err(OutboundError::from)
    }

    /// Run the outbound handler.
    ///
    /// This spawns tasks for:
    /// - Receiving queries from the channel and forwarding to DNS servers.
    /// - Receiving responses from DNS servers and routing back to inbound.
    /// - Periodically cleaning up expired NAT mappings.
    pub async fn run(self) -> Result<(), OutboundError> {
        let socket = self.socket;
        let channel_rx = self.channel_rx;
        let channel_tx = self.channel_tx;
        let mappings = self.mappings;

        let recv_socket = Arc::clone(&socket);
        let send_socket = socket;
        let recv_mappings = mappings.clone();
        let send_mappings = mappings.clone();
        let cleanup_mappings = mappings;

        // Task: receive from channel, forward to DNS servers
        let forward_task = tokio::spawn(async move {
            Self::run_forward_loop(recv_socket, channel_rx, recv_mappings).await
        });

        // Task: receive from DNS servers, send back to channel
        let response_task = tokio::spawn(async move {
            Self::run_response_loop(send_socket, channel_tx, send_mappings).await
        });

        // Task: periodic cleanup of expired mappings
        let cleanup_task = tokio::spawn(async move {
            Self::run_cleanup_loop(cleanup_mappings).await
        });

        tokio::select! {
            result = forward_task => {
                result.map_err(|e| OutboundError::TaskPanic(e.to_string()))??;
            }
            result = response_task => {
                result.map_err(|e| OutboundError::TaskPanic(e.to_string()))??;
            }
            _ = cleanup_task => {}
        }

        Ok(())
    }

    /// Split into separate forwarder and responder handles.
    pub fn split(self) -> (OutboundForwarder, OutboundResponder) {
        let socket = self.socket;
        let mappings = self.mappings;
        (
            OutboundForwarder {
                socket: Arc::clone(&socket),
                channel_rx: self.channel_rx,
                mappings: mappings.clone(),
            },
            OutboundResponder {
                socket,
                channel_tx: self.channel_tx,
                mappings,
            },
        )
    }

    async fn run_forward_loop(
        socket: Arc<UdpSocket>,
        mut channel_rx: ChannelReceiver,
        mappings: NatMappingTable,
    ) -> Result<(), OutboundError> {
        while let Some(datagram) = channel_rx.recv().await {
            // Create or get NAT mapping for this client
            let Some(_port) = mappings.get_or_create(datagram.source, datagram.dest).await else {
                tracing::warn!(
                    src = %datagram.source,
                    dest = %datagram.dest,
                    "failed to allocate NAT mapping"
                );
                continue;
            };

            tracing::trace!(
                src = %datagram.source,
                dest = %datagram.dest,
                len = datagram.data.len(),
                "outbound forwarding query"
            );

            // Forward to the actual DNS server
            if let Err(e) = socket.send_to(&datagram.data, datagram.dest).await {
                tracing::warn!(
                    dest = %datagram.dest,
                    error = %e,
                    "failed to forward query to DNS server"
                );
            }
        }

        Ok(())
    }

    async fn run_response_loop(
        socket: Arc<UdpSocket>,
        channel_tx: ChannelSender,
        mappings: NatMappingTable,
    ) -> Result<(), OutboundError> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;

            // In full-cone NAT, we need to determine which client this response is for.
            // For DNS, we typically use a simpler approach: the DNS transaction ID in
            // the payload. However, for a generic full-cone implementation, we'd need
            // to track by (external_port, dest_addr) or just external_port.
            //
            // For simplicity here, we assume responses come from the same server we
            // sent to, so we find the mapping by looking at recent mappings that sent
            // to this server.
            //
            // A more complete implementation would parse the DNS transaction ID.

            // For now, find mappings that have this server as original_dest
            // This is a simplified approach - a full implementation would need
            // better correlation (e.g., DNS transaction ID tracking)

            // Since we're doing full-cone, we need to find the client.
            // Let's iterate through mappings to find one that matches.
            // This is O(n) but mapping tables are typically small for DNS.

            let mapping = find_mapping_for_response(&mappings, src).await;

            if let Some(mapping) = mapping {
                let response = Datagram::new(
                    src,
                    mapping.internal_addr,
                    Bytes::copy_from_slice(&buf[..len]),
                );

                tracing::trace!(
                    src = %src,
                    client = %mapping.internal_addr,
                    len,
                    "outbound received response"
                );

                if let Err(e) = channel_tx.send(response).await {
                    tracing::warn!(error = %e, "failed to send response to channel");
                }
            } else {
                tracing::debug!(
                    src = %src,
                    len,
                    "received response with no matching mapping"
                );
            }
        }
    }

    async fn run_cleanup_loop(mappings: NatMappingTable) {
        let mut interval = tokio::time::interval(DEFAULT_CLEANUP_INTERVAL);

        loop {
            interval.tick().await;
            mappings.cleanup_expired().await;
        }
    }
}

/// Find a NAT mapping that corresponds to a response from the given server.
///
/// This is a simplified implementation. For better accuracy, you would:
/// - Parse the DNS transaction ID and maintain a mapping by transaction ID.
/// - Or track by (local_port, remote_addr) tuple.
async fn find_mapping_for_response(
    mappings: &NatMappingTable,
    server_addr: SocketAddr,
) -> Option<super::NatMapping> {
    // This is a limitation of the current simple design.
    // We iterate through port mappings to find one that matches.
    // A production implementation would have a reverse index.

    // For DNS proxy specifically, we often have one client sending to one server,
    // or we'd track by transaction ID. Here we do a simple match by original_dest.

    // Note: This works correctly when there's one active query per client,
    // which is common for DNS.

    let port_range = (49152u16, 65535u16);
    for port in port_range.0..=port_range.1 {
        if let Some(mapping) = mappings.lookup_by_port(port).await {
            // Check if this mapping was for querying this server
            // In full-cone NAT, any server can respond, but for DNS we typically
            // expect responses from the same server we queried
            if mapping.original_dest == server_addr
                || mapping.original_dest.ip() == server_addr.ip()
            {
                mappings.touch(port).await;
                return Some(mapping);
            }
        }
    }

    None
}

/// The forwarding half of an outbound handler.
///
/// Receives queries from the channel and forwards them to DNS servers.
pub struct OutboundForwarder {
    socket: Arc<UdpSocket>,
    channel_rx: ChannelReceiver,
    mappings: NatMappingTable,
}

impl OutboundForwarder {
    /// Run the forward loop.
    pub async fn run(self) -> Result<(), OutboundError> {
        Outbound::run_forward_loop(self.socket, self.channel_rx, self.mappings).await
    }

    /// Receive the next query from the channel.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.channel_rx.recv().await
    }

    /// Forward a datagram to an external server.
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, OutboundError> {
        self.socket.send_to(data, addr).await.map_err(OutboundError::from)
    }

    /// Get or create a NAT mapping.
    pub async fn get_or_create_mapping(
        &self,
        internal_addr: SocketAddr,
        dest: SocketAddr,
    ) -> Option<u16> {
        self.mappings.get_or_create(internal_addr, dest).await
    }
}

/// The responding half of an outbound handler.
///
/// Receives responses from DNS servers and sends them back through the channel.
pub struct OutboundResponder {
    socket: Arc<UdpSocket>,
    channel_tx: ChannelSender,
    mappings: NatMappingTable,
}

impl OutboundResponder {
    /// Run the response loop.
    pub async fn run(self) -> Result<(), OutboundError> {
        Outbound::run_response_loop(self.socket, self.channel_tx, self.mappings).await
    }

    /// Receive from the external socket.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), OutboundError> {
        let (len, src) = self.socket.recv_from(buf).await?;
        Ok((len, src))
    }

    /// Send a response through the channel.
    pub async fn send(&self, datagram: Datagram) -> Result<(), OutboundError> {
        self.channel_tx
            .send(datagram)
            .await
            .map_err(|e| OutboundError::Channel(e.to_string()))
    }

    /// Look up a NAT mapping by port.
    pub async fn lookup_mapping(&self, port: u16) -> Option<super::NatMapping> {
        self.mappings.lookup_by_port(port).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("task panic: {0}")]
    TaskPanic(String),
}
