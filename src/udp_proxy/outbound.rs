use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use super::{ChannelReceiver, ChannelSender, Datagram, NatMappingTable};
use crate::util::set_socket_mark;

/// Default cleanup interval for expired NAT mappings.
const DEFAULT_CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// The outbound side of the full-cone UDP transparent proxy.
///
/// Responsibilities:
/// - Receive datagrams from the channel (sent by inbound).
/// - Maintain NAT mappings for full-cone semantics.
/// - Forward datagrams to external destinations.
/// - Receive responses and route them back through the channel.
pub struct Outbound {
    /// The UDP socket for sending to external servers.
    socket: Arc<UdpSocket>,
    /// Channel receiver for getting datagrams from inbound.
    channel_rx: ChannelReceiver,
    /// Channel sender for sending responses back to inbound.
    channel_tx: ChannelSender,
    /// NAT mapping table for tracking client addresses.
    mappings: NatMappingTable,
    /// Reverse index: remote_addr -> internal_addr for response routing.
    /// This tracks which internal client is communicating with which remote address.
    reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
}

impl Outbound {
    /// Create a new outbound handler.
    ///
    /// # Arguments
    /// - `socket`: The UDP socket to send datagrams from.
    /// - `channel_rx`: Receiver to get datagrams from the inbound side.
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
            reverse_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Bind to any available address and create an outbound handler.
    pub async fn bind(
        channel_rx: ChannelReceiver,
        channel_tx: ChannelSender,
        mappings: NatMappingTable,
        mark: Option<u32>,
    ) -> Result<Self, OutboundError> {
        // Bind to any available address (0.0.0.0:0)
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        // Apply traffic mark if configured
        if let Some(mark) = mark {
            set_socket_mark(&socket, mark)?;
        }

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
        mark: Option<u32>,
    ) -> Result<Self, OutboundError> {
        let socket = UdpSocket::bind(addr).await?;

        // Apply traffic mark if configured
        if let Some(mark) = mark {
            set_socket_mark(&socket, mark)?;
        }

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
    /// - Receiving datagrams from the channel and forwarding to destinations.
    /// - Receiving responses from destinations and routing back to inbound.
    /// - Periodically cleaning up expired NAT mappings.
    pub async fn run(self) -> Result<(), OutboundError> {
        let socket = self.socket;
        let channel_rx = self.channel_rx;
        let channel_tx = self.channel_tx;
        let mappings = self.mappings;
        let reverse_index = self.reverse_index;

        let recv_socket = Arc::clone(&socket);
        let send_socket = socket;
        let recv_mappings = mappings.clone();
        let cleanup_mappings = mappings;
        let forward_reverse_index = Arc::clone(&reverse_index);
        let response_reverse_index = reverse_index;

        // Task: receive from channel, forward to destinations
        let forward_task = tokio::spawn(async move {
            Self::run_forward_loop(
                recv_socket,
                channel_rx,
                recv_mappings,
                forward_reverse_index,
            )
            .await
        });

        // Task: receive from destinations, send back to channel
        let response_task = tokio::spawn(async move {
            Self::run_response_loop(send_socket, channel_tx, response_reverse_index).await
        });

        // Task: periodic cleanup of expired mappings
        let cleanup_task =
            tokio::spawn(async move { Self::run_cleanup_loop(cleanup_mappings).await });

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
        let reverse_index = self.reverse_index;
        (
            OutboundForwarder {
                socket: Arc::clone(&socket),
                channel_rx: self.channel_rx,
                mappings,
                reverse_index: Arc::clone(&reverse_index),
            },
            OutboundResponder {
                socket,
                channel_tx: self.channel_tx,
                reverse_index,
            },
        )
    }

    async fn run_forward_loop(
        socket: Arc<UdpSocket>,
        mut channel_rx: ChannelReceiver,
        mappings: NatMappingTable,
        reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
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

            // Update reverse index for response routing
            {
                let mut index = reverse_index.write().await;
                index.insert(datagram.dest, datagram.source);
            }

            tracing::trace!(
                src = %datagram.source,
                dest = %datagram.dest,
                len = datagram.data.len(),
                "outbound forwarding datagram"
            );

            // Forward to the destination
            if let Err(e) = socket.send_to(&datagram.data, datagram.dest).await {
                tracing::warn!(
                    dest = %datagram.dest,
                    error = %e,
                    "failed to forward datagram"
                );
            }
        }

        Ok(())
    }

    async fn run_response_loop(
        socket: Arc<UdpSocket>,
        channel_tx: ChannelSender,
        reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
    ) -> Result<(), OutboundError> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;

            // Look up which internal client this response is for using the reverse index.
            // In full-cone NAT semantics, we route based on who was communicating with this remote.
            let internal_addr = {
                let index = reverse_index.read().await;
                index.get(&src).copied()
            };

            if let Some(internal_addr) = internal_addr {
                let response =
                    Datagram::new(src, internal_addr, Bytes::copy_from_slice(&buf[..len]));

                tracing::trace!(
                    src = %src,
                    client = %internal_addr,
                    len,
                    "outbound received response"
                );

                if let Err(e) = channel_tx.send(response).await {
                    tracing::warn!(error = %e, "failed to send response to channel");
                }
            } else {
                // In true full-cone NAT, we might still want to accept packets from
                // unknown sources if we have a mapping. For now, log and drop.
                tracing::debug!(
                    src = %src,
                    len,
                    "received datagram from unknown remote (no reverse mapping)"
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

/// The forwarding half of an outbound handler.
///
/// Receives datagrams from the channel and forwards them to destinations.
pub struct OutboundForwarder {
    socket: Arc<UdpSocket>,
    channel_rx: ChannelReceiver,
    mappings: NatMappingTable,
    reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
}

impl OutboundForwarder {
    /// Run the forward loop.
    pub async fn run(self) -> Result<(), OutboundError> {
        Outbound::run_forward_loop(
            self.socket,
            self.channel_rx,
            self.mappings,
            self.reverse_index,
        )
        .await
    }

    /// Receive the next datagram from the channel.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.channel_rx.recv().await
    }

    /// Forward a datagram to an external server.
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, OutboundError> {
        self.socket
            .send_to(data, addr)
            .await
            .map_err(OutboundError::from)
    }

    /// Get or create a NAT mapping.
    pub async fn get_or_create_mapping(
        &self,
        internal_addr: SocketAddr,
        dest: SocketAddr,
    ) -> Option<u16> {
        self.mappings.get_or_create(internal_addr, dest).await
    }

    /// Update the reverse index for response routing.
    pub async fn update_reverse_index(&self, remote_addr: SocketAddr, internal_addr: SocketAddr) {
        let mut index = self.reverse_index.write().await;
        index.insert(remote_addr, internal_addr);
    }
}

/// The responding half of an outbound handler.
///
/// Receives responses from destinations and sends them back through the channel.
pub struct OutboundResponder {
    socket: Arc<UdpSocket>,
    channel_tx: ChannelSender,
    reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>>,
}

impl OutboundResponder {
    /// Run the response loop.
    pub async fn run(self) -> Result<(), OutboundError> {
        Outbound::run_response_loop(self.socket, self.channel_tx, self.reverse_index).await
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

    /// Look up the internal address for a remote address.
    pub async fn lookup_internal(&self, remote_addr: &SocketAddr) -> Option<SocketAddr> {
        let index = self.reverse_index.read().await;
        index.get(remote_addr).copied()
    }

    /// Update the reverse index for response routing.
    pub async fn update_reverse_index(&self, remote_addr: SocketAddr, internal_addr: SocketAddr) {
        let mut index = self.reverse_index.write().await;
        index.insert(remote_addr, internal_addr);
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
