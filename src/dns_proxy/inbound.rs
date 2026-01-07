use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;

use super::{ChannelReceiver, ChannelSender, Datagram};

/// The inbound side of the DNS transparent proxy.
///
/// Responsibilities:
/// - Receive DNS queries from internal clients via UDP.
/// - Forward queries through the channel to the outbound side.
/// - Receive responses from the channel and send them back to clients.
pub struct Inbound {
    /// The UDP socket for receiving client queries.
    socket: Arc<UdpSocket>,
    /// Channel sender for forwarding queries to outbound.
    channel_tx: ChannelSender,
    /// Channel receiver for receiving responses from outbound.
    channel_rx: ChannelReceiver,
}

impl Inbound {
    /// Create a new inbound handler.
    ///
    /// # Arguments
    /// - `socket`: The UDP socket to receive client queries on.
    /// - `channel_tx`: Sender to forward queries to the outbound side.
    /// - `channel_rx`: Receiver to get responses from the outbound side.
    pub fn new(socket: UdpSocket, channel_tx: ChannelSender, channel_rx: ChannelReceiver) -> Self {
        Self {
            socket: Arc::new(socket),
            channel_tx,
            channel_rx,
        }
    }

    /// Bind to the specified address and create an inbound handler.
    pub async fn bind(
        addr: SocketAddr,
        channel_tx: ChannelSender,
        channel_rx: ChannelReceiver,
    ) -> Result<Self, InboundError> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(addr = %addr, "inbound listening");
        Ok(Self::new(socket, channel_tx, channel_rx))
    }

    /// Get the local address this inbound is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, InboundError> {
        self.socket.local_addr().map_err(InboundError::from)
    }

    /// Run the inbound handler.
    ///
    /// This spawns two tasks:
    /// - One for receiving queries from clients and forwarding to the channel.
    /// - One for receiving responses from the channel and sending to clients.
    pub async fn run(self, default_dest: SocketAddr) -> Result<(), InboundError> {
        let socket = self.socket;
        let channel_tx = self.channel_tx;
        let channel_rx = self.channel_rx;

        let recv_socket = Arc::clone(&socket);
        let send_socket = socket;

        // Task: receive from clients, forward to channel
        let recv_task = tokio::spawn(async move {
            Self::run_recv_loop(recv_socket, channel_tx, default_dest).await
        });

        // Task: receive from channel, send to clients
        let send_task = tokio::spawn(async move {
            Self::run_send_loop(send_socket, channel_rx).await
        });

        tokio::select! {
            result = recv_task => {
                result.map_err(|e| InboundError::TaskPanic(e.to_string()))??;
            }
            result = send_task => {
                result.map_err(|e| InboundError::TaskPanic(e.to_string()))??;
            }
        }

        Ok(())
    }

    /// Split into separate receiver and sender handles for more flexible usage.
    pub fn split(self) -> (InboundReceiver, InboundSender) {
        let socket = self.socket;
        (
            InboundReceiver {
                socket: Arc::clone(&socket),
                channel_tx: self.channel_tx,
            },
            InboundSender {
                socket,
                channel_rx: self.channel_rx,
            },
        )
    }

    async fn run_recv_loop(
        socket: Arc<UdpSocket>,
        channel_tx: ChannelSender,
        default_dest: SocketAddr,
    ) -> Result<(), InboundError> {
        let mut buf = vec![0u8; 65535];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;

            let datagram = Datagram::new(src, default_dest, Bytes::copy_from_slice(&buf[..len]));

            tracing::trace!(
                src = %src,
                dest = %default_dest,
                len,
                "inbound received query"
            );

            if let Err(e) = channel_tx.send(datagram).await {
                tracing::warn!(error = %e, "failed to forward query to channel");
            }
        }
    }

    async fn run_send_loop(
        socket: Arc<UdpSocket>,
        mut channel_rx: ChannelReceiver,
    ) -> Result<(), InboundError> {
        while let Some(datagram) = channel_rx.recv().await {
            tracing::trace!(
                dest = %datagram.dest,
                src = %datagram.source,
                len = datagram.data.len(),
                "inbound sending response"
            );

            // Send response back to the client (datagram.dest is the original client)
            if let Err(e) = socket.send_to(&datagram.data, datagram.dest).await {
                tracing::warn!(
                    dest = %datagram.dest,
                    error = %e,
                    "failed to send response to client"
                );
            }
        }

        Ok(())
    }
}

/// The receiving half of an inbound handler.
///
/// Receives queries from clients and forwards them to the channel.
pub struct InboundReceiver {
    socket: Arc<UdpSocket>,
    channel_tx: ChannelSender,
}

impl InboundReceiver {
    /// Run the receive loop.
    pub async fn run(self, default_dest: SocketAddr) -> Result<(), InboundError> {
        Inbound::run_recv_loop(self.socket, self.channel_tx, default_dest).await
    }

    /// Receive a single query from a client.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), InboundError> {
        let (len, src) = self.socket.recv_from(buf).await?;
        Ok((len, src))
    }

    /// Forward a datagram to the channel.
    pub async fn forward(&self, datagram: Datagram) -> Result<(), InboundError> {
        self.channel_tx
            .send(datagram)
            .await
            .map_err(|e| InboundError::Channel(e.to_string()))
    }
}

/// The sending half of an inbound handler.
///
/// Receives responses from the channel and sends them to clients.
pub struct InboundSender {
    socket: Arc<UdpSocket>,
    channel_rx: ChannelReceiver,
}

impl InboundSender {
    /// Run the send loop.
    pub async fn run(self) -> Result<(), InboundError> {
        Inbound::run_send_loop(self.socket, self.channel_rx).await
    }

    /// Receive the next response from the channel.
    pub async fn recv(&mut self) -> Option<Datagram> {
        self.channel_rx.recv().await
    }

    /// Send a datagram to a client.
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize, InboundError> {
        self.socket.send_to(data, addr).await.map_err(InboundError::from)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InboundError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("channel error: {0}")]
    Channel(String),
    #[error("task panic: {0}")]
    TaskPanic(String),
}
