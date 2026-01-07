use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::{Transport, TransportError};

/// Configuration for a tunnel client.
#[derive(Debug, Clone)]
pub struct TunnelClientConfig {
    /// Number of parallel TCP connections to establish.
    pub connection_count: usize,
    /// Buffer size for the datagram channels.
    pub buffer_size: usize,
}

impl Default for TunnelClientConfig {
    fn default() -> Self {
        Self {
            connection_count: 4,
            buffer_size: 256,
        }
    }
}

/// A tunnel client that connects to a tunnel server.
pub struct TunnelClient {
    transport: Transport,
}

impl TunnelClient {
    /// Connect to a tunnel server at the given address.
    pub async fn connect(addr: SocketAddr) -> Result<Self, TunnelClientError> {
        Self::connect_with_config(addr, TunnelClientConfig::default()).await
    }

    /// Connect to a tunnel server with custom configuration.
    pub async fn connect_with_config(
        addr: SocketAddr,
        config: TunnelClientConfig,
    ) -> Result<Self, TunnelClientError> {
        let mut connections = Vec::with_capacity(config.connection_count);

        for _ in 0..config.connection_count {
            let stream = TcpStream::connect(addr).await?;
            stream.set_nodelay(true)?;
            connections.push(stream);
        }

        tracing::info!(
            "connected to tunnel server at {} with {} connections",
            addr,
            config.connection_count
        );

        let transport = Transport::with_buffer_size(connections, config.buffer_size);

        Ok(Self { transport })
    }

    /// Get a reference to the underlying transport.
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Get a mutable reference to the underlying transport.
    pub fn transport_mut(&mut self) -> &mut Transport {
        &mut self.transport
    }

    /// Consume the client and return the transport.
    pub fn into_transport(self) -> Transport {
        self.transport
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelClientError {
    #[error("failed to connect: {0}")]
    Connect(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}
