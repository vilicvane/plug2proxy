use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

use super::{Transport, TransportError};

/// Configuration for a tunnel server.
#[derive(Debug, Clone)]
pub struct TunnelServerConfig {
    /// Expected number of connections per client.
    pub connections_per_client: usize,
    /// Buffer size for the datagram channels.
    pub buffer_size: usize,
}

impl Default for TunnelServerConfig {
    fn default() -> Self {
        Self {
            connections_per_client: 4,
            buffer_size: 256,
        }
    }
}

/// A tunnel server that accepts connections from tunnel clients.
pub struct TunnelServer {
    listener: TcpListener,
    config: TunnelServerConfig,
}

impl TunnelServer {
    /// Bind to the given address.
    pub async fn bind(addr: SocketAddr) -> Result<Self, TunnelServerError> {
        Self::bind_with_config(addr, TunnelServerConfig::default()).await
    }

    /// Bind to the given address with custom configuration.
    pub async fn bind_with_config(
        addr: SocketAddr,
        config: TunnelServerConfig,
    ) -> Result<Self, TunnelServerError> {
        let listener = TcpListener::bind(addr).await?;

        tracing::info!("tunnel server listening on {}", addr);

        Ok(Self { listener, config })
    }

    /// Accept the next client connection.
    ///
    /// This will wait for `connections_per_client` TCP connections from
    /// the same client before returning a transport.
    pub async fn accept(&self) -> Result<(Transport, SocketAddr), TunnelServerError> {
        let mut connections = Vec::with_capacity(self.config.connections_per_client);
        let mut client_addr = None;

        // Accept the required number of connections
        // In a real implementation, you'd want to group connections by client ID
        // For now, we assume sequential connections are from the same client
        for _ in 0..self.config.connections_per_client {
            let (stream, addr) = self.listener.accept().await?;
            stream.set_nodelay(true)?;

            if client_addr.is_none() {
                client_addr = Some(addr);
            }

            connections.push(stream);
        }

        let client_addr = client_addr.unwrap();
        tracing::info!(
            "accepted {} connections from {}",
            self.config.connections_per_client,
            client_addr
        );

        let transport = Transport::with_buffer_size(connections, self.config.buffer_size);

        Ok((transport, client_addr))
    }

    /// Get the local address this server is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }
}

/// Accept a single client from a set of pre-established TCP connections.
/// This is useful when the connection acceptance is handled externally.
pub fn accept_connections(
    connections: Vec<TcpStream>,
    buffer_size: usize,
) -> Transport {
    Transport::with_buffer_size(connections, buffer_size)
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelServerError {
    #[error("failed to bind: {0}")]
    Bind(#[from] std::io::Error),
    #[error("transport error: {0}")]
    Transport(#[from] TransportError),
}
