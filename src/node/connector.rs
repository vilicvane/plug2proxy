use std::sync::Arc;

use crate::tunnel::{Stream, Tunnel};

use super::in_like::{InLike, InLikeError};
use super::message::{ForwardRequest, RouteEntry, TcpForwardRequest, UdpForwardRequest};

/// Connector that forwards through HUB.
pub struct HubConnector {
    tunnel: Arc<Tunnel>,
}

impl HubConnector {
    pub fn new(tunnel: Arc<Tunnel>) -> Self {
        Self { tunnel }
    }

    /// Send a forward request and return the stream.
    async fn send_request(&self, request: ForwardRequest) -> Result<Stream, InLikeError> {
        let stream = self.tunnel.open_bi_stream().await?;
        tracing::debug!("opened data stream {}", stream.id());

        let json = serde_json::to_vec(&request).map_err(|e| {
            InLikeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        // Length-prefixed message
        let len = (json.len() as u32).to_be_bytes();
        stream.send(&len).await?;
        stream.send(&json).await?;

        Ok(stream)
    }

    /// Connect TCP with routes (label + tag pairs) for routing.
    pub async fn connect_tcp_with_routes(
        &self,
        target: &str,
        routes: Vec<RouteEntry>,
    ) -> Result<Stream, InLikeError> {
        let request = ForwardRequest::Tcp(TcpForwardRequest {
            host: target.to_string(),
            address: None,
            routes: routes.clone(),
        });
        tracing::debug!(
            "sending TCP forward request for {} (routes: {:?})",
            target,
            routes
        );
        self.send_request(request).await
    }

    /// Open a UDP forwarding stream.
    pub async fn open_udp_forward(&self, routes: Vec<RouteEntry>) -> Result<Stream, InLikeError> {
        let request = ForwardRequest::Udp(UdpForwardRequest { routes });
        tracing::debug!("sending UDP forward request");
        self.send_request(request).await
    }
}

impl InLike for HubConnector {
    async fn connect(&self, target: &str) -> Result<Stream, InLikeError> {
        self.connect_tcp_with_routes(target, vec![]).await
    }
}

/// Connector that exits locally (no forwarding).
pub struct LocalConnector;

impl InLike for LocalConnector {
    async fn connect(&self, target: &str) -> Result<Stream, InLikeError> {
        // TODO: For local exit, we don't return a tunnel Stream.
        // This needs a different abstraction - perhaps return a tokio TcpStream instead.
        // For now, this is a placeholder.
        let _ = target;
        Err(InLikeError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "local connector not yet implemented",
        )))
    }
}

/// Connector that connects directly to an OUT node.
pub struct DirectOutConnector {
    tunnel: Arc<Tunnel>,
}

impl DirectOutConnector {
    pub fn new(tunnel: Arc<Tunnel>) -> Self {
        Self { tunnel }
    }
}

impl InLike for DirectOutConnector {
    async fn connect(&self, target: &str) -> Result<Stream, InLikeError> {
        // Same protocol as HubConnector - open stream, send forward request
        let stream = self.tunnel.open_bi_stream().await?;

        let request = ForwardRequest::Tcp(TcpForwardRequest {
            host: target.to_string(),
            address: None,
            routes: vec![],
        });
        let json = serde_json::to_vec(&request).map_err(|e| {
            InLikeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        let len = (json.len() as u32).to_be_bytes();
        stream.send(&len).await?;
        stream.send(&json).await?;

        Ok(stream)
    }
}
