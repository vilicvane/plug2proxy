use std::sync::Arc;

use crate::tunnel::{Stream, Tunnel};

use super::in_like::{InLike, InLikeError};
use super::message::ConnectRequest;

/// Connector that forwards through HUB.
pub struct HubConnector {
    tunnel: Arc<Tunnel>,
}

impl HubConnector {
    pub fn new(tunnel: Arc<Tunnel>) -> Self {
        Self { tunnel }
    }
}

impl InLike for HubConnector {
    async fn connect(&self, target: &str) -> Result<Stream, InLikeError> {
        // Open a new data stream to HUB
        let stream = self.tunnel.open_bi_stream().await?;
        tracing::debug!("opened data stream {}", stream.id());

        // Send connect request
        let request = ConnectRequest {
            target: target.to_string(),
            tag: None, // Tag can be added by caller if needed
        };
        let json = serde_json::to_vec(&request).map_err(|e| {
            InLikeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        // Length-prefixed message
        let len = (json.len() as u32).to_be_bytes();
        stream.send(&len).await?;
        stream.send(&json).await?;
        tracing::debug!("sent connect request for {}", target);

        Ok(stream)
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
        // Same protocol as HubConnector - open stream, send connect request
        let stream = self.tunnel.open_bi_stream().await?;

        let request = ConnectRequest {
            target: target.to_string(),
            tag: None,
        };
        let json = serde_json::to_vec(&request).map_err(|e| {
            InLikeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        let len = (json.len() as u32).to_be_bytes();
        stream.send(&len).await?;
        stream.send(&json).await?;

        Ok(stream)
    }
}
