use std::future::Future;

use crate::tunnel::Stream;

/// Trait for creating proxied connections (frontend abstraction).
///
/// Implemented by connectors that can establish a proxied data path:
/// - HubConnector: forward through HUB
/// - DirectOutConnector: connect directly to OUT
/// - LocalConnector: exit locally (no forwarding)
pub trait InLike {
    /// Create a proxied connection to target.
    fn connect(
        &self,
        target: &str,
    ) -> impl Future<Output = Result<Stream, InLikeError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum InLikeError {
    #[error("not connected")]
    NotConnected,
    #[error("tunnel error: {0}")]
    Tunnel(#[from] crate::tunnel::TunnelError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
