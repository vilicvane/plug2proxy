use crate::tunnel::Stream;

/// Trait for nodes that can exit traffic (OUT and HUB).
pub trait OutLike {
    /// Forward a stream with the given tag.
    fn forward(
        &self,
        tag: &str,
        stream: Stream,
    ) -> impl Future<Output = Result<(), OutLikeError>> + Send;
}

use std::future::Future;

#[derive(Debug, thiserror::Error)]
pub enum OutLikeError {
    #[error("no route for tag: {0}")]
    NoRoute(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] crate::tunnel::TunnelError),
}
