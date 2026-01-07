use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::tunnel::{Stream, Tunnel, TunnelError};

use super::connection::{ConnectionError, HubConnection};
use super::message::{HubMessage, NodeMessage, NodeRole};
use super::out_like::{OutLike, OutLikeError};

/// OUT node - exit point for proxied traffic.
pub struct OutNode {
    id: String,
    tags: Vec<String>,
    /// Connection to HUB.
    hub_conn: Option<HubConnection>,
}

impl OutNode {
    pub fn new(id: String, tags: Vec<String>) -> Self {
        Self {
            id,
            tags,
            hub_conn: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Connect to HUB.
    pub async fn connect_hub(&mut self, addr: SocketAddr) -> Result<(), OutNodeError> {
        // Establish tunnel (single TCP for now)
        let tunnel = Arc::new(Tunnel::connect(addr, None, 1).await?);

        // Create control connection
        let conn = HubConnection::new(Arc::clone(&tunnel)).await?;

        // Register with HUB
        conn.send(&NodeMessage::Register {
            role: NodeRole::Out,
            id: self.id.clone(),
            tags: self.tags.clone(),
        })
        .await?;

        // Wait for registration ack
        let msg = conn.recv().await?;
        match msg {
            HubMessage::Registered => {
                tracing::info!("registered with HUB as OUT");
            }
            _ => return Err(OutNodeError::UnexpectedMessage),
        }

        self.hub_conn = Some(conn);
        Ok(())
    }

    /// Run the OUT node (accept forwarded streams from HUB).
    pub async fn run(&self) -> Result<(), OutNodeError> {
        let conn = self.hub_conn.as_ref().ok_or(OutNodeError::NotConnected)?;
        let tunnel = conn.tunnel();

        loop {
            // Accept incoming streams for forwarding
            if let Some(stream) = tunnel.accept_bi_stream().await? {
                let stream_id = stream.id();
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_forward_stream(stream).await {
                        tracing::error!("forward stream {} error: {}", stream_id, e);
                    }
                });
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    async fn handle_forward_stream(stream: Stream) -> Result<(), OutNodeError> {
        // TODO: Read target info from stream, connect to target, relay data.
        let _ = stream;
        Ok(())
    }

    /// Get HUB connection.
    pub fn hub_conn(&self) -> Option<&HubConnection> {
        self.hub_conn.as_ref()
    }
}

impl OutLike for OutNode {
    fn forward(
        &self,
        _tag: &str,
        _stream: Stream,
    ) -> impl Future<Output = Result<(), OutLikeError>> + Send {
        async move {
            // TODO: Implement actual forwarding (connect to target, relay data).
            Ok(())
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutNodeError {
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("not connected to HUB")]
    NotConnected,
    #[error("unexpected message from HUB")]
    UnexpectedMessage,
}
