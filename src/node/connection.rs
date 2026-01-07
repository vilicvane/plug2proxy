use std::sync::Arc;

use crate::tunnel::{Stream, Tunnel, TunnelError};

use super::message::{HubMessage, NodeMessage};

/// A connection to HUB (used by IN and OUT nodes).
pub struct HubConnection {
    tunnel: Arc<Tunnel>,
    /// Control stream for messages.
    control_stream: Stream,
}

impl HubConnection {
    pub async fn new(tunnel: Arc<Tunnel>) -> Result<Self, ConnectionError> {
        let control_stream = tunnel.open_bi_stream().await?;
        Ok(Self {
            tunnel,
            control_stream,
        })
    }

    pub fn tunnel(&self) -> &Arc<Tunnel> {
        &self.tunnel
    }

    /// Send a message to HUB.
    pub async fn send(&self, msg: &NodeMessage) -> Result<(), ConnectionError> {
        let json = serde_json::to_vec(msg)?;
        let len = (json.len() as u32).to_be_bytes();
        self.control_stream.send(&len).await?;
        self.control_stream.send(&json).await?;
        Ok(())
    }

    /// Receive a message from HUB.
    pub async fn recv(&self) -> Result<HubMessage, ConnectionError> {
        let mut len_buf = [0u8; 4];
        self.recv_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; len];
        self.recv_exact(&mut msg_buf).await?;

        let msg = serde_json::from_slice(&msg_buf)?;
        Ok(msg)
    }

    async fn recv_exact(&self, buf: &mut [u8]) -> Result<(), ConnectionError> {
        let mut offset = 0;
        while offset < buf.len() {
            let (n, fin) = self.control_stream.recv_wait(&mut buf[offset..]).await?;
            if fin && offset + n < buf.len() {
                return Err(ConnectionError::UnexpectedEof);
            }
            offset += n;
        }
        Ok(())
    }
}

/// A connection from a node (used by HUB).
pub struct NodeConnection {
    tunnel: Arc<Tunnel>,
    /// Control stream for messages.
    control_stream: Stream,
}

impl NodeConnection {
    pub async fn accept(tunnel: Arc<Tunnel>) -> Result<Self, ConnectionError> {
        // Wait for control stream from node
        let stream = tunnel.accept_bi_stream_wait().await?;
        Ok(Self {
            tunnel,
            control_stream: stream,
        })
    }

    pub fn tunnel(&self) -> &Arc<Tunnel> {
        &self.tunnel
    }

    /// Receive a message from node.
    pub async fn recv(&self) -> Result<NodeMessage, ConnectionError> {
        let mut len_buf = [0u8; 4];
        self.recv_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;

        let mut msg_buf = vec![0u8; len];
        self.recv_exact(&mut msg_buf).await?;

        let msg = serde_json::from_slice(&msg_buf)?;
        Ok(msg)
    }

    /// Send a message to node.
    pub async fn send(&self, msg: &HubMessage) -> Result<(), ConnectionError> {
        let json = serde_json::to_vec(msg)?;
        let len = (json.len() as u32).to_be_bytes();
        self.control_stream.send(&len).await?;
        self.control_stream.send(&json).await?;
        Ok(())
    }

    async fn recv_exact(&self, buf: &mut [u8]) -> Result<(), ConnectionError> {
        let mut offset = 0;
        while offset < buf.len() {
            let (n, fin) = self.control_stream.recv_wait(&mut buf[offset..]).await?;
            if fin && offset + n < buf.len() {
                return Err(ConnectionError::UnexpectedEof);
            }
            offset += n;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unexpected end of stream")]
    UnexpectedEof,
}
