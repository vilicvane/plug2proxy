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
        // Read the connect request from HUB
        let request = Self::read_connect_request(&stream).await?;

        tracing::info!(
            "✅ OUT EXIT: Received request for {} (forwarded from HUB)",
            request.target
        );

        // Parse target address
        let target_addr: std::net::SocketAddr = request
            .target
            .parse()
            .or_else(|_| {
                // Try adding default port
                format!("{}:80", request.target).parse()
            })
            .map_err(|e| {
                OutNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid target: {}", e),
                ))
            })?;

        // Connect to the actual target
        let mut target_stream = tokio::net::TcpStream::connect(target_addr).await?;
        tracing::info!("✅ OUT EXIT: Connected to {} from OUT node", target_addr);

        // Relay data between tunnel stream and target
        Self::relay_to_target(stream, &mut target_stream).await?;

        Ok(())
    }

    /// Read connect request from the stream.
    async fn read_connect_request(
        stream: &Stream,
    ) -> Result<super::message::ConnectRequest, OutNodeError> {
        use super::message::ConnectRequest;

        // Read length-prefixed JSON
        let mut len_buf = [0u8; 4];
        let mut offset = 0;
        while offset < 4 {
            let (n, fin) = stream.recv(&mut len_buf[offset..]).await?;
            if fin && offset + n < 4 {
                return Err(OutNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            if n == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                continue;
            }
            offset += n;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        offset = 0;
        while offset < len {
            let (n, fin) = stream.recv(&mut msg_buf[offset..]).await?;
            if fin && offset + n < len {
                return Err(OutNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            if n == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                continue;
            }
            offset += n;
        }

        let request: ConnectRequest = serde_json::from_slice(&msg_buf).map_err(|e| {
            OutNodeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        Ok(request)
    }

    /// Relay data between tunnel stream and TCP target.
    async fn relay_to_target(
        stream: Stream,
        target: &mut tokio::net::TcpStream,
    ) -> Result<(), OutNodeError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut target_read, mut target_write) = target.split();
        let stream = Arc::new(stream);
        let stream_send = Arc::clone(&stream);
        let stream_recv = Arc::clone(&stream);

        let stream_to_target = async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, fin) = stream_recv.recv(&mut buf).await?;
                if n > 0 {
                    tracing::trace!("OUT relay: stream->target {} bytes", n);
                    target_write.write_all(&buf[..n]).await?;
                    target_write.flush().await?;
                }
                if fin {
                    tracing::debug!("OUT relay: stream fin");
                    break;
                }
                if n == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            Ok::<_, OutNodeError>(())
        };

        let target_to_stream = async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = target_read.read(&mut buf).await?;
                if n == 0 {
                    tracing::debug!("OUT relay: target closed");
                    stream_send.close().await?;
                    break;
                }
                tracing::trace!("OUT relay: target->stream {} bytes", n);
                stream_send.send(&buf[..n]).await?;
            }
            Ok::<_, OutNodeError>(())
        };

        tokio::select! {
            r = stream_to_target => r?,
            r = target_to_stream => r?,
        }

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
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("not connected to HUB")]
    NotConnected,
    #[error("unexpected message from HUB")]
    UnexpectedMessage,
}
