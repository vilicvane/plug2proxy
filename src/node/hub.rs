use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::tunnel::{QuicConfig, QuicError, Stream, Tunnel, TunnelError};

use super::connection::{ConnectionError, NodeConnection};
use super::message::{ConnectRequest, HubMessage, NodeMessage, NodeRole, OutInfo, RouteRule};

/// Configuration for HUB.
pub struct HubConfig {
    pub cert_path: String,
    pub key_path: String,
}

/// Central HUB node.
pub struct Hub {
    config: HubConfig,
    /// Connected IN nodes.
    ins: Arc<RwLock<HashMap<String, InConnection>>>,
    /// Connected OUT nodes.
    outs: Arc<RwLock<HashMap<String, OutConnection>>>,
    /// Routing rules.
    route_rules: Arc<RwLock<Vec<RouteRule>>>,
}

struct InConnection {
    #[allow(dead_code)]
    conn: NodeConnection,
    tunnel: Arc<Tunnel>,
}

struct OutConnection {
    id: String,
    tags: Vec<String>,
    #[allow(dead_code)]
    conn: NodeConnection,
    tunnel: Arc<Tunnel>,
}

impl Hub {
    pub fn new(config: HubConfig) -> Self {
        Self {
            config,
            ins: Arc::new(RwLock::new(HashMap::new())),
            outs: Arc::new(RwLock::new(HashMap::new())),
            route_rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Run the HUB server.
    pub async fn serve(self: Arc<Self>, addr: SocketAddr) -> Result<(), HubError> {
        let listener = TcpListener::bind(addr).await?;
        tracing::info!("HUB listening on {}", addr);

        loop {
            let (stream, client_addr) = listener.accept().await?;
            stream.set_nodelay(true)?;
            tracing::info!("accepted connection from {}", client_addr);

            let hub = Arc::clone(&self);
            tokio::spawn(async move {
                if let Err(e) = hub.handle_connection(stream).await {
                    tracing::error!("connection error from {}: {}", client_addr, e);
                }
            });
        }
    }

    async fn handle_connection(self: &Arc<Self>, stream: TcpStream) -> Result<(), HubError> {
        // Create tunnel from single TCP stream (for now)
        let mut config =
            QuicConfig::new_server(&self.config.cert_path, &self.config.key_path)?.into_inner();
        let tunnel = Arc::new(Tunnel::from_tcp_streams_server(vec![stream], &mut config).await?);

        // Accept control connection
        let conn = NodeConnection::accept(Arc::clone(&tunnel)).await?;

        // Wait for registration
        let msg = conn.recv().await?;
        match msg {
            NodeMessage::Register { role, id, tags } => {
                tracing::info!("node registered: {} ({:?})", id, role);

                // Send registration ack
                conn.send(&HubMessage::Registered).await?;

                match role {
                    NodeRole::In => {
                        // Send route config
                        let rules = self.route_rules.read().await.clone();
                        conn.send(&HubMessage::RouteConfig { rules }).await?;

                        // Send current OUT list
                        let outs = self.get_out_info().await;
                        conn.send(&HubMessage::OutUpdate { outs }).await?;

                        // Store IN connection
                        let in_id = id.clone();
                        {
                            let mut ins = self.ins.write().await;
                            ins.insert(
                                id,
                                InConnection {
                                    conn,
                                    tunnel: Arc::clone(&tunnel),
                                },
                            );
                        }

                        // Handle data streams from this IN
                        let hub = Arc::clone(self);
                        tokio::spawn(async move {
                            hub.handle_in_data_streams(in_id, tunnel).await;
                        });
                    }
                    NodeRole::Out => {
                        // Store OUT connection
                        let out_id = id.clone();
                        {
                            let mut outs = self.outs.write().await;
                            outs.insert(
                                id.clone(),
                                OutConnection {
                                    id: id.clone(),
                                    tags,
                                    conn,
                                    tunnel: Arc::clone(&tunnel),
                                },
                            );
                        }

                        // Notify all INs about new OUT
                        self.broadcast_out_update().await;

                        // Keep connection alive (OUT waits for forwarded streams)
                        let hub = Arc::clone(self);
                        tokio::spawn(async move {
                            // Just keep the tunnel alive
                            loop {
                                if tunnel.is_closed().await {
                                    tracing::info!("OUT {} disconnected", out_id);
                                    break;
                                }
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle data streams from an IN node.
    async fn handle_in_data_streams(&self, in_id: String, tunnel: Arc<Tunnel>) {
        use std::collections::HashSet;
        let mut handled_streams: HashSet<u64> = HashSet::new();
        // Stream 0 is always the control stream
        handled_streams.insert(0);

        loop {
            // Accept data streams
            match tunnel.accept_bi_stream().await {
                Ok(Some(stream)) => {
                    let stream_id = stream.id();
                    if handled_streams.contains(&stream_id) {
                        // Already handling this stream
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        continue;
                    }

                    handled_streams.insert(stream_id);
                    tracing::debug!("accepting new data stream {}", stream_id);

                    let hub_outs = Arc::clone(&self.outs);
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_data_stream(stream, hub_outs).await {
                            tracing::error!("data stream {} error: {}", stream_id, e);
                        }
                    });
                }
                Ok(None) => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
                Err(e) => {
                    tracing::error!("IN {} stream accept error: {}", in_id, e);
                    break;
                }
            }

            if tunnel.is_closed().await {
                tracing::info!("IN {} disconnected", in_id);
                break;
            }
        }
    }

    /// Handle a single data stream (connect request from IN).
    async fn handle_data_stream(
        stream: Stream,
        outs: Arc<RwLock<HashMap<String, OutConnection>>>,
    ) -> Result<(), HubError> {
        tracing::debug!("handling data stream {}", stream.id());

        // Read connect request
        let request = Self::read_connect_request(&stream).await?;

        // Determine if we should forward to an OUT or exit directly from HUB
        if let Some(tag) = &request.tag {
            // Try to find an OUT with matching tag
            let out_tunnel = {
                let outs_read = outs.read().await;
                outs_read
                    .values()
                    .find(|out| out.tags.contains(tag))
                    .map(|out| (out.id.clone(), out.tunnel.clone()))
            };

            if let Some((out_id, out_tunnel)) = out_tunnel {
                tracing::info!(
                    "🔀 ROUTING: {} → OUT [{}] (tag: '{}')",
                    request.target,
                    out_id,
                    tag
                );
                return Self::forward_to_out(stream, out_tunnel, request).await;
            } else {
                tracing::warn!(
                    "⚠️  ROUTING: {} → HUB DIRECT (no OUT found for tag '{}')",
                    request.target,
                    tag
                );
            }
        } else {
            tracing::info!("🔀 ROUTING: {} → HUB DIRECT (no tag)", request.target);
        }

        // No tag or no matching OUT - HUB exits directly
        Self::exit_from_hub(stream, request).await
    }

    /// Forward request to an OUT node.
    async fn forward_to_out(
        in_stream: Stream,
        out_tunnel: Arc<Tunnel>,
        request: ConnectRequest,
    ) -> Result<(), HubError> {
        // Open a new stream to the OUT node
        let out_stream = out_tunnel.open_bi_stream().await?;
        tracing::debug!("opened stream {} to OUT", out_stream.id());

        // Forward the connect request to the OUT
        let json = serde_json::to_vec(&request)
            .map_err(|e| HubError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let len = (json.len() as u32).to_be_bytes();
        out_stream.send(&len).await?;
        out_stream.send(&json).await?;

        // Relay data bidirectionally between IN stream and OUT stream
        Self::relay_streams(in_stream, out_stream).await?;

        Ok(())
    }

    /// HUB exits traffic directly to the target.
    async fn exit_from_hub(stream: Stream, request: ConnectRequest) -> Result<(), HubError> {
        // Parse target address
        let target_addr: SocketAddr = request
            .target
            .parse()
            .or_else(|_| {
                // Try adding default port
                format!("{}:80", request.target).parse()
            })
            .map_err(|e| {
                HubError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid target: {}", e),
                ))
            })?;

        // Connect to target
        let mut target_stream = TcpStream::connect(target_addr).await?;
        tracing::info!(
            "✅ HUB EXIT: Connected to {} directly from HUB",
            target_addr
        );

        // Relay data between tunnel stream and target
        Self::relay(stream, &mut target_stream).await?;

        Ok(())
    }

    /// Relay data bidirectionally between two tunnel streams.
    async fn relay_streams(stream1: Stream, stream2: Stream) -> Result<(), HubError> {
        let stream1 = Arc::new(stream1);
        let stream2 = Arc::new(stream2);

        let s1_to_s2 = {
            let stream1 = Arc::clone(&stream1);
            let stream2 = Arc::clone(&stream2);
            async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let (n, fin) = stream1.recv(&mut buf).await?;
                    if n > 0 {
                        tracing::trace!("relay: stream1->stream2 {} bytes", n);
                        stream2.send(&buf[..n]).await?;
                    }
                    if fin {
                        tracing::debug!("relay: stream1 fin");
                        stream2.close().await?;
                        break;
                    }
                    if n == 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
                Ok::<_, HubError>(())
            }
        };

        let s2_to_s1 = {
            let stream1 = Arc::clone(&stream1);
            let stream2 = Arc::clone(&stream2);
            async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let (n, fin) = stream2.recv(&mut buf).await?;
                    if n > 0 {
                        tracing::trace!("relay: stream2->stream1 {} bytes", n);
                        stream1.send(&buf[..n]).await?;
                    }
                    if fin {
                        tracing::debug!("relay: stream2 fin");
                        stream1.close().await?;
                        break;
                    }
                    if n == 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                }
                Ok::<_, HubError>(())
            }
        };

        tokio::select! {
            r = s1_to_s2 => r?,
            r = s2_to_s1 => r?,
        }

        Ok(())
    }

    async fn read_connect_request(stream: &Stream) -> Result<ConnectRequest, HubError> {
        // Read length-prefixed JSON
        let mut len_buf = [0u8; 4];
        let mut offset = 0;
        while offset < 4 {
            let (n, fin) = stream.recv(&mut len_buf[offset..]).await?;
            if fin && offset + n < 4 {
                return Err(HubError::Io(std::io::Error::new(
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
                return Err(HubError::Io(std::io::Error::new(
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

        let request: ConnectRequest = serde_json::from_slice(&msg_buf)
            .map_err(|e| HubError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;

        Ok(request)
    }

    async fn relay(stream: Stream, target: &mut TcpStream) -> Result<(), HubError> {
        let (mut target_read, mut target_write) = target.split();

        // Use Arc to share stream between tasks
        let stream = Arc::new(stream);
        let stream_send = Arc::clone(&stream);
        let stream_recv = Arc::clone(&stream);

        let stream_to_target = async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let (n, fin) = stream_recv.recv(&mut buf).await?;
                if n > 0 {
                    tracing::debug!("relay: stream->target {} bytes", n);
                    target_write.write_all(&buf[..n]).await?;
                    target_write.flush().await?;
                }
                if fin {
                    tracing::debug!("relay: stream fin");
                    break;
                }
                if n == 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
            Ok::<_, HubError>(())
        };

        let target_to_stream = async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = target_read.read(&mut buf).await?;
                if n == 0 {
                    tracing::debug!("relay: target closed");
                    stream_send.close().await?;
                    break;
                }
                tracing::debug!("relay: target->stream {} bytes", n);
                stream_send.send(&buf[..n]).await?;
            }
            Ok::<_, HubError>(())
        };

        tokio::select! {
            r = stream_to_target => r?,
            r = target_to_stream => r?,
        }

        Ok(())
    }

    /// Broadcast OUT update to all IN nodes.
    async fn broadcast_out_update(&self) {
        let outs = self.get_out_info().await;
        let msg = HubMessage::OutUpdate { outs };

        let ins = self.ins.read().await;
        for (id, in_conn) in ins.iter() {
            if let Err(e) = in_conn.conn.send(&msg).await {
                tracing::warn!("failed to send OUT update to IN {}: {}", id, e);
            }
        }
    }

    /// Get OUT info for IN nodes.
    pub async fn get_out_info(&self) -> Vec<OutInfo> {
        let outs = self.outs.read().await;
        outs.values()
            .map(|out| OutInfo {
                id: out.id.clone(),
                tags: out.tags.clone(),
                direct_addr: None, // TODO: populate if direct connection supported
            })
            .collect()
    }

    /// Set routing rules.
    pub async fn set_route_rules(&self, rules: Vec<RouteRule>) {
        let mut route_rules = self.route_rules.write().await;
        *route_rules = rules;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HubError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("quic error: {0}")]
    Quic(#[from] QuicError),
}
