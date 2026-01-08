use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::route::RuleConfig;
use crate::tunnel::{Stream, Tunnel, TunnelError};
use crate::udp_proxy::Datagram;

use super::connection::{ConnectionError, HubConnection};
use super::hub::ClientConfig;
use super::message::{HubMessage, NodeMessage, NodeRole};
use super::out_like::{OutLike, OutLikeError};

/// OUT node - exit point for proxied traffic.
pub struct OutNode {
    tags: Vec<String>,
    /// Routing rules this OUT provides.
    routing_rules: Vec<RuleConfig>,
    /// Priority for routing rules.
    routing_priority: i64,
    /// Client TLS configuration.
    client_config: ClientConfig,
    /// Connection to HUB.
    hub_conn: Option<HubConnection>,
}

impl OutNode {
    pub fn new(
        tags: Vec<String>,
        routing_rules: Vec<RuleConfig>,
        routing_priority: i64,
        client_config: ClientConfig,
    ) -> Self {
        Self {
            tags,
            routing_rules,
            routing_priority,
            client_config,
            hub_conn: None,
        }
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Connect to HUB.
    pub async fn connect_hub(
        &mut self,
        addr: SocketAddr,
        connection_count: usize,
    ) -> Result<(), OutNodeError> {
        let tunnel = Arc::new(
            Tunnel::connect_with_cert(
                addr,
                None,
                connection_count,
                self.client_config.pem_path.as_deref(),
                self.client_config.ca_pem_path.as_deref(),
            )
            .await?,
        );

        // Create control connection
        let conn = HubConnection::new(Arc::clone(&tunnel)).await?;

        // Register with HUB (HUB assigns UUID, name is from our cert's CN)
        conn.send(&NodeMessage::Register {
            role: NodeRole::Out,
            tags: self.tags.clone(),
            routing_rules: self.routing_rules.clone(),
            routing_priority: self.routing_priority,
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
        use std::collections::HashSet;

        let conn = self.hub_conn.as_ref().ok_or(OutNodeError::NotConnected)?;
        let tunnel = conn.tunnel();

        // Track streams we've already accepted to avoid re-accepting
        let mut handled_streams: HashSet<u64> = HashSet::new();
        // Stream 0 is the control stream
        handled_streams.insert(0);

        loop {
            // Wait for and accept incoming streams for forwarding, excluding already-handled
            // This prevents busy-looping when existing streams have data
            match tunnel
                .accept_bi_stream_wait_excluding(&handled_streams)
                .await
            {
                Ok(stream) => {
                    let stream_id = stream.id();
                    handled_streams.insert(stream_id);
                    tracing::debug!("accepting forward stream {}", stream_id);

                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_forward_stream(stream).await {
                            tracing::error!("forward stream {} error: {}", stream_id, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("stream accept error: {}", e);
                    return Err(e.into());
                }
            }
        }
    }

    async fn handle_forward_stream(stream: Stream) -> Result<(), OutNodeError> {
        // Read the connect request from HUB
        let request = Self::read_connect_request(&stream).await?;

        // Check if this is a UDP forwarding request
        if request.target == "udp-forward" {
            tracing::info!(
                "✅ OUT EXIT: UDP forwarding stream {} activated",
                stream.id()
            );
            return Self::handle_udp_forward(stream).await;
        }

        tracing::info!(
            "✅ OUT EXIT: Received TCP request for {} (forwarded from HUB)",
            request.target
        );

        // Connect to the actual target (supports both IP:port and domain:port)
        let mut target_stream = tokio::net::TcpStream::connect(&request.target).await?;
        tracing::info!("✅ OUT EXIT: Connected to {} from OUT node", request.target);

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
            let (n, fin) = stream.recv_wait(&mut len_buf[offset..]).await?;
            if fin && offset + n < 4 {
                return Err(OutNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            offset += n;
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        let mut msg_buf = vec![0u8; len];
        offset = 0;
        while offset < len {
            let (n, fin) = stream.recv_wait(&mut msg_buf[offset..]).await?;
            if fin && offset + n < len {
                return Err(OutNodeError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            offset += n;
        }

        let request: ConnectRequest = serde_json::from_slice(&msg_buf).map_err(|e| {
            OutNodeError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;

        Ok(request)
    }

    /// Handle UDP forwarding through the tunnel.
    /// Receives serialized datagrams, forwards them with full-cone NAT, and sends responses back.
    async fn handle_udp_forward(stream: Stream) -> Result<(), OutNodeError> {
        let stream = Arc::new(stream);
        let stream_recv = Arc::clone(&stream);
        let stream_send = Arc::clone(&stream);

        // Create channels for UDP proxy
        let (inbound_tx, inbound_rx) = mpsc::channel::<Datagram>(1024);
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<Datagram>(1024);

        // Spawn UDP outbound handler with full-cone NAT
        tokio::spawn(async move {
            // Bind a UDP socket for forwarding
            let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => {
                    tracing::info!("UDP outbound socket bound to {}", s.local_addr().unwrap());
                    Arc::new(s)
                }
                Err(e) => {
                    tracing::error!("Failed to bind UDP socket: {}", e);
                    return;
                }
            };

            // Create NAT mapping table (use full port range)
            use crate::udp_proxy::NatMappingTable;
            let mappings = NatMappingTable::default();

            // Run forward and response loops
            use std::collections::HashMap;
            use tokio::sync::RwLock;
            let reverse_index: Arc<RwLock<HashMap<SocketAddr, SocketAddr>>> =
                Arc::new(RwLock::new(HashMap::new()));

            let forward_socket = Arc::clone(&socket);
            let response_socket = socket;
            let forward_mappings = mappings.clone();
            let forward_index = Arc::clone(&reverse_index);
            let response_index = reverse_index;

            // Forward task: receive from inbound channel, send to destinations
            let forward_task = tokio::spawn(async move {
                let mut inbound_rx = inbound_rx;
                while let Some(datagram) = inbound_rx.recv().await {
                    // Create or get NAT mapping
                    let _port = forward_mappings
                        .get_or_create(datagram.source, datagram.dest)
                        .await;

                    // Update reverse index
                    {
                        let mut index = forward_index.write().await;
                        index.insert(datagram.dest, datagram.source);
                    }

                    tracing::trace!(
                        "Forwarding UDP: {} -> {} ({} bytes)",
                        datagram.source,
                        datagram.dest,
                        datagram.data.len()
                    );

                    // Forward to destination
                    if let Err(e) = forward_socket.send_to(&datagram.data, datagram.dest).await {
                        tracing::warn!("Failed to forward UDP to {}: {}", datagram.dest, e);
                    }
                }
            });

            // Response task: receive from destinations, send to outbound channel
            let response_task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    match response_socket.recv_from(&mut buf).await {
                        Ok((len, src)) => {
                            // Look up which client this is for
                            let internal_addr = {
                                let index = response_index.read().await;
                                index.get(&src).copied()
                            };

                            if let Some(internal_addr) = internal_addr {
                                let response = Datagram::new(
                                    src,
                                    internal_addr,
                                    Bytes::copy_from_slice(&buf[..len]),
                                );

                                tracing::trace!(
                                    "Received UDP response: {} -> {} ({} bytes)",
                                    src,
                                    internal_addr,
                                    len
                                );

                                if let Err(e) = outbound_tx.send(response).await {
                                    tracing::error!(
                                        "Failed to send UDP response to channel: {}",
                                        e
                                    );
                                    break;
                                }
                            } else {
                                tracing::debug!(
                                    "Received UDP from unknown source {} (no reverse mapping)",
                                    src
                                );
                            }
                        }
                        Err(e) => {
                            tracing::error!("UDP socket recv error: {}", e);
                            break;
                        }
                    }
                }
            });

            tokio::select! {
                _ = forward_task => {},
                _ = response_task => {},
            }
        });

        // Task 1: Read datagrams from tunnel and forward to UDP proxy
        let recv_task = tokio::spawn(async move {
            loop {
                // Read length prefix (4 bytes)
                let mut len_buf = [0u8; 4];
                let mut offset = 0;
                while offset < 4 {
                    match stream_recv.recv_wait(&mut len_buf[offset..]).await {
                        Ok((0, true)) => {
                            tracing::info!("UDP tunnel stream closed");
                            return;
                        }
                        Ok((n, _)) => {
                            offset += n;
                        }
                        Err(e) => {
                            tracing::error!("Failed to read length from tunnel: {}", e);
                            return;
                        }
                    }
                }

                let datagram_len = u32::from_be_bytes(len_buf) as usize;
                if datagram_len == 0 || datagram_len > 65535 {
                    tracing::error!("Invalid datagram length: {}", datagram_len);
                    break;
                }

                // Read datagram data
                let mut datagram_buf = vec![0u8; datagram_len];
                let mut offset = 0;
                while offset < datagram_len {
                    match stream_recv.recv_wait(&mut datagram_buf[offset..]).await {
                        Ok((0, true)) => {
                            tracing::warn!("Tunnel closed while reading datagram");
                            return;
                        }
                        Ok((n, _)) => {
                            offset += n;
                        }
                        Err(e) => {
                            tracing::error!("Failed to read datagram from tunnel: {}", e);
                            return;
                        }
                    }
                }

                // Deserialize and forward to UDP proxy
                match Datagram::deserialize(Bytes::from(datagram_buf)) {
                    Ok(datagram) => {
                        tracing::info!(
                            "📤 OUT UDP: Received from tunnel {} -> {} ({} bytes)",
                            datagram.source,
                            datagram.dest,
                            datagram.data.len()
                        );

                        if let Err(e) = inbound_tx.send(datagram).await {
                            tracing::error!("Failed to send to UDP proxy: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to deserialize datagram: {}", e);
                    }
                }
            }
            tracing::info!("OUT UDP recv task ended");
        });

        // Task 2: Read responses from UDP proxy and send back through tunnel
        let send_task = tokio::spawn(async move {
            while let Some(response) = outbound_rx.recv().await {
                tracing::info!(
                    "📥 OUT UDP: Sending response {} <- {} ({} bytes)",
                    response.dest,
                    response.source,
                    response.data.len()
                );

                // Serialize and send through tunnel
                let serialized = response.serialize();
                let len_bytes = (serialized.len() as u32).to_be_bytes();

                if let Err(e) = stream_send.send(&len_bytes).await {
                    tracing::error!("Failed to send length to tunnel: {}", e);
                    break;
                }
                if let Err(e) = stream_send.send(&serialized).await {
                    tracing::error!("Failed to send datagram to tunnel: {}", e);
                    break;
                }
            }
        });

        tokio::select! {
            _ = recv_task => {
                tracing::info!("UDP recv task completed");
            },
            _ = send_task => {
                tracing::info!("UDP send task completed");
            },
        }

        // Close stream with FIN to properly return stream credits
        let _ = stream.close().await;
        tracing::debug!("OUT UDP: stream closed");

        Ok(())
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
                let (n, fin) = stream_recv.recv_wait(&mut buf).await?;
                if n > 0 {
                    tracing::trace!("OUT relay: stream->target {} bytes", n);
                    target_write.write_all(&buf[..n]).await?;
                    target_write.flush().await?;
                }
                if fin {
                    tracing::debug!("OUT relay: stream fin");
                    break;
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
                    break;
                }
                tracing::trace!("OUT relay: target->stream {} bytes", n);
                stream_send.send(&buf[..n]).await?;
            }
            Ok::<_, OutNodeError>(())
        };

        // Wait for either direction to finish
        tokio::select! {
            r = stream_to_target => { let _ = r; }
            r = target_to_stream => { let _ = r; }
        }

        // Shutdown stream to immediately release stream credits
        let _ = stream.shutdown().await;
        tracing::debug!("OUT relay: stream shutdown");

        Ok(())
    }

    /// Get HUB connection.
    pub fn hub_conn(&self) -> Option<&HubConnection> {
        self.hub_conn.as_ref()
    }
}

impl OutLike for OutNode {
    async fn forward(&self, _tag: &str, _stream: Stream) -> Result<(), OutLikeError> {
        // TODO: Implement actual forwarding (connect to target, relay data).
        Ok(())
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
