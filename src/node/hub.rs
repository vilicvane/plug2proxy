use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};

use crate::route::{BuiltInLabel, Label, RuleConfig};
use crate::tunnel::{FrameCodec, QuicConfig, QuicError, Stream, Tunnel, TunnelError};

use super::connection::{ConnectionError, NodeConnection};
use super::message::{
    ForwardRequest, HubMessage, NodeMessage, NodeRole, OutInfo, TcpForwardRequest,
    UdpForwardRequest,
};

/// Generate a unique node ID using UUID v4.
fn generate_node_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Configuration for HUB.
pub struct HubConfig {
    /// Path to server PEM file (cert + key).
    pub pem_path: String,
    /// Path to CA PEM file (for verifying client certs).
    /// If None, client certificate verification is disabled.
    pub ca_pem_path: Option<String>,
    /// Labels this HUB provides for level 1 routing (when acting as an OUT).
    pub labels: Vec<String>,
}

/// Configuration for client nodes (IN/OUT).
#[derive(Clone)]
pub struct ClientConfig {
    /// Path to client PEM file (cert + key).
    pub pem_path: Option<String>,
    /// Path to CA PEM file (for verifying server cert).
    pub ca_pem_path: Option<String>,
}

/// Central HUB node.
pub struct Hub {
    config: HubConfig,
    /// Connected IN nodes.
    ins: Arc<RwLock<HashMap<String, InConnection>>>,
    /// Connected OUT nodes.
    outs: Arc<RwLock<HashMap<String, OutConnection>>>,
    /// Base routing rules (from config).
    route_rules: Arc<RwLock<Vec<RuleConfig>>>,
    /// Registry of active tunnels by QUIC connection ID (for routing additional TCP connections).
    tunnel_registry: Arc<RwLock<HashMap<Vec<u8>, Arc<Tunnel>>>>,
}

struct InConnection {
    #[allow(dead_code)]
    conn: NodeConnection,
    #[allow(dead_code)]
    tunnel: Arc<Tunnel>,
}

struct OutConnection {
    id: String,
    name: Option<String>,
    /// Labels for level 1 routing.
    labels: Vec<String>,
    /// Direct address for IN→OUT connections (if available).
    direct_addr: Option<String>,
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
            tunnel_registry: Arc::new(RwLock::new(HashMap::new())),
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
                if let Err(e) = hub.route_connection(stream, client_addr).await {
                    tracing::error!("connection error from {}: {}", client_addr, e);
                }
            });
        }
    }

    /// Route a TCP connection to an existing tunnel or create a new one.
    async fn route_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        client_addr: SocketAddr,
    ) -> Result<(), HubError> {
        use futures::{SinkExt, StreamExt};
        use tokio_util::codec::Decoder;

        // Read the first frame
        let mut framed = FrameCodec::new().framed(stream);
        let first_frame = framed.next().await;

        let first_frame = match first_frame {
            Some(Ok(data)) => data,
            Some(Err(e)) => {
                return Err(HubError::Tunnel(TunnelError::Io(std::io::Error::other(
                    e.to_string(),
                ))));
            }
            None => return Err(HubError::Tunnel(TunnelError::ConnectionFailed)),
        };

        // Check if this is a routing header (additional connection)
        // Routing header format: ROUTING_MAGIC (1 byte) + length (1 byte) + connection_id
        if !first_frame.is_empty() && first_frame[0] == crate::tunnel::ROUTING_MAGIC {
            if first_frame.len() < 2 {
                return Err(HubError::Tunnel(TunnelError::ConnectionFailed));
            }
            let conn_id_len = first_frame[1] as usize;
            if first_frame.len() < 2 + conn_id_len {
                return Err(HubError::Tunnel(TunnelError::ConnectionFailed));
            }
            let conn_id = first_frame[2..2 + conn_id_len].to_vec();

            // Look up existing tunnel
            let existing_tunnel = {
                let registry = self.tunnel_registry.read().await;
                registry.get(&conn_id).cloned()
            };

            if let Some(tunnel) = existing_tunnel {
                tracing::debug!(
                    "routing additional TCP connection from {} to existing tunnel",
                    client_addr
                );
                // Send ACK before adding connection
                framed
                    .send(bytes::Bytes::from_static(&[crate::tunnel::ROUTING_ACK]))
                    .await
                    .map_err(|e| {
                        HubError::Tunnel(TunnelError::Io(std::io::Error::other(e.to_string())))
                    })?;
                let tcp_stream = framed.into_inner();
                tunnel.add_tcp_connection(tcp_stream).await?;
                return Ok(());
            } else {
                // This can happen when clients reconnect after HUB restart -
                // they may try to use old connection IDs. Log at debug level.
                tracing::debug!(
                    "received routing header for unknown connection ID from {} (stale connection?)",
                    client_addr
                );
                return Err(HubError::Tunnel(TunnelError::ConnectionFailed));
            }
        }

        // Not a routing header, this is a new QUIC connection
        // Parse the first frame to get the client's source connection ID for routing
        let mut header_buf = first_frame.to_vec();
        let client_scid = match quiche::Header::from_slice(&mut header_buf, quiche::MAX_CONN_ID_LEN)
        {
            Ok(hdr) => hdr.scid.to_vec(),
            Err(_) => Vec::new(),
        };

        let tcp_stream = framed.into_inner();
        self.handle_new_connection(tcp_stream, first_frame, client_scid)
            .await
    }

    /// Handle a new connection (no existing tunnel).
    async fn handle_new_connection(
        self: &Arc<Self>,
        stream: TcpStream,
        first_frame: Bytes,
        client_scid: Vec<u8>,
    ) -> Result<(), HubError> {
        // Create tunnel from single TCP stream with the first frame already read
        // Note: This does NOT wait for handshake - we register immediately so
        // additional TCP connections can be routed while handshake is in progress
        let mut config =
            QuicConfig::new_server(&self.config.pem_path, self.config.ca_pem_path.as_deref())?
                .into_inner();

        let tunnel = Arc::new(
            Tunnel::from_tcp_stream_server_with_initial_data_no_wait(
                stream,
                first_frame,
                &mut config,
                None, // HUB doesn't mark traffic
            )
            .await?,
        );

        // Register this tunnel IMMEDIATELY using client's source ID
        // (before handshake completes, so additional connections can be routed)
        let conn_id = client_scid;
        {
            let mut registry = self.tunnel_registry.write().await;
            registry.insert(conn_id.clone(), Arc::clone(&tunnel));
        }

        // Clone for cleanup task
        let registry = Arc::clone(&self.tunnel_registry);
        let conn_id_for_cleanup = conn_id;
        let tunnel_for_cleanup = Arc::clone(&tunnel);

        // Spawn cleanup task that removes the tunnel when it closes
        tokio::spawn(async move {
            // Wait for tunnel to close
            loop {
                if tunnel_for_cleanup.is_closed().await {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }

            // Cleanup: remove from registry
            {
                let mut registry = registry.write().await;
                registry.remove(&conn_id_for_cleanup);
            }
        });

        // Run the connection handler
        self.handle_connection_inner(Arc::clone(&tunnel)).await
    }

    async fn handle_connection_inner(
        self: &Arc<Self>,
        tunnel: Arc<Tunnel>,
    ) -> Result<(), HubError> {
        // Wait for QUIC handshake to complete
        tunnel.wait_established().await?;

        // Extract the peer's Common Name from their TLS certificate
        let peer_name = tunnel.peer_common_name().await;

        // Accept control connection
        let conn = NodeConnection::accept(Arc::clone(&tunnel)).await?;

        // Wait for registration
        let msg = conn.recv().await?;
        match msg {
            NodeMessage::Register {
                role,
                labels,
                direct_addr,
            } => {
                // Generate a unique UUID for this node
                let id = generate_node_id();

                tracing::info!(
                    "node registered: {} (name: {:?}, role: {:?})",
                    id,
                    peer_name,
                    role
                );

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
                        let tunnel_clone = Arc::clone(&tunnel);
                        tokio::spawn(async move {
                            // Heartbeat task to prevent QUIC idle timeout
                            tokio::spawn(async move {
                                let heartbeat_stream_result = tunnel_clone.open_bi_stream().await;
                                if let Ok(heartbeat_stream) = heartbeat_stream_result {
                                    loop {
                                        tokio::time::sleep(std::time::Duration::from_secs(10))
                                            .await;
                                        if tunnel_clone.is_closed().await {
                                            break;
                                        }
                                        // Send a ping by writing empty data
                                        if let Err(e) = heartbeat_stream.send(b"ping").await {
                                            tracing::debug!("Heartbeat send error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            });

                            hub.handle_in_data_streams(in_id, tunnel).await;
                        });
                    }
                    NodeRole::Out => {
                        // Store OUT connection
                        let out_id = id.clone();

                        {
                            // Build labels: configured labels + CN (if present) as automatic label
                            let mut all_labels = labels;
                            if let Some(ref cn) = peer_name {
                                // Add CN as automatic label if not already present
                                if !all_labels.contains(cn) {
                                    all_labels.push(cn.clone());
                                }
                            }

                            let mut outs = self.outs.write().await;
                            outs.insert(
                                id.clone(),
                                OutConnection {
                                    id: id.clone(),
                                    name: peer_name.clone(),
                                    labels: all_labels,
                                    direct_addr: direct_addr.clone(),
                                    conn,
                                    tunnel: Arc::clone(&tunnel),
                                },
                            );

                            if direct_addr.is_some() {
                                tracing::info!("OUT {} has direct address: {:?}", id, direct_addr);
                            }
                        }

                        // Notify all INs about new OUT
                        self.broadcast_out_update().await;

                        // Monitor OUT connection with heartbeat to prevent QUIC idle timeout
                        let tunnel_clone = Arc::clone(&tunnel);
                        tokio::spawn(async move {
                            // Heartbeat task to prevent QUIC idle timeout
                            tokio::spawn(async move {
                                let heartbeat_stream_result = tunnel_clone.open_bi_stream().await;
                                if let Ok(heartbeat_stream) = heartbeat_stream_result {
                                    loop {
                                        tokio::time::sleep(std::time::Duration::from_secs(10))
                                            .await;
                                        if tunnel_clone.is_closed().await {
                                            break;
                                        }
                                        // Send a ping by writing empty data
                                        if let Err(e) = heartbeat_stream.send(b"ping").await {
                                            tracing::debug!("Heartbeat send error: {}", e);
                                            break;
                                        }
                                    }
                                }
                            });

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
            // Check if tunnel is closed
            if tunnel.is_closed().await {
                tracing::info!("IN {} disconnected", in_id);
                break;
            }

            // Wait for and accept data streams, excluding already-handled streams
            // This prevents busy-looping when existing streams have data
            match tunnel
                .accept_bi_stream_wait_excluding(&handled_streams)
                .await
            {
                Ok(stream) => {
                    let stream_id = stream.id();
                    handled_streams.insert(stream_id);
                    tracing::debug!("accepting new data stream {}", stream_id);

                    let hub_outs = Arc::clone(&self.outs);
                    // HUB always has "hub" as a fixed label, plus any configured labels
                    let mut hub_labels = self.config.labels.clone();
                    if !hub_labels.contains(&"hub".to_string()) {
                        hub_labels.push("hub".to_string());
                    }
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_data_stream(stream, hub_outs, hub_labels).await
                        {
                            tracing::error!("data stream {} error: {}", stream_id, e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("IN {} stream accept error: {}", in_id, e);
                    break;
                }
            }
        }
    }

    /// Handle a single data stream (forward request from IN).
    async fn handle_data_stream(
        stream: Stream,
        outs: Arc<RwLock<HashMap<String, OutConnection>>>,
        hub_labels: Vec<String>,
    ) -> Result<(), HubError> {
        tracing::debug!("handling data stream {}", stream.id());

        // Read forward request
        let request = Self::read_forward_request(&stream).await?;

        match request {
            ForwardRequest::Tcp(tcp_req) => {
                Self::handle_tcp_forward(stream, outs, hub_labels, tcp_req).await
            }
            ForwardRequest::Udp(udp_req) => {
                Self::handle_udp_forward_request(stream, outs, hub_labels, udp_req).await
            }
        }
    }

    /// Handle TCP forwarding request.
    async fn handle_tcp_forward(
        stream: Stream,
        outs: Arc<RwLock<HashMap<String, OutConnection>>>,
        hub_labels: Vec<String>,
        request: TcpForwardRequest,
    ) -> Result<(), HubError> {
        // Process routes to determine routing
        // Each route has a label (first-level routing) and optional tag (second-level for OUT)
        for route in &request.routes {
            match &route.label {
                Label::BuiltIn(BuiltInLabel::Direct) => {
                    // Direct connection - exit from HUB
                    tracing::info!("🔀 RELAY: {} → HUB DIRECT (DIRECT)", request.host);
                    return Self::exit_tcp_from_hub(stream, &request.host).await;
                }
                Label::BuiltIn(BuiltInLabel::Proxy) => {
                    // Route through any available OUT
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .next()
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!("🔀 RELAY: {} → OUT [{}] (PROXY)", request.host, out_id);
                        // Forward with tag info for second-level routing at OUT
                        return Self::forward_tcp_to_out(stream, out_tunnel, request).await;
                    }
                    // No OUT available, fall through to try next route or exit from HUB
                }
                Label::BuiltIn(BuiltInLabel::Any) => {
                    // Accept any route - try OUT first, then HUB
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .next()
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!("🔀 RELAY: {} → OUT [{}] (ANY)", request.host, out_id);
                        return Self::forward_tcp_to_out(stream, out_tunnel, request).await;
                    } else {
                        tracing::info!("🔀 RELAY: {} → HUB DIRECT (ANY)", request.host);
                        return Self::exit_tcp_from_hub(stream, &request.host).await;
                    }
                }
                Label::Custom(node_label) => {
                    // Try to find an OUT with matching tag (first-level routing)
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .find(|out| out.labels.contains(node_label))
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!(
                            "🔀 RELAY: {} → OUT [{}] (label: '{}', tag: {:?})",
                            request.host,
                            out_id,
                            node_label,
                            route.tag
                        );
                        // Forward request with tag info for second-level routing at OUT
                        return Self::forward_tcp_to_out(stream, out_tunnel, request).await;
                    } else if hub_labels.contains(node_label) {
                        // HUB itself has this tag, exit from HUB
                        tracing::info!(
                            "🔀 RELAY: {} → HUB DIRECT (label: '{}')",
                            request.host,
                            node_label
                        );
                        return Self::exit_tcp_from_hub(stream, &request.host).await;
                    }
                    // No match for this label, try next route
                }
            }
        }

        // No routes matched - exit directly from HUB
        if request.routes.is_empty() {
            tracing::info!("🔀 RELAY: {} → HUB DIRECT (no routes)", request.host);
        } else {
            tracing::warn!(
                "⚠️ RELAY: {} → HUB DIRECT (no OUT found for routes: {:?})",
                request.host,
                request.routes
            );
        }

        Self::exit_tcp_from_hub(stream, &request.host).await
    }

    /// Forward TCP request to an OUT node.
    async fn forward_tcp_to_out(
        in_stream: Stream,
        out_tunnel: Arc<Tunnel>,
        request: TcpForwardRequest,
    ) -> Result<(), HubError> {
        // Open a new stream to the OUT node
        let out_stream = out_tunnel.open_bi_stream().await?;
        tracing::debug!("opened stream {} to OUT", out_stream.id());

        // Forward as a ForwardRequest::Tcp
        let forward_request = ForwardRequest::Tcp(request);
        let json = serde_json::to_vec(&forward_request)
            .map_err(|e| HubError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let len = (json.len() as u32).to_be_bytes();
        out_stream.send(&len).await?;
        out_stream.send(&json).await?;

        // Relay data bidirectionally between IN stream and OUT stream
        Self::relay_streams(in_stream, out_stream).await?;

        Ok(())
    }

    /// HUB exits TCP traffic directly to the target.
    async fn exit_tcp_from_hub(stream: Stream, target: &str) -> Result<(), HubError> {
        // Connect to target (supports both IP:port and domain:port)
        let target = if target.contains(':') {
            target.to_string()
        } else {
            format!("{}:80", target)
        };

        let mut target_stream = TcpStream::connect(&target).await?;
        target_stream.set_nodelay(true)?;
        tracing::info!("✅ HUB EXIT: Connected to {} directly from HUB", target);

        // Relay data between tunnel stream and target
        Self::relay(stream, &mut target_stream).await?;

        Ok(())
    }

    /// Handle UDP forwarding request with routing.
    async fn handle_udp_forward_request(
        stream: Stream,
        outs: Arc<RwLock<HashMap<String, OutConnection>>>,
        hub_labels: Vec<String>,
        request: UdpForwardRequest,
    ) -> Result<(), HubError> {
        // Process routes to determine routing (similar to TCP)
        for route in &request.routes {
            match &route.label {
                Label::BuiltIn(BuiltInLabel::Direct) => {
                    tracing::info!("🔀 RELAY: UDP → HUB DIRECT (DIRECT)");
                    return Self::handle_udp_forward(stream).await;
                }
                Label::BuiltIn(BuiltInLabel::Proxy) => {
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .next()
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!("🔀 RELAY: UDP → OUT [{}] (PROXY)", out_id);
                        return Self::forward_udp_to_out(stream, out_tunnel, request).await;
                    }
                }
                Label::BuiltIn(BuiltInLabel::Any) => {
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .next()
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!("🔀 RELAY: UDP → OUT [{}] (ANY)", out_id);
                        return Self::forward_udp_to_out(stream, out_tunnel, request).await;
                    } else {
                        tracing::info!("🔀 RELAY: UDP → HUB DIRECT (ANY)");
                        return Self::handle_udp_forward(stream).await;
                    }
                }
                Label::Custom(node_label) => {
                    let out_tunnel = {
                        let outs_read = outs.read().await;
                        outs_read
                            .values()
                            .find(|out| out.labels.contains(node_label))
                            .map(|out| (out.id.clone(), out.tunnel.clone()))
                    };

                    if let Some((out_id, out_tunnel)) = out_tunnel {
                        tracing::info!(
                            "🔀 RELAY: UDP → OUT [{}] (label: '{}')",
                            out_id,
                            node_label
                        );
                        return Self::forward_udp_to_out(stream, out_tunnel, request).await;
                    } else if hub_labels.contains(node_label) {
                        tracing::info!("🔀 RELAY: UDP → HUB DIRECT (label: '{}')", node_label);
                        return Self::handle_udp_forward(stream).await;
                    }
                }
            }
        }

        // No routes matched - exit directly from HUB
        tracing::info!("🔀 RELAY: UDP → HUB DIRECT (no routes)");
        Self::handle_udp_forward(stream).await
    }

    /// Forward UDP request to an OUT node.
    async fn forward_udp_to_out(
        in_stream: Stream,
        out_tunnel: Arc<Tunnel>,
        request: UdpForwardRequest,
    ) -> Result<(), HubError> {
        let out_stream = out_tunnel.open_bi_stream().await?;
        tracing::debug!("opened UDP stream {} to OUT", out_stream.id());

        // Forward as a ForwardRequest::Udp
        let forward_request = ForwardRequest::Udp(request);
        let json = serde_json::to_vec(&forward_request)
            .map_err(|e| HubError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))?;
        let len = (json.len() as u32).to_be_bytes();
        out_stream.send(&len).await?;
        out_stream.send(&json).await?;

        // Relay data bidirectionally between IN stream and OUT stream
        Self::relay_streams(in_stream, out_stream).await?;

        Ok(())
    }

    /// Handle UDP forwarding through the tunnel (HUB direct exit).
    async fn handle_udp_forward(stream: Stream) -> Result<(), HubError> {
        use crate::udp_proxy::{Datagram, NatMappingTable};
        use std::collections::HashMap;
        use tokio::sync::RwLock;

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
                    tracing::info!("HUB UDP socket bound to {}", s.local_addr().unwrap());
                    Arc::new(s)
                }
                Err(e) => {
                    tracing::error!("Failed to bind UDP socket: {}", e);
                    return;
                }
            };

            let mappings = NatMappingTable::default();
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
                    let _port = forward_mappings
                        .get_or_create(datagram.source, datagram.dest)
                        .await;

                    {
                        let mut index = forward_index.write().await;
                        index.insert(datagram.dest, datagram.source);
                    }

                    tracing::trace!(
                        "HUB UDP forward: {} -> {} ({} bytes)",
                        datagram.source,
                        datagram.dest,
                        datagram.data.len()
                    );

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
                                    "HUB UDP response: {} -> {} ({} bytes)",
                                    src,
                                    internal_addr,
                                    len
                                );

                                if let Err(e) = outbound_tx.send(response).await {
                                    tracing::error!("Failed to send UDP response: {}", e);
                                    break;
                                }
                            } else {
                                tracing::debug!("HUB UDP from unknown source {} (no mapping)", src);
                            }
                        }
                        Err(e) => {
                            tracing::error!("HUB UDP recv error: {}", e);
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
                            tracing::info!("HUB UDP tunnel stream closed");
                            return;
                        }
                        Ok((n, _)) => {
                            offset += n;
                        }
                        Err(e) => {
                            tracing::debug!("HUB UDP recv error: {}", e);
                            return;
                        }
                    }
                }

                let datagram_len = u32::from_be_bytes(len_buf) as usize;
                if datagram_len == 0 || datagram_len > 65535 {
                    tracing::error!("HUB UDP invalid datagram length: {}", datagram_len);
                    break;
                }

                // Read datagram data
                let mut datagram_buf = vec![0u8; datagram_len];
                let mut offset = 0;
                while offset < datagram_len {
                    match stream_recv.recv_wait(&mut datagram_buf[offset..]).await {
                        Ok((0, true)) => {
                            tracing::warn!("HUB UDP tunnel closed while reading datagram");
                            return;
                        }
                        Ok((n, _)) => {
                            offset += n;
                        }
                        Err(e) => {
                            tracing::debug!("HUB UDP read error: {}", e);
                            return;
                        }
                    }
                }

                match Datagram::deserialize(Bytes::from(datagram_buf)) {
                    Ok(datagram) => {
                        tracing::debug!(
                            "HUB UDP: {} -> {} ({} bytes)",
                            datagram.source,
                            datagram.dest,
                            datagram.data.len()
                        );

                        if let Err(e) = inbound_tx.send(datagram).await {
                            tracing::error!("HUB UDP channel send error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::error!("HUB UDP deserialize error: {}", e);
                    }
                }
            }
        });

        // Task 2: Read responses from UDP proxy and send back through tunnel
        let send_task = tokio::spawn(async move {
            while let Some(response) = outbound_rx.recv().await {
                tracing::debug!(
                    "HUB UDP response: {} <- {} ({} bytes)",
                    response.dest,
                    response.source,
                    response.data.len()
                );

                let serialized = response.serialize();
                let len_bytes = (serialized.len() as u32).to_be_bytes();

                if let Err(e) = stream_send.send(&len_bytes).await {
                    tracing::error!("HUB UDP send length error: {}", e);
                    break;
                }
                if let Err(e) = stream_send.send(&serialized).await {
                    tracing::error!("HUB UDP send data error: {}", e);
                    break;
                }
            }
        });

        tokio::select! {
            _ = recv_task => {},
            _ = send_task => {},
        }

        let _ = stream.shutdown().await;
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
                    let (n, fin) = stream1.recv_wait(&mut buf).await?;
                    if n > 0 {
                        tracing::trace!("relay: stream1->stream2 {} bytes", n);
                        stream2.send(&buf[..n]).await?;
                    }
                    if fin {
                        tracing::debug!("relay: stream1 fin");
                        break;
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
                    let (n, fin) = stream2.recv_wait(&mut buf).await?;
                    if n > 0 {
                        tracing::trace!("relay: stream2->stream1 {} bytes", n);
                        stream1.send(&buf[..n]).await?;
                    }
                    if fin {
                        tracing::debug!("relay: stream2 fin");
                        break;
                    }
                }
                Ok::<_, HubError>(())
            }
        };

        // Wait for either direction to finish
        tokio::select! {
            r = s1_to_s2 => { let _ = r; }
            r = s2_to_s1 => { let _ = r; }
        }

        // Shutdown BOTH streams to immediately release stream credits
        // Use shutdown (RESET) instead of close (FIN) since we don't need graceful close
        let _ = stream1.shutdown().await;
        let _ = stream2.shutdown().await;
        tracing::debug!("relay_streams: both streams shutdown");

        Ok(())
    }

    async fn read_forward_request(stream: &Stream) -> Result<ForwardRequest, HubError> {
        // Read length-prefixed JSON
        let mut len_buf = [0u8; 4];
        let mut offset = 0;
        while offset < 4 {
            let (n, fin) = stream.recv_wait(&mut len_buf[offset..]).await?;
            if fin && offset + n < 4 {
                return Err(HubError::Io(std::io::Error::new(
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
                return Err(HubError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "unexpected end of stream",
                )));
            }
            offset += n;
        }

        let request: ForwardRequest = serde_json::from_slice(&msg_buf)
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
                let (n, fin) = stream_recv.recv_wait(&mut buf).await?;
                if n > 0 {
                    tracing::debug!("relay: stream->target {} bytes", n);
                    target_write.write_all(&buf[..n]).await?;
                    target_write.flush().await?;
                }
                if fin {
                    tracing::debug!("relay: stream fin");
                    break;
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
                    break;
                }
                tracing::debug!("relay: target->stream {} bytes", n);
                stream_send.send(&buf[..n]).await?;
            }
            Ok::<_, HubError>(())
        };

        // Wait for either direction to finish
        tokio::select! {
            r = stream_to_target => { let _ = r; }
            r = target_to_stream => { let _ = r; }
        }

        // Shutdown stream to immediately release stream credits
        let _ = stream.shutdown().await;
        tracing::debug!("relay: stream shutdown");

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
                name: out.name.clone(),
                labels: out.labels.clone(),
                direct_addr: out.direct_addr.clone(),
            })
            .collect()
    }

    /// Set routing rules.
    pub async fn set_route_rules(&self, rules: Vec<RuleConfig>) {
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
