use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::route::{BuiltInLabel, GeoLite2, Label, MatchContext, Router, RuleConfig};
use crate::tunnel::{ProxyStream, Stream, Tunnel, TunnelError};

use super::connection::{ConnectionError, HubConnection};
use super::connector::HubConnector;
use super::hub::ClientConfig;
use super::in_like::InLikeError;
use super::message::{HubMessage, NodeMessage, NodeRole, OutInfo, RouteEntry};

/// IN node - entry point for proxied traffic.
pub struct InNode {
    /// Client TLS configuration.
    client_config: ClientConfig,
    /// Router for matching targets.
    router: Arc<RwLock<Router>>,
    /// GeoLite2 database for IP geolocation.
    geolite2: Option<GeoLite2>,
    /// Available OUTs (received from HUB).
    outs: Arc<RwLock<HashMap<String, OutInfo>>>,
    /// Direct connections to OUT nodes (for IN→OUT bypass).
    direct_out_tunnels: Arc<RwLock<HashMap<String, Arc<Tunnel>>>>,
    /// Filter for which OUT labels to connect directly.
    /// Empty means no direct connections (all through HUB).
    direct_filter: Vec<String>,
    /// Connection to HUB.
    hub_conn: Option<HubConnection>,
}

impl InNode {
    pub fn new(
        client_config: ClientConfig,
        direct_filter: Vec<String>,
        geolite2: Option<GeoLite2>,
    ) -> Self {
        Self {
            client_config,
            router: Arc::new(RwLock::new(Router::new(Vec::new()))),
            geolite2,
            outs: Arc::new(RwLock::new(HashMap::new())),
            direct_out_tunnels: Arc::new(RwLock::new(HashMap::new())),
            direct_filter,
            hub_conn: None,
        }
    }

    /// Connect to HUB.
    pub async fn connect_hub(
        &mut self,
        addr: SocketAddr,
        connection_count: usize,
    ) -> Result<(), InNodeError> {
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
            role: NodeRole::In,
            labels: vec![],
            direct_addr: None,
        })
        .await?;

        // Wait for registration ack
        let msg = conn.recv().await?;
        match msg {
            HubMessage::Registered => {
                tracing::info!("registered with HUB as IN");
            }
            _ => return Err(InNodeError::UnexpectedMessage),
        }

        // Receive route config
        let msg = conn.recv().await?;
        match msg {
            HubMessage::RouteConfig { rules } => {
                tracing::info!("received {} route rules", rules.len());
                self.update_route_rules(rules).await;
            }
            _ => return Err(InNodeError::UnexpectedMessage),
        }

        // Receive initial OUT list
        let msg = conn.recv().await?;
        match msg {
            HubMessage::OutUpdate { outs } => {
                tracing::info!("received {} OUTs", outs.len());
                self.update_outs(outs).await;
            }
            _ => return Err(InNodeError::UnexpectedMessage),
        }

        self.hub_conn = Some(conn);
        Ok(())
    }

    /// Run message loop to receive updates from HUB.
    pub async fn run(&self) -> Result<(), InNodeError> {
        let conn = self.hub_conn.as_ref().ok_or(InNodeError::NotConnected)?;

        loop {
            let msg = conn.recv().await?;
            match msg {
                HubMessage::RouteConfig { rules } => {
                    tracing::info!("route config updated: {} rules", rules.len());
                    self.update_route_rules(rules).await;
                }
                HubMessage::OutUpdate { outs } => {
                    tracing::info!("OUT list updated: {} OUTs", outs.len());
                    self.update_outs(outs).await;
                }
                HubMessage::Registered => {
                    // Ignore duplicate
                }
            }
        }
    }

    /// Update routing rules.
    pub async fn update_route_rules(&self, rules: Vec<RuleConfig>) {
        let mut router = self.router.write().await;
        *router = Router::new(rules);
    }

    /// Update available OUTs.
    pub async fn update_outs(&self, outs: Vec<OutInfo>) {
        let mut out_map = self.outs.write().await;
        out_map.clear();
        for out in outs {
            out_map.insert(out.id.clone(), out);
        }
    }

    /// Resolve routes for a given target using the router.
    /// Returns RouteEntry pairs (label + tag) for routing decisions.
    pub async fn resolve_routes(&self, target: &str) -> Vec<RouteEntry> {
        let router = self.router.read().await;

        // Parse target to extract host and port
        let (host, port) = if let Some(colon_pos) = target.rfind(':') {
            let host = &target[..colon_pos];
            let port = target[colon_pos + 1..].parse::<u16>().unwrap_or(0);
            (host, port)
        } else {
            (target, 0)
        };

        // Check if host is a domain or IP
        let is_ip = host.parse::<IpAddr>().is_ok();
        let domain = if is_ip { None } else { Some(host) };

        // Try to parse as IP address, or resolve domain if GeoIP is needed
        let ip: Option<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            Some(ip)
        } else {
            // Try DNS resolution for GeoIP lookup
            tokio::net::lookup_host(format!("{}:{}", host, port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
                .map(|addr| addr.ip())
        };

        let addr: SocketAddr = ip
            .map(|ip| SocketAddr::new(ip, port))
            .unwrap_or_else(|| format!("0.0.0.0:{}", port).parse().unwrap());

        // Look up region codes from GeoIP database
        let region_codes = ip.and_then(|ip| {
            self.geolite2
                .as_ref()
                .and_then(|geolite2| geolite2.lookup(ip))
        });

        let ctx = MatchContext {
            address: addr,
            domain,
            region_codes: region_codes.as_deref(),
        };

        let results = router.match_target(&ctx).await;

        // Flatten results into RouteEntry list, preserving tags
        results
            .into_iter()
            .flat_map(|group| {
                group.into_iter().map(|r| RouteEntry {
                    label: r.label,
                    tag: r.tag,
                })
            })
            .collect()
    }

    /// Get HUB connection for forwarding.
    pub fn hub_conn(&self) -> Option<&HubConnection> {
        self.hub_conn.as_ref()
    }

    /// Get available OUTs.
    pub async fn get_outs(&self) -> Vec<OutInfo> {
        self.outs.read().await.values().cloned().collect()
    }

    /// Get HubConnector for creating proxied connections through HUB.
    pub fn hub_connector(&self) -> Option<HubConnector> {
        self.hub_conn
            .as_ref()
            .map(|conn| HubConnector::new(Arc::clone(conn.tunnel())))
    }

    /// Check if the HUB connection is still alive.
    pub async fn is_hub_connected(&self) -> bool {
        if let Some(conn) = &self.hub_conn {
            !conn.tunnel().is_closed().await
        } else {
            false
        }
    }

    /// Create a proxied TCP connection to target.
    ///
    /// Resolves routing and handles:
    /// 1. DIRECT - connect directly from IN to target
    /// 2. Custom label with direct OUT - connect directly to OUT
    /// 3. Fallback - relay through HUB
    pub async fn connect(&self, target: &str) -> Result<ProxyStream, InNodeError> {
        let routes = self.resolve_routes(target).await;

        // Check for DIRECT label first - exit directly from IN
        for route in &routes {
            if matches!(route.label, Label::BuiltIn(BuiltInLabel::Direct)) {
                tracing::debug!("DIRECT exit from IN for {}", target);
                return self.connect_direct(target).await;
            }
        }

        // Try to find a direct OUT connection for the first matching route
        for route in &routes {
            if let Label::Custom(label) = &route.label {
                // Check if this OUT has direct connection
                if let Some(stream) = self.try_direct_out_connect(label, target, &routes).await? {
                    tracing::debug!("using direct OUT connection for {}", target);
                    return Ok(ProxyStream::from_quic(stream));
                }
            }
        }

        // Check if HUB connection is still alive before using it
        if !self.is_hub_connected().await {
            return Err(InNodeError::NotConnected);
        }

        // Fall back to HUB relay
        let connector = self.hub_connector().ok_or(InNodeError::NotConnected)?;
        let stream = connector.connect_tcp_with_routes(target, routes).await?;

        Ok(ProxyStream::from_quic(stream))
    }

    /// Connect directly to target without proxy (for DIRECT routing).
    async fn connect_direct(&self, target: &str) -> Result<ProxyStream, InNodeError> {
        use tokio::net::TcpStream;

        let tcp_stream = TcpStream::connect(target)
            .await
            .map_err(|e| InNodeError::DirectConnect(e.to_string()))?;

        tcp_stream
            .set_nodelay(true)
            .map_err(|e| InNodeError::DirectConnect(e.to_string()))?;

        Ok(ProxyStream::from_tcp(tcp_stream))
    }

    /// Try to connect directly to an OUT node.
    async fn try_direct_out_connect(
        &self,
        out_label: &str,
        target: &str,
        routes: &[RouteEntry],
    ) -> Result<Option<Stream>, InNodeError> {
        use super::message::{ForwardRequest, TcpForwardRequest};

        // Check if this OUT tag is in our direct filter
        // Empty filter means no direct connections allowed
        if self.direct_filter.is_empty() || !self.direct_filter.contains(&out_label.to_string()) {
            return Ok(None);
        }

        // Find OUT with this tag
        let out_info = {
            let outs = self.outs.read().await;
            outs.values()
                .find(|out| out.labels.contains(&out_label.to_string()))
                .cloned()
        };

        let out_info = match out_info {
            Some(info) => info,
            None => return Ok(None),
        };

        // Check if OUT has direct address
        let direct_addr = match &out_info.direct_addr {
            Some(addr) => addr.clone(),
            None => return Ok(None),
        };

        // Try to get or create direct tunnel
        let tunnel = self
            .get_or_create_direct_tunnel(&out_info.id, &direct_addr)
            .await?;

        // Open stream and send request
        let stream = tunnel.open_bi_stream().await?;
        tracing::debug!(
            "opened direct stream {} to OUT {} at {}",
            stream.id(),
            out_info.id,
            direct_addr
        );

        // Send forward request directly to OUT
        let request = ForwardRequest::Tcp(TcpForwardRequest {
            host: target.to_string(),
            address: None,
            routes: routes.to_vec(),
        });
        let json = serde_json::to_vec(&request).map_err(|e| {
            InNodeError::Connect(InLikeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                e,
            )))
        })?;

        let len = (json.len() as u32).to_be_bytes();
        stream.send(&len).await?;
        stream.send(&json).await?;

        tracing::info!(
            "📡 Direct connection to {} via OUT {} ({})",
            target,
            out_info.name.as_deref().unwrap_or(&out_info.id),
            direct_addr
        );

        Ok(Some(stream))
    }

    /// Get or create a direct tunnel to an OUT node.
    async fn get_or_create_direct_tunnel(
        &self,
        out_id: &str,
        direct_addr: &str,
    ) -> Result<Arc<Tunnel>, InNodeError> {
        // Check if we already have a connection
        {
            let tunnels = self.direct_out_tunnels.read().await;
            if let Some(tunnel) = tunnels.get(out_id) {
                if !tunnel.is_closed().await {
                    return Ok(Arc::clone(tunnel));
                }
            }
        }

        // Parse address
        let addr: SocketAddr = direct_addr.parse().map_err(|e| {
            InNodeError::Connect(InLikeError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid direct address {}: {}", direct_addr, e),
            )))
        })?;

        // Create new connection
        tracing::info!("establishing direct connection to OUT at {}", direct_addr);
        let tunnel = Tunnel::connect_with_cert(
            addr,
            None,
            1, // Single TCP connection for direct
            self.client_config.pem_path.as_deref(),
            self.client_config.ca_pem_path.as_deref(),
        )
        .await?;

        let tunnel = Arc::new(tunnel);

        // Store for reuse
        {
            let mut tunnels = self.direct_out_tunnels.write().await;
            tunnels.insert(out_id.to_string(), Arc::clone(&tunnel));
        }

        Ok(tunnel)
    }

    /// Open a UDP forwarding stream.
    pub async fn open_udp_forward(&self) -> Result<Stream, InNodeError> {
        let connector = self.hub_connector().ok_or(InNodeError::NotConnected)?;
        // For UDP, we don't have a target to route, so use empty routes
        // (routing will be determined by the stream content or default)
        let stream = connector.open_udp_forward(vec![]).await?;
        Ok(stream)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InNodeError {
    #[error("tunnel error: {0}")]
    Tunnel(#[from] TunnelError),
    #[error("connection error: {0}")]
    Connection(#[from] ConnectionError),
    #[error("connect error: {0}")]
    Connect(#[from] InLikeError),
    #[error("direct connect error: {0}")]
    DirectConnect(String),
    #[error("not connected to HUB")]
    NotConnected,
    #[error("unexpected message from HUB")]
    UnexpectedMessage,
}
