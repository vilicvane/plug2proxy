use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::route::{MatchContext, Router, RuleConfig};
use crate::tunnel::{Stream, Tunnel, TunnelError};

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
    /// Available OUTs (received from HUB).
    outs: Arc<RwLock<HashMap<String, OutInfo>>>,
    /// Connection to HUB.
    hub_conn: Option<HubConnection>,
}

impl InNode {
    pub fn new(client_config: ClientConfig) -> Self {
        Self {
            client_config,
            router: Arc::new(RwLock::new(Router::new(Vec::new()))),
            outs: Arc::new(RwLock::new(HashMap::new())),
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
            tags: vec![],
            routing_rules: vec![],
            routing_priority: 0,
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
        let domain = if host.chars().any(|c| !c.is_ascii_digit() && c != '.') {
            Some(host)
        } else {
            None
        };

        // Try to parse as IP address, or use a placeholder
        let addr: SocketAddr = target.parse().unwrap_or_else(|_| {
            // Can't parse as socket addr, use placeholder
            format!("0.0.0.0:{}", port).parse().unwrap()
        });

        let ctx = MatchContext {
            address: addr,
            domain,
            region_codes: None, // GeoIP not implemented yet
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

    /// Create a proxied connection to target.
    ///
    /// Resolves routing and delegates to the appropriate connector.
    pub async fn connect(&self, target: &str) -> Result<Stream, InNodeError> {
        let routes = self.resolve_routes(target).await;

        // TODO: Based on routes, pick the right connector:
        // - HubConnector for HUB-routed traffic
        // - DirectOutConnector for direct OUT connections
        // - LocalConnector for local exit
        //
        // For now, always use HubConnector.
        let connector = self.hub_connector().ok_or(InNodeError::NotConnected)?;
        let stream = connector.connect_with_routes(target, routes).await?;

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
    #[error("not connected to HUB")]
    NotConnected,
    #[error("unexpected message from HUB")]
    UnexpectedMessage,
}
