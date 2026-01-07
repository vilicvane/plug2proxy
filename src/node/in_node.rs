use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::tunnel::{Stream, Tunnel, TunnelError};

use super::connection::{ConnectionError, HubConnection};
use super::connector::HubConnector;
use super::in_like::InLikeError;
use super::message::{HubMessage, NodeMessage, NodeRole, OutInfo, RouteRule};

/// IN node - entry point for proxied traffic.
pub struct InNode {
    id: String,
    /// Routing rules (received from HUB).
    route_rules: Arc<RwLock<Vec<RouteRule>>>,
    /// Available OUTs (received from HUB).
    outs: Arc<RwLock<HashMap<String, OutInfo>>>,
    /// Connection to HUB.
    hub_conn: Option<HubConnection>,
}

impl InNode {
    pub fn new(id: String) -> Self {
        Self {
            id,
            route_rules: Arc::new(RwLock::new(Vec::new())),
            outs: Arc::new(RwLock::new(HashMap::new())),
            hub_conn: None,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    /// Connect to HUB.
    pub async fn connect_hub(&mut self, addr: SocketAddr) -> Result<(), InNodeError> {
        // Establish tunnel (single TCP for now)
        let tunnel = Arc::new(Tunnel::connect(addr, None, 1).await?);

        // Create control connection
        let conn = HubConnection::new(Arc::clone(&tunnel)).await?;

        // Register with HUB
        conn.send(&NodeMessage::Register {
            role: NodeRole::In,
            id: self.id.clone(),
            tags: vec![],
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
    pub async fn update_route_rules(&self, rules: Vec<RouteRule>) {
        let mut route_rules = self.route_rules.write().await;
        *route_rules = rules;
    }

    /// Update available OUTs.
    pub async fn update_outs(&self, outs: Vec<OutInfo>) {
        let mut out_map = self.outs.write().await;
        out_map.clear();
        for out in outs {
            out_map.insert(out.id.clone(), out);
        }
    }

    /// Determine route tag for a given target (e.g., domain).
    pub async fn resolve_tag(&self, target: &str) -> Option<String> {
        let rules = self.route_rules.read().await;
        for rule in rules.iter() {
            // TODO: Implement proper pattern matching.
            if target.contains(&rule.pattern) {
                return Some(rule.tag.clone());
            }
        }
        None
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
        let tag = self.resolve_tag(target).await;

        // TODO: Based on tag, pick the right connector:
        // - HubConnector for HUB-routed traffic
        // - DirectOutConnector for direct OUT connections
        // - LocalConnector for local exit
        //
        // For now, always use HubConnector.
        let connector = self.hub_connector().ok_or(InNodeError::NotConnected)?;
        let stream = connector.connect_with_tag(target, tag.as_deref()).await?;

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
