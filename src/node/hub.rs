use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use crate::tunnel::{QuicConfig, QuicError, Tunnel, TunnelError};

use super::connection::{ConnectionError, NodeConnection};
use super::message::{HubMessage, NodeMessage, NodeRole, OutInfo, RouteRule};

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
    conn: NodeConnection,
}

struct OutConnection {
    id: String,
    tags: Vec<String>,
    #[allow(dead_code)]
    conn: NodeConnection,
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

    async fn handle_connection(&self, stream: TcpStream) -> Result<(), HubError> {
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
                        let mut ins = self.ins.write().await;
                        ins.insert(id, InConnection { conn });
                    }
                    NodeRole::Out => {
                        // Store OUT connection
                        let mut outs = self.outs.write().await;
                        outs.insert(
                            id.clone(),
                            OutConnection {
                                id: id.clone(),
                                tags,
                                conn,
                            },
                        );
                        drop(outs);

                        // Notify all INs about new OUT
                        self.broadcast_out_update().await;
                    }
                }
            }
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
