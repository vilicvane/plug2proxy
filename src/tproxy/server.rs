//! TPROXY server for transparent proxying (TCP and UDP).

use std::net::SocketAddr;
use std::sync::Arc;

use crate::fake_ip::FakeIpResolver;
use crate::node::{InNode, UdpForwardHandler};
use crate::relay::{
    DirectUdpForwarder, TcpRelayLogConfig, UdpRelayLogConfig, relay_tcp, relay_udp_direct,
    relay_udp_tunnel,
};

use super::adapter::TProxyClientSocket;
use super::tcp::TProxyTcpListener;
use super::udp::TProxyUdpSocket;

/// TPROXY server that handles transparently proxied connections.
pub struct TProxyServer {
    in_node: Arc<InNode>,
    listen_addr: SocketAddr,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
}

impl TProxyServer {
    /// Create a new TPROXY server.
    pub fn new(in_node: Arc<InNode>, listen_addr: SocketAddr) -> Self {
        Self {
            in_node,
            listen_addr,
            fake_ip_resolver: None,
        }
    }

    /// Set the fake IP resolver for translating fake IPs back to hostnames.
    pub fn with_fake_ip_resolver(mut self, resolver: Arc<FakeIpResolver>) -> Self {
        self.fake_ip_resolver = Some(resolver);
        self
    }

    /// Run the TPROXY server (TCP and UDP).
    pub async fn run(&self) -> Result<(), TProxyServerError> {
        let mark = self.in_node.mark();

        // Start TCP listener
        let tcp_listener = TProxyTcpListener::bind(self.listen_addr, mark).await?;
        tracing::info!("TPROXY TCP server listening on {}", self.listen_addr);

        // Start UDP listener
        let udp_socket = TProxyUdpSocket::bind(self.listen_addr, mark).await?;
        tracing::info!("TPROXY UDP server listening on {}", self.listen_addr);

        let in_node_tcp = Arc::clone(&self.in_node);
        let fake_ip_resolver_tcp = self.fake_ip_resolver.clone();

        let in_node_udp = Arc::clone(&self.in_node);
        let fake_ip_resolver_udp = self.fake_ip_resolver.clone();

        // Run TCP and UDP handlers concurrently
        tokio::select! {
            result = Self::run_tcp_loop(tcp_listener, in_node_tcp, fake_ip_resolver_tcp) => {
                result?;
            }
            result = Self::run_udp_loop(udp_socket, in_node_udp, fake_ip_resolver_udp) => {
                result?;
            }
        }

        Ok(())
    }

    /// TCP accept loop.
    async fn run_tcp_loop(
        listener: TProxyTcpListener,
        in_node: Arc<InNode>,
        fake_ip_resolver: Option<Arc<FakeIpResolver>>,
    ) -> Result<(), TProxyServerError> {
        let log_config = TcpRelayLogConfig::default().with_prefix("TPROXY TCP");

        loop {
            match listener.accept().await {
                Ok(conn) => {
                    let in_node = Arc::clone(&in_node);
                    let fake_ip_resolver = fake_ip_resolver.clone();

                    tokio::spawn(async move {
                        if let Err(e) =
                            relay_tcp(conn, &in_node, fake_ip_resolver.as_ref(), log_config).await
                        {
                            tracing::debug!("TPROXY TCP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("TPROXY TCP accept error: {}", e);
                }
            }
        }
    }

    /// UDP receive loop.
    async fn run_udp_loop(
        socket: TProxyUdpSocket,
        in_node: Arc<InNode>,
        fake_ip_resolver: Option<Arc<FakeIpResolver>>,
    ) -> Result<(), TProxyServerError> {
        let socket = Arc::new(socket);

        // Create client socket adapter
        let mut client_socket = TProxyClientSocket::new(Arc::clone(&socket));
        if let Some(resolver) = fake_ip_resolver {
            client_socket = client_socket.with_fake_ip_resolver(resolver);
        }
        let client_socket = Arc::new(client_socket);

        // Open UDP forwarder once - it's shared across all sessions
        let udp_handler = in_node
            .open_udp_forward()
            .await
            .map_err(|e| TProxyServerError::Connect(e.to_string()))?;

        let log_config = UdpRelayLogConfig::default().with_prefix("TPROXY UDP");

        match udp_handler {
            UdpForwardHandler::Tunnel(tunnel_stream) => {
                tracing::info!(
                    "TPROXY UDP using tunnel stream {} for forwarding",
                    tunnel_stream.id()
                );
                relay_udp_tunnel(client_socket, Arc::new(tunnel_stream), log_config)
                    .await
                    .map_err(|e| TProxyServerError::Relay(e.to_string()))
            }
            UdpForwardHandler::Direct(direct_handler) => {
                tracing::info!("TPROXY UDP using direct handler for forwarding");
                let forwarder =
                    Arc::new(DirectUdpForwarder::new(Arc::clone(direct_handler.socket())));
                relay_udp_direct(client_socket, forwarder, log_config)
                    .await
                    .map_err(|e| TProxyServerError::Relay(e.to_string()))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TProxyServerError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("relay error: {0}")]
    Relay(String),
}
