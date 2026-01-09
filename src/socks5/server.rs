use std::net::SocketAddr;
use std::sync::Arc;

use lits::duration;
use socks5_server::{
    AssociatedUdpSocket, Command, IncomingConnection, Server,
    proto::{Address, Reply},
};
use tokio::net::UdpSocket;

use crate::fake_ip::FakeIpResolver;
use crate::node::{InNode, UdpForwardHandler};
use crate::relay::{
    DirectUdpForwarder, UdpRelayLogConfig, relay_udp_direct, relay_udp_tunnel,
    resolve_target_from_socks5_address,
};

use super::adapter::Socks5ClientSocket;

/// SOCKS5 server that accepts connections and proxies through InNode.
pub struct Socks5Server {
    in_node: Arc<InNode>,
    bind_addr: SocketAddr,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
}

impl Socks5Server {
    pub fn new(in_node: Arc<InNode>, bind_addr: SocketAddr) -> Self {
        Self {
            in_node,
            bind_addr,
            fake_ip_resolver: None,
        }
    }

    /// Set the fake IP resolver for translating fake IPs to hostnames.
    pub fn with_fake_ip_resolver(mut self, resolver: Arc<FakeIpResolver>) -> Self {
        self.fake_ip_resolver = Some(resolver);
        self
    }

    /// Run the SOCKS5 server.
    /// Returns when HUB connection is lost.
    pub async fn run(&self) -> Result<(), Socks5Error> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        let auth = Arc::new(socks5_server::auth::NoAuth);
        let server = Server::new(listener, auth);

        tracing::info!("SOCKS5 server listening on {}", self.bind_addr);

        // Spawn a task to check HUB connection health
        let in_node_health = Arc::clone(&self.in_node);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(duration!("1 second")).await;
                if !in_node_health.is_hub_connected().await {
                    tracing::warn!("HUB connection lost, shutting down SOCKS5 server");
                    let _ = shutdown_tx.send(());
                    break;
                }
            }
        });

        loop {
            tokio::select! {
                result = server.accept() => {
                    match result {
                        Ok((conn, addr)) => {
                            tracing::debug!("accepted SOCKS5 connection from {}", addr);

                            let in_node = Arc::clone(&self.in_node);
                            let bind_addr = self.bind_addr;
                            let fake_ip_resolver = self.fake_ip_resolver.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(conn, in_node, bind_addr, fake_ip_resolver).await {
                                    tracing::error!("SOCKS5 client {} error: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("failed to accept connection: {}", e);
                        }
                    }
                }
                _ = &mut shutdown_rx => {
                    tracing::info!("SOCKS5 server shutting down");
                    return Ok(());
                }
            }
        }
    }
}

/// Handle a single SOCKS5 connection.
async fn handle_connection<A>(
    conn: IncomingConnection<A, socks5_server::connection::state::NeedAuthenticate>,
    in_node: Arc<InNode>,
    bind_addr: SocketAddr,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
) -> Result<(), Socks5Error> {
    // Perform authentication
    let (conn, _auth_result) = conn.authenticate().await.map_err(|(e, _)| e)?;

    // Wait for command from client
    match conn.wait().await.map_err(|(e, _)| e)? {
        Command::Connect(connect, addr) => {
            let target = resolve_target_from_socks5_address(&addr, fake_ip_resolver.as_deref());
            tracing::debug!("SOCKS5 CONNECT to {}", target);
            handle_connect(connect, &target, in_node).await
        }
        Command::Bind(_bind, _addr) => {
            tracing::warn!("BIND command not supported");
            Err(Socks5Error::UnsupportedCommand)
        }
        Command::Associate(associate, addr) => {
            tracing::debug!("SOCKS5 UDP ASSOCIATE from {}", addr);
            handle_udp_associate(associate, in_node, bind_addr).await
        }
    }
}

/// Handle TCP CONNECT command.
async fn handle_connect(
    connect: socks5_server::Connect<socks5_server::connection::connect::state::NeedReply>,
    target: &str,
    in_node: Arc<InNode>,
) -> Result<(), Socks5Error> {
    // Connect through InNode
    let mut proxy_stream = match in_node.connect(target).await {
        Ok(stream) => stream,
        Err(e) => {
            tracing::error!("failed to connect to {}: {}", target, e);
            let _ = connect
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await;
            return Err(Socks5Error::ConnectFailed(e.into()));
        }
    };

    tracing::debug!("SOCKS5 TCP: connected to {} via {:?}", target, proxy_stream);

    // Send success reply
    let mut client = connect
        .reply(Reply::Succeeded, Address::unspecified())
        .await
        .map_err(|(e, _)| e)?;

    // Relay data bidirectionally
    let result = proxy_stream
        .relay_bidirectional(&mut client)
        .await
        .map_err(|e| Socks5Error::IoError(std::io::Error::other(e)));

    tracing::debug!("SOCKS5 TCP: relay completed for {}", target);
    result
}

/// Handle UDP ASSOCIATE command.
async fn handle_udp_associate(
    associate: socks5_server::Associate<socks5_server::connection::associate::state::NeedReply>,
    in_node: Arc<InNode>,
    server_addr: SocketAddr,
) -> Result<(), Socks5Error> {
    // Bind UDP relay socket
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let relay_socket = UdpSocket::bind(bind_addr).await?;
    let relay_local_addr = relay_socket.local_addr()?;

    tracing::debug!("SOCKS5 UDP: relay socket bound to {}", relay_local_addr);

    // Build reply address (use server IP with relay port)
    let reply_ip = if server_addr.ip().is_loopback() {
        if server_addr.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
    } else {
        server_addr.ip()
    };
    let reply_addr = SocketAddr::new(reply_ip, relay_local_addr.port());

    tracing::debug!("SOCKS5 UDP: relay address {} sent to client", reply_addr);

    // Send success reply with relay address
    let mut associate = associate
        .reply(Reply::Succeeded, Address::SocketAddress(reply_addr))
        .await
        .map_err(|(e, _)| e)?;

    // Wrap relay socket with SOCKS5 UDP handling
    let associated_socket = AssociatedUdpSocket::new(relay_socket, 65535);

    // Spawn UDP relay task
    let relay_task = tokio::spawn(async move {
        if let Err(e) = run_udp_relay(associated_socket, in_node).await {
            tracing::error!("SOCKS5 UDP relay error: {}", e);
        }
    });

    // Wait for TCP control connection to close
    if let Err(e) = associate.wait_close().await {
        tracing::debug!("SOCKS5 TCP control connection closed: {}", e);
    }

    tracing::debug!("SOCKS5 UDP: control connection closed, stopping relay");
    relay_task.abort();

    Ok(())
}

/// Run the UDP relay between SOCKS5 client and tunnel/direct.
async fn run_udp_relay(
    socket: AssociatedUdpSocket,
    in_node: Arc<InNode>,
) -> Result<(), Socks5Error> {
    // Open UDP forwarding handler (tunnel or direct)
    let udp_handler = match in_node.open_udp_forward().await {
        Ok(handler) => handler,
        Err(e) => {
            tracing::error!("failed to open UDP forward handler: {}", e);
            return Err(Socks5Error::ConnectFailed(e.into()));
        }
    };

    // Create client socket adapter
    let client_socket = Arc::new(Socks5ClientSocket::new(Arc::new(socket)));
    let log_config = UdpRelayLogConfig::default().with_prefix("SOCKS5 UDP");

    match udp_handler {
        UdpForwardHandler::Tunnel(tunnel_stream) => {
            tracing::debug!(
                "SOCKS5 UDP: using tunnel stream {} for forwarding",
                tunnel_stream.id()
            );
            relay_udp_tunnel(client_socket, Arc::new(tunnel_stream), log_config)
                .await
                .map_err(|e| Socks5Error::RelayError(e.into()))
        }
        UdpForwardHandler::Direct(direct_handler) => {
            tracing::debug!("SOCKS5 UDP: using direct handler for forwarding");
            let forwarder = Arc::new(DirectUdpForwarder::new(Arc::clone(direct_handler.socket())));
            relay_udp_direct(client_socket, forwarder, log_config)
                .await
                .map_err(|e| Socks5Error::RelayError(e.into()))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("SOCKS5 protocol error: {0}")]
    ProtocolError(#[from] socks5_server::proto::Error),

    #[error("unsupported SOCKS5 command")]
    UnsupportedCommand,

    #[error("connection failed: {0}")]
    ConnectFailed(Box<dyn std::error::Error + Send + Sync>),

    #[error("relay error: {0}")]
    RelayError(Box<dyn std::error::Error + Send + Sync>),
}
