//! Unified TCP relay logic for both SOCKS5 and TPROXY.
//!
//! This module provides common TCP relay functionality. The only difference
//! between SOCKS5 and TPROXY is how they accept connections and extract the
//! target - this is abstracted via the `TcpClientStream` trait.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::fake_ip::FakeIpResolver;
use crate::node::InNode;

/// Abstraction over client-facing TCP connections.
///
/// Different protocols (SOCKS5, TPROXY) have different ways of accepting
/// connections and determining the target address. This trait provides
/// a unified interface for the relay logic.
pub trait TcpClientStream: AsyncRead + AsyncWrite + Unpin + Send {
    /// Get the original destination address.
    fn original_dst(&self) -> SocketAddr;

    /// Get the client's source address (for logging).
    fn source(&self) -> SocketAddr;
}

/// Configuration for TCP relay logging.
#[derive(Debug, Clone, Copy)]
pub struct TcpRelayLogConfig {
    /// Prefix for log messages.
    pub prefix: &'static str,
}

impl Default for TcpRelayLogConfig {
    fn default() -> Self {
        Self { prefix: "TCP" }
    }
}

impl TcpRelayLogConfig {
    pub fn with_prefix(mut self, prefix: &'static str) -> Self {
        self.prefix = prefix;
        self
    }
}

/// Relay a TCP connection through the proxy.
///
/// This handles:
/// 1. Resolving the target (fake IP → hostname if resolver is available)
/// 2. Connecting via InNode
/// 3. Relaying data bidirectionally
pub async fn relay_tcp<S: TcpClientStream>(
    client: S,
    in_node: &InNode,
    fake_ip_resolver: Option<&Arc<FakeIpResolver>>,
    log_config: TcpRelayLogConfig,
) -> Result<(), TcpRelayError> {
    let original_dst = client.original_dst();
    let source = client.source();

    // Resolve fake IP to hostname if available
    let target = resolve_target(fake_ip_resolver, original_dst);

    tracing::debug!(
        "{}: {} -> {} (target: {})",
        log_config.prefix,
        source,
        original_dst,
        target
    );

    // Connect through InNode
    let proxy_stream = in_node
        .connect(&target)
        .await
        .map_err(|e| TcpRelayError::Connect(e.to_string()))?;

    tracing::debug!(
        "{}: connected to {} via {:?}",
        log_config.prefix,
        target,
        proxy_stream
    );

    // Relay data between client and proxy
    proxy_stream
        .relay_bidirectional(client)
        .await
        .map_err(|e| TcpRelayError::Relay(e.to_string()))?;

    tracing::debug!("{}: relay completed for {}", log_config.prefix, target);

    Ok(())
}

/// Relay a TCP connection with a pre-resolved target.
///
/// Use this when the target is already known (e.g., from SOCKS5 CONNECT command).
pub async fn relay_tcp_with_target<C>(
    client: C,
    target: &str,
    in_node: &InNode,
    log_config: TcpRelayLogConfig,
) -> Result<(), TcpRelayError>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    tracing::debug!("{}: connecting to {}", log_config.prefix, target);

    // Connect through InNode
    let proxy_stream = in_node
        .connect(target)
        .await
        .map_err(|e| TcpRelayError::Connect(e.to_string()))?;

    tracing::debug!(
        "{}: connected to {} via {:?}",
        log_config.prefix,
        target,
        proxy_stream
    );

    // Relay data between client and proxy
    proxy_stream
        .relay_bidirectional(client)
        .await
        .map_err(|e| TcpRelayError::Relay(e.to_string()))?;

    tracing::debug!("{}: relay completed for {}", log_config.prefix, target);

    Ok(())
}

/// Resolve target address, translating fake IPs to hostnames if resolver is available.
pub fn resolve_target(
    fake_ip_resolver: Option<&Arc<FakeIpResolver>>,
    original_dst: SocketAddr,
) -> String {
    if let Some(resolver) = fake_ip_resolver {
        if let Some((real_ip, hostname)) = resolver.resolve(&original_dst.ip()) {
            if let Some(hostname) = hostname {
                // Use hostname for the connection (important for SNI in TLS)
                tracing::debug!(
                    "resolved fake IP {} to hostname {} (real IP: {})",
                    original_dst.ip(),
                    hostname,
                    real_ip
                );
                return format!("{}:{}", hostname, original_dst.port());
            }
            // No hostname stored, use real IP
            tracing::debug!(
                "fake IP {} resolved to real IP {} (no hostname)",
                original_dst.ip(),
                real_ip
            );
            return format!("{}:{}", real_ip, original_dst.port());
        }
    }
    // Not a fake IP or no resolver, use as-is
    original_dst.to_string()
}

/// Resolve target from SOCKS5 Address, translating fake IPs to hostnames.
pub fn resolve_target_from_socks5_address(
    addr: &socks5_server::proto::Address,
    fake_ip_resolver: Option<&FakeIpResolver>,
) -> String {
    match addr {
        socks5_server::proto::Address::SocketAddress(socket_addr) => {
            if let Some(resolver) = fake_ip_resolver {
                if let Some((real_ip, hostname)) = resolver.resolve(&socket_addr.ip()) {
                    if let Some(hostname) = hostname {
                        tracing::debug!(
                            "resolved fake IP {} to hostname {} (real IP: {})",
                            socket_addr.ip(),
                            hostname,
                            real_ip
                        );
                        return format!("{}:{}", hostname, socket_addr.port());
                    }
                    tracing::debug!(
                        "fake IP {} resolved to real IP {} (no hostname)",
                        socket_addr.ip(),
                        real_ip
                    );
                    return format!("{}:{}", real_ip, socket_addr.port());
                }
            }
            socket_addr.to_string()
        }
        socks5_server::proto::Address::DomainAddress(domain, port) => {
            let domain_str = String::from_utf8_lossy(domain);
            format!("{}:{}", domain_str, port)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TcpRelayError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("connect error: {0}")]
    Connect(String),
    #[error("relay error: {0}")]
    Relay(String),
}
