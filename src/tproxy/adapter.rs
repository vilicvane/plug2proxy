//! TPROXY socket adapter for unified UDP relay.

use std::net::SocketAddr;
use std::sync::Arc;

use crate::fake_ip::FakeIpResolver;
use crate::relay::{UdpClientDatagram, UdpClientSocket, UdpRelayError};

use super::udp::TProxyUdpSocket;

/// Adapter that wraps a TProxyUdpSocket to implement ClientSocket.
pub struct TProxyClientSocket {
    socket: Arc<TProxyUdpSocket>,
    fake_ip_resolver: Option<Arc<FakeIpResolver>>,
}

impl TProxyClientSocket {
    pub fn new(socket: Arc<TProxyUdpSocket>) -> Self {
        Self {
            socket,
            fake_ip_resolver: None,
        }
    }

    pub fn with_fake_ip_resolver(mut self, resolver: Arc<FakeIpResolver>) -> Self {
        self.fake_ip_resolver = Some(resolver);
        self
    }

    /// Resolve fake IP to real destination.
    fn resolve_dest(&self, original_dst: SocketAddr) -> SocketAddr {
        if let Some(resolver) = &self.fake_ip_resolver {
            if let Some((real_ip, _)) = resolver.resolve(&original_dst.ip()) {
                return SocketAddr::new(real_ip, original_dst.port());
            }
        }
        original_dst
    }
}

#[async_trait::async_trait]
impl UdpClientSocket for TProxyClientSocket {
    async fn recv(&self, buf: &mut [u8]) -> Result<UdpClientDatagram, UdpRelayError> {
        let datagram = self.socket.recv(buf).await.map_err(UdpRelayError::Io)?;

        // Resolve fake IP if configured
        let dest = self.resolve_dest(datagram.original_dst);

        Ok(UdpClientDatagram::new(datagram.source, dest, datagram.data))
    }

    async fn send(
        &self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), UdpRelayError> {
        self.socket
            .send_from(data, from, to)
            .await
            .map_err(UdpRelayError::Io)?;
        Ok(())
    }
}
