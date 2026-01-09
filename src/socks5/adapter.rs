//! SOCKS5 socket adapter for unified UDP relay.

use std::net::SocketAddr;
use std::sync::Arc;

use socks5_server::{AssociatedUdpSocket, proto::Address};

use crate::relay::{UdpClientDatagram, UdpClientSocket, UdpRelayError};

/// Adapter that wraps a SOCKS5 AssociatedUdpSocket to implement ClientSocket.
pub struct Socks5ClientSocket {
    socket: Arc<AssociatedUdpSocket>,
}

impl Socks5ClientSocket {
    pub fn new(socket: Arc<AssociatedUdpSocket>) -> Self {
        Self { socket }
    }
}

#[async_trait::async_trait]
impl UdpClientSocket for Socks5ClientSocket {
    async fn recv(&self, _buf: &mut [u8]) -> Result<UdpClientDatagram, UdpRelayError> {
        let (data, header, client_addr) = self
            .socket
            .recv_from()
            .await
            .map_err(|(e, _)| UdpRelayError::Protocol(e.to_string()))?;

        // Parse destination from SOCKS5 header
        let dest = match header.address {
            Address::SocketAddress(addr) => addr,
            Address::DomainAddress(domain, port) => {
                let domain_str = String::from_utf8_lossy(&domain);
                return Err(UdpRelayError::Protocol(format!(
                    "domain addresses not supported: {}:{}",
                    domain_str, port
                )));
            }
        };

        Ok(UdpClientDatagram::new(client_addr, dest, data.to_vec()))
    }

    async fn send(
        &self,
        data: &[u8],
        from: SocketAddr,
        to: SocketAddr,
    ) -> Result<(), UdpRelayError> {
        let header = socks5_server::proto::UdpHeader {
            frag: 0,
            address: Address::SocketAddress(from),
        };

        self.socket
            .send_to(data, &header, to)
            .await
            .map_err(UdpRelayError::Io)?;
        Ok(())
    }
}
