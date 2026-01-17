use async_trait::async_trait;
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{primitives::SocketDestination, udp_forwarder::OutgoingUdpPacket};

#[async_trait]
pub trait Outbound {
  type TcpStream: AsyncRead + AsyncWrite;
  type UdpPacketStream: Sink<OutgoingUdpPacket> + Stream<Item = OutgoingUdpPacket>;

  async fn connect_tcp(
    &self,
    destination: SocketDestination,
  ) -> Result<Self::TcpStream, OutboundError>;

  async fn get_udp_packet_stream(&self) -> Result<Self::UdpPacketStream, OutboundError>;
}

#[derive(thiserror::Error, Debug)]
pub enum OutboundError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
}
