use async_trait::async_trait;
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{primitives::Destination, udp::UdpPacket};

#[async_trait]
pub trait Inbound {
  type TcpStream: AsyncRead + AsyncWrite;
  type UdpPacketStream: Sink<UdpPacket> + Stream<Item = UdpPacket>;

  async fn accept_tcp_connect(&self) -> Result<(Destination, Self::TcpStream), InboundError>;

  async fn get_udp_packet_stream(&self) -> Result<Self::UdpPacketStream, InboundError>;
}

#[derive(thiserror::Error, Debug)]
pub enum InboundError {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Inbound closed")]
  Closed,
}
