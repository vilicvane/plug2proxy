use async_trait::async_trait;
use futures::{Sink, Stream};

use crate::{
  inbound::Error,
  primitives::{BidiStream, SocketDestination},
  udp_forwarder::OutgoingUdpPacket,
};

#[async_trait]
pub trait Inbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error>;

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error>;
}

pub trait InboundUdpPacketStream:
  Sink<OutgoingUdpPacket, Error = Error> + Stream<Item = OutgoingUdpPacket>
{
}

impl<T> InboundUdpPacketStream for T where
  T: Sink<OutgoingUdpPacket, Error = Error> + Stream<Item = OutgoingUdpPacket>
{
}
