use crate::{
  inbound::Error,
  primitives::{BidiStream, SocketDestination},
  udp_forwarder::InboundUdpPacketStream,
};
use async_trait::async_trait;

#[async_trait]
pub trait Inbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error>;

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error>;
}
