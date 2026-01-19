use async_trait::async_trait;

use crate::{
  inbound::{Error, Inbound, InboundUdpPacketStream, Socks5Inbound},
  primitives::{BidiStream, SocketDestination},
};

#[derive(derive_more::From, Debug)]
pub enum AnyInbound {
  Socks5(Socks5Inbound),
}

#[async_trait]
impl Inbound for AnyInbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error> {
    match self {
      AnyInbound::Socks5(socks5) => socks5.accept_tcp_connect().await,
    }
  }

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error> {
    match self {
      AnyInbound::Socks5(socks5) => socks5.get_udp_packet_stream().await,
    }
  }
}
