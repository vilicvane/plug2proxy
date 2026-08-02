use async_trait::async_trait;

use crate::{
  inbound::{Error, Inbound, Socks5Inbound, TproxyInbound},
  primitives::{BidiStream, SocketDestination},
  udp_forwarder::InboundUdpPacketStream,
};

#[derive(derive_more::From, Debug)]
pub enum AnyInbound {
  Socks5(Socks5Inbound),
  Tproxy(TproxyInbound),
}

#[async_trait]
impl Inbound for AnyInbound {
  async fn accept_tcp_connect(&self) -> Result<(SocketDestination, Box<dyn BidiStream>), Error> {
    match self {
      AnyInbound::Socks5(socks5) => socks5.accept_tcp_connect().await,
      AnyInbound::Tproxy(tproxy) => tproxy.accept_tcp_connect().await,
    }
  }

  async fn get_udp_packet_stream(&self) -> Result<Box<dyn InboundUdpPacketStream>, Error> {
    match self {
      AnyInbound::Socks5(socks5) => socks5.get_udp_packet_stream().await,
      AnyInbound::Tproxy(tproxy) => tproxy.get_udp_packet_stream().await,
    }
  }
}
