use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{primitives::SocketDestination, tunnel::TunnelId};

#[derive(Serialize, Deserialize)]
pub struct OutgoingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketDestination,
  pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct UdpPacketSource {
  pub via: Vec<TunnelId>,
  pub address: SocketAddr,
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct IncomingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketAddr,
  pub payload: Vec<u8>,
}
