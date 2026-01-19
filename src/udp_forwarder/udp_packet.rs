use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{node::NodeId, primitives::SocketDestination};

#[derive(Serialize, Deserialize)]
pub struct OutgoingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketDestination,
  pub payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct UdpPacketSource {
  pub via: Vec<NodeId>,
  pub address: SocketAddr,
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct IncomingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketAddr,
  pub payload: Vec<u8>,
}
