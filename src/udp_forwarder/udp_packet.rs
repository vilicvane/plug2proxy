use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{node::NodeId, primitives::SocketDestination};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketDestination,
  /// Source address that must be presented with the response when the
  /// outbound resolves a domain instead of using the transparent target.
  pub response_destination: Option<SocketAddr>,
  pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct UdpPacketSource {
  pub via: Vec<NodeId>,
  pub address: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct IncomingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketAddr,
  pub payload: Vec<u8>,
}
