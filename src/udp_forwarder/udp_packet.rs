use std::{
  collections::hash_map::DefaultHasher,
  hash::{Hash, Hasher},
  net::SocketAddr,
};

use serde::{Deserialize, Serialize};

use crate::{node::NodeId, primitives::SocketDestination, qomt::QomtPacketFlow};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutgoingUdpPacket {
  pub source: UdpPacketSource,
  pub destination: SocketDestination,
  /// Source address that must be presented with the response when the
  /// outbound resolves a domain instead of using the transparent target.
  pub response_destination: Option<SocketAddr>,
  pub payload: Vec<u8>,
}

impl QomtPacketFlow for OutgoingUdpPacket {
  fn flow_key_hash(&self) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    self.source.hash(&mut hasher);
    self.destination.host.hash(&mut hasher);
    self.destination.port.hash(&mut hasher);
    Some(hasher.finish())
  }
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

impl QomtPacketFlow for IncomingUdpPacket {
  fn flow_key_hash(&self) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    self.source.hash(&mut hasher);
    self.destination.hash(&mut hasher);
    Some(hasher.finish())
  }
}
