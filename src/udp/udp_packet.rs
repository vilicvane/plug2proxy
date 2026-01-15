use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::primitives::Destination;

#[derive(Serialize, Deserialize)]
pub struct UdpPacket {
  pub source: SocketAddr,
  pub destination: Destination,
  pub payload: Vec<u8>,
}
