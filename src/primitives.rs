use std::net::IpAddr;

use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq)]
pub enum ConnectionSide {
  Client,
  Server,
}

impl std::fmt::Display for ConnectionSide {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        ConnectionSide::Client => "client".cyan(),
        ConnectionSide::Server => "server".magenta(),
      }
    )
  }
}

#[derive(Serialize, Deserialize)]
pub struct Destination {
  pub address: DestinationAddress,
  pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub enum DestinationAddress {
  DomainName(String),
  IpAddress(IpAddr),
}
