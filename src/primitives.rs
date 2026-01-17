use std::net::{IpAddr, SocketAddr};

use colored::Colorize;
use itertools::Itertools;
use lowkit::SelfWrapExt;
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

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
pub struct SocketDestination {
  pub host: SocketDestinationHost,
  pub port: u16,
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub enum SocketDestinationHost {
  DomainName(String),
  IpAddress(IpAddr),
}

impl SocketDestination {
  pub async fn resolve_to_socket_addresses_for_source(
    &self,
    source: &SocketAddr,
  ) -> Result<Vec<SocketAddr>, std::io::Error> {
    let source_ip_version = get_ip_version(source);

    match &self.host {
      SocketDestinationHost::DomainName(domain) => {
        lookup_host((domain.as_str(), self.port)).await?.collect()
      }
      SocketDestinationHost::IpAddress(ip) => vec![SocketAddr::from((*ip, self.port))],
    }
    .into_iter()
    .filter(|socket_address| get_ip_version(socket_address) == source_ip_version)
    .collect_vec()
    .wrap_ok()
  }
}

fn get_ip_version(socket_addr: &SocketAddr) -> u8 {
  match socket_addr {
    SocketAddr::V4(_) => 4,
    SocketAddr::V6(_) => 6,
  }
}
