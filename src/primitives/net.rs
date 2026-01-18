use std::net::{IpAddr, SocketAddr};

use lowkit::SelfWrapExt;
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

use crate::utils::net::SocketAddressExt;

#[derive(Serialize, Deserialize)]
pub struct SocketDestination {
  pub host: SocketDestinationHost,
  pub port: u16,
}

impl SocketDestination {
  pub async fn resolve(&self) -> Result<Vec<SocketAddr>, std::io::Error> {
    match &self.host {
      SocketDestinationHost::DomainName(domain) => {
        lookup_host((domain.as_str(), self.port)).await?.collect()
      }
      SocketDestinationHost::IpAddress(ip) => vec![SocketAddr::from((*ip, self.port))],
    }
    .wrap_ok()
  }

  pub async fn resolve_connectable(&self) -> Result<Option<SocketAddr>, std::io::Error> {
    let addresses = self.resolve().await?;

    for address in addresses {
      if address.test_udp_connect().await {
        return Ok(Some(address));
      }
    }

    Ok(None)
  }
}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub enum SocketDestinationHost {
  DomainName(String),
  IpAddress(IpAddr),
}

impl SocketDestinationHost {
  pub fn as_domain_name(&self) -> Option<String> {
    match self {
      SocketDestinationHost::DomainName(domain) => domain.clone().some(),
      SocketDestinationHost::IpAddress(_) => None,
    }
  }
}
