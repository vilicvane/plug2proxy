use std::net::{IpAddr, SocketAddr};

use lowkit::SelfWrapExt;
use serde::{Deserialize, Serialize};
use tokio::net::lookup_host;

use crate::utils::net::SocketAddressExt;

#[derive(Serialize, Deserialize, Debug, derive_more::Display, Hash, Eq, PartialEq, Clone)]
#[display("{host}:{port}")]
pub struct SocketDestination {
  pub host: SocketDestinationHost,
  pub port: u16,
  #[serde(skip)]
  pub routing_domain: Option<String>,
}

impl SocketDestination {
  pub fn routing_domain(&self) -> Option<String> {
    self
      .routing_domain
      .clone()
      .or_else(|| self.host.as_domain_name())
  }

  pub fn set_routing_domain(&mut self, domain: Option<String>) {
    self.routing_domain = domain;
  }

  pub fn route_label(&self) -> String {
    match (&self.host, self.routing_domain.as_deref()) {
      (SocketDestinationHost::IpAddress(_), Some(domain)) => {
        format!("{self} ({domain})")
      }
      _ => self.to_string(),
    }
  }

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

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq, Debug, derive_more::Display)]
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

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn routing_domain_does_not_replace_or_serialize_the_dial_target() -> anyhow::Result<()> {
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse()?),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
    };

    assert_eq!(
      destination.routing_domain().as_deref(),
      Some("c2c.cdn.weixin.qq.com")
    );
    assert_eq!(
      destination.host,
      SocketDestinationHost::IpAddress("182.140.143.139".parse()?)
    );
    assert_eq!(
      destination.route_label(),
      "182.140.143.139:443 (c2c.cdn.weixin.qq.com)"
    );

    let decoded: SocketDestination = postcard::from_bytes(&postcard::to_allocvec(&destination)?)?;
    assert_eq!(decoded.host, destination.host);
    assert_eq!(decoded.port, 443);
    assert_eq!(decoded.routing_domain, None);
    Ok(())
  }

  #[test]
  fn domain_target_is_also_available_as_routing_metadata() {
    let destination = SocketDestination {
      host: SocketDestinationHost::DomainName("Example.COM".to_owned()),
      port: 443,
      routing_domain: None,
    };

    assert_eq!(destination.routing_domain().as_deref(), Some("Example.COM"));
    assert_eq!(destination.route_label(), "Example.COM:443");
  }
}
