use std::{collections::HashSet, net::SocketAddr};

use lowkit::SerdeSocketAddress;
use serde::{Deserialize, Deserializer, de};

use crate::{
  dns::DnsConfig, r#in::InHubOptions, inbound::InboundsConfig,
  mt_connections::TunnelInterfaceConfig, route::RouteConfig, utils::serde::SerdeOneOrMany,
};

#[derive(Clone, Debug, Deserialize)]
pub struct InConfig {
  pub hub: InHubConfig,
  #[serde(default)]
  pub interfaces: Vec<TunnelInterfaceConfig>,
  pub route: Option<RouteConfig>,
  pub inbounds: Option<InboundsConfig>,
  pub dns: Option<DnsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InHubConfig {
  #[serde(deserialize_with = "deserialize_in_hub_addresses")]
  pub address: SerdeOneOrMany<SerdeSocketAddress>,
  pub connections: Option<usize>,
}

fn deserialize_in_hub_addresses<'de, D>(
  deserializer: D,
) -> Result<SerdeOneOrMany<SerdeSocketAddress>, D::Error>
where
  D: Deserializer<'de>,
{
  let value = SerdeOneOrMany::<SerdeSocketAddress>::deserialize(deserializer)?;
  let addresses: Vec<SocketAddr> = match &value {
    SerdeOneOrMany::One(address) => vec![address.into_inner()],
    SerdeOneOrMany::Many(addresses) => addresses.iter().map(|addr| addr.into_inner()).collect(),
  };

  if addresses.is_empty() {
    return Err(de::Error::custom("IN HUB address list must not be empty"));
  }

  let mut seen = HashSet::new();
  for address in addresses {
    if !seen.insert(address) {
      return Err(de::Error::custom(format!(
        "duplicate IN HUB address {address}"
      )));
    }
  }

  Ok(value)
}

impl From<InHubConfig> for InHubOptions {
  fn from(
    InHubConfig {
      address,
      connections,
    }: InHubConfig,
  ) -> Self {
    InHubOptions {
      addresses: address.into(),
      connections: connections.unwrap_or(4),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn parses_multi_hub_addresses_and_interfaces() {
    let config = serde_json::from_str::<InConfig>(
      r#"{
        "hub": {
          "address": ["127.0.0.1:1122", "127.0.0.2:1122"],
          "connections": 3
        },
        "interfaces": [
          {
            "address": "127.0.0.1",
            "bandwidth": { "in": "1Mbps", "out": "850kbps" }
          },
          {
            "address": "127.0.0.2",
            "metered": true
          }
        ]
      }"#,
    )
    .unwrap();

    let hub_options = InHubOptions::from(config.hub);
    assert_eq!(hub_options.addresses.len(), 2);
    assert_eq!(hub_options.connections, 3);
    assert_eq!(config.interfaces.len(), 2);
  }

  #[test]
  fn rejects_empty_or_duplicate_hub_addresses() {
    assert!(serde_json::from_str::<InConfig>(r#"{"hub":{"address":[]}}"#).is_err());
    assert!(
      serde_json::from_str::<InConfig>(
        r#"{"hub":{"address":["127.0.0.1:1122","127.0.0.1:1122"]}}"#
      )
      .is_err()
    );
  }
}
