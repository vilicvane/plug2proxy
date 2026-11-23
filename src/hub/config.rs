use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{
  dns::DnsConfig, inbound::InboundsConfig, mt_connections::TunnelInterfaceConfig, out::ExitConfig,
  route::RouteConfig, utils::serde::deserialize_listen_socket_address,
};

#[derive(Clone, Debug, Deserialize)]
pub struct HubConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
  #[serde(default)]
  pub interfaces: Vec<TunnelInterfaceConfig>,
  #[serde(default)]
  pub exits: Vec<ExitConfig>,
  pub route: Option<RouteConfig>,
  pub inbounds: Option<InboundsConfig>,
  pub dns: Option<DnsConfig>,
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn rejects_zero_listen_port() {
    let error = serde_json::from_str::<HubConfig>(r#"{"listen":"127.0.0.1:0"}"#).unwrap_err();

    assert!(error.to_string().contains("listen port must be non-zero"));
  }

  #[test]
  fn parses_interfaces_config() {
    let config = serde_json::from_str::<HubConfig>(
      r#"{
        "listen": "0.0.0.0:1122",
        "interfaces": [
          {
            "address": "127.0.0.1",
            "advertise": "203.0.113.10",
            "bandwidth": "1Mbps",
            "connections_limit": 2
          },
          {
            "address": "127.0.0.2",
            "advertise": "203.0.113.20:2233",
            "metered": true,
            "udp": false
          }
        ]
      }"#,
    )
    .unwrap();

    assert_eq!(config.interfaces.len(), 2);
    assert!(!config.interfaces[0].metered);
    assert_eq!(config.interfaces[0].connections_limit, Some(2));
    assert!(config.interfaces[1].metered);
    assert!(!config.interfaces[1].udp);
  }
}
