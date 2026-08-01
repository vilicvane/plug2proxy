use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{
  dns::DnsConfig, inbound::InboundsConfig, out::ExitConfig, route::RouteConfig,
  utils::serde::deserialize_listen_socket_address,
};

#[derive(Clone, Debug, Deserialize)]
pub struct HubConfig {
  #[serde(deserialize_with = "deserialize_listen_socket_address")]
  pub listen: SerdeSocketAddress,
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
}
