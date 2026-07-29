use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{dns::DnsConfig, r#in::InHubOptions, inbound::InboundsConfig, route::RouteConfig};

#[derive(Clone, Debug, Deserialize)]
pub struct InConfig {
  pub hub: InHubConfig,
  pub route: Option<RouteConfig>,
  pub inbounds: Option<InboundsConfig>,
  pub dns: Option<DnsConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct InHubConfig {
  pub address: SerdeSocketAddress,
  pub connections: Option<usize>,
}

impl From<InHubConfig> for InHubOptions {
  fn from(
    InHubConfig {
      address,
      connections,
    }: InHubConfig,
  ) -> Self {
    InHubOptions {
      address: address.into(),
      connections: connections.unwrap_or(4),
    }
  }
}
