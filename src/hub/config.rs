use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{inbound::InboundsConfig, out::ExitConfig, route::RouteConfig};

#[derive(Clone, Debug, Deserialize)]
pub struct HubConfig {
  pub listen: SerdeSocketAddress,
  #[serde(default)]
  pub exits: Vec<ExitConfig>,
  pub route: Option<RouteConfig>,
  pub inbounds: Option<InboundsConfig>,
}
