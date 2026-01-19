use lowkit::SerdeSocketAddress;
use serde::Deserialize;

use crate::{inbound::InboundsConfig, primitives::OutExitTag, route::RouteConfig};

#[derive(Clone, Debug, Deserialize)]
pub struct HubConfig {
  pub listen: SerdeSocketAddress,
  pub tags: Option<Vec<OutExitTag>>,
  pub route: Option<RouteConfig>,
  pub inbounds: Option<InboundsConfig>,
}
