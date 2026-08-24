use std::num::NonZeroU64;

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
  pub peer_connections: Option<usize>,
  pub peer_tcp_max_pacing_rate_bps: Option<NonZeroU64>,
}

impl From<InHubConfig> for InHubOptions {
  fn from(
    InHubConfig {
      address,
      connections,
      peer_connections,
      peer_tcp_max_pacing_rate_bps,
    }: InHubConfig,
  ) -> Self {
    let connections = connections.unwrap_or(4);

    InHubOptions {
      address: address.into(),
      connections,
      peer_connections: peer_connections.unwrap_or(connections),
      peer_tcp_max_pacing_rate_bps,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn peer_connections_default_to_hub_connections() {
    let config: InHubConfig =
      serde_json::from_str(r#"{"address":"127.0.0.1:1122","connections":3}"#).unwrap();
    let options = InHubOptions::from(config);

    assert_eq!(options.connections, 3);
    assert_eq!(options.peer_connections, 3);
    assert_eq!(options.peer_tcp_max_pacing_rate_bps, None);
  }

  #[test]
  fn peer_connections_can_be_configured_independently() {
    let config: InHubConfig =
      serde_json::from_str(r#"{"address":"127.0.0.1:1122","connections":4,"peer_connections":1}"#)
        .unwrap();
    let options = InHubOptions::from(config);

    assert_eq!(options.connections, 4);
    assert_eq!(options.peer_connections, 1);
  }

  #[test]
  fn peer_tcp_max_pacing_rate_can_be_configured() {
    let config: InHubConfig = serde_json::from_str(
      r#"{"address":"127.0.0.1:1122","peer_tcp_max_pacing_rate_bps":2000000}"#,
    )
    .unwrap();
    let options = InHubOptions::from(config);

    assert_eq!(
      options.peer_tcp_max_pacing_rate_bps,
      NonZeroU64::new(2_000_000)
    );
  }

  #[test]
  fn peer_tcp_max_pacing_rate_rejects_zero() {
    assert!(
      serde_json::from_str::<InHubConfig>(
        r#"{"address":"127.0.0.1:1122","peer_tcp_max_pacing_rate_bps":0}"#,
      )
      .is_err()
    );
  }
}
