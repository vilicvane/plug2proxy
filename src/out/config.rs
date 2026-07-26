use std::net::SocketAddr;

use anyhow::Context;
use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::{Deserialize, Deserializer};

use crate::{
  node::{DefaultLocalExit, LocalOutDispatcher},
  out::OutHubOptions,
  primitives::{OutExit, OutExitTag},
};

#[derive(Clone, Debug, Deserialize)]
pub struct OutConfig {
  pub hub: OutHubConfig,
  #[serde(default)]
  pub exits: Vec<ExitConfig>,
  pub listen: Option<SerdeSocketAddress>,
  pub advertise: Option<SerdeSocketAddress>,
}

impl OutConfig {
  /// Returns the configured peer listener and optional address override.
  ///
  /// A missing advertise address is intentionally left unresolved: the
  /// unspecified address sent to the HUB needs the listener's actual port
  /// after binding.
  pub fn peer_addresses(&self) -> anyhow::Result<Option<(SocketAddr, Option<SocketAddr>)>> {
    let Some(listen) = self.listen else {
      anyhow::ensure!(
        self.advertise.is_none(),
        "OUT advertise requires a peer listener"
      );

      return Ok(None);
    };

    let advertise = self.advertise.map(SerdeSocketAddress::into_inner);

    anyhow::ensure!(
      advertise.is_none_or(|address| address.port() != 0),
      "OUT advertise port must be non-zero"
    );

    Ok(Some((listen.into_inner(), advertise)))
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct OutHubConfig {
  pub address: SerdeSocketAddress,
  pub connections: Option<usize>,
}

impl From<OutHubConfig> for OutHubOptions {
  fn from(
    OutHubConfig {
      address,
      connections,
    }: OutHubConfig,
  ) -> Self {
    OutHubOptions {
      address: address.into(),
      connections: connections.unwrap_or(4),
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
pub enum ExitConfig {
  #[serde(rename = "local")]
  Local(LocalExitConfig),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExitConfig {
  #[serde(default)]
  pub tags: Vec<OutExitTag>,
  pub bind: Option<LocalExitBindConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalExitBindConfig {
  pub interface: Option<String>,
}

pub fn build_local_out_dispatchers(
  exit_configs: Vec<ExitConfig>,
) -> anyhow::Result<Vec<LocalOutDispatcher>> {
  let mut default_local_tags = None;
  let mut bound_dispatchers = vec![];

  for exit_config in exit_configs {
    match exit_config {
      ExitConfig::Local(LocalExitConfig { tags, bind }) => {
        let interface = bind.and_then(|bind| bind.interface);

        if let Some(interface) = interface {
          let dispatcher = LocalOutDispatcher::new_bound(tags, interface.clone())
            .with_context(|| format!("invalid bind.interface {interface:?}"))?;

          bound_dispatchers.push(dispatcher);
        } else {
          anyhow::ensure!(
            default_local_tags.replace(tags).is_none(),
            "only one local exit without bind restrictions may be configured"
          );
        }
      }
    }
  }

  let default_local_exit = match default_local_tags {
    Some(tags) => DefaultLocalExit::Advertised { tags },
    None => DefaultLocalExit::Private,
  };

  let mut dispatchers = vec![LocalOutDispatcher::new_default(default_local_exit)];
  dispatchers.extend(bound_dispatchers);

  Ok(dispatchers)
}

#[derive(Clone, Debug)]
pub struct OutExitConfig(pub OutExit);

impl<'de> Deserialize<'de> for OutExitConfig {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    let value = String::deserialize(deserializer)?;

    let out_exit = match value.as_str() {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value)),
    };

    OutExitConfig(out_exit).wrap_ok()
  }
}

impl From<OutExitConfig> for OutExit {
  fn from(value: OutExitConfig) -> Self {
    value.0
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn builds_private_default_when_exits_are_omitted() {
    let dispatchers = build_local_out_dispatchers(vec![]).unwrap();

    assert_eq!(dispatchers.len(), 1);
    assert_eq!(dispatchers[0].exits().as_slice(), &[OutExit::Direct]);
    assert_eq!(dispatchers[0].interface(), None);
  }

  #[test]
  fn rejects_advertise_without_peer_listener() {
    let config: OutConfig = serde_yaml::from_str(
      r#"
hub:
  address: 127.0.0.1:1122
advertise: 203.0.113.10:2233
"#,
    )
    .unwrap();

    assert_eq!(
      config.peer_addresses().unwrap_err().to_string(),
      "OUT advertise requires a peer listener"
    );
  }

  #[test]
  fn rejects_zero_advertise_port() {
    let config: OutConfig = serde_yaml::from_str(
      r#"
hub:
  address: 127.0.0.1:1122
listen: 0.0.0.0:1122
advertise: 0.0.0.0:0
"#,
    )
    .unwrap();

    assert_eq!(
      config.peer_addresses().unwrap_err().to_string(),
      "OUT advertise port must be non-zero"
    );
  }

  #[test]
  fn leaves_omitted_advertise_unresolved_for_listener_port() {
    let config: OutConfig = serde_yaml::from_str(
      r#"
hub:
  address: 127.0.0.1:1122
listen: 0.0.0.0:0
"#,
    )
    .unwrap();

    assert_eq!(
      config.peer_addresses().unwrap(),
      Some(("0.0.0.0:0".parse().unwrap(), None))
    );
  }

  #[test]
  fn parses_default_and_interface_bound_local_exits() {
    let config: OutConfig = serde_yaml::from_str(
      r#"
hub:
  address: 127.0.0.1:1122
exits:
  - type: local
    tags: [us, youtube]
  - type: local
    tags: [us, netflix]
    bind:
      interface: wg0
"#,
    )
    .unwrap();

    let dispatchers = build_local_out_dispatchers(config.exits).unwrap();

    assert_eq!(dispatchers.len(), 2);
    assert_eq!(
      dispatchers[0].exits().as_slice(),
      &[
        OutExit::Direct,
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("youtube"),
      ]
    );
    assert_eq!(dispatchers[0].interface(), None);
    assert_eq!(
      dispatchers[1].exits().as_slice(),
      &[
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("netflix"),
      ]
    );
    assert_eq!(dispatchers[1].interface(), Some("wg0"));

    let default = dispatchers[0].exits();
    let bound = dispatchers[1].exits();

    for selector in [OutExit::Direct, OutExit::from("youtube")] {
      assert!(default.match_exit(&selector).is_some(), "{selector}");
      assert!(bound.match_exit(&selector).is_none(), "{selector}");
    }

    assert!(default.match_exit(&OutExit::from("netflix")).is_none());
    assert!(bound.match_exit(&OutExit::from("netflix")).is_some());

    for selector in [OutExit::Proxy, OutExit::from("us")] {
      assert!(default.match_exit(&selector).is_some(), "{selector}");
      assert!(bound.match_exit(&selector).is_some(), "{selector}");
    }

    assert!(default.match_exit(&OutExit::from("unknown")).is_none());
    assert!(bound.match_exit(&OutExit::from("unknown")).is_none());
  }

  #[test]
  fn rejects_multiple_default_local_exits() {
    let config: OutConfig = serde_yaml::from_str(
      r#"
hub:
  address: 127.0.0.1:1122
exits:
  - type: local
  - type: local
    bind: {}
"#,
    )
    .unwrap();

    assert!(build_local_out_dispatchers(config.exits).is_err());
  }
}
