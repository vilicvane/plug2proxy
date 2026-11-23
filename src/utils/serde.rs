use std::{net::IpAddr, ops::Deref};

use ipnet::IpNet;
use lowkit::{SelfWrapExt, SerdeSocketAddress};
use serde::{Deserialize, Deserializer, Serialize, de};

pub fn deserialize_u32_or_hex<'de, TDeserializer>(
  deserializer: TDeserializer,
) -> Result<u32, TDeserializer::Error>
where
  TDeserializer: Deserializer<'de>,
{
  #[derive(Deserialize)]
  #[serde(untagged)]
  enum U32OrHex {
    Number(u32),
    Hex(String),
  }

  match U32OrHex::deserialize(deserializer)? {
    U32OrHex::Number(value) => Ok(value),
    U32OrHex::Hex(value) => {
      let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .ok_or_else(|| de::Error::custom("expected a hexadecimal u32 string starting with 0x"))?;

      u32::from_str_radix(digits, 16)
        .map_err(|_| de::Error::custom(format!("invalid hexadecimal u32 value: {value}")))
    }
  }
}

pub fn deserialize_listen_socket_address<'de, TDeserializer>(
  deserializer: TDeserializer,
) -> Result<SerdeSocketAddress, TDeserializer::Error>
where
  TDeserializer: Deserializer<'de>,
{
  let address = SerdeSocketAddress::deserialize(deserializer)?;

  if address.port() == 0 {
    return Err(de::Error::custom("listen port must be non-zero"));
  }

  Ok(address)
}

pub fn deserialize_optional_listen_socket_address<'de, TDeserializer>(
  deserializer: TDeserializer,
) -> Result<Option<SerdeSocketAddress>, TDeserializer::Error>
where
  TDeserializer: Deserializer<'de>,
{
  let address = Option::<SerdeSocketAddress>::deserialize(deserializer)?;

  if address.as_ref().is_some_and(|address| address.port() == 0) {
    return Err(de::Error::custom("listen port must be non-zero"));
  }

  Ok(address)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SerdeOneOrMany<T> {
  One(T),
  Many(Vec<T>),
}

impl<T, TFrom> From<SerdeOneOrMany<TFrom>> for Vec<T>
where
  TFrom: Into<T>,
{
  fn from(value: SerdeOneOrMany<TFrom>) -> Self {
    match value {
      SerdeOneOrMany::One(value) => vec![value.into()],
      SerdeOneOrMany::Many(values) => values.into_iter().map(|value| value.into()).collect(),
    }
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SerdeIpNet(ipnet::IpNet);

impl Deref for SerdeIpNet {
  type Target = ipnet::IpNet;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl<'de> Deserialize<'de> for SerdeIpNet {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: Deserializer<'de>,
  {
    if !deserializer.is_human_readable() {
      return IpNet::deserialize(deserializer).map(Self);
    }

    let ip_net = String::deserialize(deserializer)?;

    let ip_net = ip_net.parse::<IpNet>().or_else(|error| {
      let ip = ip_net
        .parse::<IpAddr>()
        .map_err(|_| de::Error::custom(error.to_string()))?;

      let prefix_length = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
      };

      IpNet::new(ip, prefix_length).unwrap().wrap_ok()
    })?;

    SerdeIpNet(ip_net).wrap_ok()
  }
}

#[cfg(test)]
mod tests {
  use crate::{
    node::{NodeMessageToIn, NodeMessageToInUpdate},
    primitives::{OutExit, OutExits},
    route::{AddressRule, AnyRule},
    utils::postcard::postcard_read_stream,
  };

  use super::*;

  #[test]
  fn deserializes_cidr_and_bare_ip_from_json() {
    for (input, expected) in [
      (r#""10.0.0.0/8""#, "10.0.0.0/8"),
      (r#""127.0.0.1""#, "127.0.0.1/32"),
      (r#""fd00::/8""#, "fd00::/8"),
      (r#""::1""#, "::1/128"),
    ] {
      let parsed: SerdeIpNet = serde_json::from_str(input).unwrap();
      assert_eq!(*parsed, expected.parse::<IpNet>().unwrap());
    }
  }

  #[test]
  fn round_trips_through_postcard() {
    let inputs = vec![
      SerdeIpNet("127.0.0.1/32".parse().unwrap()),
      SerdeIpNet("192.168.1.0/24".parse().unwrap()),
      SerdeIpNet("fd00::/8".parse().unwrap()),
    ];

    let encoded = postcard::to_allocvec(&inputs).unwrap();
    let decoded: Vec<SerdeIpNet> = postcard::from_bytes(&encoded).unwrap();

    assert_eq!(decoded, inputs);
  }

  #[tokio::test]
  async fn node_update_with_address_rule_match_ips_round_trips_over_postcard_stream() {
    let expected_ips = vec![
      SerdeIpNet("127.0.0.1/32".parse().unwrap()),
      SerdeIpNet("::1/128".parse().unwrap()),
    ];
    let update = NodeMessageToIn::Update(NodeMessageToInUpdate {
      exits: OutExits::new([OutExit::Proxy, OutExit::from("cd-test")]),
      peer_outs: vec![],
      route_rules: vec![
        AddressRule {
          match_ips: Some(expected_ips.clone()),
          match_ports: Some(vec![28888, 28889]),
          priority: 10,
          negate: false,
          exits: vec![OutExit::from("cd-test")],
        }
        .into(),
      ],
    });

    let encoded = postcard::to_allocvec(&update).unwrap();
    let mut cursor = encoded.as_slice();
    let NodeMessageToIn::Update(decoded) = postcard_read_stream(&mut cursor).await.unwrap();

    assert!(cursor.is_empty());
    let [AnyRule::Address(rule)] = decoded.route_rules.as_slice() else {
      panic!("expected AddressRule");
    };
    assert_eq!(rule.match_ips.as_ref(), Some(&expected_ips));
    assert_eq!(rule.match_ports.as_deref(), Some(&[28888, 28889][..]));
    assert_eq!(rule.priority, 10);
    assert_eq!(rule.exits, [OutExit::from("cd-test")]);
  }
}
