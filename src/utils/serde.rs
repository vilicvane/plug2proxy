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

#[derive(Clone, Debug, Serialize)]
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
