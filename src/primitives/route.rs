use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[derive(
  Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::From, derive_more::Display,
)]
pub enum OutExit {
  #[display("DIRECT")]
  Direct,
  Tag(#[from] OutExitTag),
  #[display("PROXY")]
  Proxy,
  #[display("ANY")]
  Any,
}

impl<T> From<T> for OutExit
where
  T: AsRef<str>,
{
  fn from(value: T) -> Self {
    let value = value.as_ref();

    match value {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value.to_owned())),
    }
  }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq, derive_more::Display)]
pub struct OutExitTag(pub String);

impl<T> From<T> for OutExitTag
where
  T: AsRef<str>,
{
  fn from(value: T) -> Self {
    OutExitTag(value.as_ref().to_owned())
  }
}

/// The normalized, unordered exits exposed by a dispatcher or advertised by
/// a node. Ordered route selector lists deliberately continue to use
/// `Vec<OutExit>`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OutExits(Vec<OutExit>);

impl OutExits {
  pub fn new(exits: impl IntoIterator<Item = OutExit>) -> Self {
    // Keep wire snapshots deterministic. `unique()` uses a set for
    // deduplication while preserving first-seen order; collecting directly
    // into a HashSet would randomize serialized exit order.
    let normalized = exits
      .into_iter()
      .filter(|exit| *exit != OutExit::Any)
      .unique()
      .collect::<Vec<_>>();

    // OutExits is exchanged only by same-version trusted nodes. Missing this
    // marker is therefore a programming or protocol invariant violation.
    assert!(
      normalized.contains(&OutExit::Proxy)
        || !normalized
          .iter()
          .any(|exit| matches!(exit, OutExit::Tag(_))),
      "OutExits tags require PROXY"
    );

    Self(normalized)
  }

  /// Builds the canonical exits safe to advertise to another node. `DIRECT`
  /// is local to the node currently executing a route, while `PROXY`
  /// explicitly marks that at least one provider exit exists.
  pub fn for_advertising(&self) -> Self {
    if !self.0.contains(&OutExit::Proxy) {
      return Self::default();
    }

    Self::new(
      std::iter::once(OutExit::Proxy).chain(
        self
          .0
          .iter()
          .filter(|exit| matches!(exit, OutExit::Tag(_)))
          .cloned(),
      ),
    )
  }

  pub fn match_exit(&self, requested: &OutExit) -> Option<OutExitMatch> {
    let has_direct = self.0.contains(&OutExit::Direct);
    let has_proxy = self.0.contains(&OutExit::Proxy);

    let (priority, resolved_exit) = match requested {
      OutExit::Direct if has_direct => (OutExitMatchPriority::DefaultLocal, OutExit::Direct),
      OutExit::Proxy if has_proxy => (OutExitMatchPriority::Provider, OutExit::Proxy),
      OutExit::Any if has_direct => (OutExitMatchPriority::DefaultLocal, OutExit::Direct),
      OutExit::Any if has_proxy => (OutExitMatchPriority::Provider, OutExit::Proxy),
      OutExit::Tag(_) if has_proxy && self.0.contains(requested) => {
        (OutExitMatchPriority::Provider, requested.clone())
      }
      _ => return None,
    };

    Some(OutExitMatch {
      priority,
      resolved_exit,
    })
  }

  pub fn as_slice(&self) -> &[OutExit] {
    &self.0
  }

  pub fn iter(&self) -> std::slice::Iter<'_, OutExit> {
    self.0.iter()
  }
}

impl FromIterator<OutExit> for OutExits {
  fn from_iter<T: IntoIterator<Item = OutExit>>(iter: T) -> Self {
    Self::new(iter)
  }
}

impl<'de> Deserialize<'de> for OutExits {
  fn deserialize<TDeserializer>(deserializer: TDeserializer) -> Result<Self, TDeserializer::Error>
  where
    TDeserializer: serde::Deserializer<'de>,
  {
    Vec::<OutExit>::deserialize(deserializer).map(Self::new)
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutExitMatchPriority {
  /// The current inbound node's default local exit.
  DefaultLocal,
  /// An explicitly published exit, reached locally or through another node.
  Provider,
}

/// A successful selector match, including the selector safe to pass to the
/// chosen dispatcher or next hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutExitMatch {
  pub priority: OutExitMatchPriority,
  pub resolved_exit: OutExit,
}

#[cfg(test)]
mod tests {
  use super::*;

  fn matched(priority: OutExitMatchPriority, resolved_exit: OutExit) -> Option<OutExitMatch> {
    Some(OutExitMatch {
      priority,
      resolved_exit,
    })
  }

  #[test]
  fn dispatcher_and_advertised_exits_are_normalized() {
    let exits = OutExits::new(vec![
      OutExit::Any,
      OutExit::Direct,
      OutExit::Proxy,
      OutExit::from("us"),
      OutExit::from("youtube"),
      OutExit::from("us"),
    ]);

    assert_eq!(
      exits.as_slice(),
      &[
        OutExit::Direct,
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("youtube")
      ]
    );
    assert_eq!(
      exits.for_advertising().as_slice(),
      &[
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("youtube")
      ]
    );
    assert_eq!(
      OutExits::new([
        OutExit::Direct,
        OutExit::Any,
        OutExit::Proxy,
        OutExit::Proxy,
        OutExit::from("us"),
        OutExit::from("us"),
      ])
      .for_advertising()
      .as_slice(),
      &[OutExit::Proxy, OutExit::from("us")],
      "wire exits contain neither local/request-only selectors nor duplicates"
    );
  }

  #[test]
  #[should_panic(expected = "OutExits tags require PROXY")]
  fn tags_without_proxy_panic() {
    OutExits::new([OutExit::Direct, OutExit::from("us")]);
  }

  #[test]
  #[should_panic(expected = "OutExits tags require PROXY")]
  fn wire_tags_without_proxy_panic() {
    let raw = postcard::to_allocvec(&vec![OutExit::from("us")]).unwrap();
    postcard::from_bytes::<OutExits>(&raw).unwrap();
  }

  #[test]
  fn wire_format_matches_vec_and_deserialization_normalizes() {
    let raw = vec![
      OutExit::Any,
      OutExit::Direct,
      OutExit::Proxy,
      OutExit::Proxy,
      OutExit::from("us"),
    ];
    let exits = OutExits::new(raw.clone());
    let normalized = vec![OutExit::Direct, OutExit::Proxy, OutExit::from("us")];

    assert_eq!(
      postcard::to_allocvec(&exits).unwrap(),
      postcard::to_allocvec(&normalized).unwrap()
    );

    let decoded = postcard::from_bytes::<OutExits>(&postcard::to_allocvec(&raw).unwrap()).unwrap();

    assert_eq!(decoded.as_slice(), normalized);
  }

  #[test]
  fn selector_matching_is_centralized_and_resolves_any() {
    let cases = [
      (
        "no exits",
        vec![],
        vec![
          (OutExit::Direct, None),
          (OutExit::Proxy, None),
          (OutExit::Any, None),
          (OutExit::from("cn"), None),
        ],
      ),
      (
        "private default local",
        vec![OutExit::Direct],
        vec![
          (
            OutExit::Direct,
            matched(OutExitMatchPriority::DefaultLocal, OutExit::Direct),
          ),
          (OutExit::Proxy, None),
          (
            OutExit::Any,
            matched(OutExitMatchPriority::DefaultLocal, OutExit::Direct),
          ),
          (OutExit::from("cn"), None),
        ],
      ),
      (
        "published default local",
        vec![OutExit::Direct, OutExit::Proxy, OutExit::from("cn")],
        vec![
          (
            OutExit::Direct,
            matched(OutExitMatchPriority::DefaultLocal, OutExit::Direct),
          ),
          (
            OutExit::Proxy,
            matched(OutExitMatchPriority::Provider, OutExit::Proxy),
          ),
          (
            OutExit::Any,
            matched(OutExitMatchPriority::DefaultLocal, OutExit::Direct),
          ),
          (
            OutExit::from("cn"),
            matched(OutExitMatchPriority::Provider, OutExit::from("cn")),
          ),
          (OutExit::from("us"), None),
        ],
      ),
      (
        "tagless provider",
        vec![OutExit::Proxy],
        vec![
          (OutExit::Direct, None),
          (
            OutExit::Proxy,
            matched(OutExitMatchPriority::Provider, OutExit::Proxy),
          ),
          (
            OutExit::Any,
            matched(OutExitMatchPriority::Provider, OutExit::Proxy),
          ),
          (OutExit::from("us"), None),
        ],
      ),
      (
        "tagged provider",
        vec![
          OutExit::Proxy,
          OutExit::from("us"),
          OutExit::from("youtube"),
        ],
        vec![
          (OutExit::Direct, None),
          (
            OutExit::Proxy,
            matched(OutExitMatchPriority::Provider, OutExit::Proxy),
          ),
          (
            OutExit::Any,
            matched(OutExitMatchPriority::Provider, OutExit::Proxy),
          ),
          (
            OutExit::from("us"),
            matched(OutExitMatchPriority::Provider, OutExit::from("us")),
          ),
          (
            OutExit::from("youtube"),
            matched(OutExitMatchPriority::Provider, OutExit::from("youtube")),
          ),
          (OutExit::from("netflix"), None),
        ],
      ),
    ];

    for (case, exits, selectors) in cases {
      for (selector, expected) in selectors {
        assert_eq!(
          OutExits::new(exits.clone()).match_exit(&selector),
          expected,
          "{case}: {selector}"
        );
      }
    }
  }
}
