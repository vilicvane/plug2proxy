use std::{
  collections::HashMap,
  net::SocketAddr,
  path::Path,
  sync::{Arc, Mutex},
};

use itertools::Itertools as _;
use lits::duration;
use lowkit::SelfWrapExt;
use moka::sync::Cache;

use crate::{
  node::NodeId,
  primitives::{OutExit, SocketDestination},
  route::{FallbackRule, GeoLite2, Geosite},
};

use super::{rule::AnyRule, rule::Rule, rule::RuleKind};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct RouteMatch {
  pub exit: OutExit,
  /// 命中原因（按什么种类的条件匹配的），由规则的匹配过程产出。
  pub rule_kinds: Vec<RuleKind>,
  pub matched_address: Option<SocketAddr>,
}

impl RouteMatch {
  pub fn fixed(exit: OutExit) -> Self {
    Self {
      exit,
      rule_kinds: vec![RuleKind::Fallback],
      matched_address: None,
    }
  }
}

pub struct Router {
  geolite2: GeoLite2,
  geosite: Geosite,
  rules_map: Mutex<HashMap<RulesKey, Vec<Arc<AnyRule>>>>,
  merged_rules_cache: Mutex<Vec<Arc<AnyRule>>>,
  cache: Cache<SocketDestination, Vec<RouteMatch>>,
  dns_cache: Cache<String, Vec<RouteMatch>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, derive_more::From)]
enum RulesKey {
  Node(NodeId),
  Local,
}

impl Router {
  pub fn new(dir: impl AsRef<Path>) -> Self {
    let dir = dir.as_ref();
    let cache = Cache::builder().time_to_live(duration!("1h")).build();
    let dns_cache = Cache::builder().time_to_live(duration!("1h")).build();
    let geolite2 = GeoLite2::new(dir);
    let geosite = Geosite::new(dir, cache.clone());

    Self {
      geolite2,
      geosite,
      rules_map: HashMap::new().mutex(),
      merged_rules_cache: Vec::new().mutex(),
      cache,
      dns_cache,
    }
  }

  /// 构建下发给其他节点的规则。fallback 是节点本地概念，不下发。
  pub fn build_rules(&self) -> Vec<AnyRule> {
    self
      .merged_rules_cache
      .lock()
      .unwrap()
      .iter()
      .map(|rule| rule.as_ref().clone())
      .filter(|rule| !matches!(rule, AnyRule::Fallback(_)))
      .collect()
  }

  pub async fn match_routes(&self, socket_destination: &SocketDestination) -> Vec<RouteMatch> {
    if let Some(routes) = self.cache.get(socket_destination) {
      return routes;
    }

    let address = socket_destination
      .resolve()
      .await
      .ok()
      .and_then(|addresses| addresses.first().copied());

    let domain = socket_destination.routing_domain();
    let protocol = socket_destination.routing_protocol();

    let rules = self.merged_rules_cache.lock().unwrap();

    let region_codes = if let Some(address) = address {
      self.geolite2.lookup(address.ip())
    } else {
      None
    };

    let routes = rules
      .iter()
      .filter(|rule| !rule.dns_only())
      .filter_map(|rule| {
        rule
          .test(&address, &domain, &protocol, &region_codes, &self.geosite)
          .map(|rule_kinds| (rule, rule_kinds))
      })
      .fold(Vec::new(), |mut routes, (rule, rule_kinds)| {
        if matches!(**rule, AnyRule::Fallback(_)) && !routes.is_empty() {
          return routes;
        }

        for exit in rule.exits() {
          if routes.iter().any(|route: &RouteMatch| route.exit == *exit) {
            continue;
          }

          routes.push(RouteMatch {
            exit: exit.clone(),
            rule_kinds: rule_kinds.clone(),
            matched_address: address,
          });
        }

        routes
      });

    self
      .cache
      .insert(socket_destination.clone(), routes.clone());

    routes
  }

  pub async fn match_exits(&self, socket_destination: &SocketDestination) -> Vec<OutExit> {
    self
      .match_routes(socket_destination)
      .await
      .into_iter()
      .map(|route| route.exit)
      .collect()
  }

  /// DNS 阶段的匹配：只认 domain 规则，不做本地预解析。无命中时回退本地解析。
  pub fn match_dns(&self, domain: &str) -> Vec<RouteMatch> {
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();

    if let Some(routes) = self.dns_cache.get(&domain) {
      return routes;
    }

    let rules = self.merged_rules_cache.lock().unwrap();

    let routes = rules
      .iter()
      .filter(|rule| matches!(***rule, AnyRule::Domain(_)))
      .filter_map(|rule| {
        rule
          .test(&None, &Some(domain.clone()), &None, &None, &self.geosite)
          .map(|rule_kinds| (rule, rule_kinds))
      })
      .fold(Vec::new(), |mut routes, (rule, rule_kinds)| {
        for exit in rule.exits() {
          if routes.iter().any(|route: &RouteMatch| route.exit == *exit) {
            continue;
          }

          routes.push(RouteMatch {
            exit: exit.clone(),
            rule_kinds: rule_kinds.clone(),
            matched_address: None,
          });
        }

        routes
      });

    let routes = if routes.is_empty() {
      vec![RouteMatch::fixed(OutExit::Direct)]
    } else {
      routes
    };

    self.dns_cache.insert(domain, routes.clone());

    routes
  }

  pub fn register_local_rules(&self, rules: Vec<AnyRule>) {
    self.register_rules(RulesKey::Local, rules);
  }

  pub fn register_node_rules(&self, node_id: NodeId, rules: Vec<AnyRule>) {
    self.register_rules(node_id.into(), rules);
  }

  fn register_rules(&self, key: RulesKey, rules: Vec<AnyRule>) {
    if rules.iter().any(Rule::requires_geosite) {
      self.geosite.ensure_updating();
    }

    self
      .rules_map
      .lock()
      .unwrap()
      .entry(key)
      .insert_entry(rules.into_iter().map(|rule| rule.arc()).collect());

    self.update_rules_cache();
  }

  pub fn unregister_node_rules(&self, node_id: NodeId) {
    self.rules_map.lock().unwrap().remove(&node_id.into());

    self.update_rules_cache();
  }

  fn update_rules_cache(&self) {
    let mut rules = self
      .rules_map
      .lock()
      .unwrap()
      .values()
      .flatten()
      .cloned()
      .collect_vec();

    rules.sort_by_key(|rule| rule.priority());

    if !rules
      .iter()
      .any(|rule| matches!(**rule, AnyRule::Fallback(_)))
    {
      rules.push(Arc::new(
        FallbackRule {
          exits: vec![OutExit::Direct],
        }
        .into(),
      ));
    }

    *self.merged_rules_cache.lock().unwrap() = rules;

    self.cache.invalidate_all();
    self.dns_cache.invalidate_all();
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{
    primitives::{SniffedProtocol, SocketDestination, SocketDestinationHost},
    route::{AddressRule, AndRule, DomainRule, ProtocolRule, RuleKind},
    test::test_dir,
  };

  #[tokio::test]
  async fn rule_updates_invalidate_cached_destination_matches() {
    let router = Router::new(test_dir());
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("127.0.0.1".parse().unwrap()),
      port: 80,
      routing_domain: None,
      routing_protocol: None,
    };

    router.register_local_rules(vec![
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    assert_eq!(
      router.match_exits(&destination).await,
      vec![OutExit::Direct]
    );

    router.register_local_rules(vec![
      FallbackRule {
        exits: vec![OutExit::Proxy],
      }
      .into(),
    ]);

    assert_eq!(router.match_exits(&destination).await, vec![OutExit::Proxy]);
  }

  #[tokio::test]
  async fn sniffed_domain_routes_without_changing_the_resolved_ip() {
    let router = Router::new(test_dir());
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse().unwrap()),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
      routing_protocol: Some(crate::primitives::SniffedProtocol::Tls),
    };
    router.register_local_rules(vec![
      DomainRule {
        matchers: vec!["weixin.qq.com".to_owned().into()],
        priority: 0,
        negate: false,
        exits: vec![OutExit::Proxy],
        dns_only: false,
      }
      .into(),
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    assert_eq!(
      destination.resolve().await.unwrap(),
      vec!["182.140.143.139:443".parse().unwrap()]
    );
    assert_eq!(router.match_exits(&destination).await, vec![OutExit::Proxy]);
    assert_eq!(
      router.match_routes(&destination).await,
      vec![RouteMatch {
        exit: OutExit::Proxy,
        rule_kinds: vec![RuleKind::Domain],
        matched_address: Some("182.140.143.139:443".parse().unwrap()),
      }]
    );
  }

  #[tokio::test]
  async fn first_rule_for_an_exit_controls_resolution_provenance() {
    let router = Router::new(test_dir());
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
      port: 443,
      routing_domain: Some("example.com".to_owned()),
      routing_protocol: None,
    };
    router.register_local_rules(vec![
      DomainRule {
        matchers: vec!["example.com".to_owned().into()],
        priority: 10,
        negate: false,
        exits: vec![OutExit::Proxy],
        dns_only: false,
      }
      .into(),
      AddressRule {
        match_ips: None,
        match_ports: Some(vec![443]),
        priority: 20,
        negate: false,
        exits: vec![OutExit::Proxy],
      }
      .into(),
    ]);

    assert_eq!(
      router.match_routes(&destination).await,
      vec![RouteMatch {
        exit: OutExit::Proxy,
        rule_kinds: vec![RuleKind::Domain],
        matched_address: Some("203.0.113.8:443".parse().unwrap()),
      }]
    );
  }

  #[tokio::test]
  async fn protocol_rules_match_sniffed_protocol_and_cache_it_separately() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![
      ProtocolRule {
        matches: vec![SniffedProtocol::Ssh],
        priority: 0,
        negate: false,
        exits: vec![OutExit::Direct],
      }
      .into(),
      FallbackRule {
        exits: vec![OutExit::Proxy],
      }
      .into(),
    ]);

    let mut destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
      port: 2222,
      routing_domain: None,
      routing_protocol: None,
    };
    assert_eq!(router.match_exits(&destination).await, vec![OutExit::Proxy]);

    destination.routing_protocol = Some(SniffedProtocol::Ssh);
    assert_eq!(
      router.match_routes(&destination).await,
      vec![RouteMatch {
        exit: OutExit::Direct,
        rule_kinds: vec![RuleKind::Protocol],
        matched_address: Some("203.0.113.8:2222".parse().unwrap()),
      }]
    );
  }

  #[tokio::test]
  async fn and_rule_matches_only_when_all_conditions_match() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![
      // domain AND port 443，priority/exit 由组级提供。
      AndRule {
        rules: vec![
          DomainRule {
            matchers: vec!["example.com".to_owned().into()],
            priority: i64::MAX,
            negate: false,
            exits: vec![],
            dns_only: false,
          }
          .into(),
          AddressRule {
            match_ips: None,
            match_ports: Some(vec![443]),
            priority: i64::MAX,
            negate: false,
            exits: vec![],
          }
          .into(),
        ],
        priority: 10,
        exits: vec![OutExit::Proxy],
      }
      .into(),
      DomainRule {
        matchers: vec!["example.com".to_owned().into()],
        priority: 20,
        negate: false,
        exits: vec![OutExit::Direct],
        dns_only: false,
      }
      .into(),
    ]);

    let mut destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
      port: 443,
      routing_domain: Some("example.com".to_owned()),
      routing_protocol: None,
    };
    assert_eq!(
      router.match_routes(&destination).await,
      vec![
        RouteMatch {
          exit: OutExit::Proxy,
          rule_kinds: vec![RuleKind::Domain, RuleKind::Address],
          matched_address: Some("203.0.113.8:443".parse().unwrap()),
        },
        RouteMatch {
          exit: OutExit::Direct,
          rule_kinds: vec![RuleKind::Domain],
          matched_address: Some("203.0.113.8:443".parse().unwrap()),
        },
      ]
    );

    // 端口不命中时 AND 规则不命中，只剩单条域名规则。
    destination.port = 80;
    assert_eq!(
      router.match_exits(&destination).await,
      vec![OutExit::Direct]
    );
  }

  #[tokio::test]
  async fn build_rules_pushes_and_rules_but_not_fallback() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![
      AndRule {
        rules: vec![
          DomainRule {
            matchers: vec!["example.com".to_owned().into()],
            priority: i64::MAX,
            negate: false,
            exits: vec![],
            dns_only: false,
          }
          .into(),
          AddressRule {
            match_ips: None,
            match_ports: Some(vec![443]),
            priority: i64::MAX,
            negate: false,
            exits: vec![],
          }
          .into(),
        ],
        priority: 10,
        exits: vec![OutExit::Proxy],
      }
      .into(),
      ProtocolRule {
        matches: vec![SniffedProtocol::Ssh],
        priority: 20,
        negate: false,
        exits: vec![OutExit::Direct],
      }
      .into(),
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    let built_rules = router.build_rules();
    let [AnyRule::And(_), AnyRule::Protocol(_)] = built_rules.as_slice() else {
      panic!("expected the AND rule and the protocol rule, without fallback");
    };
  }

  #[tokio::test]
  async fn dns_only_rules_apply_to_dns_but_not_connections() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![
      DomainRule {
        matchers: vec!["example.com".to_owned().into()],
        priority: 0,
        negate: false,
        exits: vec![OutExit::Proxy],
        dns_only: true,
      }
      .into(),
      FallbackRule {
        exits: vec![OutExit::Direct],
      }
      .into(),
    ]);

    let destination = SocketDestination {
      host: SocketDestinationHost::DomainName("example.com".to_owned()),
      port: 443,
      routing_domain: None,
      routing_protocol: None,
    };
    // 连接路由阶段跳过 dns_only 规则，走 fallback。
    assert_eq!(
      router.match_exits(&destination).await,
      vec![OutExit::Direct]
    );
    // DNS 阶段命中 dns_only 规则。
    assert_eq!(
      router.match_dns("example.com"),
      vec![RouteMatch {
        exit: OutExit::Proxy,
        rule_kinds: vec![RuleKind::Domain],
        matched_address: None,
      }]
    );
  }

  #[tokio::test]
  async fn dns_matching_ignores_non_domain_rules_and_falls_back_to_direct() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![
      AddressRule {
        match_ips: None,
        match_ports: Some(vec![443]),
        priority: 0,
        negate: false,
        exits: vec![OutExit::Proxy],
      }
      .into(),
    ]);

    // 无 domain 规则命中 → 本地解析。
    assert_eq!(
      router.match_dns("example.com"),
      vec![RouteMatch {
        exit: OutExit::Direct,
        rule_kinds: vec![RuleKind::Fallback],
        matched_address: None,
      }]
    );
  }
}
