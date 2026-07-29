use std::{str::FromStr, sync::Arc, time::Duration};

use async_trait::async_trait;
use hickory_server::{
  proto::{
    op::{Message, ResponseCode},
    rr::{LowerName, Name, RecordType, TSigResponseContext},
  },
  resolver::lookup::Lookup,
  server::{Request, RequestInfo},
  zone_handler::{
    AuthLookup, AxfrPolicy, LookupControlFlow, LookupError, LookupOptions, ZoneHandler, ZoneType,
  },
};
use moka::{Expiry, sync::Cache};

use crate::{
  node::{NodeResolveAnswers, ResolveQuery},
  r#in::InLike,
};

/// 应答缓存有效期上限：记录 TTL 超过该值时按该值缓存。
const MAX_CACHE_TTL: u32 = 5 * 60;

/// 按路由配置把域名解析代理到对应出口解析的 ZoneHandler。
pub struct RoutingZoneHandler {
  origin: LowerName,
  node: Arc<dyn InLike + Send + Sync>,
  cache: Cache<(String, u16), Arc<Message>>,
}

impl RoutingZoneHandler {
  pub fn new(node: Arc<dyn InLike + Send + Sync>) -> Self {
    Self {
      origin: LowerName::from_str(".").unwrap(),
      node,
      cache: Cache::builder()
        .max_capacity(1024 * 64)
        .expire_after(AnswerExpiry)
        .build(),
    }
  }

  async fn resolve(&self, name: &str, record_type: RecordType) -> Result<Lookup, LookupError> {
    let key = (name.to_string(), u16::from(record_type));
    let query = hickory_server::proto::op::Query::query(
      Name::from_str(name).map_err(|_| LookupError::from(ResponseCode::FormErr))?,
      record_type,
    );

    if let Some(message) = self.cache.get(&key) {
      return Ok(Lookup::new_with_max_ttl(query, message.answers.to_vec()));
    }

    let routes = self.node.router().match_dns(name);
    let answers = self
      .node
      .resolve_routes(
        routes,
        &ResolveQuery {
          name: name.to_string(),
          record_type: key.1,
        },
      )
      .await;

    match answers {
      Ok(NodeResolveAnswers::Success(bytes)) => {
        let message =
          Message::from_vec(&bytes).map_err(|_| LookupError::from(ResponseCode::ServFail))?;

        if message.answers.is_empty() {
          // NODATA 应答不缓存。
          return Ok(Lookup::new_with_max_ttl(query, []));
        }

        let message = Arc::new(message);
        self.cache.insert(key, message.clone());

        Ok(Lookup::new_with_max_ttl(
          query,
          message.answers.to_vec(),
        ))
      }
      Ok(NodeResolveAnswers::NxDomain) => Err(LookupError::from(ResponseCode::NXDomain)),
      Ok(NodeResolveAnswers::Failure) | Err(_) => Err(LookupError::from(ResponseCode::ServFail)),
    }
  }
}

#[async_trait]
impl ZoneHandler for RoutingZoneHandler {
  fn zone_type(&self) -> ZoneType {
    ZoneType::External
  }

  fn axfr_policy(&self) -> AxfrPolicy {
    AxfrPolicy::Deny
  }

  fn origin(&self) -> &LowerName {
    &self.origin
  }

  async fn lookup(
    &self,
    name: &LowerName,
    rtype: RecordType,
    _request_info: Option<&RequestInfo<'_>>,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    match rtype {
      RecordType::AXFR | RecordType::IXFR | RecordType::ANY => {
        LookupControlFlow::Break(Err(LookupError::from(ResponseCode::NotImp)))
      }
      _ => LookupControlFlow::Break(
        self
          .resolve(&name.to_string(), rtype)
          .await
          .map(AuthLookup::from),
      ),
    }
  }

  async fn search(
    &self,
    request: &Request,
    lookup_options: LookupOptions,
  ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
    let request_info = match request.request_info() {
      Ok(info) => info,
      Err(error) => return (LookupControlFlow::Break(Err(error)), None),
    };

    (
      self
        .lookup(
          request_info.query.name(),
          request_info.query.query_type(),
          Some(&request_info),
          lookup_options,
        )
        .await,
      None,
    )
  }

  async fn nsec_records(
    &self,
    _name: &LowerName,
    _lookup_options: LookupOptions,
  ) -> LookupControlFlow<AuthLookup> {
    LookupControlFlow::Break(Err(LookupError::from(ResponseCode::NotImp)))
  }
}

/// 按应答记录的最小 TTL 过期，上限 MAX_CACHE_TTL。
struct AnswerExpiry;

impl Expiry<(String, u16), Arc<Message>> for AnswerExpiry {
  fn expire_after_create(
    &self,
    _key: &(String, u16),
    value: &Arc<Message>,
    _current_time: std::time::Instant,
  ) -> Option<Duration> {
    let ttl = value
      .answers
      .iter()
      .map(|record| record.ttl)
      .min()
      .unwrap_or(0);

    Some(Duration::from_secs(u64::from(ttl.min(MAX_CACHE_TTL))))
  }
}


#[cfg(test)]
mod tests {
  use std::{
    net::Ipv4Addr,
    sync::Mutex,
  };

  use hickory_server::proto::{
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RData, Record, rdata::A},
  };
  use tokio::{net::UdpSocket, time::timeout};

  use super::*;
  use crate::{
    inbound::AnyInbound,
    node::{Error, Node, NodeId, OutDispatcher},
    primitives::OutExit,
    route::{DomainRule, RouteMatch, Router},
    test::test_dir,
  };

  struct MockDnsNode {
    router: Router,
    answers: NodeResolveAnswers,
    queries: Mutex<Vec<(Vec<RouteMatch>, ResolveQuery)>>,
  }

  impl MockDnsNode {
    fn new(router: Router, answers: NodeResolveAnswers) -> Self {
      Self {
        router,
        answers,
        queries: Mutex::new(Vec::new()),
      }
    }
  }

  #[async_trait]
  impl Node for MockDnsNode {
    fn id(&self) -> NodeId {
      NodeId::new()
    }

    fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
      vec![]
    }

    async fn resolve_routes(
      &self,
      routes: Vec<RouteMatch>,
      query: &ResolveQuery,
    ) -> Result<NodeResolveAnswers, Error> {
      self
        .queries
        .lock()
        .unwrap()
        .push((routes, query.clone()));
      Ok(self.answers.clone())
    }
  }

  impl InLike for MockDnsNode {
    fn router(&self) -> &Router {
      &self.router
    }

    fn inbounds(&self) -> &[Arc<AnyInbound>] {
      &[]
    }
  }

  fn success_answers(ip: Ipv4Addr) -> NodeResolveAnswers {
    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.add_answers([Record::from_rdata(
      Name::from_str("example.com.").unwrap(),
      60,
      RData::A(A(ip)),
    )]);
    NodeResolveAnswers::Success(message.to_vec().unwrap())
  }

  async fn start_test_server(
    node: Arc<MockDnsNode>,
  ) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();

    let mut server = crate::dns::build_dns_server(node);
    server.register_socket(socket);

    let handle = tokio::spawn(async move {
      server.block_until_done().await.unwrap();
    });

    (address, handle)
  }

  async fn query(
    socket: &UdpSocket,
    server: std::net::SocketAddr,
    name: &str,
    record_type: RecordType,
  ) -> Message {
    let mut request = Message::new(1234, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(
      Name::from_str(name).unwrap(),
      record_type,
    ));

    socket
      .send_to(&request.to_vec().unwrap(), server)
      .await
      .unwrap();

    let mut buffer = [0_u8; 4096];
    let (length, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buffer))
      .await
      .expect("timed out waiting for DNS response")
      .unwrap();

    Message::from_vec(&buffer[..length]).unwrap()
  }

  #[tokio::test]
  async fn a_query_is_routed_and_cached() {
    let router = Router::new(test_dir());
    router.register_local_rules(vec![DomainRule {
      matchers: vec!["proxied.example.com".to_owned().into()],
      priority: 0,
      negate: false,
      exits: vec![OutExit::from("us")],
      dns_only: true,
    }
    .into()]);

    let node = Arc::new(MockDnsNode::new(
      router,
      success_answers(Ipv4Addr::new(203, 0, 113, 7)),
    ));

    let (server_address, _server) = start_test_server(node.clone()).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    // dns_only 规则命中的域名按规则出口解析。
    let response = query(&client, server_address, "proxied.example.com.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert!(
      response
        .answers
        .iter()
        .any(|record| matches!(&record.data, RData::A(a) if a.0 == Ipv4Addr::new(203, 0, 113, 7))),
      "unexpected answers: {:?}",
      response.answers
    );

    {
      let queries = node.queries.lock().unwrap();
      assert_eq!(queries.len(), 1);
      let (routes, resolve_query) = &queries[0];
      assert_eq!(resolve_query.name, "proxied.example.com.");
      assert_eq!(resolve_query.record_type, u16::from(RecordType::A));
      assert_eq!(routes.len(), 1);
      assert_eq!(routes[0].exit, OutExit::from("us"));
    }

    // 第二次查询命中缓存，不再转发。
    let response = query(&client, server_address, "proxied.example.com.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(node.queries.lock().unwrap().len(), 1);

    // 无规则命中的域名回退 DIRECT（本地解析）。
    let response = query(&client, server_address, "other.example.com.", RecordType::AAAA).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    {
      let queries = node.queries.lock().unwrap();
      assert_eq!(queries.len(), 2);
      let (routes, resolve_query) = &queries[1];
      assert_eq!(resolve_query.record_type, u16::from(RecordType::AAAA));
      assert_eq!(routes[0].exit, OutExit::Direct);
    }
  }

  #[tokio::test]
  async fn any_query_is_not_implemented() {
    let node = Arc::new(MockDnsNode::new(
      Router::new(test_dir()),
      success_answers(Ipv4Addr::new(203, 0, 113, 7)),
    ));

    let (server_address, _server) = start_test_server(node).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let response = query(&client, server_address, "example.com.", RecordType::ANY).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NotImp);
  }

  #[tokio::test]
  async fn nxdomain_and_failure_are_mapped() {
    let node = Arc::new(MockDnsNode::new(
      Router::new(test_dir()),
      NodeResolveAnswers::NxDomain,
    ));
    let (server_address, _server) = start_test_server(node).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let response = query(&client, server_address, "missing.example.com.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);

    let node = Arc::new(MockDnsNode::new(
      Router::new(test_dir()),
      NodeResolveAnswers::Failure,
    ));
    let (server_address, _server) = start_test_server(node).await;

    let response = query(&client, server_address, "broken.example.com.", RecordType::A).await;
    assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
  }
}
