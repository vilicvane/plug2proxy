use std::{
  collections::HashMap,
  io,
  net::SocketAddr,
  pin::Pin,
  sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
  },
  task::{Context, Poll},
  time::{Duration, Instant},
};

use async_trait::async_trait;
use colored::Colorize;
use futures::{SinkExt, StreamExt};
use itertools::Itertools;
use lits::duration;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use tokio::{
  io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional},
  sync::mpsc,
  task::JoinSet,
  time::{Instant as TokioInstant, MissedTickBehavior, interval_at},
};
use uuid::Uuid;

use crate::{
  node::{OutDispatcher, OutDispatcherLoad},
  out::PeerOut,
  primitives::{
    BidiStream, OutExit, OutExitMatch, OutExitMatchPriority, OutExits, SocketDestination,
    SocketDestinationHost,
  },
  route::{AnyRule, RouteMatch, Router, RuleKind},
  udp_forwarder::{
    InboundUdpPacketStream, IncomingUdpPacket, OutboundUdpPacketStream, OutgoingUdpPacket,
    UdpPacketSource, UdpPacketStreamError,
  },
};

static NEXT_OUT_DISPATCHER: AtomicUsize = AtomicUsize::new(0);
static NEXT_TCP_FLOW_ID: AtomicU64 = AtomicU64::new(1);
const PENDING_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(30);
const TRANSFER_DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(5 * 60);
const UDP_FLOW_LOG_CACHE_CAPACITY: u64 = 1024 * 64;
const UDP_FLOW_LOG_IDLE_TIMEOUT: Duration = duration!("1m");

type UdpFlow = (UdpPacketSource, SocketDestination, OutExit);

struct FlowIoMetrics {
  started_at: Instant,
  read_bytes: AtomicU64,
  written_bytes: AtomicU64,
  read_pending: AtomicBool,
  write_pending: AtomicBool,
  last_read_progress_millis: AtomicU64,
  last_write_progress_millis: AtomicU64,
}

impl FlowIoMetrics {
  fn new() -> Self {
    Self {
      started_at: Instant::now(),
      read_bytes: AtomicU64::new(0),
      written_bytes: AtomicU64::new(0),
      read_pending: AtomicBool::new(false),
      write_pending: AtomicBool::new(false),
      last_read_progress_millis: AtomicU64::new(0),
      last_write_progress_millis: AtomicU64::new(0),
    }
  }

  fn elapsed_millis(&self) -> u64 {
    self.started_at.elapsed().as_millis().min(u64::MAX as u128) as u64
  }

  fn record_read(&self, bytes: usize) {
    if bytes == 0 {
      return;
    }

    self.read_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    self
      .last_read_progress_millis
      .store(self.elapsed_millis(), Ordering::Release);
  }

  fn record_write(&self, bytes: usize) {
    if bytes == 0 {
      return;
    }

    self
      .written_bytes
      .fetch_add(bytes as u64, Ordering::Relaxed);
    self
      .last_write_progress_millis
      .store(self.elapsed_millis(), Ordering::Release);
  }

  fn snapshot(&self) -> String {
    let elapsed_millis = self.elapsed_millis();

    format!(
      "read_bytes={} written_bytes={} read_pending={} write_pending={} \
       read_idle_ms={} write_idle_ms={}",
      self.read_bytes.load(Ordering::Relaxed),
      self.written_bytes.load(Ordering::Relaxed),
      self.read_pending.load(Ordering::Acquire),
      self.write_pending.load(Ordering::Acquire),
      elapsed_millis.saturating_sub(self.last_read_progress_millis.load(Ordering::Acquire)),
      elapsed_millis.saturating_sub(self.last_write_progress_millis.load(Ordering::Acquire)),
    )
  }
}

struct MeteredBidiStream {
  inner: Box<dyn BidiStream>,
  metrics: Arc<FlowIoMetrics>,
}

impl MeteredBidiStream {
  fn new(inner: Box<dyn BidiStream>, metrics: Arc<FlowIoMetrics>) -> Self {
    Self { inner, metrics }
  }
}

impl AsyncRead for MeteredBidiStream {
  fn poll_read(
    self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &mut ReadBuf<'_>,
  ) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    let previous_length = buffer.filled().len();
    let result = Pin::new(&mut *this.inner).poll_read(context, buffer);

    match &result {
      Poll::Ready(Ok(())) => {
        this.metrics.read_pending.store(false, Ordering::Release);
        this
          .metrics
          .record_read(buffer.filled().len().saturating_sub(previous_length));
      }
      Poll::Ready(Err(_)) => {
        this.metrics.read_pending.store(false, Ordering::Release);
      }
      Poll::Pending => {
        this.metrics.read_pending.store(true, Ordering::Release);
      }
    }

    result
  }
}

impl AsyncWrite for MeteredBidiStream {
  fn poll_write(
    self: Pin<&mut Self>,
    context: &mut Context<'_>,
    buffer: &[u8],
  ) -> Poll<io::Result<usize>> {
    let this = self.get_mut();
    let result = Pin::new(&mut *this.inner).poll_write(context, buffer);

    match &result {
      Poll::Ready(Ok(bytes)) => {
        this.metrics.write_pending.store(false, Ordering::Release);
        this.metrics.record_write(*bytes);
      }
      Poll::Ready(Err(_)) => {
        this.metrics.write_pending.store(false, Ordering::Release);
      }
      Poll::Pending => {
        this.metrics.write_pending.store(true, Ordering::Release);
      }
    }

    result
  }

  fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    let result = Pin::new(&mut *this.inner).poll_flush(context);
    this
      .metrics
      .write_pending
      .store(result.is_pending(), Ordering::Release);
    result
  }

  fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
    let this = self.get_mut();
    let result = Pin::new(&mut *this.inner).poll_shutdown(context);
    this
      .metrics
      .write_pending
      .store(result.is_pending(), Ordering::Release);
    result
  }
}

fn new_diagnostic_interval(period: Duration) -> tokio::time::Interval {
  let mut interval = interval_at(TokioInstant::now() + period, period);
  interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
  interval
}

fn destination_for_route(
  destination: &SocketDestination,
  route: &RouteMatch,
  dispatcher_is_local: bool,
) -> SocketDestination {
  let domain_matched = route.rule_kinds.contains(&RuleKind::Domain);

  // 仅当命中 domain 规则且出口在远端时才把域名交给远端解析（抗 DNS 污染）；
  // 其余情况保留客户端指定的字面 IP，避免远端把 IP 换成域名重新解析到不同地址。
  if !dispatcher_is_local
    && domain_matched
    && let Some(domain) = destination.routing_domain()
  {
    return SocketDestination {
      host: SocketDestinationHost::DomainName(domain),
      port: destination.port,
      routing_domain: None,
      routing_protocol: None,
    };
  }

  // 非 domain 命中的域名目标：携带匹配时已解析的地址，本地避免重复解析，
  // 远端按原 IP 拨号而不重新解析。
  if !domain_matched
    && matches!(destination.host, SocketDestinationHost::DomainName(_))
    && let Some(address) = route.matched_address
  {
    let mut destination = destination.clone();
    destination.host = SocketDestinationHost::IpAddress(address.ip());
    return destination;
  }

  destination.clone()
}

#[async_trait]
pub trait Node {
  fn id(&self) -> NodeId;

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>>;

  fn out_dispatcher_revision(&self) -> u64 {
    0
  }

  async fn tcp_connect(
    &self,
    exits: Vec<OutExit>,
    destination: SocketDestination,
    stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    self
      .tcp_connect_routes(
        exits.into_iter().map(RouteMatch::fixed).collect(),
        destination,
        stream,
      )
      .await
  }

  async fn tcp_connect_routes(
    &self,
    routes: Vec<RouteMatch>,
    destination: SocketDestination,
    stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    let flow_id = NEXT_TCP_FLOW_ID.fetch_add(1, Ordering::Relaxed);
    let route_label = destination.route_label();
    let exits = routes.iter().map(|route| route.exit.clone()).collect_vec();

    if routes.is_empty() {
      log::info!("TCP flow {flow_id} {route_label} no exit matched.");
      return Ok(());
    }

    let mut may_retry_peer_unavailable = true;
    let mut attempt = 0_u32;

    loop {
      attempt += 1;
      let out_dispatchers = self.get_out_dispatchers();

      let Some((matched_route, matched, out_dispatcher)) =
        select_route_dispatcher(&routes, &out_dispatchers)
      else {
        log::info!("TCP flow {flow_id} {route_label} no out dispatcher matched.");
        return Ok(());
      };
      let matched_exit = &matched_route.exit;
      let dial_destination =
        destination_for_route(&destination, &matched_route, out_dispatcher.is_local());

      // A transfer only needs the dispatcher that opens its stream. Keeping
      // the full routing snapshot here pins every QUIC connection that was
      // present when the transfer started, even after its dispatcher is
      // withdrawn or replaced.
      drop(out_dispatchers);

      let dispatcher_label = out_dispatcher.diagnostic_label();
      log::info!(
        "TCP flow {flow_id} attempt {attempt} {route_label} -> {} via \
         {dispatcher_label}, priority={:?}, resolved_exit={}",
        exits
          .iter()
          .map(|exit| if exit == matched_exit {
            exit.to_string().cyan().to_string()
          } else {
            exit.to_string()
          })
          .join(","),
        matched.priority,
        matched.resolved_exit,
      );

      out_dispatcher.transfer_started();
      let started_at = Instant::now();
      let connect = out_dispatcher.connect(matched.resolved_exit, dial_destination.clone());
      tokio::pin!(connect);
      let mut diagnostic_interval = new_diagnostic_interval(PENDING_DIAGNOSTIC_INTERVAL);
      let connect_result = loop {
        tokio::select! {
          result = &mut connect => break result,
          _ = diagnostic_interval.tick() => {
            log::debug!(
              "TCP flow {flow_id} attempt {attempt} connect pending for {} ms: \
               destination={dial_destination}, dispatcher=[{}]",
              started_at.elapsed().as_millis(),
              out_dispatcher.diagnostics(),
            );
          }
        }
      };

      let out_stream = match connect_result {
        Ok(out_stream) => {
          log::debug!(
            "TCP flow {flow_id} attempt {attempt} connected in {} ms: \
             destination={dial_destination}, dispatcher={dispatcher_label}",
            started_at.elapsed().as_millis(),
          );
          out_stream
        }
        Err(Error::OutDispatcherUnavailable)
          if may_retry_peer_unavailable
            && matched.priority == OutExitMatchPriority::PeerProvider =>
        {
          out_dispatcher.transfer_finished(0, started_at.elapsed());
          may_retry_peer_unavailable = false;
          log::debug!(
            "TCP flow {flow_id} attempt {attempt} peer dispatcher became unavailable \
             after {} ms; selecting again: destination={destination}, \
             dispatcher={dispatcher_label}",
            started_at.elapsed().as_millis(),
          );
          continue;
        }
        Err(error) => {
          out_dispatcher.transfer_finished(0, started_at.elapsed());
          log::warn!(
            "TCP flow {flow_id} attempt {attempt} connect failed after {} ms: \
             destination={dial_destination}, dispatcher={dispatcher_label}, error={error}",
            started_at.elapsed().as_millis(),
          );
          return Err(error);
        }
      };

      let client_metrics = Arc::new(FlowIoMetrics::new());
      let outbound_metrics = Arc::new(FlowIoMetrics::new());
      let mut metered_client = MeteredBidiStream::new(stream, client_metrics.clone());
      let mut metered_outbound = MeteredBidiStream::new(out_stream, outbound_metrics.clone());
      let transfer = copy_bidirectional(&mut metered_client, &mut metered_outbound);
      tokio::pin!(transfer);
      let mut diagnostic_interval = new_diagnostic_interval(TRANSFER_DIAGNOSTIC_INTERVAL);
      let transfer_result = loop {
        tokio::select! {
          result = &mut transfer => break result.map_err(Error::from),
          _ = diagnostic_interval.tick() => {
            log::debug!(
              "TCP flow {flow_id} attempt {attempt} transfer diagnostic after {} ms: \
               destination={dial_destination}, dispatcher={dispatcher_label}, \
               client=[{}], outbound=[{}]",
              started_at.elapsed().as_millis(),
              client_metrics.snapshot(),
              outbound_metrics.snapshot(),
            );
          }
        }
      };
      let transferred_bytes = transfer_result
        .as_ref()
        .map(|(upstream, downstream)| upstream.saturating_add(*downstream))
        .unwrap_or(0);

      out_dispatcher.transfer_finished(transferred_bytes, started_at.elapsed());

      match &transfer_result {
        Ok((upstream, downstream)) => {
          log::debug!(
            "TCP flow {flow_id} attempt {attempt} completed after {} ms: \
             destination={dial_destination}, dispatcher={dispatcher_label}, \
             upstream_bytes={upstream}, downstream_bytes={downstream}",
            started_at.elapsed().as_millis(),
          );
        }
        Err(error) => {
          log::warn!(
            "TCP flow {flow_id} attempt {attempt} transfer failed after {} ms: \
             destination={dial_destination}, dispatcher={dispatcher_label}, \
             client=[{}], outbound=[{}], error={error}",
            started_at.elapsed().as_millis(),
            client_metrics.snapshot(),
            outbound_metrics.snapshot(),
          );
        }
      }

      transfer_result?;

      return Ok(());
    }
  }

  async fn route_udp(
    &self,
    router: &Router,
    packet_stream: Box<dyn InboundUdpPacketStream>,
  ) -> Result<(), Error> {
    forward_udp(self, UdpRoute::Router(router), packet_stream).await
  }

  async fn relay_udp(
    &self,
    exit: OutExit,
    packet_stream: Box<dyn InboundUdpPacketStream>,
  ) -> Result<(), Error> {
    forward_udp(self, UdpRoute::Fixed(exit), packet_stream).await
  }

  /// 按路由选择 dispatcher 执行 DNS 解析；relay 节点（HUB）收到 Resolve 后
  /// 也是经此方法把原 exit 再匹配、转发给发布该 exit 的下一节点。
  async fn resolve_routes(
    &self,
    routes: Vec<RouteMatch>,
    query: &ResolveQuery,
  ) -> Result<NodeResolveAnswers, Error> {
    let out_dispatchers = self.get_out_dispatchers();

    let Some((_route, matched, out_dispatcher)) =
      select_route_dispatcher(&routes, &out_dispatchers)
    else {
      log::info!(
        "DNS resolve {} type {} no out dispatcher matched.",
        query.name,
        query.record_type
      );
      return Ok(NodeResolveAnswers::Failure);
    };

    log::debug!(
      "DNS resolve {} type {} -> exit {} via {}",
      query.name,
      query.record_type,
      matched.resolved_exit,
      out_dispatcher.diagnostic_label(),
    );

    out_dispatcher.resolve(matched.resolved_exit, query).await
  }
}

enum UdpRoute<'a> {
  Router(&'a Router),
  Fixed(OutExit),
}

impl UdpRoute<'_> {
  async fn match_routes(&self, destination: &SocketDestination) -> Vec<RouteMatch> {
    match self {
      UdpRoute::Router(router) => router.match_routes(destination).await,
      UdpRoute::Fixed(exit) => vec![RouteMatch::fixed(exit.clone())],
    }
  }
}

#[derive(Clone)]
struct UdpAssociationSender {
  sender: mpsc::UnboundedSender<OutgoingUdpPacket>,
  is_local: bool,
}

async fn forward_udp(
  node: &(impl Node + ?Sized),
  route: UdpRoute<'_>,
  mut packet_stream: Box<dyn InboundUdpPacketStream>,
) -> Result<(), Error> {
  let (incoming_sender, mut incoming_receiver) = mpsc::unbounded_channel();
  let mut association_senders = HashMap::<OutExit, UdpAssociationSender>::new();
  let mut association_tasks = JoinSet::new();
  let logged_flows = new_udp_flow_log_cache(UDP_FLOW_LOG_IDLE_TIMEOUT);
  let mut out_dispatcher_revision = node.out_dispatcher_revision();

  loop {
    tokio::select! {
      outgoing = packet_stream.next() => {
        let Some(outgoing) = outgoing else {
          break;
        };
        let routes = route.match_routes(&outgoing.destination).await;
        let exits = routes
          .iter()
          .map(|route| route.exit.clone())
          .collect_vec();

        if routes.is_empty() {
          log::trace!(
            "UDP {} no exit matched.",
            outgoing.destination.route_label()
          );
          continue;
        }

        let current_out_dispatcher_revision = node.out_dispatcher_revision();

        if current_out_dispatcher_revision != out_dispatcher_revision {
          association_senders.clear();
          out_dispatcher_revision = current_out_dispatcher_revision;
        }

        let mut selected_association = None;

        for requested_route in &routes {
          let requested_exit = &requested_route.exit;
          if association_senders
            .get(requested_exit)
            .is_some_and(|association| association.sender.is_closed())
          {
            association_senders.remove(requested_exit);
          }

          if let Some(association) = association_senders.get(requested_exit) {
            selected_association = Some((requested_route.clone(), association.clone()));
            break;
          }

          let Some((matched_route, outbound, is_local)) = open_udp_association(
            node,
            std::slice::from_ref(requested_route),
            &outgoing.destination,
          )
          .await?
          else {
            continue;
          };
          let (association_sender, association_receiver) = mpsc::unbounded_channel();

          association_tasks.spawn(run_udp_association(
            matched_route.exit.clone(),
            outbound,
            association_receiver,
            incoming_sender.clone(),
          ));
          association_senders.insert(
            matched_route.exit.clone(),
            UdpAssociationSender {
              sender: association_sender.clone(),
              is_local,
            },
          );

          log::info!(
            "UDP association opened: exit={}, first_destination={}",
            matched_route.exit,
            outgoing.destination.route_label()
          );

          selected_association = Some((
            matched_route,
            UdpAssociationSender {
              sender: association_sender,
              is_local,
            },
          ));
          break;
        }

        let Some((matched_route, association)) = selected_association else {
          log::trace!(
            "UDP {} no out dispatcher matched.",
            outgoing.destination.route_label()
          );
          continue;
        };

        if should_log_udp_flow(
          &logged_flows,
          &outgoing.source,
          &outgoing.destination,
          &matched_route.exit,
        ) {
          log::info!(
            "UDP {} -> {} via {}",
            outgoing.source.address,
            outgoing.destination.route_label(),
            exits
              .iter()
              .map(|exit| if exit == &matched_route.exit {
                exit.to_string().cyan().to_string()
              } else {
                exit.to_string()
              })
              .join(",")
          );
        }

        let mut outgoing = outgoing;
        let dial_destination = destination_for_route(
          &outgoing.destination,
          &matched_route,
          association.is_local,
        );
        if outgoing.response_destination.is_none()
          && let SocketDestinationHost::IpAddress(address) = outgoing.destination.host
          && matches!(
            dial_destination.host,
            SocketDestinationHost::DomainName(_)
          )
        {
          outgoing.response_destination =
            Some(SocketAddr::from((address, outgoing.destination.port)));
        }
        outgoing.destination = dial_destination;

        if association.sender.send(outgoing).is_err() {
          association_senders.remove(&matched_route.exit);
        }
      }
      Some(incoming) = incoming_receiver.recv() => {
        packet_stream.send(incoming).await?;
      }
      Some(result) = association_tasks.join_next(), if !association_tasks.is_empty() => {
        let (exit, result) = result.expect("UDP association task panicked");

        if association_senders
          .get(&exit)
          .is_some_and(|association| association.sender.is_closed())
        {
          association_senders.remove(&exit);
        }

        if let Err(error) = result {
          log::debug!("UDP association {exit} stopped: {error}");
        }
      }
    }
  }

  Ok(())
}

fn new_udp_flow_log_cache(idle_timeout: Duration) -> Cache<UdpFlow, ()> {
  Cache::builder()
    .max_capacity(UDP_FLOW_LOG_CACHE_CAPACITY)
    .time_to_idle(idle_timeout)
    .build()
}

fn should_log_udp_flow(
  logged_flows: &Cache<UdpFlow, ()>,
  source: &UdpPacketSource,
  destination: &SocketDestination,
  exit: &OutExit,
) -> bool {
  let flow = (source.clone(), destination.clone(), exit.clone());

  if logged_flows.get(&flow).is_some() {
    return false;
  }

  logged_flows.insert(flow, ());
  true
}

async fn open_udp_association(
  node: &(impl Node + ?Sized),
  routes: &[RouteMatch],
  destination: &SocketDestination,
) -> Result<Option<(RouteMatch, Box<dyn OutboundUdpPacketStream>, bool)>, Error> {
  let mut may_retry_peer_unavailable = true;
  let route_label = destination.route_label();

  loop {
    let out_dispatchers = node.get_out_dispatchers();
    let Some((matched_route, matched, out_dispatcher)) =
      select_route_dispatcher(routes, &out_dispatchers)
    else {
      return Ok(None);
    };
    drop(out_dispatchers);
    let priority = matched.priority;
    let dispatcher_label = out_dispatcher.diagnostic_label();
    let started_at = Instant::now();

    log::info!(
      "UDP association selecting: first_destination={route_label}, requested_exit={matched_exit}, \
       resolved_exit={}, priority={priority:?}, dispatcher={dispatcher_label}",
      matched.resolved_exit,
      matched_exit = matched_route.exit,
    );

    let associate = out_dispatcher.associate(matched.resolved_exit);
    tokio::pin!(associate);
    let mut diagnostic_interval = new_diagnostic_interval(PENDING_DIAGNOSTIC_INTERVAL);
    let associate_result = loop {
      tokio::select! {
        result = &mut associate => break result,
        _ = diagnostic_interval.tick() => {
          log::debug!(
            "UDP association pending for {} ms: first_destination={route_label}, \
             requested_exit={matched_exit}, dispatcher=[{}]",
            started_at.elapsed().as_millis(),
            out_dispatcher.diagnostics(),
            matched_exit = matched_route.exit,
          );
        }
      }
    };

    match associate_result {
      Ok(outbound) => {
        log::info!(
          "UDP association connected in {} ms: first_destination={route_label}, \
           requested_exit={matched_exit}, dispatcher={dispatcher_label}",
          started_at.elapsed().as_millis(),
          matched_exit = matched_route.exit,
        );
        return Ok(Some((matched_route, outbound, out_dispatcher.is_local())));
      }
      Err(Error::OutDispatcherUnavailable)
        if may_retry_peer_unavailable && priority == OutExitMatchPriority::PeerProvider =>
      {
        may_retry_peer_unavailable = false;
        log::debug!(
          "peer OUT for UDP {destination} became unavailable before opening an association; \
           selecting again."
        );
      }
      Err(error) => return Err(error),
    }
  }
}

async fn run_udp_association(
  exit: OutExit,
  mut outbound: Box<dyn OutboundUdpPacketStream>,
  mut outgoing_receiver: mpsc::UnboundedReceiver<OutgoingUdpPacket>,
  incoming_sender: mpsc::UnboundedSender<IncomingUdpPacket>,
) -> (OutExit, Result<(), Error>) {
  let result = async {
    loop {
      tokio::select! {
        outgoing = outgoing_receiver.recv() => {
          let Some(outgoing) = outgoing else {
            break;
          };

          outbound.send(outgoing).await?;
        }
        incoming = outbound.next() => {
          let Some(incoming) = incoming else {
            break;
          };

          if incoming_sender.send(incoming).is_err() {
            break;
          }
        }
      }
    }

    Ok(())
  }
  .await;

  (exit, result)
}

fn select_route_dispatcher(
  routes: &[RouteMatch],
  out_dispatchers: &[Arc<dyn OutDispatcher>],
) -> Option<(RouteMatch, OutExitMatch, Arc<dyn OutDispatcher>)> {
  routes.iter().find_map(|route| {
    let mut matching_dispatchers = out_dispatchers
      .iter()
      .filter_map(|dispatcher| {
        dispatcher
          .match_exit(&route.exit)
          .map(|matched| (dispatcher, matched))
      })
      .collect_vec();

    if matching_dispatchers.is_empty() {
      return None;
    }

    // Selector order remains the outer priority. Within one selector, ANY
    // prefers the current node's default local exit, then a connected peer
    // provider path, independently of dispatcher insertion order. Load and
    // goodput only compare candidates in the same semantic priority layer.
    let best_priority = matching_dispatchers
      .iter()
      .map(|(_, matched)| matched.priority)
      .min()
      .unwrap();

    matching_dispatchers.retain(|(_, matched)| matched.priority == best_priority);

    let index = select_dispatcher_index(
      &matching_dispatchers
        .iter()
        .map(|(dispatcher, _)| dispatcher.load())
        .collect_vec(),
      NEXT_OUT_DISPATCHER.fetch_add(1, Ordering::Relaxed),
    );

    let (dispatcher, matched) = matching_dispatchers.swap_remove(index);

    Some((route.clone(), matched, Arc::clone(dispatcher)))
  })
}

fn select_dispatcher_index(loads: &[OutDispatcherLoad], round_robin: usize) -> usize {
  if loads.len() <= 1 || loads.iter().any(|load| !load.adaptive) {
    return round_robin % loads.len();
  }

  let unmeasured = loads
    .iter()
    .enumerate()
    .filter(|(_, load)| load.goodput_bytes_per_second.is_none())
    .collect_vec();

  if !unmeasured.is_empty() {
    let minimum_active = unmeasured
      .iter()
      .map(|(_, load)| load.active_transfers)
      .min()
      .unwrap();
    let candidates = unmeasured
      .into_iter()
      .filter(|(_, load)| load.active_transfers == minimum_active)
      .map(|(index, _)| index)
      .collect_vec();

    return candidates[round_robin % candidates.len()];
  }

  let scores = loads
    .iter()
    .map(|load| load.goodput_bytes_per_second.unwrap() / (load.active_transfers as u64 + 1))
    .collect_vec();
  let best_score = *scores.iter().max().unwrap();
  let candidates = scores
    .iter()
    .enumerate()
    .filter_map(|(index, score)| (*score == best_score).then_some(index))
    .collect_vec();

  candidates[round_robin % candidates.len()]
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize, derive_more::Display)]
#[serde(transparent)]
#[display("{}", _0.hyphenated().to_string().split_once("-").unwrap().0)]
pub struct NodeId(#[serde(with = "uuid::serde::compact")] pub Uuid);

impl NodeId {
  pub fn new() -> Self {
    Self(Uuid::new_v4())
  }
}

impl Default for NodeId {
  fn default() -> Self {
    Self::new()
  }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NodeHello {
  In(NodeId),
  Out(NodeHelloOut),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeHelloOut {
  /// Stable provider identity shared by every HUB connection pool slot.
  pub id: NodeId,
  pub exits: OutExits,
  /// Endpoint advertised for an optional HUB-coordinated peer path.
  pub peer_endpoint: Option<SocketAddr>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeHelloAck(pub NodeId);

#[derive(Serialize, Deserialize)]
pub enum NodeMessageToOut {
  Connect(OutExit, SocketDestination),
  Associate(OutExit),
  // 新增变体必须保持在末尾，保证 postcard 线上兼容。
  Resolve(OutExit, ResolveQuery),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolveQuery {
  pub name: String,
  pub record_type: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeResolveAnswers {
  /// DNS wire format 的完整应答 Message（保真 TTL/CNAME 链/各类型 rdata）。
  Success(Vec<u8>),
  NxDomain,
  Failure,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NodeMessageToIn {
  Update(NodeMessageToInUpdate),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeMessageToInUpdate {
  pub exits: OutExits,
  pub peer_outs: Vec<PeerOut>,
  pub route_rules: Vec<AnyRule>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher not matched")]
  OutDispatcherNotMatched,
  #[error("Out dispatcher is unavailable")]
  OutDispatcherUnavailable,
  #[error("UDP packet stream error: {0}")]
  UdpPacketStream(#[from] UdpPacketStreamError),
  #[error("postcard stream error: {0}")]
  PostcardStream(#[from] crate::utils::postcard::PostcardStreamError),
}

#[cfg(test)]
mod tests {
  use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{
      Mutex,
      atomic::{AtomicU64, AtomicUsize},
    },
    task::{Context, Poll},
  };

  use futures::{Sink, Stream};
  use tokio::{
    io::{DuplexStream, duplex},
    sync::oneshot,
    time::{Duration, sleep, timeout},
  };

  use super::*;

  struct TakingTestNode {
    dispatchers: Mutex<Option<Vec<Arc<dyn OutDispatcher>>>>,
  }

  impl Node for TakingTestNode {
    fn id(&self) -> NodeId {
      NodeId::new()
    }

    fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
      self.dispatchers.lock().unwrap().take().unwrap()
    }
  }

  struct StaticTestNode {
    dispatchers: Vec<Arc<dyn OutDispatcher>>,
  }

  impl Node for StaticTestNode {
    fn id(&self) -> NodeId {
      NodeId::new()
    }

    fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
      self.dispatchers.clone()
    }
  }

  struct MutableTestNode {
    dispatchers: Mutex<Vec<Arc<dyn OutDispatcher>>>,
    out_dispatcher_revision: AtomicU64,
  }

  impl MutableTestNode {
    fn set_dispatchers(&self, dispatchers: Vec<Arc<dyn OutDispatcher>>) {
      *self.dispatchers.lock().unwrap() = dispatchers;
      self.out_dispatcher_revision.fetch_add(1, Ordering::Relaxed);
    }
  }

  impl Node for MutableTestNode {
    fn id(&self) -> NodeId {
      NodeId::new()
    }

    fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
      self.dispatchers.lock().unwrap().clone()
    }

    fn out_dispatcher_revision(&self) -> u64 {
      self.out_dispatcher_revision.load(Ordering::Relaxed)
    }
  }

  struct SnapshotTestNode {
    dispatcher_snapshots: Mutex<VecDeque<Vec<Arc<dyn OutDispatcher>>>>,
  }

  impl SnapshotTestNode {
    fn new(dispatcher_snapshots: Vec<Vec<Arc<dyn OutDispatcher>>>) -> Self {
      Self {
        dispatcher_snapshots: Mutex::new(dispatcher_snapshots.into()),
      }
    }

    fn remaining_snapshots(&self) -> usize {
      self.dispatcher_snapshots.lock().unwrap().len()
    }
  }

  impl Node for SnapshotTestNode {
    fn id(&self) -> NodeId {
      NodeId::new()
    }

    fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
      self
        .dispatcher_snapshots
        .lock()
        .unwrap()
        .pop_front()
        .expect("test requested an unexpected dispatcher snapshot")
    }
  }

  struct BlockingTestDispatcher {
    peer_sender: Mutex<Option<oneshot::Sender<DuplexStream>>>,
  }

  #[async_trait]
  impl OutDispatcher for BlockingTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch> {
      OutExits::new([OutExit::Proxy]).match_exit(exit)
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      let (stream, peer) = duplex(64);

      self
        .peer_sender
        .lock()
        .unwrap()
        .take()
        .unwrap()
        .send(peer)
        .map_err(|_| std::io::Error::other("test peer receiver was dropped"))?;

      Ok(Box::new(stream))
    }
  }

  struct UnmatchedTestDispatcher;

  #[async_trait]
  impl OutDispatcher for UnmatchedTestDispatcher {
    fn match_exit(&self, _exit: &OutExit) -> Option<OutExitMatch> {
      None
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      unreachable!("unmatched dispatcher must not be connected")
    }
  }

  struct RecordingTestDispatcher {
    exits: OutExits,
    match_priority: OutExitMatchPriority,
    load: OutDispatcherLoad,
    connected_exits: Mutex<Vec<OutExit>>,
    associated_exits: Mutex<Vec<OutExit>>,
  }

  impl RecordingTestDispatcher {
    fn new(exits: Vec<OutExit>) -> Self {
      Self {
        exits: OutExits::new(exits),
        match_priority: OutExitMatchPriority::Provider,
        load: OutDispatcherLoad::default(),
        connected_exits: Mutex::new(vec![]),
        associated_exits: Mutex::new(vec![]),
      }
    }

    fn new_peer(exits: Vec<OutExit>) -> Self {
      Self {
        match_priority: OutExitMatchPriority::PeerProvider,
        ..Self::new(exits)
      }
    }

    fn with_load(mut self, load: OutDispatcherLoad) -> Self {
      self.load = load;
      self
    }

    fn connected_exits(&self) -> Vec<OutExit> {
      self.connected_exits.lock().unwrap().clone()
    }

    fn associated_exits(&self) -> Vec<OutExit> {
      self.associated_exits.lock().unwrap().clone()
    }
  }

  #[async_trait]
  impl OutDispatcher for RecordingTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch> {
      self.exits.match_exit(exit).map(|mut matched| {
        if matched.priority == OutExitMatchPriority::Provider {
          matched.priority = self.match_priority;
        }
        matched
      })
    }

    fn load(&self) -> OutDispatcherLoad {
      self.load
    }

    async fn connect(
      &self,
      exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      self.connected_exits.lock().unwrap().push(exit);

      let (stream, peer) = duplex(64);
      drop(peer);

      Ok(Box::new(stream))
    }

    async fn associate(&self, exit: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
      self.associated_exits.lock().unwrap().push(exit);

      let (stream, peer) = duplex(4096);
      let outbound =
        crate::udp_forwarder::UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(
          Box::new(stream),
        );
      let mut peer =
        crate::udp_forwarder::UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(
          Box::new(peer),
        );
      tokio::spawn(async move { while peer.next().await.is_some() {} });

      Ok(Box::new(outbound))
    }
  }

  #[derive(Clone, Copy)]
  enum TestConnectFailure {
    Unavailable,
    Io,
  }

  struct FailingPeerTestDispatcher {
    failure: TestConnectFailure,
    connect_attempts: AtomicUsize,
  }

  struct FailingUdpPacketStream;

  struct TestInboundUdpPacketStream {
    outgoing: VecDeque<OutgoingUdpPacket>,
  }

  impl Sink<IncomingUdpPacket> for TestInboundUdpPacketStream {
    type Error = UdpPacketStreamError;

    fn poll_ready(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _packet: IncomingUdpPacket) -> Result<(), Self::Error> {
      Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }
  }

  impl Stream for TestInboundUdpPacketStream {
    type Item = OutgoingUdpPacket;

    fn poll_next(mut self: Pin<&mut Self>, _context: &mut Context) -> Poll<Option<Self::Item>> {
      self
        .outgoing
        .pop_front()
        .map_or(Poll::Pending, |packet| Poll::Ready(Some(packet)))
    }
  }

  impl Sink<OutgoingUdpPacket> for FailingUdpPacketStream {
    type Error = UdpPacketStreamError;

    fn poll_ready(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, _packet: OutgoingUdpPacket) -> Result<(), Self::Error> {
      Err(UdpPacketStreamError::Closed)
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Result<(), Self::Error>> {
      Poll::Ready(Ok(()))
    }
  }

  impl Stream for FailingUdpPacketStream {
    type Item = IncomingUdpPacket;

    fn poll_next(self: Pin<&mut Self>, _context: &mut Context) -> Poll<Option<Self::Item>> {
      Poll::Pending
    }
  }

  struct RecoveringUdpTestDispatcher {
    exit: OutExit,
    association_attempts: AtomicUsize,
  }

  struct RecordingUdpTestDispatcher {
    exit: OutExit,
    match_priority: OutExitMatchPriority,
    received_payloads: Arc<Mutex<Vec<Vec<u8>>>>,
    received_destinations: Arc<Mutex<Vec<SocketDestination>>>,
    received_response_destinations: Arc<Mutex<Vec<Option<SocketAddr>>>>,
  }

  impl RecordingUdpTestDispatcher {
    fn new(exit: OutExit, match_priority: OutExitMatchPriority) -> Self {
      Self {
        exit,
        match_priority,
        received_payloads: Arc::new(Mutex::new(vec![])),
        received_destinations: Arc::new(Mutex::new(vec![])),
        received_response_destinations: Arc::new(Mutex::new(vec![])),
      }
    }

    fn received_payloads(&self) -> Vec<Vec<u8>> {
      self.received_payloads.lock().unwrap().clone()
    }

    fn received_destinations(&self) -> Vec<SocketDestination> {
      self.received_destinations.lock().unwrap().clone()
    }

    fn received_response_destinations(&self) -> Vec<Option<SocketAddr>> {
      self.received_response_destinations.lock().unwrap().clone()
    }
  }

  #[async_trait]
  impl OutDispatcher for RecordingUdpTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch> {
      OutExits::new([OutExit::Proxy, self.exit.clone()])
        .match_exit(exit)
        .map(|mut matched| {
          matched.priority = self.match_priority;
          matched
        })
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      unreachable!("this dispatcher is only used for UDP")
    }

    async fn associate(&self, _exit: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
      let (stream, peer) = duplex(4096);
      let outbound =
        crate::udp_forwarder::UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(
          Box::new(stream),
        );
      let mut peer =
        crate::udp_forwarder::UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(
          Box::new(peer),
        );
      let received_payloads = self.received_payloads.clone();
      let received_destinations = self.received_destinations.clone();
      let received_response_destinations = self.received_response_destinations.clone();

      tokio::spawn(async move {
        while let Some(packet) = peer.next().await {
          received_response_destinations
            .lock()
            .unwrap()
            .push(packet.response_destination);
          received_destinations
            .lock()
            .unwrap()
            .push(packet.destination);
          received_payloads.lock().unwrap().push(packet.payload);
        }
      });

      Ok(Box::new(outbound))
    }
  }

  #[async_trait]
  impl OutDispatcher for RecoveringUdpTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch> {
      OutExits::new([OutExit::Proxy, self.exit.clone()]).match_exit(exit)
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      unreachable!("this dispatcher is only used for UDP")
    }

    async fn associate(&self, _exit: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
      if self.association_attempts.fetch_add(1, Ordering::Relaxed) == 0 {
        return Ok(Box::new(FailingUdpPacketStream));
      }

      let (stream, peer) = duplex(4096);
      let outbound =
        crate::udp_forwarder::UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(
          Box::new(stream),
        );
      let mut peer =
        crate::udp_forwarder::UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(
          Box::new(peer),
        );
      tokio::spawn(async move { while peer.next().await.is_some() {} });

      Ok(Box::new(outbound))
    }
  }

  impl FailingPeerTestDispatcher {
    fn new(failure: TestConnectFailure) -> Self {
      Self {
        failure,
        connect_attempts: AtomicUsize::new(0),
      }
    }

    fn connect_attempts(&self) -> usize {
      self.connect_attempts.load(Ordering::Relaxed)
    }
  }

  #[async_trait]
  impl OutDispatcher for FailingPeerTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch> {
      OutExits::new([OutExit::Proxy])
        .match_exit(exit)
        .map(|mut matched| {
          matched.priority = OutExitMatchPriority::PeerProvider;
          matched
        })
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      self.connect_attempts.fetch_add(1, Ordering::Relaxed);

      match self.failure {
        TestConnectFailure::Unavailable => Err(Error::OutDispatcherUnavailable),
        TestConnectFailure::Io => Err(std::io::Error::other("simulated connect I/O error").into()),
      }
    }
  }

  fn test_destination() -> SocketDestination {
    SocketDestination {
      host: crate::primitives::SocketDestinationHost::IpAddress("127.0.0.1".parse().unwrap()),
      port: 80,
      routing_domain: None,
      routing_protocol: None,
    }
  }

  #[test]
  fn remote_domain_matched_routes_promote_routing_domain_to_dial_target() {
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse().unwrap()),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
      routing_protocol: Some(crate::primitives::SniffedProtocol::Tls),
    };
    let route = RouteMatch {
      exit: OutExit::from("us"),
      rule_kinds: vec![RuleKind::Domain],
      matched_address: Some("182.140.143.139:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, false),
      SocketDestination {
        host: SocketDestinationHost::DomainName("c2c.cdn.weixin.qq.com".to_owned()),
        port: 443,
        routing_domain: None,
        routing_protocol: None,
      }
    );
  }

  #[test]
  fn remote_non_domain_routes_keep_literal_ip_dial_target() {
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse().unwrap()),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
      routing_protocol: Some(crate::primitives::SniffedProtocol::Tls),
    };
    let route = RouteMatch {
      exit: OutExit::from("us"),
      rule_kinds: vec![RuleKind::GeoIp],
      matched_address: Some("182.140.143.139:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, false),
      destination
    );
  }

  #[test]
  fn local_routes_preserve_original_ip() {
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("182.140.143.139".parse().unwrap()),
      port: 443,
      routing_domain: Some("c2c.cdn.weixin.qq.com".to_owned()),
      routing_protocol: Some(crate::primitives::SniffedProtocol::Tls),
    };
    let route = RouteMatch {
      exit: OutExit::Direct,
      rule_kinds: vec![RuleKind::Domain],
      matched_address: Some("182.140.143.139:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, true),
      destination
    );
  }

  #[test]
  fn remote_non_domain_routes_carry_resolved_ip_for_domain_targets() {
    let destination = SocketDestination {
      host: SocketDestinationHost::DomainName("example.com".to_owned()),
      port: 443,
      routing_domain: None,
      routing_protocol: None,
    };
    let route = RouteMatch {
      exit: OutExit::from("us"),
      rule_kinds: vec![RuleKind::GeoIp],
      matched_address: Some("203.0.113.8:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, false),
      SocketDestination {
        host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
        port: 443,
        routing_domain: None,
        routing_protocol: None,
      }
    );
  }

  #[test]
  fn remote_domain_matched_routes_keep_domain_targets_for_remote_resolution() {
    let destination = SocketDestination {
      host: SocketDestinationHost::DomainName("example.com".to_owned()),
      port: 443,
      routing_domain: None,
      routing_protocol: None,
    };
    let route = RouteMatch {
      exit: OutExit::from("us"),
      rule_kinds: vec![RuleKind::Domain],
      matched_address: Some("203.0.113.8:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, false),
      SocketDestination {
        host: SocketDestinationHost::DomainName("example.com".to_owned()),
        port: 443,
        routing_domain: None,
        routing_protocol: None,
      }
    );
  }

  #[test]
  fn remote_unsniffed_ip_stays_ip() {
    let destination = SocketDestination {
      host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
      port: 443,
      routing_domain: None,
      routing_protocol: None,
    };
    let route = RouteMatch {
      exit: OutExit::from("us"),
      rule_kinds: vec![RuleKind::GeoIp],
      matched_address: Some("203.0.113.8:443".parse().unwrap()),
    };

    assert_eq!(
      destination_for_route(&destination, &route, false),
      destination
    );
  }

  async fn run_selection(
    exits: Vec<OutExit>,
    dispatchers: Vec<Arc<dyn OutDispatcher>>,
  ) -> Result<(), Error> {
    let node = TakingTestNode {
      dispatchers: Mutex::new(Some(dispatchers)),
    };
    let (node_stream, client_stream) = duplex(64);
    drop(client_stream);

    node
      .tcp_connect(exits, test_destination(), Box::new(node_stream))
      .await
  }

  fn adaptive_load(goodput: Option<u64>, active_transfers: usize) -> OutDispatcherLoad {
    OutDispatcherLoad {
      adaptive: true,
      active_transfers,
      goodput_bytes_per_second: goodput,
    }
  }

  #[test]
  fn udp_flow_logging_deduplicates_only_the_same_flow() {
    let logged_flows = new_udp_flow_log_cache(Duration::from_secs(60));
    let source = UdpPacketSource {
      via: vec![],
      address: "127.0.0.1:50000".parse().unwrap(),
    };
    let destination = test_destination();
    let exit = OutExit::from("us");

    assert!(should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &exit
    ));
    assert!(!should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &exit
    ));

    let mut other_source = source.clone();
    other_source.address.set_port(50001);
    assert!(should_log_udp_flow(
      &logged_flows,
      &other_source,
      &destination,
      &exit
    ));

    let mut other_destination = destination.clone();
    other_destination.port += 1;
    assert!(should_log_udp_flow(
      &logged_flows,
      &source,
      &other_destination,
      &exit
    ));

    assert!(should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &OutExit::Direct
    ));
  }

  #[tokio::test]
  async fn udp_flow_logging_repeats_after_the_flow_expires() {
    let logged_flows = new_udp_flow_log_cache(Duration::from_millis(25));
    let source = UdpPacketSource {
      via: vec![],
      address: "127.0.0.1:50000".parse().unwrap(),
    };
    let destination = test_destination();
    let exit = OutExit::from("us");

    assert!(should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &exit
    ));
    assert!(!should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &exit
    ));

    sleep(Duration::from_millis(75)).await;

    assert!(should_log_udp_flow(
      &logged_flows,
      &source,
      &destination,
      &exit
    ));
  }

  #[test]
  fn dispatcher_selection_samples_unmeasured_idle_paths_first() {
    let loads = [
      adaptive_load(None, 1),
      adaptive_load(None, 0),
      adaptive_load(None, 0),
    ];

    assert_eq!(select_dispatcher_index(&loads, 0), 1);
    assert_eq!(select_dispatcher_index(&loads, 1), 2);
  }

  #[test]
  fn dispatcher_selection_avoids_known_slow_paths() {
    let loads = [
      adaptive_load(Some(2_000_000), 0),
      adaptive_load(Some(20_000), 0),
      adaptive_load(Some(1_000_000), 0),
    ];

    assert_eq!(select_dispatcher_index(&loads, 0), 0);
  }

  #[test]
  fn dispatcher_selection_accounts_for_current_load() {
    let loads = [
      adaptive_load(Some(2_000_000), 3),
      adaptive_load(Some(1_000_000), 0),
    ];

    assert_eq!(select_dispatcher_index(&loads, 0), 1);
  }

  #[test]
  fn dispatcher_selection_keeps_round_robin_for_mixed_dispatchers() {
    let loads = [
      adaptive_load(Some(2_000_000), 0),
      OutDispatcherLoad::default(),
    ];

    assert_eq!(select_dispatcher_index(&loads, 3), 1);
  }

  #[tokio::test]
  async fn any_prefers_default_local_independently_of_dispatcher_order() -> anyhow::Result<()> {
    let provider = Arc::new(RecordingTestDispatcher::new_peer(vec![OutExit::Proxy]));
    let default_local = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Direct]));
    let dispatchers: Vec<Arc<dyn OutDispatcher>> = vec![provider.clone(), default_local.clone()];

    run_selection(vec![OutExit::Any], dispatchers).await?;

    assert_eq!(default_local.connected_exits(), vec![OutExit::Direct]);
    assert!(provider.connected_exits().is_empty());

    Ok(())
  }

  #[tokio::test]
  async fn peer_provider_precedes_faster_relay_provider() -> anyhow::Result<()> {
    let route = OutExit::from("youtube");
    let relay = Arc::new(
      RecordingTestDispatcher::new(vec![OutExit::Proxy, route.clone()])
        .with_load(adaptive_load(Some(100_000_000), 0)),
    );
    let peer = Arc::new(
      RecordingTestDispatcher::new_peer(vec![OutExit::Proxy, route.clone()])
        .with_load(adaptive_load(Some(1), 100)),
    );
    let dispatchers: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone(), peer.clone()];

    run_selection(vec![route.clone()], dispatchers).await?;

    assert_eq!(peer.connected_exits(), vec![route]);
    assert!(relay.connected_exits().is_empty());

    Ok(())
  }

  #[tokio::test]
  async fn unmatched_peer_provider_does_not_block_matching_relay() -> anyhow::Result<()> {
    let relay_route = OutExit::from("okx");
    let peer = Arc::new(RecordingTestDispatcher::new_peer(vec![
      OutExit::Proxy,
      OutExit::from("youtube"),
    ]));
    let relay = Arc::new(RecordingTestDispatcher::new(vec![
      OutExit::Proxy,
      relay_route.clone(),
    ]));
    let dispatchers: Vec<Arc<dyn OutDispatcher>> = vec![peer.clone(), relay.clone()];

    run_selection(vec![relay_route.clone()], dispatchers).await?;

    assert_eq!(relay.connected_exits(), vec![relay_route]);
    assert!(peer.connected_exits().is_empty());

    Ok(())
  }

  #[tokio::test]
  async fn unavailable_peer_reselects_from_one_fresh_snapshot() -> anyhow::Result<()> {
    let peer = Arc::new(FailingPeerTestDispatcher::new(
      TestConnectFailure::Unavailable,
    ));
    let relay = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Proxy]));
    let first_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone(), peer.clone()];
    let second_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone()];
    let node = SnapshotTestNode::new(vec![first_snapshot, second_snapshot]);
    let (node_stream, client_stream) = duplex(64);
    drop(client_stream);

    node
      .tcp_connect(
        vec![OutExit::Proxy],
        test_destination(),
        Box::new(node_stream),
      )
      .await?;

    assert_eq!(peer.connect_attempts(), 1);
    assert_eq!(relay.connected_exits(), vec![OutExit::Proxy]);
    assert_eq!(node.remaining_snapshots(), 0);

    Ok(())
  }

  #[tokio::test]
  async fn unavailable_peer_does_not_skip_another_connected_peer() -> anyhow::Result<()> {
    let unavailable_peer = Arc::new(FailingPeerTestDispatcher::new(
      TestConnectFailure::Unavailable,
    ));
    let connected_peer = Arc::new(RecordingTestDispatcher::new_peer(vec![OutExit::Proxy]));
    let relay = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Proxy]));
    let first_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone(), unavailable_peer.clone()];
    let second_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone(), connected_peer.clone()];
    let node = SnapshotTestNode::new(vec![first_snapshot, second_snapshot]);
    let (node_stream, peer) = duplex(64);
    drop(peer);

    node
      .tcp_connect(
        vec![OutExit::Proxy],
        test_destination(),
        Box::new(node_stream),
      )
      .await?;

    assert_eq!(unavailable_peer.connect_attempts(), 1);
    assert_eq!(connected_peer.connected_exits(), vec![OutExit::Proxy]);
    assert!(relay.connected_exits().is_empty());

    Ok(())
  }

  #[tokio::test]
  async fn peer_io_error_does_not_retry_relay() {
    let peer = Arc::new(FailingPeerTestDispatcher::new(TestConnectFailure::Io));
    let relay = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Proxy]));
    let first_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone(), peer.clone()];
    let second_snapshot: Vec<Arc<dyn OutDispatcher>> = vec![relay.clone()];
    let node = SnapshotTestNode::new(vec![first_snapshot, second_snapshot]);
    let (node_stream, client_stream) = duplex(64);
    drop(client_stream);

    let result = node
      .tcp_connect(
        vec![OutExit::Proxy],
        test_destination(),
        Box::new(node_stream),
      )
      .await;

    assert!(matches!(result, Err(Error::Io(_))));
    assert_eq!(peer.connect_attempts(), 1);
    assert!(relay.connected_exits().is_empty());
    assert_eq!(node.remaining_snapshots(), 1);
  }

  #[tokio::test]
  async fn any_resolves_to_proxy_when_only_provider_matches() -> anyhow::Result<()> {
    let provider = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Proxy]));
    let dispatchers: Vec<Arc<dyn OutDispatcher>> = vec![provider.clone()];

    run_selection(vec![OutExit::Any], dispatchers).await?;

    assert_eq!(provider.connected_exits(), vec![OutExit::Proxy]);

    Ok(())
  }

  #[tokio::test]
  async fn selector_order_precedes_any_internal_priority() -> anyhow::Result<()> {
    let provider = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Proxy]));
    let default_local = Arc::new(RecordingTestDispatcher::new(vec![OutExit::Direct]));
    let dispatchers: Vec<Arc<dyn OutDispatcher>> = vec![default_local.clone(), provider.clone()];

    run_selection(vec![OutExit::Proxy, OutExit::Any], dispatchers).await?;

    assert_eq!(provider.connected_exits(), vec![OutExit::Proxy]);
    assert!(default_local.connected_exits().is_empty());

    Ok(())
  }

  #[tokio::test]
  async fn udp_selector_order_precedes_an_existing_lower_priority_association() -> anyhow::Result<()>
  {
    use crate::{
      route::{AddressRule, FallbackRule},
      test::test_dir,
      udp_forwarder::{UdpPacketSource, UdpPacketStream},
    };

    let us = OutExit::from("us");
    let okx = OutExit::from("okx");
    let dispatcher = Arc::new(RecordingTestDispatcher::new(vec![
      OutExit::Proxy,
      us.clone(),
      okx.clone(),
    ]));
    let node = Arc::new(StaticTestNode {
      dispatchers: vec![dispatcher.clone()],
    });
    let router = Arc::new(Router::new(test_dir()));
    router.register_local_rules(vec![
      AddressRule {
        match_ips: None,
        match_ports: Some(vec![1000]),
        priority: 0,
        negate: false,
        exits: vec![us.clone()],
      }
      .into(),
      FallbackRule {
        exits: vec![okx.clone(), us.clone()],
      }
      .into(),
    ]);

    let (node_stream, client_stream) = duplex(4096);
    let node_packets =
      UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(node_stream));
    let mut client_packets =
      UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(client_stream));
    let route_task = tokio::spawn({
      let node = node.clone();
      let router = router.clone();
      async move { node.route_udp(&router, Box::new(node_packets)).await }
    });
    let source = UdpPacketSource {
      via: vec![],
      address: "127.0.0.1:50000".parse()?,
    };

    client_packets
      .send(OutgoingUdpPacket {
        source: source.clone(),
        destination: SocketDestination {
          host: crate::primitives::SocketDestinationHost::IpAddress("127.0.0.1".parse()?),
          port: 1000,
          routing_domain: None,
          routing_protocol: None,
        },
        response_destination: None,
        payload: vec![1],
      })
      .await?;
    timeout(std::time::Duration::from_secs(1), async {
      while dispatcher.associated_exits().is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    client_packets
      .send(OutgoingUdpPacket {
        source,
        destination: SocketDestination {
          host: crate::primitives::SocketDestinationHost::IpAddress("127.0.0.1".parse()?),
          port: 2000,
          routing_domain: None,
          routing_protocol: None,
        },
        response_destination: None,
        payload: vec![2],
      })
      .await?;
    timeout(std::time::Duration::from_secs(1), async {
      while dispatcher.associated_exits().len() < 2 {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    assert_eq!(dispatcher.associated_exits(), vec![us, okx]);

    route_task.abort();
    route_task.await.unwrap_err();

    Ok(())
  }

  #[tokio::test]
  async fn udp_remote_route_sends_domain_to_remote_dispatcher() -> anyhow::Result<()> {
    use crate::{route::DomainRule, test::test_dir, udp_forwarder::UdpPacketSource};

    let exit = OutExit::from("us");
    let dispatcher = Arc::new(RecordingUdpTestDispatcher::new(
      exit.clone(),
      OutExitMatchPriority::Provider,
    ));
    let node = Arc::new(StaticTestNode {
      dispatchers: vec![dispatcher.clone()],
    });
    let router = Arc::new(Router::new(test_dir()));
    router.register_local_rules(vec![DomainRule {
      matchers: vec!["www.example.com".to_owned().into()],
      priority: 0,
      negate: false,
      exits: vec![exit],
      dns_only: false,
    }
    .into()]);
    let route_task = tokio::spawn({
      let node = node.clone();
      let router = router.clone();
      async move {
        node
          .route_udp(
            &router,
            Box::new(TestInboundUdpPacketStream {
              outgoing: VecDeque::from([OutgoingUdpPacket {
                source: UdpPacketSource {
                  via: vec![],
                  address: "127.0.0.1:50000".parse().unwrap(),
                },
                destination: SocketDestination {
                  host: SocketDestinationHost::IpAddress("203.0.113.8".parse().unwrap()),
                  port: 443,
                  routing_domain: Some("www.example.com".to_owned()),
                  routing_protocol: Some(crate::primitives::SniffedProtocol::Tls),
                },
                response_destination: None,
                payload: vec![1],
              }]),
            }),
          )
          .await
      }
    });

    timeout(Duration::from_secs(1), async {
      while dispatcher.received_destinations().is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    assert_eq!(
      dispatcher.received_destinations(),
      vec![SocketDestination {
        host: SocketDestinationHost::DomainName("www.example.com".to_owned()),
        port: 443,
        routing_domain: None,
        routing_protocol: None,
      }]
    );
    assert_eq!(
      dispatcher.received_response_destinations(),
      vec![Some("203.0.113.8:443".parse().unwrap())]
    );

    route_task.abort();
    route_task.await.unwrap_err();

    Ok(())
  }

  #[tokio::test]
  async fn udp_association_failure_does_not_stop_the_inbound() -> anyhow::Result<()> {
    use crate::{
      route::FallbackRule,
      test::test_dir,
      udp_forwarder::{UdpPacketSource, UdpPacketStream},
    };

    let exit = OutExit::from("us");
    let dispatcher = Arc::new(RecoveringUdpTestDispatcher {
      exit: exit.clone(),
      association_attempts: AtomicUsize::new(0),
    });
    let node = Arc::new(StaticTestNode {
      dispatchers: vec![dispatcher.clone()],
    });
    let router = Arc::new(Router::new(test_dir()));
    router.register_local_rules(vec![FallbackRule { exits: vec![exit] }.into()]);
    let (node_stream, client_stream) = duplex(4096);
    let node_packets =
      UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(node_stream));
    let mut client_packets =
      UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(client_stream));
    let route_task = tokio::spawn({
      let node = node.clone();
      let router = router.clone();
      async move { node.route_udp(&router, Box::new(node_packets)).await }
    });
    let packet = OutgoingUdpPacket {
      source: UdpPacketSource {
        via: vec![],
        address: "127.0.0.1:50000".parse()?,
      },
      destination: test_destination(),
      response_destination: None,
      payload: vec![1],
    };

    timeout(Duration::from_secs(1), async {
      while dispatcher.association_attempts.load(Ordering::Relaxed) < 2 {
        client_packets.send(packet.clone()).await.unwrap();
        sleep(Duration::from_millis(10)).await;
      }
    })
    .await?;

    assert!(!route_task.is_finished());
    route_task.abort();
    route_task.await.unwrap_err();

    Ok(())
  }

  #[tokio::test]
  async fn udp_association_follows_dispatcher_changes() -> anyhow::Result<()> {
    use crate::udp_forwarder::{UdpPacketSource, UdpPacketStream};

    let exit = OutExit::from("us");
    let relay_dispatcher = Arc::new(RecordingUdpTestDispatcher::new(
      exit.clone(),
      OutExitMatchPriority::Provider,
    ));
    let old_peer_dispatcher = Arc::new(RecordingUdpTestDispatcher::new(
      exit.clone(),
      OutExitMatchPriority::PeerProvider,
    ));
    let new_peer_dispatcher = Arc::new(RecordingUdpTestDispatcher::new(
      exit.clone(),
      OutExitMatchPriority::PeerProvider,
    ));
    let node = Arc::new(MutableTestNode {
      dispatchers: Mutex::new(vec![relay_dispatcher.clone()]),
      out_dispatcher_revision: AtomicU64::new(0),
    });
    let (node_stream, client_stream) = duplex(4096);
    let node_packets =
      UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(node_stream));
    let mut client_packets =
      UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(client_stream));
    let relay_task = tokio::spawn({
      let node = node.clone();
      let exit = exit.clone();
      async move { node.relay_udp(exit, Box::new(node_packets)).await }
    });
    let packet = |payload| OutgoingUdpPacket {
      source: UdpPacketSource {
        via: vec![],
        address: "127.0.0.1:50000".parse().unwrap(),
      },
      destination: test_destination(),
      response_destination: None,
      payload,
    };

    client_packets.send(packet(vec![1])).await?;
    timeout(Duration::from_secs(1), async {
      while relay_dispatcher.received_payloads().is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    node.set_dispatchers(vec![relay_dispatcher.clone(), old_peer_dispatcher.clone()]);
    client_packets.send(packet(vec![2])).await?;
    timeout(Duration::from_secs(1), async {
      while old_peer_dispatcher.received_payloads().is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    node.set_dispatchers(vec![relay_dispatcher.clone(), new_peer_dispatcher.clone()]);
    client_packets.send(packet(vec![3])).await?;
    timeout(Duration::from_secs(1), async {
      while new_peer_dispatcher.received_payloads().is_empty() {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    assert_eq!(relay_dispatcher.received_payloads(), vec![vec![1]]);
    assert_eq!(old_peer_dispatcher.received_payloads(), vec![vec![2]]);
    assert_eq!(new_peer_dispatcher.received_payloads(), vec![vec![3]]);

    relay_task.abort();
    relay_task.await.unwrap_err();

    Ok(())
  }

  #[tokio::test]
  async fn active_transfer_releases_unmatched_dispatchers() -> anyhow::Result<()> {
    let (outbound_peer_sender, outbound_peer_receiver) = oneshot::channel();
    let selected_dispatcher: Arc<dyn OutDispatcher> = Arc::new(BlockingTestDispatcher {
      peer_sender: Mutex::new(Some(outbound_peer_sender)),
    });
    let selected_dispatcher_weak = Arc::downgrade(&selected_dispatcher);
    let unmatched_dispatcher: Arc<dyn OutDispatcher> = Arc::new(UnmatchedTestDispatcher);
    let unmatched_dispatcher_weak = Arc::downgrade(&unmatched_dispatcher);

    let node = TakingTestNode {
      dispatchers: Mutex::new(Some(vec![selected_dispatcher, unmatched_dispatcher])),
    };
    let destination = SocketDestination {
      host: crate::primitives::SocketDestinationHost::IpAddress("127.0.0.1".parse()?),
      port: 80,
      routing_domain: None,
      routing_protocol: None,
    };
    let (node_stream, client_stream) = duplex(64);

    let transfer = tokio::spawn(async move {
      node
        .tcp_connect(vec![OutExit::Any], destination, Box::new(node_stream))
        .await
    });

    let outbound_peer =
      timeout(std::time::Duration::from_secs(1), outbound_peer_receiver).await??;

    tokio::task::yield_now().await;
    assert!(
      unmatched_dispatcher_weak.upgrade().is_none(),
      "an active transfer retained an unrelated dispatcher"
    );
    assert!(
      selected_dispatcher_weak.upgrade().is_some(),
      "an active transfer released its selected dispatcher"
    );

    drop(client_stream);
    drop(outbound_peer);
    transfer.await??;
    assert!(
      selected_dispatcher_weak.upgrade().is_none(),
      "the selected dispatcher remained after its transfer finished"
    );

    Ok(())
  }

  #[test]
  fn resolve_messages_postcard_round_trip() {
    let message = NodeMessageToOut::Resolve(
      OutExit::from("wshq"),
      ResolveQuery {
        name: "example.com".to_owned(),
        record_type: 28,
      },
    );

    let bytes = postcard::to_allocvec(&message).unwrap();
    let NodeMessageToOut::Resolve(exit, query) = postcard::from_bytes(&bytes).unwrap() else {
      panic!("expected Resolve variant");
    };

    assert_eq!(exit, OutExit::from("wshq"));
    assert_eq!(query.name, "example.com");
    assert_eq!(query.record_type, 28);

    let success = NodeResolveAnswers::Success(vec![1, 2, 3]);
    let bytes = postcard::to_allocvec(&success).unwrap();
    let NodeResolveAnswers::Success(bytes) = postcard::from_bytes(&bytes).unwrap() else {
      panic!("expected Success variant");
    };
    assert_eq!(bytes, vec![1, 2, 3]);

    for answers in [NodeResolveAnswers::NxDomain, NodeResolveAnswers::Failure] {
      let bytes = postcard::to_allocvec(&answers).unwrap();
      let decoded: NodeResolveAnswers = postcard::from_bytes(&bytes).unwrap();
      assert!(
        matches!(
          (&answers, &decoded),
          (NodeResolveAnswers::NxDomain, NodeResolveAnswers::NxDomain)
            | (NodeResolveAnswers::Failure, NodeResolveAnswers::Failure)
        ),
        "round trip changed the variant"
      );
    }
  }
}
