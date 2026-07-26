use std::{
  collections::HashMap,
  net::SocketAddr,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::Instant,
};

use async_trait::async_trait;
use colored::Colorize;
use futures::{SinkExt, StreamExt};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::{io::copy_bidirectional, sync::mpsc, task::JoinSet};
use uuid::Uuid;

use crate::{
  node::{OutDispatcher, OutDispatcherLoad},
  out::PeerOut,
  primitives::{
    BidiStream, OutExit, OutExitMatch, OutExitMatchPriority, OutExits, SocketDestination,
  },
  route::{AnyRule, Router},
  udp_forwarder::{
    InboundUdpPacketStream, IncomingUdpPacket, OutboundUdpPacketStream, OutgoingUdpPacket,
    UdpPacketStreamError,
  },
};

static NEXT_OUT_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

#[async_trait]
pub trait Node {
  fn id(&self) -> NodeId;

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>>;

  async fn tcp_connect(
    &self,
    exits: Vec<OutExit>,
    destination: SocketDestination,
    mut stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    if exits.is_empty() {
      log::info!("TCP {destination} no exit matched.");
      return Ok(());
    }

    let mut may_retry_peer_unavailable = true;

    loop {
      let out_dispatchers = self.get_out_dispatchers();

      let Some((matched_exit, matched, out_dispatcher)) =
        select_out_dispatcher(&exits, &out_dispatchers)
      else {
        log::info!("TCP {destination} no out dispatcher matched.");
        return Ok(());
      };

      // A transfer only needs the dispatcher that opens its stream. Keeping
      // the full routing snapshot here pins every QUIC connection that was
      // present when the transfer started, even after its dispatcher is
      // withdrawn or replaced.
      drop(out_dispatchers);

      log::info!(
        "TCP {destination} -> {}",
        exits
          .iter()
          .map(|exit| if exit == &matched_exit {
            exit.to_string().cyan().to_string()
          } else {
            exit.to_string()
          })
          .join(",")
      );

      out_dispatcher.transfer_started();
      let started_at = Instant::now();
      let connect_result = out_dispatcher
        .connect(matched.resolved_exit, destination.clone())
        .await;

      let mut out_stream = match connect_result {
        Ok(out_stream) => out_stream,
        Err(Error::OutDispatcherUnavailable)
          if may_retry_peer_unavailable
            && matched.priority == OutExitMatchPriority::PeerProvider =>
        {
          out_dispatcher.transfer_finished(0, started_at.elapsed());
          may_retry_peer_unavailable = false;
          log::debug!(
            "peer OUT for TCP {destination} became unavailable before opening a stream; \
             selecting again."
          );
          continue;
        }
        Err(error) => {
          out_dispatcher.transfer_finished(0, started_at.elapsed());
          return Err(error);
        }
      };

      let transfer_result = copy_bidirectional(&mut stream, &mut out_stream)
        .await
        .map_err(Error::from);
      let transferred_bytes = transfer_result
        .as_ref()
        .map(|(upstream, downstream)| upstream.saturating_add(*downstream))
        .unwrap_or(0);

      out_dispatcher.transfer_finished(transferred_bytes, started_at.elapsed());
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
}

enum UdpRoute<'a> {
  Router(&'a Router),
  Fixed(OutExit),
}

impl UdpRoute<'_> {
  async fn match_exits(&self, destination: &SocketDestination) -> Vec<OutExit> {
    match self {
      UdpRoute::Router(router) => router.match_exits(destination).await,
      UdpRoute::Fixed(exit) => vec![exit.clone()],
    }
  }
}

async fn forward_udp(
  node: &(impl Node + ?Sized),
  route: UdpRoute<'_>,
  mut packet_stream: Box<dyn InboundUdpPacketStream>,
) -> Result<(), Error> {
  let (incoming_sender, mut incoming_receiver) = mpsc::unbounded_channel();
  let mut association_senders = HashMap::<OutExit, mpsc::UnboundedSender<OutgoingUdpPacket>>::new();
  let mut association_tasks = JoinSet::new();

  loop {
    tokio::select! {
      outgoing = packet_stream.next() => {
        let Some(outgoing) = outgoing else {
          break;
        };
        let exits = route.match_exits(&outgoing.destination).await;

        if exits.is_empty() {
          log::debug!("UDP {} no exit matched.", outgoing.destination);
          continue;
        }

        let mut selected_association = None;

        for requested_exit in &exits {
          if let Some(sender) = association_senders
            .get(requested_exit)
            .filter(|sender| !sender.is_closed())
          {
            selected_association = Some((requested_exit.clone(), sender.clone()));
            break;
          }

          let Some((matched_exit, outbound)) = open_udp_association(
            node,
            std::slice::from_ref(requested_exit),
            &outgoing.destination,
          )
          .await?
          else {
            continue;
          };
          let (association_sender, association_receiver) = mpsc::unbounded_channel();

          association_tasks.spawn(run_udp_association(
            matched_exit.clone(),
            outbound,
            association_receiver,
            incoming_sender.clone(),
          ));
          association_senders.insert(matched_exit.clone(), association_sender.clone());

          log::info!(
            "UDP {} -> {}",
            outgoing.destination,
            exits
              .iter()
              .map(|exit| if exit == &matched_exit {
                exit.to_string().cyan().to_string()
              } else {
                exit.to_string()
              })
              .join(",")
          );

          selected_association = Some((matched_exit, association_sender));
          break;
        }

        let Some((matched_exit, association_sender)) = selected_association else {
          log::debug!("UDP {} no out dispatcher matched.", outgoing.destination);
          continue;
        };

        if association_sender.send(outgoing).is_err() {
          association_senders.remove(&matched_exit);
        }
      }
      Some(incoming) = incoming_receiver.recv() => {
        packet_stream.send(incoming).await?;
      }
      Some(result) = association_tasks.join_next(), if !association_tasks.is_empty() => {
        let (exit, result) = result.expect("UDP association task panicked");

        if association_senders
          .get(&exit)
          .is_some_and(mpsc::UnboundedSender::is_closed)
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

async fn open_udp_association(
  node: &(impl Node + ?Sized),
  exits: &[OutExit],
  destination: &SocketDestination,
) -> Result<Option<(OutExit, Box<dyn OutboundUdpPacketStream>)>, Error> {
  let mut may_retry_peer_unavailable = true;

  loop {
    let out_dispatchers = node.get_out_dispatchers();
    let Some((matched_exit, matched, out_dispatcher)) =
      select_out_dispatcher(exits, &out_dispatchers)
    else {
      return Ok(None);
    };
    drop(out_dispatchers);
    let priority = matched.priority;

    match out_dispatcher.associate(matched.resolved_exit).await {
      Ok(outbound) => return Ok(Some((matched_exit, outbound))),
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

fn select_out_dispatcher(
  exits: &[OutExit],
  out_dispatchers: &[Arc<dyn OutDispatcher>],
) -> Option<(OutExit, OutExitMatch, Arc<dyn OutDispatcher>)> {
  exits.iter().find_map(|route| {
    let mut matching_dispatchers = out_dispatchers
      .iter()
      .filter_map(|dispatcher| {
        dispatcher
          .match_exit(route)
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
}

#[cfg(test)]
mod tests {
  use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Mutex, atomic::AtomicUsize},
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
    }
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
      route::{AddressRule, FallbackRule, GeoLite2},
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
    let router = Arc::new(Router::new(GeoLite2::new(test_dir())));
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
        },
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
        },
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
  async fn udp_association_failure_does_not_stop_the_inbound() -> anyhow::Result<()> {
    use crate::{
      route::{FallbackRule, GeoLite2},
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
    let router = Arc::new(Router::new(GeoLite2::new(test_dir())));
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
}
