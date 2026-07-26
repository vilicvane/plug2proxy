use std::sync::{
  Arc,
  atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;

use async_trait::async_trait;
use colored::Colorize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio::io::copy_bidirectional;
use uuid::Uuid;

use crate::{
  node::{OutDispatcher, OutDispatcherLoad},
  out::DirectOut,
  primitives::{BidiStream, OutExit, OutExitTag, SocketDestination},
  route::AnyRule,
};

static NEXT_PROXY_DISPATCHER: AtomicUsize = AtomicUsize::new(0);

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

    let out_dispatchers = self.get_out_dispatchers();

    let Some((matched_exit, out_dispatcher)) = exits.iter().find_map(|route| {
      let matching_dispatchers = out_dispatchers
        .iter()
        .filter(|dispatcher| dispatcher.match_exit(route))
        .collect_vec();

      if matching_dispatchers.is_empty() {
        return None;
      }

      // Preserve the established DIRECT-first behavior for ANY. Explicit
      // proxy/tag routes are spread across equivalent OUT connections so each
      // one has an independent QUIC and TCP congestion window. Once real
      // transfers have sampled those paths, avoid persistently slow pool slots.
      let index = if *route == OutExit::Any {
        0
      } else {
        select_dispatcher_index(
          &matching_dispatchers
            .iter()
            .map(|dispatcher| dispatcher.load())
            .collect_vec(),
          NEXT_PROXY_DISPATCHER.fetch_add(1, Ordering::Relaxed),
        )
      };

      Some((route, matching_dispatchers[index].clone()))
    }) else {
      log::info!("TCP {destination} no out dispatcher matched.");
      return Ok(());
    };

    // A transfer only needs the dispatcher that opened its stream. Keeping
    // the full routing snapshot here pins every QUIC connection that was
    // present when the transfer started, even after its dispatcher is
    // withdrawn or replaced.
    drop(out_dispatchers);

    log::info!(
      "TCP {destination} -> {}",
      exits
        .iter()
        .map(|exit| if exit == matched_exit {
          exit.to_string().cyan().to_string()
        } else {
          exit.to_string()
        })
        .join(",")
    );

    out_dispatcher.transfer_started();
    let started_at = Instant::now();

    let transfer_result = async {
      let mut out_stream = out_dispatcher
        .connect(matched_exit.clone(), destination)
        .await?;

      copy_bidirectional(&mut stream, &mut out_stream)
        .await
        .map_err(Error::from)
    }
    .await;

    let transferred_bytes = transfer_result
      .as_ref()
      .map(|(upstream, downstream)| upstream.saturating_add(*downstream))
      .unwrap_or(0);

    out_dispatcher.transfer_finished(transferred_bytes, started_at.elapsed());

    transfer_result?;

    Ok(())
  }
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
  pub id: NodeId,
  pub tags: Vec<OutExitTag>,
  pub direct_out: Option<DirectOut>,
}

#[derive(Serialize, Deserialize)]
pub struct NodeHelloAck(pub NodeId);

#[derive(Serialize, Deserialize)]
pub enum NodeMessageToOut {
  Connect(OutExit, SocketDestination),
  Associate(OutExit, SocketDestination),
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NodeMessageToIn {
  Update(NodeMessageToInUpdate),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct NodeMessageToInUpdate {
  pub tags: Vec<OutExitTag>,
  pub direct_outs: Vec<DirectOut>,
  pub route_rules: Vec<AnyRule>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher not matched")]
  OutDispatcherNotMatched,
}

#[cfg(test)]
mod tests {
  use std::sync::Mutex;

  use tokio::{
    io::{DuplexStream, duplex},
    sync::oneshot,
    time::timeout,
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

  struct BlockingTestDispatcher {
    peer_sender: Mutex<Option<oneshot::Sender<DuplexStream>>>,
  }

  #[async_trait]
  impl OutDispatcher for BlockingTestDispatcher {
    fn match_exit(&self, exit: &OutExit) -> bool {
      exit == &OutExit::Any
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
    fn match_exit(&self, _exit: &OutExit) -> bool {
      false
    }

    async fn connect(
      &self,
      _exit: OutExit,
      _destination: SocketDestination,
    ) -> Result<Box<dyn BidiStream>, Error> {
      unreachable!("unmatched dispatcher must not be connected")
    }
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
