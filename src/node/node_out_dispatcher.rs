use std::{
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, AtomicUsize, Ordering},
  },
  time::Duration,
};

use async_trait::async_trait;
use lowkit::SelfWrapExt;
use tokio::io::AsyncWriteExt;

use crate::{
  node::{Error, NodeMessageToOut, NodeResolveAnswers, OutDispatcher, OutDispatcherLoad, ResolveQuery},
  primitives::{
    BidiStream, OutExit, OutExitMatch, OutExitMatchPriority, OutExits, SocketDestination,
  },
  quic_connection::{QuicConnection, State as QuicConnectionState},
  udp_forwarder::{IncomingUdpPacket, OutboundUdpPacketStream, OutgoingUdpPacket, UdpPacketStream},
  utils::postcard::postcard_read_stream,
};

pub struct NodeOutDispatcher {
  exits: Mutex<OutExits>,
  match_priority: OutExitMatchPriority,
  qomt_connection: Arc<QuicConnection>,
  active_transfers: AtomicUsize,
  goodput_bytes_per_second: AtomicU64,
}

impl NodeOutDispatcher {
  const MIN_GOODPUT_SAMPLE_BYTES: u64 = 64 * 1024;

  pub fn new(exits: OutExits, qomt_connection: Arc<QuicConnection>) -> Self {
    Self::with_match_priority(exits, OutExitMatchPriority::Provider, qomt_connection)
  }

  pub fn new_peer(exits: OutExits, qomt_connection: Arc<QuicConnection>) -> Self {
    Self::with_match_priority(exits, OutExitMatchPriority::PeerProvider, qomt_connection)
  }

  fn with_match_priority(
    exits: OutExits,
    match_priority: OutExitMatchPriority,
    qomt_connection: Arc<QuicConnection>,
  ) -> Self {
    Self {
      exits: exits.for_advertising().mutex(),
      match_priority,
      qomt_connection,
      active_transfers: AtomicUsize::new(0),
      goodput_bytes_per_second: AtomicU64::new(0),
    }
  }

  pub fn update_exits(&self, exits: OutExits) {
    *self.exits.lock().unwrap() = exits.for_advertising();
  }
}

#[async_trait]
impl OutDispatcher for NodeOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> Option<OutExitMatch> {
    if self.qomt_connection.state() != QuicConnectionState::Established {
      return None;
    }

    self
      .exits
      .lock()
      .unwrap()
      .match_exit(route)
      .map(|mut matched| {
        assert_eq!(
          matched.priority,
          OutExitMatchPriority::Provider,
          "node dispatcher exits must match as provider exits"
        );
        matched.priority = self.match_priority;
        matched
      })
  }

  fn diagnostic_label(&self) -> String {
    format!(
      "qomt(priority={:?}, cid={})",
      self.match_priority,
      self.qomt_connection.diagnostic_id()
    )
  }

  fn diagnostics(&self) -> String {
    format!(
      "{} {}",
      self.diagnostic_label(),
      self.qomt_connection.diagnostics()
    )
  }

  fn load(&self) -> OutDispatcherLoad {
    let goodput = self.goodput_bytes_per_second.load(Ordering::Relaxed);

    OutDispatcherLoad {
      adaptive: true,
      active_transfers: self.active_transfers.load(Ordering::Relaxed),
      goodput_bytes_per_second: (goodput != 0).then_some(goodput),
    }
  }

  fn transfer_started(&self) {
    self.active_transfers.fetch_add(1, Ordering::Relaxed);
  }

  fn transfer_finished(&self, bytes: u64, elapsed: Duration) {
    self.active_transfers.fetch_sub(1, Ordering::Relaxed);

    if bytes < Self::MIN_GOODPUT_SAMPLE_BYTES || elapsed.is_zero() {
      return;
    }

    let sample = (bytes as u128)
      .saturating_mul(1_000_000_000)
      .checked_div(elapsed.as_nanos())
      .unwrap_or(0)
      .min(u64::MAX as u128) as u64;

    if sample == 0 {
      return;
    }

    let _ = self.goodput_bytes_per_second.fetch_update(
      Ordering::Relaxed,
      Ordering::Relaxed,
      |previous| {
        // Keep a lightweight EWMA so a recovered path can regain traffic,
        // while one unusually fast response doesn't erase a slow history.
        Some(if previous == 0 {
          sample
        } else {
          previous.saturating_mul(3) / 4 + sample / 4
        })
      },
    );
  }

  async fn connect(
    &self,
    exit: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn BidiStream>, Error> {
    if self.qomt_connection.state() != QuicConnectionState::Established {
      return Err(Error::OutDispatcherUnavailable);
    }

    let mut stream = self.qomt_connection.open_stream();
    let stream_id = stream.id();

    log::debug!(
      "QOMT {} stream {stream_id} sending CONNECT {destination} via {exit}.",
      self.qomt_connection.diagnostic_id()
    );
    let message = NodeMessageToOut::Connect(exit, destination);

    if let Err(error) = stream
      .write_all(&postcard::to_allocvec(&message).unwrap())
      .await
    {
      if self.qomt_connection.state() != QuicConnectionState::Established {
        return Err(Error::OutDispatcherUnavailable);
      }

      return Err(error.into());
    }

    log::debug!(
      "QOMT {} stream {stream_id} CONNECT request queued.",
      self.qomt_connection.diagnostic_id()
    );

    if self.qomt_connection.state() != QuicConnectionState::Established {
      return Err(Error::OutDispatcherUnavailable);
    }

    Ok(stream.wrap_box())
  }

  async fn associate(&self, exit: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
    if self.qomt_connection.state() != QuicConnectionState::Established {
      return Err(Error::OutDispatcherUnavailable);
    }

    let mut stream = self.qomt_connection.open_stream();
    let stream_id = stream.id();
    log::debug!(
      "QOMT {} stream {stream_id} sending ASSOCIATE via {exit}.",
      self.qomt_connection.diagnostic_id()
    );
    let message = NodeMessageToOut::Associate(exit);

    if let Err(error) = stream
      .write_all(&postcard::to_allocvec(&message).unwrap())
      .await
    {
      if self.qomt_connection.state() != QuicConnectionState::Established {
        return Err(Error::OutDispatcherUnavailable);
      }

      return Err(error.into());
    }

    log::debug!(
      "QOMT {} stream {stream_id} ASSOCIATE request queued.",
      self.qomt_connection.diagnostic_id()
    );

    if self.qomt_connection.state() != QuicConnectionState::Established {
      return Err(Error::OutDispatcherUnavailable);
    }

    Ok(Box::new(UdpPacketStream::<
      OutgoingUdpPacket,
      IncomingUdpPacket,
    >::new(Box::new(stream))))
  }

  async fn resolve(&self, exit: OutExit, query: &ResolveQuery) -> Result<NodeResolveAnswers, Error> {
    if self.qomt_connection.state() != QuicConnectionState::Established {
      return Err(Error::OutDispatcherUnavailable);
    }

    let mut stream = self.qomt_connection.open_stream();
    let stream_id = stream.id();
    log::debug!(
      "QOMT {} stream {stream_id} sending RESOLVE {} type {} via {exit}.",
      self.qomt_connection.diagnostic_id(),
      query.name,
      query.record_type,
    );
    let message = NodeMessageToOut::Resolve(exit, query.clone());

    if let Err(error) = stream
      .write_all(&postcard::to_allocvec(&message).unwrap())
      .await
    {
      if self.qomt_connection.state() != QuicConnectionState::Established {
        return Err(Error::OutDispatcherUnavailable);
      }

      return Err(error.into());
    }

    let answers = postcard_read_stream::<NodeResolveAnswers>(&mut stream).await?;

    log::debug!(
      "QOMT {} stream {stream_id} RESOLVE {} answered: {:?}.",
      self.qomt_connection.diagnostic_id(),
      query.name,
      answers,
    );

    Ok(answers)
  }
}
