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
  node::{Error, NodeMessageToOut, OutDispatcher, OutDispatcherLoad},
  primitives::{BidiStream, OutExit, OutExitTag, SocketDestination},
  quic_connection::QuicConnection,
};

pub struct NodeOutDispatcher {
  tags: Mutex<Vec<OutExitTag>>,
  qomt_connection: Arc<QuicConnection>,
  active_transfers: AtomicUsize,
  goodput_bytes_per_second: AtomicU64,
}

impl NodeOutDispatcher {
  const MIN_GOODPUT_SAMPLE_BYTES: u64 = 64 * 1024;

  pub fn new(tags: Vec<OutExitTag>, qomt_connection: Arc<QuicConnection>) -> Self {
    Self {
      tags: tags.mutex(),
      qomt_connection,
      active_transfers: AtomicUsize::new(0),
      goodput_bytes_per_second: AtomicU64::new(0),
    }
  }

  pub fn update_tags(&self, tags: Vec<OutExitTag>) {
    *self.tags.lock().unwrap() = tags;
  }
}

#[async_trait]
impl OutDispatcher for NodeOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> bool {
    match route {
      OutExit::Direct => false,
      OutExit::Proxy => true,
      OutExit::Any => true,
      OutExit::Tag(route_tag) => self.tags.lock().unwrap().iter().any(|tag| tag == route_tag),
    }
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
    let mut stream = self.qomt_connection.open_stream();

    let message = NodeMessageToOut::Connect(exit, destination);

    stream
      .write_all(&postcard::to_allocvec(&message).unwrap())
      .await?;

    Ok(stream.wrap_box())
  }
}
