use std::time::Duration;

use async_trait::async_trait;

use crate::{
  node::Error,
  primitives::{BidiStream, OutExit, OutExitMatch, SocketDestination},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutDispatcherLoad {
  pub adaptive: bool,
  pub active_transfers: usize,
  pub goodput_bytes_per_second: Option<u64>,
}

#[async_trait]
pub trait OutDispatcher: Send + Sync {
  fn match_exit(&self, exit: &OutExit) -> Option<OutExitMatch>;

  fn load(&self) -> OutDispatcherLoad {
    OutDispatcherLoad::default()
  }

  fn transfer_started(&self) {}

  fn transfer_finished(&self, _bytes: u64, _elapsed: Duration) {}

  async fn connect(
    &self,
    exit: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn BidiStream>, Error>;
}
