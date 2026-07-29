use std::time::Duration;

use async_trait::async_trait;

use crate::{
  node::{Error, NodeResolveAnswers, ResolveQuery},
  primitives::{BidiStream, OutExit, OutExitMatch, SocketDestination},
  udp_forwarder::OutboundUdpPacketStream,
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

  fn is_local(&self) -> bool {
    false
  }

  fn diagnostic_label(&self) -> String {
    "unknown".to_owned()
  }

  fn diagnostics(&self) -> String {
    self.diagnostic_label()
  }

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

  async fn associate(&self, _exit: OutExit) -> Result<Box<dyn OutboundUdpPacketStream>, Error> {
    Err(
      std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "UDP is not supported by this dispatcher",
      )
      .into(),
    )
  }

  async fn resolve(
    &self,
    _exit: OutExit,
    _query: &ResolveQuery,
  ) -> Result<NodeResolveAnswers, Error> {
    Err(
      std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "DNS resolve is not supported by this dispatcher",
      )
      .into(),
    )
  }
}
