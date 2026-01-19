use async_trait::async_trait;

use crate::{
  node::Error,
  primitives::{BidiStream, OutExit, SocketDestination},
};

#[async_trait]
pub trait OutDispatcher: Send + Sync {
  fn match_exit(&self, exit: &OutExit) -> bool;

  async fn connect(
    &self,
    exit: OutExit,
    destination: SocketDestination,
  ) -> Result<Box<dyn BidiStream>, Error>;
}
