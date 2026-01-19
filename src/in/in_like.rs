use async_trait::async_trait;

use crate::{
  node::{self, Node},
  primitives::{BidiStream, SocketDestination},
  route::Router,
};

#[async_trait]
pub trait InLike: Node {
  fn router(&self) -> &Router;

  async fn in_tcp_connect(
    &self,
    destination: SocketDestination,
    stream: Box<dyn BidiStream>,
  ) -> Result<(), Error> {
    let exits = self.router().match_exits(&destination).await;

    self.tcp_connect(exits, destination, stream).await?;

    Ok(())
  }

  async fn run_in(&self) {}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("node error: {0}")]
  Node(#[from] node::Error),
}
