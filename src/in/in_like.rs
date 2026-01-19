use std::sync::Arc;

use async_trait::async_trait;
use tokio::task::JoinSet;

use crate::{
  inbound::{AnyInbound, Inbound},
  node::{self, Node},
  primitives::{BidiStream, SocketDestination},
  route::Router,
};

#[async_trait]
pub trait InLike: Node + 'static {
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

  fn inbounds(&self) -> &[Arc<AnyInbound>];

  async fn run_inbounds(self: Arc<Self>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    for inbound in self.inbounds().iter() {
      join_set.spawn(self.clone().run_inbound(inbound.clone()));
    }

    let Some(result) = join_set.join_next().await else {
      return Ok(());
    };

    result??;

    unreachable!();
  }

  async fn run_inbound(self: Arc<Self>, inbound: Arc<AnyInbound>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    loop {
      let (destination, stream) = inbound.accept_tcp_connect().await?;

      let hub = self.clone();

      join_set.spawn(async move {
        hub
          .in_tcp_connect(destination, stream)
          .await
          .inspect_err(|error| {
            log::warn!("inbound TCP connection error: {}", error);
          })
          .ok();
      });
    }
  }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("node error: {0}")]
  Node(#[from] node::Error),
}
