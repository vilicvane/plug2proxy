use std::sync::Arc;

use async_trait::async_trait;
use itertools::Itertools;

use crate::{
  r#in::out_dispatcher::{self, OutDispatcher, OutTcpStream},
  node::Node,
  out::OutExit,
  primitives::SocketDestination,
};

#[async_trait]
pub trait InLike: Node {
  async fn route(&self, destination: &SocketDestination) -> Result<Vec<OutExit>, Error>;

  async fn in_tcp_connect(
    &self,
    destination: SocketDestination,
  ) -> Result<Box<dyn OutTcpStream>, Error> {
    let exits = self.route(&destination).await?;

    if exits.is_empty() {
      return Err(Error::RouteNotFound);
    }

    let out_dispatchers = self.get_out_dispatchers();

    let (exit, out_dispatcher) = exits
      .into_iter()
      .find_map(|route| {
        out_dispatchers
          .iter()
          .find(|dispatcher| dispatcher.match_exit(&route))
          .map(|dispatcher| (route, dispatcher))
      })
      .ok_or(Error::RouteNotFound)?;

    let tcp_stream = out_dispatcher.connect(exit, destination).await?;

    Ok(tcp_stream)
  }

  async fn run_in(&self) {}
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher error: {0}")]
  OutDispatcher(#[from] out_dispatcher::Error),
  #[error("Route not found")]
  RouteNotFound,
  #[error("Out dispatcher not found")]
  OutDispatcherNotFound,
}
