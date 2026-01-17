use std::sync::Arc;

use async_trait::async_trait;
use itertools::Itertools;

use crate::{
  r#in::out_dispatcher::{self, OutDispatcher, OutTcpStream},
  node::Node,
  primitives::{Route, SocketDestination},
};

#[async_trait]
pub trait InLike: Node {
  async fn route(&self, destination: &SocketDestination) -> Result<Vec<Route>, Error>;

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>>;

  async fn tcp_connect(
    &self,
    destination: SocketDestination,
  ) -> Result<Box<dyn OutTcpStream>, Error> {
    let routes = self.route(&destination).await?;

    if routes.is_empty() {
      return Err(Error::RouteNotFound);
    }

    let (route, out_dispatcher) = self
      .get_out_dispatchers()
      .into_iter()
      .filter_map(|dispatcher| {
        routes
          .iter()
          .find(|route| dispatcher.match_out(route))
          .map(|route| (route, dispatcher))
      })
      .sorted_by(|(a, _), (b, _)| a.priority().cmp(&b.priority()))
      .next()
      .ok_or(Error::RouteNotFound)?;

    let tcp_stream = out_dispatcher.connect(route, destination).await?;

    Ok(tcp_stream)
  }
}

pub async fn run_in(node: &impl InLike) {}

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
