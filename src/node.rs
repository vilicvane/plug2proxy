use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::copy_bidirectional;
use uuid::Uuid;

use crate::{
  r#in::out_dispatcher::{self, OutDispatcher},
  out::DirectOut,
  primitives::{BidiStream, OutExit, SocketDestination},
  route::AnyRule,
};

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
    let out_dispatchers = self.get_out_dispatchers();

    let (exit, out_dispatcher) = exits
      .into_iter()
      .find_map(|route| {
        out_dispatchers
          .iter()
          .find(|dispatcher| dispatcher.match_exit(&route))
          .map(|dispatcher| (route, dispatcher))
      })
      .ok_or(Error::OutDispatcherNotMatched)?;

    let mut out_stream = out_dispatcher.connect(exit, destination).await?;

    copy_bidirectional(&mut stream, &mut out_stream).await?;

    Ok(())
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
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

#[derive(Serialize, Deserialize)]
pub enum NodeHello {
  In,
  Out(Option<DirectOut>),
}

#[derive(Serialize, Deserialize)]
pub enum NodeInMessage {
  Connect((OutExit, SocketDestination)),
  Associate((OutExit, SocketDestination)),
}

#[derive(Serialize, Deserialize)]
pub enum NodeHubMessage {
  RouteRules(Vec<AnyRule>),
  DirectOuts(Vec<DirectOut>),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher error: {0}")]
  OutDispatcher(#[from] out_dispatcher::Error),
  #[error("Out dispatcher not matched")]
  OutDispatcherNotMatched,
}
