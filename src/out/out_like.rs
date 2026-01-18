use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::copy_bidirectional;

use crate::{
  r#in::out_dispatcher::{self, OutTcpStream},
  node::Node,
  primitives::SocketDestination,
};

#[async_trait]
pub trait OutLike: Node {
  async fn out_tcp_connect(
    &self,
    exit: OutExit,
    destination: SocketDestination,
    mut tcp_stream: Box<dyn OutTcpStream>,
  ) -> Result<(), Error> {
    let out_dispatchers = self.get_out_dispatchers();

    let out_dispatcher = out_dispatchers
      .iter()
      .find(|dispatcher| dispatcher.match_exit(&exit))
      .ok_or(Error::OutDispatcherNotFound)?;

    let mut out_tcp_stream = out_dispatcher.connect(exit, destination).await?;

    copy_bidirectional(&mut tcp_stream, &mut out_tcp_stream).await?;

    Ok(())
  }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, derive_more::From)]
pub enum OutExit {
  Direct,
  Tag(#[from] OutExitTag),
  Proxy,
  Any,
}

impl From<String> for OutExit {
  fn from(value: String) -> Self {
    match value.as_str() {
      "DIRECT" => OutExit::Direct,
      "PROXY" => OutExit::Proxy,
      "ANY" => OutExit::Any,
      _ => OutExit::Tag(OutExitTag(value)),
    }
  }
}

#[derive(Debug, Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct OutExitTag(pub String);

#[derive(thiserror::Error, Debug)]
pub enum Error {
  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),
  #[error("Out dispatcher error: {0}")]
  OutDispatcher(#[from] out_dispatcher::Error),
  #[error("Out dispatcher not found")]
  OutDispatcherNotFound,
}
