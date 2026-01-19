use std::sync::Arc;

use async_trait::async_trait;
use lowkit::SelfWrapExt;
use tokio::io::AsyncWriteExt;

use crate::{
  node::{Error, NodeMessageToOut, OutDispatcher},
  primitives::{BidiStream, OutExit, OutExitTag, SocketDestination},
  quic_connection::QuicConnection,
};

pub struct NodeOutDispatcher {
  tags: Vec<OutExitTag>,
  qomt_connection: Arc<QuicConnection>,
}

impl NodeOutDispatcher {
  pub fn new(tags: Vec<OutExitTag>, qomt_connection: Arc<QuicConnection>) -> Self {
    Self {
      tags,
      qomt_connection,
    }
  }
}

#[async_trait]
impl OutDispatcher for NodeOutDispatcher {
  fn match_exit(&self, route: &OutExit) -> bool {
    match route {
      OutExit::Direct => false,
      OutExit::Proxy => true,
      OutExit::Any => true,
      OutExit::Tag(route_tag) => self.tags.iter().any(|tag| tag == route_tag),
    }
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
