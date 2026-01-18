use std::sync::Arc;

use crate::r#in::out_dispatcher::OutDispatcher;
use crate::node::Node;
use crate::node::NodeId;

pub struct In {
  id: NodeId,
}

impl In {
  pub fn new() -> Self {
    Self { id: NodeId::new() }
  }
}

impl Default for In {
  fn default() -> Self {
    Self::new()
  }
}

impl Node for In {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    todo!()
  }
}

// #[async_trait]
// impl InLike for In {
//   type TcpStream = DuplexStream;

//   async fn tcp_connect(&self, destination: SocketDestination) -> Result<Self::TcpStream, Error> {
//     todo!()
//   }
// }
