use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use lowkit::SelfWrapExt;
use tokio::io::DuplexStream;
use uuid::Uuid;

use crate::{
  r#in::{
    self,
    direct_out_dispatcher::DirectOutDispatcher,
    in_like::{self, InLike},
    out_dispatcher::OutDispatcher,
  },
  node::{Node, NodeId},
  out::{OutExitTag, OutLike, run_out},
  primitives::{Route, SocketDestination},
  tunnel::TunnelId,
};

pub struct Hub {
  id: NodeId,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: HashMap<TunnelId, Arc<dyn OutDispatcher>>,
}

pub struct HubOptions {
  pub tags: Option<Vec<OutExitTag>>,
}

impl Hub {
  pub fn new(options: HubOptions) -> Self {
    Self {
      id: NodeId::new(),
      direct_out_dispatcher: DirectOutDispatcher::new(options.tags).arc(),
      connected_out_dispatcher_map: HashMap::new(),
    }
  }

  pub fn in_enabled(&self) -> bool {
    false
  }

  pub fn out_enabled(&self) -> bool {
    false
  }
}

impl Node for Hub {
  fn id(&self) -> NodeId {
    self.id
  }
}

#[async_trait]
impl InLike for Hub {
  async fn route(&self, destination: &SocketDestination) -> Result<Vec<Route>, in_like::Error> {
    todo!()
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    let mut dispatchers = vec![self.direct_out_dispatcher.clone()];

    dispatchers.extend(self.connected_out_dispatcher_map.values().cloned());

    dispatchers
  }
}

impl OutLike for Hub {}

async fn run_hub(node: &Hub) {
  tokio::join!(
    async {
      // if node.in_enabled() {
      //   run_in(node).await;
      // }
    },
    async {
      if node.out_enabled() {
        run_out(node).await;
      }
    }
  );
}
