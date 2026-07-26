use std::{
  net::SocketAddr,
  path::{Path, PathBuf},
  sync::Arc,
};

use lits::duration;
use lowkit::SelfWrapExt;
use serde::{Deserialize, Serialize};
use tokio::{io::AsyncWriteExt, task::JoinSet, time::sleep};

use crate::{
  cert::NODE_PEM_FILE_NAME,
  node::{
    LocalOutDispatcher, Node, NodeHello, NodeHelloOut, NodeId, NodeMessageToOut, OutDispatcher,
  },
  out::{OutConfig, build_local_out_dispatchers},
  primitives::{OutExitTag, OutExits},
  qomt::qomt_connect,
  quic_connection::{QuicConnection, create_quiche_config},
  utils::{postcard::postcard_read_stream, task::reap_finished_tasks},
};

pub struct Out {
  id: NodeId,
  exits: OutExits,
  local_out_dispatchers: Vec<Arc<dyn OutDispatcher>>,
  hub_options: OutHubOptions,
  context_dir: PathBuf,
}

pub struct OutOptions {
  pub local_out_dispatchers: Vec<LocalOutDispatcher>,
  pub hub: OutHubOptions,
  pub context_dir: PathBuf,
}

pub struct OutHubOptions {
  pub address: SocketAddr,
  pub connections: usize,
}

impl Out {
  pub fn new(
    OutOptions {
      local_out_dispatchers,
      hub: hub_options,
      context_dir,
    }: OutOptions,
  ) -> Self {
    let exits = local_out_dispatchers
      .iter()
      .flat_map(|dispatcher| dispatcher.exits().iter().cloned())
      .collect::<OutExits>()
      .for_advertising();
    let local_out_dispatchers = local_out_dispatchers
      .into_iter()
      .map(|dispatcher| -> Arc<dyn OutDispatcher> { dispatcher.arc() })
      .collect();

    Self {
      id: NodeId::new(),
      exits,
      local_out_dispatchers,
      hub_options,
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let this = self.arc();
    let connection_count = this.hub_options.connections.max(1);
    let mut join_set = JoinSet::new();

    for index in 0..connection_count {
      let this = this.clone();
      let node_id = if index == 0 { this.id } else { NodeId::new() };

      join_set.spawn(async move { this.run_hub_connection(node_id, index).await });
    }

    while let Some(result) = join_set.join_next().await {
      result??;
    }

    anyhow::bail!("all OUT connection pool tasks stopped")
  }

  async fn run_hub_connection(
    self: Arc<Self>,
    node_id: NodeId,
    index: usize,
  ) -> anyhow::Result<()> {
    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    loop {
      async {
        let qomt_connection = qomt_connect(&mut quiche_config, self.hub_options.address, 1).await?;

        log::info!("connection pool slot {index} to HUB established.");

        let mut stream = qomt_connection.open_stream();

        let hello = NodeHello::Out(NodeHelloOut {
          id: node_id,
          exits: self.exits.clone(),
          direct_out: None,
        });

        stream
          .write_all(&postcard::to_allocvec(&hello).unwrap())
          .await?;

        stream.shutdown().await?;

        self.clone().handle_hub_node(qomt_connection).await?;

        anyhow::Ok(())
      }
      .await
      .inspect_err(|error| {
        log::error!("HUB connection pool slot {index} error: {error}");
      })
      .ok();

      sleep(duration!("5s")).await;
    }
  }

  async fn handle_hub_node(self: Arc<Self>, qomt_connection: QuicConnection) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    loop {
      let Some(mut stream) = qomt_connection.accept_stream().await? else {
        break;
      };

      let this = self.clone();

      reap_finished_tasks(&mut join_set, "OUT stream task");

      join_set.spawn(async move {
        async {
          let message = postcard_read_stream::<NodeMessageToOut>(&mut stream).await?;

          match message {
            NodeMessageToOut::Connect(exit, destination) => {
              this
                .tcp_connect(vec![exit], destination, stream.wrap_box())
                .await?;
            }
            NodeMessageToOut::Associate(exit, destination) => todo!(),
          }

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("error handling TCP stream: {}", error);
        })
        .ok();
      });
    }

    log::info!("connection to HUB closed.");

    Ok(())
  }
}

impl Node for Out {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    self.local_out_dispatchers.clone()
  }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DirectOut {
  pub tags: Vec<OutExitTag>,
  pub address: SocketAddr,
}

pub async fn run_out(
  context_dir: impl AsRef<Path>,
  OutConfig { hub, exits }: OutConfig,
) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();
  let local_out_dispatchers = build_local_out_dispatchers(exits)?;

  let out = Out::new(OutOptions {
    local_out_dispatchers,
    hub: hub.into(),
    context_dir: context_dir.to_owned(),
  });

  out.run().await
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::node::DefaultLocalExit;

  #[test]
  fn advertises_union_of_explicit_local_exits() {
    let out = Out::new(OutOptions {
      local_out_dispatchers: vec![
        LocalOutDispatcher::new_default(DefaultLocalExit::Private),
        LocalOutDispatcher::new_bound(
          vec![OutExitTag::from("us"), OutExitTag::from("netflix")],
          "wg0".to_owned(),
        )
        .unwrap(),
      ],
      hub: OutHubOptions {
        address: "127.0.0.1:1122".parse().unwrap(),
        connections: 1,
      },
      context_dir: PathBuf::new(),
    });

    assert_eq!(
      out.exits.as_slice(),
      &[
        crate::primitives::OutExit::Proxy,
        crate::primitives::OutExit::from("us"),
        crate::primitives::OutExit::from("netflix"),
      ]
    );
  }
}
