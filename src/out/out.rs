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
    DirectOutDispatcher, Node, NodeHello, NodeHelloOut, NodeId, NodeMessageToOut, OutDispatcher,
  },
  out::OutConfig,
  primitives::OutExitTag,
  qomt::qomt_connect,
  quic_connection::{QuicConnection, create_quiche_config},
  utils::postcard::postcard_read_stream,
};

pub struct Out {
  id: NodeId,
  tags: Vec<OutExitTag>,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  hub_options: OutHubOptions,
  context_dir: PathBuf,
}

pub struct OutOptions {
  pub tags: Vec<OutExitTag>,
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
      tags,
      hub: hub_options,
      context_dir,
    }: OutOptions,
  ) -> Self {
    Self {
      id: NodeId::new(),
      tags: tags.clone(),
      direct_out_dispatcher: DirectOutDispatcher::new(tags.some()).arc(),
      hub_options,
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    let this = self.arc();

    loop {
      async {
        let qomt_connection = qomt_connect(
          &mut quiche_config,
          this.hub_options.address,
          this.hub_options.connections,
        )
        .await?;

        log::info!("connection to HUB established.");

        let mut stream = qomt_connection.open_stream();

        let hello = NodeHello::Out(NodeHelloOut {
          id: this.id,
          direct_out: None,
          tags: this.tags.clone(),
        });

        stream
          .write_all(&postcard::to_allocvec(&hello).unwrap())
          .await?;

        stream.shutdown().await?;

        this.clone().handle_hub_node(qomt_connection).await?;

        anyhow::Ok(())
      }
      .await
      .inspect_err(|error| {
        log::error!("HUB connection error: {}", error);
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
    vec![self.direct_out_dispatcher.clone()]
  }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct DirectOut {
  pub tags: Vec<OutExitTag>,
  pub address: SocketAddr,
}

pub async fn run_out(
  context_dir: impl AsRef<Path>,
  OutConfig { hub, tags }: OutConfig,
) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();

  let out = Out::new(OutOptions {
    tags: tags.unwrap_or_default(),
    hub: hub.into(),
    context_dir: context_dir.to_owned(),
  });

  out.run().await
}
