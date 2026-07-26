use std::collections::HashMap;
use std::{
  net::SocketAddr,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
};

use lits::duration;
use lowkit::SelfWrapExt;
use tokio::io::AsyncWriteExt;
use tokio::time::sleep;

use crate::{
  cert::NODE_PEM_FILE_NAME,
  r#in::{InConfig, InLike},
  inbound::AnyInbound,
  node::{
    DefaultLocalExit, DirectOutDispatcher, Node, NodeHello, NodeHelloAck, NodeId, NodeMessageToIn,
    NodeMessageToInUpdate, NodeOutDispatcher, OutDispatcher,
  },
  primitives::OutExits,
  qomt::qomt_connect,
  quic_connection::{QuicConnection, QuicStream, create_quiche_config},
  route::{GeoLite2, Router},
  utils::postcard::postcard_read_stream,
};

pub struct In {
  id: NodeId,
  inbounds: Vec<Arc<AnyInbound>>,
  router: Router,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  hub_options: InHubOptions,
  context_dir: PathBuf,
}

pub struct InOptions {
  pub hub: InHubOptions,
  pub context_dir: PathBuf,
}

pub struct InHubOptions {
  pub address: SocketAddr,
  pub connections: usize,
}

impl In {
  pub fn new(
    inbounds: Vec<AnyInbound>,
    router: Router,
    InOptions {
      hub: hub_options,
      context_dir,
    }: InOptions,
  ) -> Self {
    Self {
      id: NodeId::new(),
      inbounds: inbounds.into_iter().map(|inbound| inbound.arc()).collect(),
      router,
      direct_out_dispatcher: DirectOutDispatcher::new(DefaultLocalExit::Private).arc(),
      connected_out_dispatcher_map: HashMap::new().mutex(),
      hub_options,
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let this = self.arc();

    tokio::try_join!(this.clone().run_inbounds(), this.run_in())?;

    Ok(())
  }

  async fn run_in(self: Arc<Self>) -> anyhow::Result<()> {
    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    loop {
      async {
        let qomt_connection = qomt_connect(
          &mut quiche_config,
          self.hub_options.address,
          self.hub_options.connections,
        )
        .await?
        .arc();

        log::info!("connection to HUB established.");

        let hub_id_future = async {
          let mut stream = qomt_connection.open_stream();

          let hello = NodeHello::In(self.id);

          stream
            .write_all(&postcard::to_allocvec(&hello).unwrap())
            .await?;

          stream.shutdown().await?;

          let NodeHelloAck(node_id) = postcard_read_stream(&mut stream).await?;

          anyhow::Ok((node_id, stream))
        };

        async {
          let (hub_id, stream) = tokio::select! {
            hub_id = hub_id_future => hub_id,
            result = qomt_connection.accept_stream() => {
              if result?.is_none() {
                return Ok(());
              }

              anyhow::anyhow!("not expecting stream from HUB now.").wrap_err()
            },
          }?;

          self
            .clone()
            .handle_hub_node(hub_id, stream, qomt_connection.clone())
            .await?;

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("error sending hello to HUB: {}", error);
        })
        .ok();

        log::info!("connection to HUB closed.");

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

  async fn handle_hub_node(
    self: Arc<Self>,
    node_id: NodeId,
    mut update_stream: QuicStream,
    qomt_connection: Arc<QuicConnection>,
  ) -> anyhow::Result<()> {
    let out_dispatcher = NodeOutDispatcher::new(OutExits::default(), qomt_connection.clone()).arc();
    let registered_out_dispatcher: Arc<dyn OutDispatcher> = out_dispatcher.clone();

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .insert(node_id, registered_out_dispatcher.clone());

    let update_result = async {
      loop {
        let message = postcard_read_stream::<NodeMessageToIn>(&mut update_stream).await?;

        match message {
          NodeMessageToIn::Update(NodeMessageToInUpdate {
            exits,
            direct_outs: _,
            route_rules,
          }) => {
            log::info!("received update from HUB.");

            out_dispatcher.update_exits(exits);
            self.router.register_node_rules(node_id, route_rules);
          }
        }
      }
      #[allow(unreachable_code)]
      anyhow::Ok(())
    }
    .await;

    let removed = {
      let mut dispatcher_map = self.connected_out_dispatcher_map.lock().unwrap();

      if dispatcher_map
        .get(&node_id)
        .is_some_and(|current| Arc::ptr_eq(current, &registered_out_dispatcher))
      {
        dispatcher_map.remove(&node_id);
        true
      } else {
        false
      }
    };

    if removed {
      self.router.unregister_node_rules(node_id);
    }

    update_result
  }
}

impl InLike for In {
  fn router(&self) -> &Router {
    &self.router
  }

  fn inbounds(&self) -> &[Arc<AnyInbound>] {
    &self.inbounds
  }
}

impl Node for In {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    let mut dispatchers = vec![self.direct_out_dispatcher.clone()];

    dispatchers.extend(
      self
        .connected_out_dispatcher_map
        .lock()
        .unwrap()
        .values()
        .cloned(),
    );

    dispatchers
  }
}

pub async fn run_in(
  context_dir: impl AsRef<Path>,
  InConfig {
    hub,
    route: route_config,
    inbounds: inbounds_config,
  }: InConfig,
) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();

  let inbounds = if let Some(inbounds_config) = inbounds_config {
    inbounds_config.into_inbounds().await?
  } else {
    vec![]
  };

  let router = Router::new(GeoLite2::new(context_dir));

  if let Some(route_config) = route_config {
    router.register_local_rules(route_config.into());
  }

  let in_node = In::new(
    inbounds,
    router,
    InOptions {
      hub: hub.into(),
      context_dir: context_dir.to_owned(),
    },
  );

  in_node.run().await
}
