use std::{
  collections::HashMap,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
};

use colored::Colorize;
use futures::StreamExt;
use itertools::Itertools;
use lowkit::SelfWrapExt;
use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinSet};

use crate::{
  cert::{CA_PEM_FILE_NAME, NODE_PEM_FILE_NAME, generate_ca_pem_file, generate_node_pem_file},
  hub::HubConfig,
  r#in::InLike,
  inbound::AnyInbound,
  mt_connections::MtConnectionsListener,
  node::{
    DirectOutDispatcher, Node, NodeHello, NodeHelloAck, NodeHelloOut, NodeId, NodeMessageToIn,
    NodeMessageToInUpdate, NodeMessageToOut, NodeOutDispatcher, OutDispatcher,
  },
  out::DirectOut,
  primitives::OutExitTag,
  quic_connection::{QuicBytesPacket, QuicConnection, QuicStream, create_quiche_config},
  route::{GeoLite2, Router},
  utils::postcard::{postcard_read_stream, postcard_read_stream_to_end},
};

pub struct Hub {
  id: NodeId,
  tags: Vec<OutExitTag>,
  mt_connections_listener: tokio::sync::Mutex<MtConnectionsListener<QuicBytesPacket>>,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  in_qomt_connection_map: Mutex<HashMap<NodeId, Arc<QuicConnection>>>,
  out_map: Mutex<HashMap<NodeId, (Vec<OutExitTag>, Option<DirectOut>)>>,
  router: Router,
  inbounds: Vec<Arc<AnyInbound>>,
  context_dir: PathBuf,
}

pub struct HubOptions {
  pub tags: Option<Vec<OutExitTag>>,
  pub context_dir: PathBuf,
}

impl Hub {
  pub fn new(
    tcp_listener: TcpListener,
    inbounds: Vec<AnyInbound>,
    router: Router,
    HubOptions { tags, context_dir }: HubOptions,
  ) -> Self {
    Self {
      id: NodeId::new(),
      tags: tags.clone().unwrap_or_default(),
      mt_connections_listener: MtConnectionsListener::new(tcp_listener).tokio_mutex(),
      direct_out_dispatcher: DirectOutDispatcher::new(tags).arc(),
      connected_out_dispatcher_map: HashMap::new().mutex(),
      in_qomt_connection_map: HashMap::new().mutex(),
      out_map: HashMap::new().mutex(),
      router,
      inbounds: inbounds.into_iter().map(|inbound| inbound.arc()).collect(),
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let this = self.arc();

    tokio::try_join!(this.clone().run_hub(), this.run_inbounds())?;

    Ok(())
  }

  async fn run_hub(self: Arc<Self>) -> anyhow::Result<()> {
    let mut mt_connections_listener = self.mt_connections_listener.lock().await;

    let mut join_set = JoinSet::new();

    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    loop {
      let mut mt_connections = mt_connections_listener.accept().await?;

      let peer_address = mt_connections.peer_address();

      let Some(first_packet) = mt_connections.next().await else {
        log::warn!("missing first packet (connection_id) in incoming mTCP connections.");
        continue;
      };

      let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

      let qomt_connection =
        QuicConnection::accept(&connection_id, &mut quiche_config, mt_connections);

      let this = self.clone();

      join_set.spawn(async move {
        async {
          qomt_connection.established().await?;

          let mut stream = qomt_connection
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("expecting hello stream"))?;

          let hello = postcard_read_stream_to_end::<NodeHello>(&mut stream).await?;

          let hello_ack = NodeHelloAck(this.id);

          stream
            .write_all(&postcard::to_allocvec(&hello_ack).unwrap())
            .await?;

          let node_type = match hello {
            NodeHello::In(_) => "IN",
            NodeHello::Out(_) => "OUT",
          };

          log::info!("connection from {node_type} {peer_address} established.");

          match hello {
            NodeHello::In(node_id) => {
              this
                .clone()
                .handle_in_node(node_id, stream, qomt_connection)
                .await;
            }
            NodeHello::Out(hello) => {
              this.clone().handle_out_node(hello, qomt_connection).await;
            }
          }

          log::info!("connection from {node_type} {peer_address} closed.");

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("error accepting node connection: {}", error);
        })
        .ok();
      });
    }
  }

  async fn handle_in_node(
    self: Arc<Self>,
    node_id: NodeId,
    mut stream: QuicStream,
    qomt_connection: QuicConnection,
  ) {
    {
      let update = self.build_in_update();

      if async {
        stream.write_all(&update).await?;
        stream.shutdown().await?;

        log::info!("sent initial IN update to {node_id}.");

        anyhow::Ok(())
      }
      .await
      .inspect_err(|error| {
        log::error!("error sending initial IN update to {node_id}: {error}");
      })
      .is_err()
      {
        return;
      }
    }

    let qomt_connection = qomt_connection.arc();

    self
      .in_qomt_connection_map
      .lock()
      .unwrap()
      .insert(node_id, qomt_connection.clone());

    let mut join_set = JoinSet::new();

    loop {
      let Ok(Some(mut stream)) = qomt_connection.accept_stream().await.inspect_err(|error| {
        log::error!("error accepting IN node stream: {}", error);
      }) else {
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
          log::error!("error handling CONNECT stream: {}", error);
        })
        .ok();
      });
    }

    self.in_qomt_connection_map.lock().unwrap().remove(&node_id);
  }

  async fn handle_out_node(
    self: Arc<Self>,
    NodeHelloOut {
      id,
      direct_out,
      tags,
    }: NodeHelloOut,
    qomt_connection: QuicConnection,
  ) {
    self
      .out_map
      .lock()
      .unwrap()
      .insert(id, (tags.clone(), direct_out));

    let qomt_connection = qomt_connection.arc();

    let out_dispatcher = NodeOutDispatcher::new(tags, qomt_connection.clone());

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .insert(id, out_dispatcher.arc());

    self.send_in_update().await;

    while qomt_connection
      .accept_stream()
      .await
      .inspect_err(|error| {
        log::error!("error handling OUT node: {}", error);
      })
      .is_ok_and(|stream| stream.is_some())
    {}

    self.out_map.lock().unwrap().remove(&id);

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .remove(&id);

    self.send_in_update().await;
  }

  fn build_in_update(&self) -> Vec<u8> {
    let update = {
      let out_map = self.out_map.lock().unwrap();

      NodeMessageToIn::Update(NodeMessageToInUpdate {
        tags: self
          .tags
          .iter()
          .chain(out_map.values().flat_map(|(tags, _)| tags))
          .unique()
          .cloned()
          .collect(),
        direct_outs: out_map
          .values()
          .flat_map(|(_, direct_out)| direct_out)
          .cloned()
          .collect(),
        route_rules: self.router.build_rules(),
      })
    };

    postcard::to_allocvec(&update).unwrap()
  }

  async fn send_in_update(&self) {
    let update = self.build_in_update();

    let in_nodes = self
      .in_qomt_connection_map
      .lock()
      .unwrap()
      .iter()
      .map(|(node_id, qomt_connection)| (*node_id, qomt_connection.clone()))
      .collect_vec();

    for (node_id, qomt_connection) in in_nodes {
      let mut stream = qomt_connection.open_stream();

      async {
        stream.write_all(&update).await?;
        stream.shutdown().await?;

        anyhow::Ok(())
      }
      .await
      .inspect_err(|error| {
        log::error!("error sending IN update to {node_id}: {}", error);
      })
      .ok();
    }
  }
}

impl Node for Hub {
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

impl InLike for Hub {
  fn router(&self) -> &Router {
    &self.router
  }

  fn inbounds(&self) -> &[Arc<AnyInbound>] {
    &self.inbounds
  }
}

pub async fn run_hub(
  context_dir: impl AsRef<Path>,
  HubConfig {
    listen,
    tags,
    route: route_config,
    inbounds: inbounds_config,
  }: HubConfig,
) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();

  let ca_pem_file_path = context_dir.join(CA_PEM_FILE_NAME);
  let node_pem_file_path = context_dir.join(NODE_PEM_FILE_NAME);

  if !node_pem_file_path.exists() {
    if !ca_pem_file_path.exists() {
      generate_ca_pem_file(context_dir).await?;
    }

    generate_node_pem_file(context_dir, "hub", false).await?;
  }

  let tcp_listener = TcpListener::bind(*listen).await?;

  log::info!(
    "{} is listening on {}...",
    "HUB".cyan(),
    tcp_listener.local_addr()?.to_string().yellow()
  );

  let inbounds = if let Some(inbounds_config) = inbounds_config {
    inbounds_config.into_inbounds().await?
  } else {
    vec![]
  };

  let router = Router::new(GeoLite2::new(context_dir));

  if let Some(route_config) = route_config {
    router.register_local_rules(route_config.into());
  }

  let hub = Hub::new(
    tcp_listener,
    inbounds,
    router,
    HubOptions {
      tags,
      context_dir: context_dir.to_path_buf(),
    },
  );

  hub.run().await
}
