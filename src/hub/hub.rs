use std::{
  collections::HashMap,
  path::{Path, PathBuf},
  sync::{Arc, Mutex},
  time::Duration,
};

use colored::Colorize;
use futures::StreamExt;
use lowkit::SelfWrapExt;
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::mpsc, task::JoinSet, time::timeout};

use crate::{
  cert::{CA_PEM_FILE_NAME, NODE_PEM_FILE_NAME, generate_ca_pem_file, generate_node_pem_file},
  hub::HubConfig,
  r#in::InLike,
  inbound::AnyInbound,
  mt_connections::MtConnectionsListener,
  node::{
    DefaultLocalExit, DirectOutDispatcher, Node, NodeHello, NodeHelloAck, NodeHelloOut, NodeId,
    NodeMessageToIn, NodeMessageToInUpdate, NodeMessageToOut, NodeOutDispatcher, OutDispatcher,
  },
  out::DirectOut,
  primitives::OutExits,
  quic_connection::{QuicBytesPacket, QuicConnection, QuicStream, create_quiche_config},
  route::{GeoLite2, Router},
  utils::{
    postcard::{postcard_read_stream, postcard_read_stream_to_end},
    task::reap_finished_tasks,
  },
};

pub struct Hub {
  id: NodeId,
  exits: OutExits,
  mt_connections_listener: tokio::sync::Mutex<MtConnectionsListener<QuicBytesPacket>>,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  in_update_sender_map: Mutex<HashMap<NodeId, Arc<mpsc::UnboundedSender<Vec<u8>>>>>,
  in_update_lock: tokio::sync::Mutex<()>,
  out_map: Mutex<HashMap<NodeId, HubOutState>>,
  router: Router,
  inbounds: Vec<Arc<AnyInbound>>,
  context_dir: PathBuf,
}

const IN_UPDATE_SEND_TIMEOUT: Duration = Duration::from_secs(10);

struct HubOutState {
  exits: OutExits,
  direct_out: Option<DirectOut>,
}

pub struct HubOptions {
  pub default_local_exit: DefaultLocalExit,
  pub context_dir: PathBuf,
}

impl Hub {
  pub fn new(
    tcp_listener: TcpListener,
    inbounds: Vec<AnyInbound>,
    router: Router,
    HubOptions {
      default_local_exit,
      context_dir,
    }: HubOptions,
  ) -> Self {
    let direct_out_dispatcher = DirectOutDispatcher::new(default_local_exit);
    let exits = direct_out_dispatcher.exits().for_advertising();

    Self {
      id: NodeId::new(),
      exits,
      mt_connections_listener: MtConnectionsListener::new(tcp_listener).tokio_mutex(),
      direct_out_dispatcher: direct_out_dispatcher.arc(),
      connected_out_dispatcher_map: HashMap::new().mutex(),
      in_update_sender_map: HashMap::new().mutex(),
      in_update_lock: tokio::sync::Mutex::new(()),
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

      reap_finished_tasks(&mut join_set, "HUB node session task");

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
    let qomt_connection = qomt_connection.arc();
    let (update_sender, mut update_receiver) = mpsc::unbounded_channel();
    let update_sender = Arc::new(update_sender);

    {
      let _update_guard = self.in_update_lock.lock().await;
      let update = self.build_in_update();

      if update_sender.send(update).is_err() {
        log::error!("initial IN update queue for {node_id} unexpectedly closed");
        return;
      }

      self
        .in_update_sender_map
        .lock()
        .unwrap()
        .insert(node_id, update_sender.clone());

      log::info!("queued initial IN update to {node_id}.");
    }

    let mut join_set = JoinSet::new();

    let update_writer = async {
      while let Some(update) = update_receiver.recv().await {
        timeout(IN_UPDATE_SEND_TIMEOUT, stream.write_all(&update))
          .await
          .map_err(|_| anyhow::anyhow!("timed out writing IN update"))??;
      }

      anyhow::Ok(())
    };

    tokio::pin!(update_writer);

    loop {
      let stream = tokio::select! {
        result = &mut update_writer => {
          result.inspect_err(|error| {
            log::error!("error writing IN update to {node_id}: {error}");
          }).ok();

          break;
        }
        result = qomt_connection.accept_stream() => {
          let Ok(Some(stream)) = result.inspect_err(|error| {
            log::error!("error accepting IN node stream: {}", error);
          }) else {
            break;
          };

          stream
        }
      };

      let this = self.clone();

      reap_finished_tasks(&mut join_set, "HUB CONNECT task");

      join_set.spawn(async move {
        let mut stream = stream;

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

    let _update_guard = self.in_update_lock.lock().await;
    let mut update_sender_map = self.in_update_sender_map.lock().unwrap();

    if update_sender_map
      .get(&node_id)
      .is_some_and(|current| Arc::ptr_eq(current, &update_sender))
    {
      update_sender_map.remove(&node_id);
    }
  }

  async fn handle_out_node(
    self: Arc<Self>,
    NodeHelloOut {
      id,
      exits,
      direct_out,
    }: NodeHelloOut,
    qomt_connection: QuicConnection,
  ) {
    let exits = exits.for_advertising();
    let qomt_connection = qomt_connection.arc();
    let out_dispatcher = NodeOutDispatcher::new(exits.clone(), qomt_connection.clone()).arc();
    let registered_out_dispatcher: Arc<dyn OutDispatcher> = out_dispatcher.clone();

    {
      let _update_guard = self.in_update_lock.lock().await;

      self
        .out_map
        .lock()
        .unwrap()
        .insert(id, HubOutState { exits, direct_out });

      self
        .connected_out_dispatcher_map
        .lock()
        .unwrap()
        .insert(id, registered_out_dispatcher.clone());

      self.queue_in_update();
    }

    while qomt_connection
      .accept_stream()
      .await
      .inspect_err(|error| {
        log::error!("error handling OUT node: {}", error);
      })
      .is_ok_and(|stream| stream.is_some())
    {}

    let _update_guard = self.in_update_lock.lock().await;
    let mut dispatcher_map = self.connected_out_dispatcher_map.lock().unwrap();

    if dispatcher_map
      .get(&id)
      .is_some_and(|current| Arc::ptr_eq(current, &registered_out_dispatcher))
    {
      dispatcher_map.remove(&id);
      drop(dispatcher_map);
      self.out_map.lock().unwrap().remove(&id);
      self.queue_in_update();
    }
  }

  fn build_in_update(&self) -> Vec<u8> {
    let update = {
      let out_map = self.out_map.lock().unwrap();
      let exits = self
        .exits
        .iter()
        .chain(out_map.values().flat_map(|out| out.exits.iter()))
        .cloned()
        .collect::<OutExits>();

      NodeMessageToIn::Update(NodeMessageToInUpdate {
        exits,
        direct_outs: out_map
          .values()
          .flat_map(|out| &out.direct_out)
          .cloned()
          .collect(),
        route_rules: self.router.build_rules(),
      })
    };

    postcard::to_allocvec(&update).unwrap()
  }

  /// Queues one complete snapshot for every registered IN. Callers serialize
  /// state mutations and calls to this method with `in_update_lock`.
  fn queue_in_update(&self) {
    let update = self.build_in_update();
    self
      .in_update_sender_map
      .lock()
      .unwrap()
      .retain(|node_id, sender| {
        sender
          .send(update.clone())
          .inspect_err(|error| {
            log::error!("error queueing IN update to {node_id}: {error}");
          })
          .is_ok()
      });
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

  let default_local_exit = match tags {
    None => DefaultLocalExit::Private,
    Some(tags) => DefaultLocalExit::Advertised { tags },
  };

  let hub = Hub::new(
    tcp_listener,
    inbounds,
    router,
    HubOptions {
      default_local_exit,
      context_dir: context_dir.to_path_buf(),
    },
  );

  hub.run().await
}
