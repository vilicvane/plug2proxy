use std::{
  collections::HashMap,
  net::SocketAddr,
  path::{Path, PathBuf},
  sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
  },
  time::Duration,
};

use anyhow::Context;
use colored::Colorize;
use lowkit::SelfWrapExt;
use tokio::{
  io::AsyncWriteExt,
  net::TcpListener,
  sync::{Semaphore, mpsc},
  task::JoinSet,
  time::timeout,
};

use crate::{
  cert::{CA_PEM_FILE_NAME, NODE_PEM_FILE_NAME, generate_ca_pem_file, generate_node_pem_file},
  hub::HubConfig,
  r#in::InLike,
  inbound::AnyInbound,
  mt_connections::{MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MtConnectionsListener},
  node::{
    LocalOutDispatcher, Node, NodeHello, NodeHelloAck, NodeHelloOut, NodeId, NodeMessageToIn,
    NodeMessageToInUpdate, NodeMessageToOut, NodeOutDispatcher, OutDispatcher,
  },
  out::{PeerOut, build_local_out_dispatchers},
  primitives::OutExits,
  qomt::{MAX_PENDING_QOMT_HANDSHAKES, qomt_accept},
  quic_connection::{QuicBytesPacket, QuicConnection, QuicStream, create_quiche_config},
  route::{GeoLite2, Router},
  udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketStream},
  utils::{
    postcard::{postcard_read_stream, postcard_read_stream_to_end},
    task::reap_finished_tasks,
  },
};

pub struct Hub {
  id: NodeId,
  exits: OutExits,
  mt_connections_listener: tokio::sync::Mutex<MtConnectionsListener<QuicBytesPacket>>,
  local_out_dispatchers: Vec<Arc<dyn OutDispatcher>>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  out_dispatcher_revision: AtomicU64,
  in_update_sender_map: Mutex<HashMap<NodeId, Arc<mpsc::UnboundedSender<Vec<u8>>>>>,
  in_update_lock: tokio::sync::Mutex<()>,
  out_map: Mutex<HashMap<NodeId, HubOutState>>,
  router: Router,
  inbounds: Vec<Arc<AnyInbound>>,
  context_dir: PathBuf,
}

const IN_UPDATE_SEND_TIMEOUT: Duration = Duration::from_secs(10);

struct HubOutState {
  provider_id: NodeId,
  exits: OutExits,
  peer_endpoint: Option<SocketAddr>,
}

pub struct HubOptions {
  pub local_out_dispatchers: Vec<LocalOutDispatcher>,
  pub context_dir: PathBuf,
}

impl Hub {
  pub fn new(
    tcp_listener: TcpListener,
    inbounds: Vec<AnyInbound>,
    router: Router,
    HubOptions {
      local_out_dispatchers,
      context_dir,
    }: HubOptions,
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
      mt_connections_listener: MtConnectionsListener::new(tcp_listener).tokio_mutex(),
      local_out_dispatchers,
      connected_out_dispatcher_map: HashMap::new().mutex(),
      out_dispatcher_revision: AtomicU64::new(0),
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

  fn mark_out_dispatchers_changed(&self) {
    self.out_dispatcher_revision.fetch_add(1, Ordering::Relaxed);
  }

  async fn run_hub(self: Arc<Self>) -> anyhow::Result<()> {
    let mut mt_connections_listener = self.mt_connections_listener.lock().await;

    let mut join_set = JoinSet::new();
    let pending_handshakes = Arc::new(Semaphore::new(MAX_PENDING_QOMT_HANDSHAKES));

    loop {
      let mt_connections = mt_connections_listener.accept().await?;
      let peer_address = mt_connections.peer_address();
      let Ok(handshake_permit) = pending_handshakes.clone().try_acquire_owned() else {
        log::warn!("too many pending node handshakes; rejecting {peer_address}.");
        continue;
      };

      let this = self.clone();

      reap_finished_tasks(&mut join_set, "HUB node session task");

      join_set.spawn(async move {
        async {
          let mut quiche_config = create_quiche_config(this.context_dir.join(NODE_PEM_FILE_NAME))?;
          let qomt_connection = qomt_accept(&mut quiche_config, mt_connections).await?;

          let (hello, stream) = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
            let mut stream = qomt_connection
              .accept_stream()
              .await?
              .ok_or_else(|| anyhow::anyhow!("expecting hello stream"))?;
            let hello = postcard_read_stream_to_end::<NodeHello>(&mut stream).await?;

            stream
              .write_all(&postcard::to_allocvec(&NodeHelloAck(this.id)).unwrap())
              .await?;

            if matches!(hello, NodeHello::Out(_)) {
              stream.shutdown().await?;
            }

            anyhow::Ok((hello, stream))
          })
          .await
          .context("timed out waiting for node hello")??;

          drop(handshake_permit);

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
              this
                .clone()
                .handle_out_node(hello, NodeId::new(), peer_address, qomt_connection)
                .await;
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
            NodeMessageToOut::Associate(exit) => {
              let packet_stream =
                UdpPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::new(Box::new(stream));
              this.relay_udp(exit, Box::new(packet_stream)).await?;
            }
          }

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("error handling IN node stream: {}", error);
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
      id: provider_id,
      exits,
      peer_endpoint,
    }: NodeHelloOut,
    session_id: NodeId,
    remote_address: SocketAddr,
    qomt_connection: QuicConnection,
  ) {
    let exits = exits.for_advertising();
    let peer_endpoint =
      peer_endpoint.map(|endpoint| complete_peer_endpoint(endpoint, remote_address));
    let qomt_connection = qomt_connection.arc();
    let out_dispatcher = NodeOutDispatcher::new(exits.clone(), qomt_connection.clone()).arc();
    let registered_out_dispatcher: Arc<dyn OutDispatcher> = out_dispatcher.clone();

    {
      let _update_guard = self.in_update_lock.lock().await;
      let provider_is_consistent = self
        .out_map
        .lock()
        .unwrap()
        .values()
        .filter(|state| state.provider_id == provider_id)
        .all(|state| state.exits == exits);

      assert!(
        provider_is_consistent,
        "one OUT provider advertised inconsistent exits"
      );

      self.out_map.lock().unwrap().insert(
        session_id,
        HubOutState {
          provider_id,
          exits,
          peer_endpoint,
        },
      );

      self
        .connected_out_dispatcher_map
        .lock()
        .unwrap()
        .insert(session_id, registered_out_dispatcher.clone());
      self.mark_out_dispatchers_changed();

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
      .get(&session_id)
      .is_some_and(|current| Arc::ptr_eq(current, &registered_out_dispatcher))
    {
      dispatcher_map.remove(&session_id);
      self.mark_out_dispatchers_changed();
      drop(dispatcher_map);
      self.out_map.lock().unwrap().remove(&session_id);
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
        peer_outs: build_peer_outs(out_map.values()),
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

fn complete_peer_endpoint(endpoint: SocketAddr, remote_address: SocketAddr) -> SocketAddr {
  assert_ne!(
    endpoint.port(),
    0,
    "peer OUT advertise port must not be zero"
  );

  if endpoint.ip().is_unspecified() {
    SocketAddr::new(remote_address.ip(), endpoint.port())
  } else {
    endpoint
  }
}

fn build_peer_outs<'a>(out_states: impl IntoIterator<Item = &'a HubOutState>) -> Vec<PeerOut> {
  let mut peer_outs = Vec::<PeerOut>::new();

  for state in out_states {
    let Some(address) = state.peer_endpoint else {
      continue;
    };

    if let Some(existing) = peer_outs
      .iter()
      .find(|peer_out| peer_out.provider_id == state.provider_id && peer_out.address == address)
    {
      assert_eq!(
        existing.exits, state.exits,
        "one peer OUT provider advertised inconsistent exits"
      );
      continue;
    }

    peer_outs.push(PeerOut {
      provider_id: state.provider_id,
      exits: state.exits.clone(),
      address,
    });
  }

  peer_outs
}

impl Node for Hub {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    let mut dispatchers = self.local_out_dispatchers.clone();

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

  fn out_dispatcher_revision(&self) -> u64 {
    self.out_dispatcher_revision.load(Ordering::Relaxed)
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
    exits,
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

  let local_out_dispatchers = build_local_out_dispatchers(exits)?;

  let hub = Hub::new(
    tcp_listener,
    inbounds,
    router,
    HubOptions {
      local_out_dispatchers,
      context_dir: context_dir.to_path_buf(),
    },
  );

  hub.run().await
}

#[cfg(test)]
mod tests {
  use lits::duration;
  use lowkit::SelfWrapExt;
  use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

  use crate::{
    cert::{generate_ca_pem_file, generate_node_pem_file},
    node::NodeMessageToIn,
    primitives::OutExit,
    qomt::qomt_connect,
    test::test_dir,
  };

  use super::*;

  fn test_out_state(provider_id: NodeId, peer_endpoint: Option<SocketAddr>) -> HubOutState {
    HubOutState {
      provider_id,
      exits: OutExits::new([OutExit::Proxy, OutExit::from("us")]),
      peer_endpoint,
    }
  }

  #[test]
  fn completes_unspecified_peer_endpoints_with_remote_ip() {
    assert_eq!(
      complete_peer_endpoint(
        "0.0.0.0:2233".parse().unwrap(),
        "[2001:db8::7]:49152".parse().unwrap(),
      ),
      "[2001:db8::7]:2233".parse().unwrap(),
    );
    assert_eq!(
      complete_peer_endpoint(
        "[::]:3344".parse().unwrap(),
        "198.51.100.7:49153".parse().unwrap(),
      ),
      "198.51.100.7:3344".parse().unwrap(),
    );
  }

  #[test]
  fn keeps_explicit_peer_endpoint_unchanged() {
    let advertised_address = "203.0.113.8:2233".parse().unwrap();

    assert_eq!(
      complete_peer_endpoint(advertised_address, "[2001:db8::7]:49152".parse().unwrap()),
      advertised_address,
    );
  }

  #[test]
  fn deduplicates_peer_out_sessions_for_one_provider_and_address() {
    let provider_id = NodeId::new();
    let address = "203.0.113.8:2233".parse().unwrap();
    let first_session = test_out_state(provider_id, Some(address));
    let second_session = test_out_state(provider_id, Some(address));

    assert_eq!(
      build_peer_outs([&first_session, &second_session]),
      vec![PeerOut {
        provider_id,
        exits: first_session.exits.clone(),
        address,
      }],
    );
  }

  #[test]
  fn keeps_different_peer_out_providers_at_the_same_address() {
    let first_provider_id = NodeId::new();
    let second_provider_id = NodeId::new();
    let address = "203.0.113.8:2233".parse().unwrap();
    let first_provider = test_out_state(first_provider_id, Some(address));
    let second_provider = test_out_state(second_provider_id, Some(address));

    let peer_outs = build_peer_outs([&first_provider, &second_provider]);

    assert_eq!(peer_outs.len(), 2);
    assert!(
      peer_outs
        .iter()
        .any(|peer_out| peer_out.provider_id == first_provider_id)
    );
    assert!(
      peer_outs
        .iter()
        .any(|peer_out| peer_out.provider_id == second_provider_id)
    );
  }

  #[test]
  fn peer_out_disappears_only_after_its_last_session_is_removed() {
    let provider_id = NodeId::new();
    let address = "203.0.113.8:2233".parse().unwrap();
    let first_session = test_out_state(provider_id, Some(address));
    let second_session = test_out_state(provider_id, Some(address));

    assert_eq!(build_peer_outs([&first_session, &second_session]).len(), 1);
    assert_eq!(build_peer_outs([&second_session]).len(), 1);
    assert!(build_peer_outs(std::iter::empty::<&HubOutState>()).is_empty());
  }

  #[tokio::test]
  async fn hub_announces_completed_peer_out_snapshot() -> anyhow::Result<()> {
    timeout(duration!("15s"), async {
      let test_dir = test_dir().join(format!("hub_peer_{}", uuid::Uuid::new_v4()));
      let hub_dir = test_dir.join("hub");
      let in_dir = test_dir.join("in");
      let out_dir = test_dir.join("out");

      generate_ca_pem_file(&test_dir).await?;
      generate_node_pem_file(&test_dir, "hub", true).await?;
      generate_node_pem_file(&test_dir, "in", true).await?;
      generate_node_pem_file(&test_dir, "out", true).await?;

      let hub_listener = TcpListener::bind("127.0.0.1:0").await?;
      let hub_address = hub_listener.local_addr()?;
      let hub = Hub::new(
        hub_listener,
        vec![],
        Router::new(GeoLite2::new(&hub_dir)),
        HubOptions {
          local_out_dispatchers: vec![LocalOutDispatcher::new_default(
            crate::node::DefaultLocalExit::Private,
          )],
          context_dir: hub_dir,
        },
      )
      .arc();
      let hub_task = tokio::spawn(hub.run_hub());

      let mut in_quiche_config = create_quiche_config(in_dir.join(NODE_PEM_FILE_NAME))?;
      let in_connection = qomt_connect(&mut in_quiche_config, hub_address, 1).await?;
      let mut in_update_stream = in_connection.open_stream();
      in_update_stream
        .write_all(&postcard::to_allocvec(&NodeHello::In(NodeId::new())).unwrap())
        .await?;
      in_update_stream.shutdown().await?;
      let NodeHelloAck(_) = postcard_read_stream::<NodeHelloAck>(&mut in_update_stream).await?;
      let NodeMessageToIn::Update(initial_update) =
        postcard_read_stream::<NodeMessageToIn>(&mut in_update_stream).await?;
      assert!(initial_update.peer_outs.is_empty());

      let provider_id = NodeId::new();
      let advertised_port = 2233;
      let advertised_exits = OutExits::new([OutExit::Proxy]);
      let mut out_quiche_config = create_quiche_config(out_dir.join(NODE_PEM_FILE_NAME))?;
      let out_connection = qomt_connect(&mut out_quiche_config, hub_address, 1).await?;
      let mut out_hello_stream = out_connection.open_stream();
      out_hello_stream
        .write_all(
          &postcard::to_allocvec(&NodeHello::Out(NodeHelloOut {
            id: provider_id,
            exits: advertised_exits.clone(),
            peer_endpoint: Some(([0, 0, 0, 0], advertised_port).into()),
          }))
          .unwrap(),
        )
        .await?;
      out_hello_stream.shutdown().await?;
      let NodeHelloAck(_) = postcard_read_stream::<NodeHelloAck>(&mut out_hello_stream).await?;

      let NodeMessageToIn::Update(update) =
        postcard_read_stream::<NodeMessageToIn>(&mut in_update_stream).await?;
      assert_eq!(
        update.peer_outs,
        vec![PeerOut {
          provider_id,
          exits: advertised_exits,
          address: ([127, 0, 0, 1], advertised_port).into(),
        }]
      );

      hub_task.abort();

      anyhow::Ok(())
    })
    .await??;

    Ok(())
  }
}
