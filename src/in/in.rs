use std::{
  collections::HashMap,
  future::Future,
  net::SocketAddr,
  path::{Path, PathBuf},
  pin::Pin,
  sync::{
    Arc, Mutex, Weak,
    atomic::{AtomicU64, Ordering},
  },
};

use anyhow::Context;
use lits::duration;
use lowkit::SelfWrapExt;
use tokio::{
  io::AsyncWriteExt,
  sync::{mpsc, oneshot},
  task::JoinSet,
  time::{sleep, timeout},
};

use crate::{
  cert::NODE_PEM_FILE_NAME,
  r#in::{InConfig, InLike},
  inbound::AnyInbound,
  mt_connections::MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
  node::{
    DefaultLocalExit, LocalOutDispatcher, Node, NodeHello, NodeHelloAck, NodeId, NodeMessageToIn,
    NodeMessageToInUpdate, NodeOutDispatcher, OutDispatcher,
  },
  out::PeerOut,
  primitives::OutExits,
  qomt::{QomtConnection, QomtStream, State as QuicConnectionState, qomt_connect},
  quic_connection::{create_quiche_config, create_udp_quiche_config},
  route::Router,
  utils::postcard::postcard_read_stream,
};

pub struct In {
  id: NodeId,
  inbounds: Vec<Arc<AnyInbound>>,
  router: Router,
  default_local_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  peer_out_dispatcher_map: Mutex<HashMap<PeerOutKey, (NodeId, Arc<dyn OutDispatcher>)>>,
  peer_out_task_map: Mutex<HashMap<PeerOutKey, PeerOutTask>>,
  peer_out_task_sender: mpsc::UnboundedSender<PeerOutTaskFuture>,
  peer_out_task_receiver: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<PeerOutTaskFuture>>>,
  out_dispatcher_revision: AtomicU64,
  hub_options: InHubOptions,
  context_dir: PathBuf,
}

type PeerOutTaskFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct PeerOutKey {
  provider_id: NodeId,
  address: SocketAddr,
}

struct PeerOutTask {
  exits: OutExits,
  generation: NodeId,
  cancel_sender: oneshot::Sender<()>,
}

struct PeerOutDispatcherRegistration {
  in_node: Weak<In>,
  key: PeerOutKey,
  generation: NodeId,
  dispatcher: Arc<dyn OutDispatcher>,
}

impl Drop for PeerOutDispatcherRegistration {
  fn drop(&mut self) {
    let Some(in_node) = self.in_node.upgrade() else {
      return;
    };

    let mut dispatcher_map = in_node.peer_out_dispatcher_map.lock().unwrap();

    if dispatcher_map
      .get(&self.key)
      .is_some_and(|(generation, current)| {
        *generation == self.generation && Arc::ptr_eq(current, &self.dispatcher)
      })
    {
      dispatcher_map.remove(&self.key);
      in_node.mark_out_dispatchers_changed();
    }
  }
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
    let (peer_out_task_sender, peer_out_task_receiver) = mpsc::unbounded_channel();

    Self {
      id: NodeId::new(),
      inbounds: inbounds.into_iter().map(|inbound| inbound.arc()).collect(),
      router,
      default_local_out_dispatcher: LocalOutDispatcher::new_default(DefaultLocalExit::Private)
        .arc(),
      connected_out_dispatcher_map: HashMap::new().mutex(),
      peer_out_dispatcher_map: HashMap::new().mutex(),
      peer_out_task_map: HashMap::new().mutex(),
      peer_out_task_sender,
      peer_out_task_receiver: Some(peer_out_task_receiver).tokio_mutex(),
      out_dispatcher_revision: AtomicU64::new(0),
      hub_options,
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    self.arc().run_shared().await
  }

  pub async fn run_shared(self: Arc<Self>) -> anyhow::Result<()> {
    tokio::try_join!(
      self.clone().run_inbounds(),
      self.clone().run_in(),
      self.run_peer_out_tasks(),
    )?;

    Ok(())
  }

  fn mark_out_dispatchers_changed(&self) {
    self.out_dispatcher_revision.fetch_add(1, Ordering::Relaxed);
  }

  async fn run_peer_out_tasks(self: Arc<Self>) -> anyhow::Result<()> {
    let mut receiver = self
      .peer_out_task_receiver
      .lock()
      .await
      .take()
      .expect("peer OUT task supervisor may only run once");
    let mut join_set = JoinSet::new();

    loop {
      tokio::select! {
        task = receiver.recv() => {
          let task = task.expect("peer OUT task queue unexpectedly closed");
          join_set.spawn(task);
        }
        result = join_set.join_next(), if !join_set.is_empty() => {
          result
            .expect("peer OUT task set unexpectedly became empty")
            .expect("peer OUT task panicked");
        }
      }
    }
  }

  async fn run_in(self: Arc<Self>) -> anyhow::Result<()> {
    let pem_path = self.context_dir.join(NODE_PEM_FILE_NAME);
    let mut quiche_config = create_quiche_config(&pem_path)?;

    loop {
      async {
        let udp_quiche_config = create_udp_quiche_config(&pem_path).ok();
        let qomt_connection = qomt_connect(
          &mut quiche_config,
          udp_quiche_config,
          self.hub_options.address,
          self.hub_options.connections,
        )
        .await?
        .arc();

        log::info!("connection to HUB established.");

        let hub_id_future = async {
          timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
            let mut stream = qomt_connection.open_stream();

            let hello = NodeHello::In(self.id);

            stream
              .write_all(&postcard::to_allocvec(&hello).unwrap())
              .await?;

            stream.shutdown().await?;

            let NodeHelloAck(node_id) = postcard_read_stream(&mut stream).await?;

            anyhow::Ok((node_id, stream))
          })
          .await
          .context("timed out waiting for HUB hello acknowledgement")?
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
    mut update_stream: QomtStream,
    qomt_connection: Arc<QomtConnection>,
  ) -> anyhow::Result<()> {
    let out_dispatcher = NodeOutDispatcher::new(OutExits::default(), qomt_connection.clone()).arc();
    let registered_out_dispatcher: Arc<dyn OutDispatcher> = out_dispatcher.clone();

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .insert(node_id, registered_out_dispatcher.clone());
    self.mark_out_dispatchers_changed();

    let update_result = async {
      loop {
        let message = postcard_read_stream::<NodeMessageToIn>(&mut update_stream).await?;

        match message {
          NodeMessageToIn::Update(NodeMessageToInUpdate {
            exits,
            peer_outs,
            route_rules,
          }) => {
            let dispatcher_map = self.connected_out_dispatcher_map.lock().unwrap();

            if !dispatcher_map
              .get(&node_id)
              .is_some_and(|current| Arc::ptr_eq(current, &registered_out_dispatcher))
            {
              break;
            }

            log::info!("received update from HUB.");

            out_dispatcher.update_exits(exits);
            self.mark_out_dispatchers_changed();
            self.update_peer_outs(peer_outs);
            self.router.register_node_rules(node_id, route_rules);
          }
        }
      }
      #[allow(unreachable_code)]
      anyhow::Ok(())
    }
    .await;

    let mut dispatcher_map = self.connected_out_dispatcher_map.lock().unwrap();

    if dispatcher_map
      .get(&node_id)
      .is_some_and(|current| Arc::ptr_eq(current, &registered_out_dispatcher))
    {
      dispatcher_map.remove(&node_id);
      self.mark_out_dispatchers_changed();
      self.update_peer_outs(vec![]);
      self.router.unregister_node_rules(node_id);
    }

    update_result
  }

  fn update_peer_outs(self: &Arc<Self>, peer_outs: Vec<PeerOut>) {
    let mut desired = HashMap::<PeerOutKey, OutExits>::new();

    for PeerOut {
      provider_id,
      exits,
      address,
    } in peer_outs
    {
      let key = PeerOutKey {
        provider_id,
        address,
      };

      if let Some(existing) = desired.insert(key, exits.clone()) {
        assert_eq!(
          existing, exits,
          "one peer OUT endpoint was declared with inconsistent exits"
        );
      }
    }

    let (removed_tasks, added_tasks) = {
      let mut task_map = self.peer_out_task_map.lock().unwrap();
      let removed_keys = task_map
        .iter()
        .filter_map(|(key, task)| {
          desired
            .get(key)
            .is_none_or(|exits| exits != &task.exits)
            .then_some(*key)
        })
        .collect::<Vec<_>>();
      let removed_tasks = removed_keys
        .into_iter()
        .filter_map(|key| task_map.remove(&key).map(|task| (key, task)))
        .collect::<Vec<_>>();
      let mut added_tasks = Vec::new();

      for (key, exits) in desired {
        if task_map.contains_key(&key) {
          continue;
        }

        let generation = NodeId::new();
        let (cancel_sender, cancel_receiver) = oneshot::channel();

        task_map.insert(
          key,
          PeerOutTask {
            exits: exits.clone(),
            generation,
            cancel_sender,
          },
        );
        added_tasks.push((key, exits, generation, cancel_receiver));
      }

      (removed_tasks, added_tasks)
    };

    for (key, task) in removed_tasks {
      let mut dispatcher_map = self.peer_out_dispatcher_map.lock().unwrap();

      if dispatcher_map
        .get(&key)
        .is_some_and(|(generation, _)| *generation == task.generation)
      {
        dispatcher_map.remove(&key);
        self.mark_out_dispatchers_changed();
      }

      drop(dispatcher_map);
      task.cancel_sender.send(()).ok();
    }

    for (key, exits, generation, cancel_receiver) in added_tasks {
      log::info!(
        "peer OUT {} ({}) declared with exits {:?}.",
        key.address,
        key.provider_id,
        exits
      );

      self
        .peer_out_task_sender
        .send(Box::pin(Self::run_peer_out(
          Arc::downgrade(self),
          key,
          exits,
          generation,
          cancel_receiver,
        )))
        .expect("peer OUT task supervisor unexpectedly stopped");
    }
  }

  async fn run_peer_out(
    in_node: Weak<Self>,
    key: PeerOutKey,
    exits: OutExits,
    generation: NodeId,
    mut cancel_receiver: oneshot::Receiver<()>,
  ) {
    loop {
      if in_node.upgrade().is_none() {
        break;
      }

      let connection_result = tokio::select! {
        _ = &mut cancel_receiver => break,
        result = Self::run_peer_out_connection(
          in_node.clone(),
          key,
          exits.clone(),
          generation,
        ) => result,
      };

      connection_result
        .inspect_err(|error| {
          log::warn!(
            "peer OUT {} ({}) connection error: {error}",
            key.address,
            key.provider_id
          );
        })
        .ok();

      tokio::select! {
        _ = &mut cancel_receiver => break,
        _ = sleep(duration!("5s")) => {}
      }
    }

    log::info!(
      "peer OUT {} ({}) declaration removed.",
      key.address,
      key.provider_id
    );
  }

  async fn run_peer_out_connection(
    in_node: Weak<Self>,
    key: PeerOutKey,
    exits: OutExits,
    generation: NodeId,
  ) -> anyhow::Result<()> {
    let Some(in_node_arc) = in_node.upgrade() else {
      return Ok(());
    };

    let node_id = in_node_arc.id;
    let connections = in_node_arc.hub_options.connections.max(1);
    let pem_path = in_node_arc.context_dir.join(NODE_PEM_FILE_NAME);
    drop(in_node_arc);

    let mut quiche_config = create_quiche_config(&pem_path)?;
    let udp_quiche_config = create_udp_quiche_config(&pem_path).ok();
    let qomt_connection = qomt_connect(
      &mut quiche_config,
      udp_quiche_config,
      key.address,
      connections,
    )
    .await?;
    let qomt_connection = qomt_connection.arc();

    let NodeHelloAck(provider_id) = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
      let mut stream = qomt_connection.open_stream();

      stream
        .write_all(&postcard::to_allocvec(&NodeHello::In(node_id)).unwrap())
        .await?;
      stream.shutdown().await?;

      let acknowledgement = postcard_read_stream(&mut stream).await?;

      anyhow::Ok(acknowledgement)
    })
    .await
    .context("timed out waiting for peer OUT hello acknowledgement")??;

    assert_eq!(
      provider_id, key.provider_id,
      "peer OUT endpoint acknowledged an unexpected provider id"
    );

    if qomt_connection.state() != QuicConnectionState::Established {
      return Ok(());
    }

    let Some(in_node_arc) = in_node.upgrade() else {
      return Ok(());
    };
    let dispatcher = NodeOutDispatcher::new_peer(exits, qomt_connection.clone()).arc();
    let registered_dispatcher: Arc<dyn OutDispatcher> = dispatcher;

    {
      let task_map = in_node_arc.peer_out_task_map.lock().unwrap();

      if !task_map
        .get(&key)
        .is_some_and(|task| task.generation == generation)
      {
        return Ok(());
      }

      in_node_arc
        .peer_out_dispatcher_map
        .lock()
        .unwrap()
        .insert(key, (generation, registered_dispatcher.clone()));
      in_node_arc.mark_out_dispatchers_changed();
    }
    drop(in_node_arc);

    let _registration = PeerOutDispatcherRegistration {
      in_node: in_node.clone(),
      key,
      generation,
      dispatcher: registered_dispatcher,
    };

    log::info!(
      "connection to peer OUT {} ({provider_id}) established: QOMT {}.",
      key.address,
      qomt_connection.diagnostic_id(),
    );

    while let Some(unexpected_stream) = qomt_connection.accept_stream().await? {
      log::warn!(
        "unexpected stream {} received from peer OUT {} ({}) on QOMT {}.",
        unexpected_stream.id(),
        key.address,
        key.provider_id,
        qomt_connection.diagnostic_id(),
      );
    }

    log::info!(
      "connection to peer OUT {} ({provider_id}) closed.",
      key.address
    );

    Ok(())
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
    let mut dispatchers = vec![self.default_local_out_dispatcher.clone()];

    dispatchers.extend(
      self
        .peer_out_dispatcher_map
        .lock()
        .unwrap()
        .values()
        .map(|(_, dispatcher)| dispatcher.clone()),
    );

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

pub async fn run_in(
  context_dir: impl AsRef<Path>,
  InConfig {
    hub,
    route: route_config,
    inbounds: inbounds_config,
    dns: dns_config,
  }: InConfig,
) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();
  let dns_hijack = dns_config.as_ref().map(|config| *config.listen);

  let inbounds = if let Some(inbounds_config) = inbounds_config {
    inbounds_config.into_inbounds(dns_hijack).await?
  } else {
    vec![]
  };

  let router = Router::new(context_dir);

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
  )
  .arc();

  match dns_config {
    Some(dns_config) => {
      tokio::try_join!(
        in_node.clone().run_shared(),
        crate::dns::run_dns_server(dns_config, in_node),
      )?;
      Ok(())
    }
    None => in_node.run_shared().await,
  }
}

#[cfg(test)]
mod tests {
  use lits::duration;
  use lowkit::SelfWrapExt;
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpListener, UdpSocket},
    time::{sleep, timeout},
  };

  use super::*;
  use crate::{
    cert::{generate_ca_pem_file, generate_node_pem_file},
    node::{DefaultLocalExit, LocalOutDispatcher},
    out::{Out, OutHubOptions, OutOptions},
    primitives::{
      OutExit, OutExitMatchPriority, OutExitTag, SocketDestination, SocketDestinationHost,
    },
    test::test_dir,
  };

  #[tokio::test]
  #[should_panic(expected = "peer OUT task panicked")]
  async fn peer_task_supervisor_propagates_protocol_panics() {
    let context_dir = test_dir().join(format!("peer_panic_{}", uuid::Uuid::new_v4()));
    let in_node = In::new(
      vec![],
      Router::new(&context_dir),
      InOptions {
        hub: InHubOptions {
          address: "127.0.0.1:1".parse().unwrap(),
          connections: 1,
        },
        context_dir,
      },
    )
    .arc();

    in_node
      .peer_out_task_sender
      .send(Box::pin(async {
        panic!("simulated peer OUT protocol error");
      }))
      .unwrap();

    in_node.run_peer_out_tasks().await.unwrap();
  }

  #[tokio::test]
  async fn equivalent_peer_snapshot_reuses_task_and_changed_exits_replace_it() {
    let context_dir = test_dir().join(format!("peer_reconcile_{}", uuid::Uuid::new_v4()));
    let in_node = In::new(
      vec![],
      Router::new(&context_dir),
      InOptions {
        hub: InHubOptions {
          address: "127.0.0.1:1".parse().unwrap(),
          connections: 1,
        },
        context_dir,
      },
    )
    .arc();
    let provider_id = NodeId::new();
    let address = "127.0.0.1:2".parse().unwrap();
    let key = PeerOutKey {
      provider_id,
      address,
    };
    let first_exits = OutExits::new([OutExit::Proxy, OutExit::from("system")]);
    let first_snapshot = PeerOut {
      provider_id,
      exits: first_exits.clone(),
      address,
    };

    in_node.update_peer_outs(vec![first_snapshot.clone()]);
    let first_generation = in_node
      .peer_out_task_map
      .lock()
      .unwrap()
      .get(&key)
      .unwrap()
      .generation;

    in_node.update_peer_outs(vec![first_snapshot]);
    assert_eq!(
      in_node
        .peer_out_task_map
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .generation,
      first_generation
    );

    in_node.update_peer_outs(vec![PeerOut {
      provider_id,
      exits: OutExits::new([
        OutExit::Proxy,
        OutExit::from("system"),
        OutExit::from("video"),
      ]),
      address,
    }]);
    assert_ne!(
      in_node
        .peer_out_task_map
        .lock()
        .unwrap()
        .get(&key)
        .unwrap()
        .generation,
      first_generation
    );

    in_node.update_peer_outs(vec![]);
    assert!(in_node.peer_out_task_map.lock().unwrap().is_empty());
    assert!(in_node.peer_out_dispatcher_map.lock().unwrap().is_empty());
  }

  #[tokio::test]
  async fn peer_out_manager_connects_removes_and_reconnects() -> anyhow::Result<()> {
    timeout(duration!("25s"), async {
      let test_dir = test_dir().join(format!("peer_manager_{}", uuid::Uuid::new_v4()));
      let in_dir = test_dir.join("in");
      let out_dir = test_dir.join("out");

      generate_ca_pem_file(&test_dir).await?;
      generate_node_pem_file(&test_dir, "in", true).await?;
      generate_node_pem_file(&test_dir, "out", true).await?;

      let peer_listener = TcpListener::bind("127.0.0.1:0").await?;
      let peer_endpoint = peer_listener.local_addr()?;
      let target_listener = TcpListener::bind("127.0.0.1:0").await?;
      let target_address = target_listener.local_addr()?;
      let target_task = tokio::spawn(async move {
        for _ in 0..2 {
          let (mut stream, _) = target_listener.accept().await?;
          let mut request = [0; 4];
          stream.read_exact(&mut request).await?;
          assert_eq!(&request, b"ping");
          stream.write_all(b"pong").await?;
        }

        anyhow::Ok(())
      });

      let out = Out::new(OutOptions {
        local_out_dispatchers: vec![LocalOutDispatcher::new_default(
          DefaultLocalExit::Advertised {
            tags: vec![OutExitTag::from("system")],
          },
        )],
        listen: None,
        advertise: None,
        hub: OutHubOptions {
          address: "127.0.0.1:1".parse()?,
          connections: 1,
        },
        context_dir: out_dir,
      })
      .arc();
      let provider_id = out.id();
      let udp_socket = UdpSocket::bind(peer_listener.local_addr()?).await.ok();

      let mut peer_listener_task = tokio::spawn(out.clone().run_out(peer_listener, udp_socket));

      let in_node = In::new(
        vec![],
        Router::new(&in_dir),
        InOptions {
          hub: InHubOptions {
            address: "127.0.0.1:1".parse()?,
            connections: 1,
          },
          context_dir: in_dir,
        },
      )
      .arc();
      let peer_task_supervisor = tokio::spawn(in_node.clone().run_peer_out_tasks());
      let peer_out = PeerOut {
        provider_id,
        exits: OutExits::new([OutExit::Proxy, OutExit::from("system")]),
        address: peer_endpoint,
      };
      let key = PeerOutKey {
        provider_id,
        address: peer_endpoint,
      };
      let destination = SocketDestination {
        host: SocketDestinationHost::IpAddress(target_address.ip()),
        port: target_address.port(),
        routing_domain: None,
        routing_protocol: None,
      };

      in_node.update_peer_outs(vec![peer_out.clone()]);
      wait_for_peer_dispatcher(&in_node, key, true).await?;
      assert_eq!(
        in_node
          .peer_out_dispatcher_map
          .lock()
          .unwrap()
          .get(&key)
          .unwrap()
          .1
          .match_exit(&OutExit::from("system"))
          .unwrap()
          .priority,
        OutExitMatchPriority::PeerProvider
      );
      assert_proxied_ping(&in_node, destination.clone()).await?;

      peer_listener_task.abort();
      peer_listener_task.await.ok();
      wait_for_peer_dispatcher(&in_node, key, false).await?;

      // 旧 listener 释放是异步的，轮询等待端口可用。
      let peer_listener = loop {
        match TcpListener::bind(peer_endpoint).await {
          Ok(listener) => break listener,
          Err(_) => sleep(duration!("20ms")).await,
        }
      };
      let udp_socket = UdpSocket::bind(peer_listener.local_addr()?).await.ok();

      peer_listener_task = tokio::spawn(out.clone().run_out(peer_listener, udp_socket));

      wait_for_peer_dispatcher(&in_node, key, true).await?;
      assert_proxied_ping(&in_node, destination).await?;

      in_node.update_peer_outs(vec![]);
      assert!(
        !in_node
          .get_out_dispatchers()
          .iter()
          .any(|dispatcher| dispatcher.match_exit(&OutExit::from("system")).is_some())
      );

      target_task.await??;
      peer_listener_task.abort();
      peer_task_supervisor.abort();

      anyhow::Ok(())
    })
    .await??;

    Ok(())
  }

  async fn wait_for_peer_dispatcher(
    in_node: &In,
    key: PeerOutKey,
    expected_present: bool,
  ) -> anyhow::Result<()> {
    timeout(duration!("8s"), async {
      loop {
        let present = in_node
          .peer_out_dispatcher_map
          .lock()
          .unwrap()
          .contains_key(&key);

        if present == expected_present {
          return;
        }

        sleep(duration!("20ms")).await;
      }
    })
    .await
    .context("timed out waiting for peer dispatcher state")?;

    Ok(())
  }

  async fn assert_proxied_ping(
    in_node: &Arc<In>,
    destination: SocketDestination,
  ) -> anyhow::Result<()> {
    let (mut client_stream, proxy_stream) = duplex(1024);
    let in_node = in_node.clone();
    let proxy_task = tokio::spawn(async move {
      in_node
        .tcp_connect(
          vec![OutExit::from("system")],
          destination,
          proxy_stream.wrap_box(),
        )
        .await
    });

    client_stream.write_all(b"ping").await?;

    let mut response = [0; 4];
    client_stream.read_exact(&mut response).await?;
    assert_eq!(&response, b"pong");
    client_stream.shutdown().await?;

    proxy_task.await??;

    Ok(())
  }
}
