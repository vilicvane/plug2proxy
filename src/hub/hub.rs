use std::{
  collections::HashMap,
  path::PathBuf,
  sync::{Arc, Mutex},
};

use futures::StreamExt;
use lowkit::SelfWrapExt;
use tokio::{net::TcpListener, task::JoinSet};

use crate::{
  cert::NODE_PEM_FILE_NAME,
  r#in::InLike,
  inbound::{AnyInbound, Inbound},
  mt_connections::MtConnectionsListener,
  node::{
    DirectOutDispatcher, Node, NodeHello, NodeHelloOut, NodeId, NodeMessageToOut,
    NodeOutDispatcher, OutDispatcher,
  },
  primitives::{OutExit, OutExitTag},
  quic_connection::{QuicBytesPacket, QuicConnection, create_quiche_config},
  route::{FallbackRule, GeoLite2, Router},
  utils::postcard::{postcard_read_stream, postcard_read_stream_to_end},
};

pub struct Hub {
  id: NodeId,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: Mutex<HashMap<NodeId, Arc<dyn OutDispatcher>>>,
  mt_connections_listener: tokio::sync::Mutex<MtConnectionsListener<QuicBytesPacket>>,
  router: Router,
  inbounds: Vec<Arc<AnyInbound>>,
  context_dir: PathBuf,
}

pub struct HubOptions {
  pub tags: Option<Vec<OutExitTag>>,
  pub context_dir: PathBuf,
}

impl Hub {
  pub fn new(tcp_listener: TcpListener, inbounds: Vec<AnyInbound>, options: HubOptions) -> Self {
    let id = NodeId::new();

    let router = Router::new(GeoLite2::new(options.context_dir.join("geolite2.mmdb")));

    router.register_rules(
      id,
      vec![
        FallbackRule {
          exits: vec![OutExit::Any],
        }
        .into(),
      ],
    );

    Self {
      id,
      direct_out_dispatcher: DirectOutDispatcher::new(options.tags).arc(),
      connected_out_dispatcher_map: HashMap::new().mutex(),
      mt_connections_listener: MtConnectionsListener::new(tcp_listener).tokio_mutex(),
      router,
      inbounds: inbounds.into_iter().map(|inbound| inbound.arc()).collect(),
      context_dir: options.context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let hub = self.arc();

    tokio::try_join!(hub.clone().run_hub(), hub.run_inbounds())?;

    Ok(())
  }

  async fn run_hub(self: Arc<Self>) -> anyhow::Result<()> {
    let mut mt_connections_listener = self.mt_connections_listener.lock().await;

    let mut join_set = JoinSet::new();

    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    loop {
      let mut mt_connections = mt_connections_listener.accept().await?;

      let Some(first_packet) = mt_connections.next().await else {
        log::warn!("missing first packet (connection_id) in incoming mTCP connections.");
        continue;
      };

      let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

      let qomt_connection =
        QuicConnection::accept(&connection_id, &mut quiche_config, mt_connections);

      let hub = self.clone();

      join_set.spawn(async move {
        async {
          qomt_connection.established().await?;

          let mut stream = qomt_connection
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("expecting hello stream"))?;

          let hello = postcard_read_stream_to_end::<NodeHello>(&mut stream).await?;

          match hello {
            NodeHello::In(node_id) => {
              hub.clone().handle_in_node(node_id, qomt_connection).await?;
            }
            NodeHello::Out(hello) => {
              hub.clone().handle_out_node(hello, qomt_connection).await?;
            }
          }

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("error accepting qomt connection: {}", error);
        })
        .ok();
      });
    }
  }

  async fn handle_in_node(
    self: Arc<Self>,
    node_id: NodeId,
    qomt_connection: QuicConnection,
  ) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    loop {
      let Some(mut stream) = qomt_connection.accept_stream().await? else {
        break;
      };

      let hub = self.clone();

      join_set.spawn(async move {
        async {
          let message = postcard_read_stream::<NodeMessageToOut>(&mut stream).await?;

          match message {
            NodeMessageToOut::Connect(exit, destination) => {
              hub
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

    Ok(())
  }

  async fn handle_out_node(
    self: Arc<Self>,
    NodeHelloOut {
      id,
      direct_out,
      tags,
    }: NodeHelloOut,
    qomt_connection: QuicConnection,
  ) -> anyhow::Result<()> {
    let qomt_connection = qomt_connection.arc();

    let out_dispatcher = NodeOutDispatcher::new(tags, qomt_connection.clone());

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .insert(id, out_dispatcher.arc());

    while qomt_connection
      .accept_stream()
      .await
      .inspect_err(|error| {
        log::error!("error handling OUT node: {}", error);
      })
      .is_ok_and(|stream| stream.is_some())
    {}

    self
      .connected_out_dispatcher_map
      .lock()
      .unwrap()
      .remove(&id);

    Ok(())
  }

  async fn run_inbounds(self: Arc<Self>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    for inbound in self.inbounds.iter() {
      join_set.spawn(self.clone().run_inbound(inbound.clone()));
    }

    let Some(result) = join_set.join_next().await else {
      return Ok(());
    };

    result??;

    unreachable!();
  }

  async fn run_inbound(self: Arc<Self>, inbound: Arc<AnyInbound>) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    loop {
      let (destination, stream) = inbound.accept_tcp_connect().await?;

      let hub = self.clone();

      join_set.spawn(async move {
        hub
          .in_tcp_connect(destination, stream)
          .await
          .inspect_err(|error| {
            log::warn!("error handling inbound TCP connect: {}", error);
          })
          .ok();
      });
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
}
