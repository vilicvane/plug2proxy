use std::{collections::HashMap, sync::Arc};

use futures::StreamExt;
use lowkit::SelfWrapExt;
use tokio::{net::TcpListener, task::JoinSet};

use crate::{
  cert::NODE_PEM_FILE_NAME,
  r#in::{
    direct_out_dispatcher::DirectOutDispatcher, in_like::InLike, out_dispatcher::OutDispatcher,
  },
  mt_connections::MtConnectionsListener,
  node::{Node, NodeHello, NodeId, NodeInMessage},
  primitives::OutExitTag,
  quic_connection::{QuicBytesPacket, QuicConnection, create_quiche_config},
  route::{GeoLite2, Router},
  tunnel::TunnelId,
  utils::postcard::read_postcard_from_stream,
};

pub struct Hub {
  id: NodeId,
  direct_out_dispatcher: Arc<dyn OutDispatcher>,
  connected_out_dispatcher_map: HashMap<TunnelId, Arc<dyn OutDispatcher>>,
  mt_connections_listener: tokio::sync::Mutex<MtConnectionsListener<QuicBytesPacket>>,
  router: Router,
}

pub struct HubOptions {
  pub tags: Option<Vec<OutExitTag>>,
}

impl Hub {
  pub async fn new(options: HubOptions) -> Result<Self, std::io::Error> {
    Self {
      id: NodeId::new(),
      direct_out_dispatcher: DirectOutDispatcher::new(options.tags).arc(),
      connected_out_dispatcher_map: HashMap::new(),
      mt_connections_listener: MtConnectionsListener::new(TcpListener::bind("127.0.0.1:0").await?)
        .tokio_mutex(),
      router: Router::new(GeoLite2::default()),
    }
    .wrap_ok()
  }

  pub fn in_enabled(&self) -> bool {
    false
  }

  pub fn out_enabled(&self) -> bool {
    false
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let hub = self.arc();

    let mut mt_connections_listener = hub.mt_connections_listener.lock().await;

    let mut join_set = JoinSet::new();

    loop {
      let hub = hub.clone();

      let mut mt_connections = mt_connections_listener.accept().await?;

      let first_packet = mt_connections
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("no packet"))?;

      let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

      let mut quiche_config = create_quiche_config(NODE_PEM_FILE_NAME)?;

      let mut qomt_connection =
        QuicConnection::accept(&connection_id, &mut quiche_config, mt_connections);

      join_set.spawn(async move {
        async {
          qomt_connection.established().await?;

          let mut stream = qomt_connection
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("expecting hello stream"))?;

          let hello = read_postcard_from_stream::<NodeHello>(&mut stream).await?;

          match hello {
            NodeHello::In => {
              hub.clone().handle_in_connection(qomt_connection).await?;
            }
            NodeHello::Out(direct_out) => {
              todo!()
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

  async fn handle_in_connection(
    self: Arc<Self>,
    mut qomt_connection: QuicConnection,
  ) -> anyhow::Result<()> {
    let mut join_set = JoinSet::new();

    tokio::try_join!(
      async {
        loop {
          let Some(mut stream) = qomt_connection.accept_stream().await? else {
            break;
          };

          let hub = self.clone();

          join_set.spawn(async move {
            async {
              let message = read_postcard_from_stream::<NodeInMessage>(&mut stream).await?;

              match message {
                NodeInMessage::Connect((exit, destination)) => {
                  hub
                    .tcp_connect(vec![exit], destination, stream.wrap_box())
                    .await?;
                }
                NodeInMessage::Associate(_) => todo!(),
              }

              anyhow::Ok(())
            }
            .await
            .inspect_err(|error| {
              log::error!("error handling IN stream: {}", error);
            })
            .ok();
          });
        }

        anyhow::Ok(())
      },
      async { anyhow::Ok(()) },
    )?;

    Ok(())
  }
}

impl Node for Hub {
  fn id(&self) -> NodeId {
    self.id
  }

  fn get_out_dispatchers(&self) -> Vec<Arc<dyn OutDispatcher>> {
    let mut dispatchers = vec![self.direct_out_dispatcher.clone()];

    dispatchers.extend(self.connected_out_dispatcher_map.values().cloned());

    dispatchers
  }
}

impl InLike for Hub {
  fn router(&self) -> &Router {
    &self.router
  }
}
