use std::{
  net::{Ipv4Addr, SocketAddr},
  path::{Path, PathBuf},
  sync::Arc,
};

use anyhow::Context;
use lits::duration;
use lowkit::SelfWrapExt;
use serde::{Deserialize, Serialize};
use tokio::{
  io::AsyncWriteExt,
  net::TcpListener,
  sync::Semaphore,
  task::JoinSet,
  time::{sleep, timeout},
};

use crate::{
  cert::NODE_PEM_FILE_NAME,
  mt_connections::{MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MtConnectionsListener},
  node::{
    LocalOutDispatcher, Node, NodeHello, NodeHelloAck, NodeHelloOut, NodeId, NodeMessageToOut,
    OutDispatcher,
  },
  out::{OutConfig, build_local_out_dispatchers},
  primitives::OutExits,
  qomt::{MAX_PENDING_QOMT_HANDSHAKES, qomt_accept, qomt_connect},
  quic_connection::{QuicBytesPacket, QuicConnection, create_quiche_config},
  udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketStream},
  utils::{
    postcard::{postcard_read_stream, postcard_read_stream_to_end},
    task::reap_finished_tasks,
  },
};

pub struct Out {
  id: NodeId,
  exits: OutExits,
  local_out_dispatchers: Vec<Arc<dyn OutDispatcher>>,
  listen: Option<SocketAddr>,
  advertise: Option<SocketAddr>,
  hub_options: OutHubOptions,
  context_dir: PathBuf,
}

pub struct OutOptions {
  pub local_out_dispatchers: Vec<LocalOutDispatcher>,
  pub listen: Option<SocketAddr>,
  pub advertise: Option<SocketAddr>,
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
      listen,
      advertise,
      hub: hub_options,
      context_dir,
    }: OutOptions,
  ) -> Self {
    assert!(
      listen.is_some() || advertise.is_none(),
      "OUT advertise requires listen"
    );
    assert!(
      advertise.is_none_or(|address| address.port() != 0),
      "OUT advertise port must not be zero"
    );

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
      listen,
      advertise,
      hub_options,
      context_dir,
    }
  }

  pub async fn run(self) -> anyhow::Result<()> {
    let this = self.arc();
    let connection_count = this.hub_options.connections.max(1);
    let mut join_set = JoinSet::new();

    let peer_endpoint = if let Some(listen) = this.listen {
      let tcp_listener = TcpListener::bind(listen).await?;
      let listen_address = tcp_listener.local_addr()?;
      let advertise = advertised_peer_endpoint(listen_address, this.advertise);

      log::info!("OUT peer listener is listening on {listen_address} (advertised as {advertise}).");

      join_set.spawn(this.clone().run_out(tcp_listener));

      Some(advertise)
    } else {
      None
    };

    for index in 0..connection_count {
      let this = this.clone();

      join_set.spawn(async move { this.run_hub_connection(index, peer_endpoint).await });
    }

    while let Some(result) = join_set.join_next().await {
      result??;
    }

    anyhow::bail!("all OUT connection pool tasks stopped")
  }

  async fn run_hub_connection(
    self: Arc<Self>,
    index: usize,
    peer_endpoint: Option<SocketAddr>,
  ) -> anyhow::Result<()> {
    let mut quiche_config = create_quiche_config(self.context_dir.join(NODE_PEM_FILE_NAME))?;

    loop {
      async {
        let qomt_connection = qomt_connect(&mut quiche_config, self.hub_options.address, 1).await?;

        log::info!("connection pool slot {index} to HUB established.");

        let hub_id = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
          let mut stream = qomt_connection.open_stream();

          let hello = NodeHello::Out(NodeHelloOut {
            id: self.id,
            exits: self.exits.clone(),
            peer_endpoint,
          });

          stream
            .write_all(&postcard::to_allocvec(&hello).unwrap())
            .await?;

          stream.shutdown().await?;

          let NodeHelloAck(hub_id) = postcard_read_stream(&mut stream).await?;

          anyhow::Ok(hub_id)
        })
        .await
        .context("timed out waiting for HUB hello acknowledgement")??;

        log::info!("connection pool slot {index} registered with HUB {hub_id}.");

        self.clone().handle_node(qomt_connection).await?;

        log::info!("connection pool slot {index} to HUB closed.");

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

  pub async fn run_out(self: Arc<Self>, tcp_listener: TcpListener) -> anyhow::Result<()> {
    let mut mt_connections_listener = MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener);
    let pending_handshakes = Arc::new(Semaphore::new(MAX_PENDING_QOMT_HANDSHAKES));
    let mut join_set = JoinSet::new();

    loop {
      let mt_connections = mt_connections_listener.accept().await?;
      let remote_address = mt_connections.peer_address();
      let Ok(handshake_permit) = pending_handshakes.clone().try_acquire_owned() else {
        log::warn!("too many pending peer IN handshakes; rejecting {remote_address}.");
        continue;
      };
      let this = self.clone();

      reap_finished_tasks(&mut join_set, "peer IN connection task");

      join_set.spawn(async move {
        async {
          let mut quiche_config = create_quiche_config(this.context_dir.join(NODE_PEM_FILE_NAME))?;
          let qomt_connection = qomt_accept(&mut quiche_config, mt_connections).await?;

          let node_id = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, async {
            let mut stream = qomt_connection
              .accept_stream()
              .await?
              .ok_or_else(|| anyhow::anyhow!("expecting hello stream from peer IN"))?;

            let NodeHello::In(node_id) =
              postcard_read_stream_to_end::<NodeHello>(&mut stream).await?
            else {
              anyhow::bail!("expecting IN hello on peer OUT connection");
            };

            stream
              .write_all(&postcard::to_allocvec(&NodeHelloAck(this.id)).unwrap())
              .await?;
            stream.shutdown().await?;

            anyhow::Ok(node_id)
          })
          .await
          .context("timed out waiting for peer IN hello")??;

          drop(handshake_permit);

          log::info!("peer connection from IN {node_id} ({remote_address}) established.");

          this.clone().handle_node(qomt_connection).await?;

          log::info!("peer connection from IN {node_id} ({remote_address}) closed.");

          anyhow::Ok(())
        }
        .await
        .inspect_err(|error| {
          log::error!("peer IN connection {remote_address} error: {error}");
        })
        .ok();
      });
    }
  }

  async fn handle_node(self: Arc<Self>, qomt_connection: QuicConnection) -> anyhow::Result<()> {
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
          log::error!("error handling node stream: {}", error);
        })
        .ok();
      });
    }

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

fn advertised_peer_endpoint(
  listen_address: SocketAddr,
  configured_advertise: Option<SocketAddr>,
) -> SocketAddr {
  configured_advertise
    .unwrap_or_else(|| SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), listen_address.port()))
}

/// An OUT endpoint advertised by the HUB for an IN to reach over a peer path.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct PeerOut {
  /// Expected in the peer listener's hello acknowledgement.
  pub provider_id: NodeId,
  pub exits: OutExits,
  pub address: SocketAddr,
}

pub async fn run_out(context_dir: impl AsRef<Path>, config: OutConfig) -> anyhow::Result<()> {
  let context_dir = context_dir.as_ref();
  let peer_addresses = config.peer_addresses()?;
  let OutConfig {
    hub,
    exits,
    listen: _,
    advertise: _,
  } = config;
  let local_out_dispatchers = build_local_out_dispatchers(exits)?;
  let (listen, advertise) = peer_addresses
    .map(|(listen, advertise)| (Some(listen), advertise))
    .unwrap_or_default();

  let out = Out::new(OutOptions {
    local_out_dispatchers,
    listen,
    advertise,
    hub: hub.into(),
    context_dir: context_dir.to_owned(),
  });

  out.run().await
}

#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use lits::duration;
  use lowkit::SelfWrapExt;
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    time::timeout,
  };

  use super::*;
  use crate::{
    cert::{generate_ca_pem_file, generate_node_pem_file},
    node::DefaultLocalExit,
    primitives::{OutExit, OutExitTag, SocketDestination, SocketDestinationHost},
    test::test_dir,
    udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource, UdpPacketStream},
  };

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
      listen: None,
      advertise: None,
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

  #[test]
  fn omitted_advertise_uses_bound_listener_port() {
    let address = advertised_peer_endpoint("127.0.0.1:49152".parse().unwrap(), None);

    assert_eq!(address, "0.0.0.0:49152".parse().unwrap());
  }

  #[tokio::test]
  async fn peer_listener_accepts_in_and_forwards_tagged_tcp_and_udp() -> anyhow::Result<()> {
    timeout(duration!("15s"), async {
      let test_dir = test_dir().join(format!("peer_out_{}", uuid::Uuid::new_v4()));
      let in_dir = test_dir.join("in");
      let out_dir = test_dir.join("out");

      generate_ca_pem_file(&test_dir).await?;
      generate_node_pem_file(&test_dir, "in", true).await?;
      generate_node_pem_file(&test_dir, "out", true).await?;

      let peer_listener = TcpListener::bind("127.0.0.1:0").await?;
      let peer_endpoint = peer_listener.local_addr()?;
      let target_listener = TcpListener::bind("127.0.0.1:0").await?;
      let target_address = target_listener.local_addr()?;
      let udp_target = UdpSocket::bind(target_address).await?;

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
      let out_id = out.id;
      let peer_listener_task = tokio::spawn(out.clone().run_out(peer_listener));
      let target_task = tokio::spawn(async move {
        let (mut stream, _) = target_listener.accept().await?;
        let mut request = [0; 4];
        stream.read_exact(&mut request).await?;
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").await?;

        anyhow::Ok(())
      });

      let mut quiche_config = create_quiche_config(in_dir.join(NODE_PEM_FILE_NAME))?;
      let qomt_connection = qomt_connect(&mut quiche_config, peer_endpoint, 1).await?;
      let mut hello_stream = qomt_connection.open_stream();

      hello_stream
        .write_all(&postcard::to_allocvec(&NodeHello::In(NodeId::new())).unwrap())
        .await?;
      hello_stream.shutdown().await?;

      let NodeHelloAck(acknowledged_out_id) =
        postcard_read_stream::<NodeHelloAck>(&mut hello_stream).await?;
      assert_eq!(acknowledged_out_id, out_id);

      let mut stream = qomt_connection.open_stream();
      let message = NodeMessageToOut::Connect(
        OutExit::from("system"),
        SocketDestination {
          host: SocketDestinationHost::IpAddress(target_address.ip()),
          port: target_address.port(),
          routing_domain: None,
        },
      );

      stream
        .write_all(&postcard::to_allocvec(&message).unwrap())
        .await?;
      stream.write_all(b"ping").await?;

      let mut response = [0; 4];
      stream.read_exact(&mut response).await?;
      assert_eq!(&response, b"pong");
      stream.shutdown().await?;

      target_task.await??;

      let udp_target_task = tokio::spawn(async move {
        let mut buffer = [0; 1500];
        let (length, source) = udp_target.recv_from(&mut buffer).await?;
        udp_target.send_to(&buffer[..length], source).await?;

        std::io::Result::Ok(())
      });
      let mut stream = qomt_connection.open_stream();
      stream
        .write_all(
          &postcard::to_allocvec(&NodeMessageToOut::Associate(OutExit::from("system"))).unwrap(),
        )
        .await?;
      let mut udp_stream =
        UdpPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::new(Box::new(stream));
      let source = UdpPacketSource {
        via: vec![],
        address: "127.0.0.1:12345".parse()?,
      };

      udp_stream
        .send(OutgoingUdpPacket {
          source: source.clone(),
          destination: SocketDestination {
            host: SocketDestinationHost::IpAddress(target_address.ip()),
            port: target_address.port(),
            routing_domain: None,
          },
          payload: b"udp ping".to_vec(),
        })
        .await?;

      let response = udp_stream
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("peer UDP stream closed before response"))?;
      assert_eq!(response.source, source);
      assert_eq!(response.destination, target_address);
      assert_eq!(response.payload, b"udp ping");
      udp_target_task.await??;

      peer_listener_task.abort();

      anyhow::Ok(())
    })
    .await??;

    Ok(())
  }
}
