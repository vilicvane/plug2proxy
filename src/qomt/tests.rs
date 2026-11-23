use std::{
  collections::HashSet,
  sync::{
    Arc, LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
  },
  time::Duration,
};

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use lits::bytes;
use rand::Rng;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional, duplex, sink},
  net::{TcpListener, TcpStream, UdpSocket},
  task::JoinSet,
  time::{Instant, sleep, timeout},
};

use crate::{
  mt_connections::{MtConnectionsListener, MtConnectionsPacket, decode_udp_frame},
  qomt::{
    QomtConnection, QomtPacketDelivery, QomtPacketSendOutcome, QomtPacketStream,
    QomtUdpReconnectPolicy, QomtUdpState, qomt_accept, qomt_connect, qomt_connect_with_udp_policy,
  },
  quic_connection::{
    MAX_DATAGRAM_SIZE, QuicBytesPacket, QuicConnection,
    tests::{get_quiche_configs, get_udp_quiche_configs},
  },
};

static RANDOM_DATA_1: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; bytes!("1 MiB") as usize];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

static RANDOM_DATA_2: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; bytes!("1 MiB") as usize];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

/// A TCP-forwarding, UDP-gated relay used to model a silent UDP blackhole
/// without closing either endpoint's socket. The QUIC branch must therefore
/// be declared dead by quiche's own idle timer rather than by transport EOF.
struct QomtTestProxy {
  address: std::net::SocketAddr,
  forward_client_udp: Arc<AtomicBool>,
  forward_server_udp: Arc<AtomicBool>,
  client_initial_dcids: Arc<Mutex<HashSet<Vec<u8>>>>,
  _join_set: JoinSet<()>,
}

impl QomtTestProxy {
  async fn start(backend_address: std::net::SocketAddr) -> anyhow::Result<Self> {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp_listener.local_addr()?;
    let udp_socket = Arc::new(UdpSocket::bind(address).await?);
    let forward_client_udp = Arc::new(AtomicBool::new(true));
    let forward_server_udp = Arc::new(AtomicBool::new(true));
    let client_initial_dcids = Arc::new(Mutex::new(HashSet::new()));
    let mut join_set = JoinSet::new();

    join_set.spawn(async move {
      let mut connections = JoinSet::new();

      loop {
        tokio::select! {
          accepted = tcp_listener.accept() => {
            let Ok((mut inbound, _)) = accepted else {
              break;
            };
            let Ok(mut outbound) = TcpStream::connect(backend_address).await else {
              break;
            };

            connections.spawn(async move {
              if let Err(error) = copy_bidirectional(&mut inbound, &mut outbound).await {
                log::debug!("QomT test TCP proxy path ended: {error}");
              }
            });
          }
          result = connections.join_next(), if !connections.is_empty() => {
            if let Some(Err(error)) = result {
              panic!("QomT test TCP proxy task panicked: {error}");
            }
          }
        }
      }
    });

    join_set.spawn({
      let udp_socket = udp_socket.clone();
      let forward_client_udp = forward_client_udp.clone();
      let forward_server_udp = forward_server_udp.clone();
      let client_initial_dcids = client_initial_dcids.clone();

      async move {
        let mut buffer = vec![0; 65536];
        let mut client_address = None;

        loop {
          let Ok((length, from)) = udp_socket.recv_from(&mut buffer).await else {
            break;
          };

          let from_server = from == backend_address;
          let destination = if from_server {
            let Some(client_address) = client_address else {
              continue;
            };
            client_address
          } else {
            client_address = Some(from);

            if let Some((_, payload)) = decode_udp_frame(&buffer[..length]) {
              let mut packet = payload.to_vec();
              if let Ok(header) = quiche::Header::from_slice(&mut packet, quiche::MAX_CONN_ID_LEN)
                && header.ty == quiche::Type::Initial
              {
                client_initial_dcids
                  .lock()
                  .unwrap()
                  .insert(header.dcid.to_vec());
              }
            }

            backend_address
          };

          let should_forward = if from_server {
            forward_server_udp.load(Ordering::Acquire)
          } else {
            forward_client_udp.load(Ordering::Acquire)
          };

          if should_forward
            && udp_socket
              .send_to(&buffer[..length], destination)
              .await
              .is_err()
          {
            break;
          }
        }
      }
    });

    Ok(Self {
      address,
      forward_client_udp,
      forward_server_udp,
      client_initial_dcids,
      _join_set: join_set,
    })
  }

  fn set_udp_forwarding(&self, enabled: bool) {
    self.forward_client_udp.store(enabled, Ordering::Release);
    self.forward_server_udp.store(enabled, Ordering::Release);
  }

  fn set_client_udp_forwarding(&self, enabled: bool) {
    self.forward_client_udp.store(enabled, Ordering::Release);
  }

  fn set_server_udp_forwarding(&self, enabled: bool) {
    self.forward_server_udp.store(enabled, Ordering::Release);
  }

  fn client_initial_generation_count(&self) -> usize {
    self.client_initial_dcids.lock().unwrap().len()
  }
}

async fn wait_for_udp_established(connection: &QomtConnection) -> anyhow::Result<()> {
  timeout(Duration::from_secs(3), async {
    loop {
      match connection.udp_state() {
        QomtUdpState::Established => return anyhow::Ok(()),
        QomtUdpState::Reconnecting | QomtUdpState::Closed => {
          anyhow::bail!("UDP path failed: {}", connection.diagnostics())
        }
        QomtUdpState::Disabled => anyhow::bail!("UDP path unexpectedly disabled"),
        QomtUdpState::Connecting => sleep(Duration::from_millis(10)).await,
      }
    }
  })
  .await
  .context("timed out waiting for UDP path")?
}

async fn wait_for_datagram_payload_len(connection: &QomtConnection) -> anyhow::Result<usize> {
  timeout(Duration::from_secs(1), async {
    loop {
      if let Some(length) = connection.max_association_datagram_payload_len() {
        return length;
      }

      sleep(Duration::from_millis(5)).await;
    }
  })
  .await
  .context("timed out waiting for QomT DATAGRAM router")
}

async fn wait_for_udp_unavailable(connection: &QomtConnection) -> anyhow::Result<()> {
  timeout(Duration::from_secs(5), async {
    loop {
      if connection.max_association_datagram_payload_len().is_none()
        && connection.udp_state() != QomtUdpState::Established
      {
        return;
      }

      sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .context("timed out waiting for QomT UDP path to become unavailable")
}

async fn wait_for_udp_reestablished(connection: &QomtConnection) -> anyhow::Result<()> {
  timeout(Duration::from_secs(8), async {
    loop {
      if connection.udp_state() == QomtUdpState::Established
        && connection.max_association_datagram_payload_len().is_some()
      {
        return;
      }

      sleep(Duration::from_millis(10)).await;
    }
  })
  .await
  .context("timed out waiting for QomT UDP path to reconnect")
}

type TestPacketStream = QomtPacketStream<Vec<u8>, Vec<u8>>;

async fn connect_real_qomt_pair(
  enable_udp: bool,
) -> anyhow::Result<(
  MtConnectionsListener<QuicBytesPacket>,
  Arc<QomtConnection>,
  Arc<QomtConnection>,
)> {
  timeout(Duration::from_secs(8), async {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp_listener.local_addr()?;
    let udp_socket = if enable_udp {
      Some(UdpSocket::bind(address).await?)
    } else {
      None
    };

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let (server_udp_config, client_udp_config) = if enable_udp {
      let [server_udp_config, client_udp_config] = get_udp_quiche_configs().await?;
      (Some(server_udp_config), Some(client_udp_config))
    } else {
      (None, None)
    };

    let server = async {
      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, udp_socket);
      let mt_connections = listener.accept().await?;
      let connection = qomt_accept(&mut server_config, server_udp_config, mt_connections).await?;

      anyhow::Ok((listener, connection))
    };

    let client = async { qomt_connect(&mut client_config, client_udp_config, address, 1).await };

    let ((listener, server), client) = tokio::try_join!(server, client)?;
    let server = Arc::new(server);
    let client = Arc::new(client);

    if enable_udp {
      tokio::try_join!(
        wait_for_udp_established(&server),
        wait_for_udp_established(&client),
      )?;
    }

    anyhow::Ok((listener, server, client))
  })
  .await
  .context("timed out establishing real QomT test pair")?
}

async fn open_test_packet_stream_pair(
  client: Arc<QomtConnection>,
  server: Arc<QomtConnection>,
) -> anyhow::Result<(TestPacketStream, TestPacketStream)> {
  timeout(Duration::from_secs(3), async {
    // A real association has already written its control message before
    // QomtPacketStream::connect waits for the ready acknowledgement. Send and
    // consume a marker here to create the main QUIC stream in the same order.
    let mut client_stream = client.open_stream();
    client_stream.write_u8(0xa5).await?;

    let mut server_stream = server
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing packet association stream"))?;
    anyhow::ensure!(server_stream.read_u8().await? == 0xa5);

    let (client_packets, server_packets) = tokio::try_join!(
      QomtPacketStream::connect(client, client_stream),
      QomtPacketStream::accept(server, server_stream),
    )?;

    anyhow::Ok((client_packets, server_packets))
  })
  .await
  .context("timed out opening QomT packet stream pair")?
}

fn large_test_packet(byte: u8) -> anyhow::Result<Vec<u8>> {
  let packet = vec![byte; 1024];
  let encoded_len = postcard::to_allocvec(&packet)?.len();
  anyhow::ensure!(encoded_len >= 1024);

  Ok(packet)
}

/// QomtConnection wrap 后的端到端双端测试：flume 通道模拟底层包传输，
/// 验证握手、open_stream/accept_stream 双向数据与 FIN 语义完整透传。
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn test_qomt_connection() -> anyhow::Result<()> {
  let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);

  let connection_id = QuicConnection::generate_connection_id();

  let out_qomt_connection = QomtConnection::new(QuicConnection::connect_with_sink_and_stream(
    &connection_id,
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    hub_to_out_packet_receiver.into_stream(),
  ));

  let hub_qomt_connection = QomtConnection::new(QuicConnection::accept_with_sink_and_stream(
    out_qomt_connection.id(),
    &mut hub_quiche_config,
    hub_to_out_packet_sender.into_sink(),
    out_to_hub_packet_receiver.into_stream(),
  ));

  tokio::try_join!(
    async {
      out_qomt_connection.established().await?;

      {
        let mut stream = out_qomt_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *RANDOM_DATA_2);
      }

      {
        let mut stream = out_qomt_connection.accept_stream().await?.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;
      }

      anyhow::Ok(())
    },
    async {
      hub_qomt_connection.established().await?;

      {
        let mut stream = hub_qomt_connection.accept_stream().await?.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;
      }

      {
        let mut stream = hub_qomt_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *RANDOM_DATA_2);
      }

      anyhow::Ok(())
    },
  )?;

  Ok(())
}

/// 真实 TCP + UDP socket 上同时建立主 QomT 与 UDP QUIC，并显式断言两侧
/// 旁路进入 Established。
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn udp_quic_path_establishes_end_to_end() -> anyhow::Result<()> {
  let (_listener, server, client) = connect_real_qomt_pair(true).await?;

  assert_eq!(server.udp_state(), QomtUdpState::Established);
  assert_eq!(client.udp_state(), QomtUdpState::Established);

  Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn large_best_effort_packet_uses_udp_datagram_end_to_end() -> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let client_max_payload = wait_for_datagram_payload_len(&client).await?;
    let packet = large_test_packet(0x31)?;
    let encoded_len = postcard::to_allocvec(&packet)?.len();
    assert!(encoded_len <= client_max_payload);

    let client_datagrams_before = client.udp_datagram_stats();
    let server_datagrams_before = server.udp_datagram_stats();
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    assert_eq!(client.datagram_route_count(), 1);
    assert_eq!(server.datagram_route_count(), 1);
    assert_eq!(
      client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );

    let received = timeout(Duration::from_secs(2), server_packets.next())
      .await
      .context("timed out receiving QomT UDP DATAGRAM packet")?
      .ok_or_else(|| anyhow::anyhow!("server packet stream closed"))?;
    assert_eq!(received, packet);

    let client_stream_stats = client_packets.stats();
    let server_stream_stats = server_packets.stats();
    assert_eq!(client_stream_stats.datagram_queued, 1);
    assert_eq!(client_stream_stats.reliable_queued, 0);
    assert_eq!(server_stream_stats.received_datagram, 1);
    assert_eq!(server_stream_stats.received_reliable, 0);

    let client_datagrams_after = client.udp_datagram_stats();
    let server_datagrams_after = server.udp_datagram_stats();
    assert_eq!(
      client_datagrams_after.sent,
      client_datagrams_before.sent + 1
    );
    assert_eq!(
      server_datagrams_after.received,
      server_datagrams_before.received + 1
    );

    drop(client_packets);
    drop(server_packets);
    assert_eq!(client.datagram_route_count(), 0);
    assert_eq!(server.datagram_route_count(), 0);

    anyhow::Ok(())
  })
  .await
  .context("large best-effort UDP DATAGRAM test timed out")?
}

/// A silent UDP blackhole must be classified by quiche's idle timer. The
/// QomT supervisor then replaces only the UDP QUIC generation while the main
/// connection and existing packet association remain usable throughout.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn udp_quic_reconnects_after_idle_timeout() -> anyhow::Result<()> {
  timeout(Duration::from_secs(20), async {
    let backend_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = backend_tcp_listener.local_addr()?;
    let backend_udp_socket = UdpSocket::bind(backend_address).await?;
    let proxy = QomtTestProxy::start(backend_address).await?;

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [mut server_udp_config, mut client_udp_config] = get_udp_quiche_configs().await?;
    for config in [&mut server_udp_config, &mut client_udp_config] {
      config.set_max_idle_timeout(500);
      config.set_initial_rtt(Duration::from_millis(20));
    }
    let reconnect_policy = QomtUdpReconnectPolicy {
      keepalive_interval: Duration::from_millis(50),
      reconnect_initial_delay: Duration::from_millis(50),
      reconnect_max_delay: Duration::from_millis(200),
    };

    let server = async {
      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(
        backend_tcp_listener,
        Some(backend_udp_socket),
      );
      let mt_connections = listener.accept().await?;
      let connection =
        qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;

      anyhow::Ok((listener, connection))
    };
    let client = async {
      qomt_connect_with_udp_policy(
        &mut client_config,
        Some(client_udp_config),
        proxy.address,
        1,
        reconnect_policy,
      )
      .await
    };

    let ((listener, server), client) = tokio::try_join!(server, client)?;
    let server = Arc::new(server);
    let client = Arc::new(client);
    tokio::try_join!(
      wait_for_udp_reestablished(&server),
      wait_for_udp_reestablished(&client),
    )?;
    sleep(Duration::from_millis(700)).await;
    assert_eq!(client.udp_state(), QomtUdpState::Established);
    assert_eq!(server.udp_state(), QomtUdpState::Established);

    let main_connection_id = client.id().to_vec();
    let packet_before_blackhole = large_test_packet(0x61)?;
    let packet_during_reconnect = large_test_packet(0x62)?;
    let packet_after_reconnect = large_test_packet(0x63)?;
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    assert_eq!(
      client_packets
        .send_packet(
          packet_before_blackhole.clone(),
          QomtPacketDelivery::BestEffort,
        )
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );
    assert_eq!(
      timeout(Duration::from_secs(2), server_packets.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("server packet stream closed before blackhole"))?,
      packet_before_blackhole,
    );
    assert_eq!(proxy.client_initial_generation_count(), 1);
    let initial_udp_connection_id = client
      .udp_connection_id()
      .ok_or_else(|| anyhow::anyhow!("client UDP generation disappeared before blackhole"))?;

    proxy.set_udp_forwarding(false);
    let blackhole_started = Instant::now();
    wait_for_udp_unavailable(&client).await?;
    assert!(
      blackhole_started.elapsed() >= Duration::from_millis(300),
      "UDP generation closed before quiche's configured idle timeout could classify the blackhole"
    );
    assert_eq!(client.state(), crate::quic_connection::State::Established);
    assert_eq!(server.state(), crate::quic_connection::State::Established);

    assert_eq!(
      client_packets
        .send_packet(
          packet_during_reconnect.clone(),
          QomtPacketDelivery::BestEffort,
        )
        .await?,
      QomtPacketSendOutcome::ReliableQueued,
    );
    assert_eq!(
      timeout(Duration::from_secs(2), server_packets.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("main fallback packet stream closed"))?,
      packet_during_reconnect,
    );

    proxy.set_udp_forwarding(true);
    tokio::try_join!(
      wait_for_udp_reestablished(&server),
      wait_for_udp_reestablished(&client),
    )?;
    let replacement_udp_connection_id = client
      .udp_connection_id()
      .ok_or_else(|| anyhow::anyhow!("replacement client UDP generation disappeared"))?;
    assert_ne!(replacement_udp_connection_id, initial_udp_connection_id);

    assert_eq!(
      client_packets
        .send_packet(
          packet_after_reconnect.clone(),
          QomtPacketDelivery::BestEffort,
        )
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );
    assert_eq!(
      timeout(Duration::from_secs(2), server_packets.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("server packet stream closed after reconnect"))?,
      packet_after_reconnect,
    );

    assert_eq!(client.id().as_ref(), &main_connection_id);
    assert_eq!(client.state(), crate::quic_connection::State::Established);
    assert_eq!(server.state(), crate::quic_connection::State::Established);
    assert_eq!(client.datagram_route_count(), 1);
    assert_eq!(server.datagram_route_count(), 1);
    assert_eq!(listener.udp_dispatch_count(), 1);

    // Keeping the client owner alive after its main QUIC closes must not keep
    // the UDP reconnect supervisor alive. Blackhole UDP as well, then retain
    // `client`/`client_packets` long enough to catch an orphaned retry loop.
    let initial_count_before_main_close = proxy.client_initial_generation_count();
    proxy.set_udp_forwarding(false);
    drop(server_packets);
    drop(server);
    timeout(Duration::from_secs(3), async {
      while client.state() != crate::quic_connection::State::Closed
        || client.udp_state() != QomtUdpState::Closed
      {
        sleep(Duration::from_millis(10)).await;
      }
    })
    .await
    .context("main close did not stop the UDP supervisor")?;
    sleep(Duration::from_millis(700)).await;
    assert_eq!(
      proxy.client_initial_generation_count(),
      initial_count_before_main_close,
      "UDP supervisor retried after the main QUIC connection closed",
    );

    anyhow::Ok(())
  })
  .await
  .context("QomT UDP reconnect test timed out")?
}

#[derive(Clone, Copy, Debug)]
enum OneWayUdpBlackhole {
  ClientToServer,
  ServerToClient,
}

async fn assert_udp_recovers_from_one_way_blackhole(
  direction: OneWayUdpBlackhole,
) -> anyhow::Result<()> {
  timeout(Duration::from_secs(15), async {
    let backend_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = backend_tcp_listener.local_addr()?;
    let backend_udp_socket = UdpSocket::bind(backend_address).await?;
    let proxy = QomtTestProxy::start(backend_address).await?;

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [mut server_udp_config, mut client_udp_config] = get_udp_quiche_configs().await?;
    for config in [&mut server_udp_config, &mut client_udp_config] {
      config.set_max_idle_timeout(500);
      config.set_initial_rtt(Duration::from_millis(20));
    }
    let reconnect_policy = QomtUdpReconnectPolicy {
      keepalive_interval: Duration::from_millis(50),
      reconnect_initial_delay: Duration::from_millis(50),
      reconnect_max_delay: Duration::from_millis(200),
    };

    let server = async {
      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(
        backend_tcp_listener,
        Some(backend_udp_socket),
      );
      let mt_connections = listener.accept().await?;
      let connection =
        qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;

      anyhow::Ok((listener, connection))
    };
    let client = async {
      qomt_connect_with_udp_policy(
        &mut client_config,
        Some(client_udp_config),
        proxy.address,
        1,
        reconnect_policy,
      )
      .await
    };

    let ((listener, server), client) = tokio::try_join!(server, client)?;
    let server = Arc::new(server);
    let client = Arc::new(client);
    tokio::try_join!(
      wait_for_udp_reestablished(&server),
      wait_for_udp_reestablished(&client),
    )?;
    let original_client_udp_id = client
      .udp_connection_id()
      .ok_or_else(|| anyhow::anyhow!("initial client UDP generation disappeared"))?;

    match direction {
      OneWayUdpBlackhole::ClientToServer => proxy.set_client_udp_forwarding(false),
      OneWayUdpBlackhole::ServerToClient => proxy.set_server_udp_forwarding(false),
    }
    tokio::try_join!(
      wait_for_udp_unavailable(&server),
      wait_for_udp_unavailable(&client),
    )?;

    match direction {
      OneWayUdpBlackhole::ClientToServer => proxy.set_client_udp_forwarding(true),
      OneWayUdpBlackhole::ServerToClient => proxy.set_server_udp_forwarding(true),
    }
    tokio::try_join!(
      wait_for_udp_reestablished(&server),
      wait_for_udp_reestablished(&client),
    )?;
    assert_ne!(
      client
        .udp_connection_id()
        .ok_or_else(|| anyhow::anyhow!("replacement client UDP generation disappeared"))?,
      original_client_udp_id,
    );

    let payload = large_test_packet(match direction {
      OneWayUdpBlackhole::ClientToServer => 0x71,
      OneWayUdpBlackhole::ServerToClient => 0x72,
    })?;
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    let (sender, receiver) = match direction {
      OneWayUdpBlackhole::ClientToServer => (&mut client_packets, &mut server_packets),
      OneWayUdpBlackhole::ServerToClient => (&mut server_packets, &mut client_packets),
    };
    assert_eq!(
      sender
        .send_packet(payload.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );
    assert_eq!(
      timeout(Duration::from_secs(2), receiver.next())
        .await?
        .ok_or_else(|| anyhow::anyhow!("recovered one-way UDP path did not deliver"))?,
      payload,
    );
    assert_eq!(client.state(), crate::quic_connection::State::Established);
    assert_eq!(server.state(), crate::quic_connection::State::Established);
    assert_eq!(listener.udp_dispatch_count(), 1);

    anyhow::Ok(())
  })
  .await
  .with_context(|| format!("{direction:?} UDP blackhole recovery timed out"))?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn udp_quic_recovers_from_client_to_server_blackhole() -> anyhow::Result<()> {
  assert_udp_recovers_from_one_way_blackhole(OneWayUdpBlackhole::ClientToServer).await
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn udp_quic_recovers_from_server_to_client_blackhole() -> anyhow::Result<()> {
  assert_udp_recovers_from_one_way_blackhole(OneWayUdpBlackhole::ServerToClient).await
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn oversized_datagram_payload_falls_back_to_reliable() -> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let max_payload = wait_for_datagram_payload_len(&client).await?;

    // Vec's postcard length prefix makes the encoded packet exceed the
    // current DATAGRAM application budget while remaining a valid logical
    // QomT packet.
    let packet = vec![0x51; max_payload];
    let encoded_len = postcard::to_allocvec(&packet)?.len();
    assert!(encoded_len > max_payload);
    assert!(encoded_len <= MAX_DATAGRAM_SIZE);

    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    assert_eq!(
      client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::ReliableQueued,
    );

    let received = timeout(Duration::from_secs(2), server_packets.next())
      .await
      .context("timed out receiving oversized DATAGRAM fallback")?
      .ok_or_else(|| anyhow::anyhow!("server packet stream closed"))?;
    assert_eq!(received, packet);
    assert_eq!(client_packets.stats().reliable_queued, 1);
    assert_eq!(client_packets.stats().datagram_queued, 0);
    assert_eq!(server_packets.stats().received_reliable, 1);
    assert_eq!(client.udp_datagram_stats().sent, 0);

    anyhow::Ok(())
  })
  .await
  .context("oversized DATAGRAM reliable fallback test timed out")?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn reliable_delivery_uses_main_lane_even_when_udp_is_available() -> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let packet = large_test_packet(0x61)?;
    assert!(postcard::to_allocvec(&packet)?.len() <= wait_for_datagram_payload_len(&client).await?);

    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    assert_eq!(
      client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::Reliable)
        .await?,
      QomtPacketSendOutcome::ReliableQueued,
    );

    let received = timeout(Duration::from_secs(2), server_packets.next())
      .await
      .context("timed out receiving explicit reliable packet")?
      .ok_or_else(|| anyhow::anyhow!("server packet stream closed"))?;
    assert_eq!(received, packet);
    assert_eq!(client_packets.stats().reliable_queued, 1);
    assert_eq!(client_packets.stats().datagram_queued, 0);
    assert_eq!(server_packets.stats().received_reliable, 1);
    assert_eq!(client.udp_datagram_stats().sent, 0);

    anyhow::Ok(())
  })
  .await
  .context("explicit reliable QomT packet test timed out")?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn sink_close_drains_accepted_reliable_fallback_frames() -> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(false).await?;
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    let packets = (0..12)
      .map(|sequence| vec![sequence; 4096])
      .collect::<Vec<_>>();
    for packet in &packets {
      client_packets.feed(packet.clone()).await?;
    }

    // close() places a barrier behind all reliable fallback frames and waits
    // for the writer to shutdown. Dropping immediately afterwards must not
    // abort already accepted packets.
    client_packets.close().await?;
    assert!(matches!(
      client_packets
        .send_packet(vec![0xff], QomtPacketDelivery::BestEffort)
        .await,
      Err(crate::udp_forwarder::UdpPacketStreamError::Closed),
    ));
    drop(client_packets);
    assert_eq!(client.datagram_route_count(), 0);

    for expected in packets {
      let received = server_packets
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("packet stream closed before draining accepted frames"))?;
      assert_eq!(received, expected);
    }
    assert!(server_packets.next().await.is_none());
    assert_eq!(server.datagram_route_count(), 0);

    anyhow::Ok(())
  })
  .await
  .context("QomT packet Sink close/drain test timed out")?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn best_effort_packet_falls_back_to_reliable_when_udp_is_disabled() -> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(false).await?;
    assert_eq!(server.udp_state(), QomtUdpState::Disabled);
    assert_eq!(client.udp_state(), QomtUdpState::Disabled);

    let packet = large_test_packet(0x42)?;
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    assert_eq!(
      client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::ReliableQueued,
    );

    let received = timeout(Duration::from_secs(2), server_packets.next())
      .await
      .context("timed out receiving reliable QomT packet fallback")?
      .ok_or_else(|| anyhow::anyhow!("server packet stream closed"))?;
    assert_eq!(received, packet);

    let client_stream_stats = client_packets.stats();
    let server_stream_stats = server_packets.stats();
    assert_eq!(client_stream_stats.reliable_queued, 1);
    assert_eq!(client_stream_stats.datagram_queued, 0);
    assert_eq!(server_stream_stats.received_reliable, 1);
    assert_eq!(server_stream_stats.received_datagram, 0);
    assert_eq!(client.udp_datagram_stats().sent, 0);
    assert_eq!(server.udp_datagram_stats().received, 0);

    anyhow::Ok(())
  })
  .await
  .context("best-effort reliable fallback test timed out")?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn concurrent_packet_associations_are_isolated_and_unregister_on_drop() -> anyhow::Result<()>
{
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let max_payload = wait_for_datagram_payload_len(&client)
      .await?
      .min(wait_for_datagram_payload_len(&server).await?);

    let (mut client_one, mut server_one) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    let (mut client_two, mut server_two) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;
    assert_ne!(client_one.association_id(), client_two.association_id());
    assert_eq!(client_one.association_id(), server_one.association_id());
    assert_eq!(client_two.association_id(), server_two.association_id());
    assert_eq!(client.datagram_route_count(), 2);
    assert_eq!(server.datagram_route_count(), 2);

    let client_one_packet = large_test_packet(0x11)?;
    let server_one_packet = large_test_packet(0x12)?;
    let client_two_packet = large_test_packet(0x21)?;
    let server_two_packet = large_test_packet(0x22)?;
    for packet in [
      &client_one_packet,
      &server_one_packet,
      &client_two_packet,
      &server_two_packet,
    ] {
      assert!(postcard::to_allocvec(packet)?.len() <= max_payload);
    }

    let (client_one_outcome, server_one_outcome, client_two_outcome, server_two_outcome) =
      tokio::try_join!(
        client_one.send_packet(client_one_packet.clone(), QomtPacketDelivery::BestEffort),
        server_one.send_packet(server_one_packet.clone(), QomtPacketDelivery::BestEffort),
        client_two.send_packet(client_two_packet.clone(), QomtPacketDelivery::BestEffort),
        server_two.send_packet(server_two_packet.clone(), QomtPacketDelivery::BestEffort),
      )?;
    assert_eq!(client_one_outcome, QomtPacketSendOutcome::DatagramQueued);
    assert_eq!(server_one_outcome, QomtPacketSendOutcome::DatagramQueued);
    assert_eq!(client_two_outcome, QomtPacketSendOutcome::DatagramQueued);
    assert_eq!(server_two_outcome, QomtPacketSendOutcome::DatagramQueued);

    let (at_server_one, at_client_one, at_server_two, at_client_two) = tokio::try_join!(
      async {
        timeout(Duration::from_secs(2), server_one.next())
          .await
          .context("association one server receive timed out")?
          .ok_or_else(|| anyhow::anyhow!("association one server stream closed"))
      },
      async {
        timeout(Duration::from_secs(2), client_one.next())
          .await
          .context("association one client receive timed out")?
          .ok_or_else(|| anyhow::anyhow!("association one client stream closed"))
      },
      async {
        timeout(Duration::from_secs(2), server_two.next())
          .await
          .context("association two server receive timed out")?
          .ok_or_else(|| anyhow::anyhow!("association two server stream closed"))
      },
      async {
        timeout(Duration::from_secs(2), client_two.next())
          .await
          .context("association two client receive timed out")?
          .ok_or_else(|| anyhow::anyhow!("association two client stream closed"))
      },
    )?;

    assert_eq!(at_server_one, client_one_packet);
    assert_eq!(at_client_one, server_one_packet);
    assert_eq!(at_server_two, client_two_packet);
    assert_eq!(at_client_two, server_two_packet);
    assert_eq!(client_one.stats().received_datagram, 1);
    assert_eq!(server_one.stats().received_datagram, 1);
    assert_eq!(client_two.stats().received_datagram, 1);
    assert_eq!(server_two.stats().received_datagram, 1);

    drop(client_one);
    drop(server_one);
    assert_eq!(client.datagram_route_count(), 1);
    assert_eq!(server.datagram_route_count(), 1);
    drop(client_two);
    drop(server_two);
    assert_eq!(client.datagram_route_count(), 0);
    assert_eq!(server.datagram_route_count(), 0);

    anyhow::Ok(())
  })
  .await
  .context("concurrent QomT packet association test timed out")?
}

/// 对端 UDP 不可达时，后台旁路握手失败/超时不能把本地主连接返回拖到 2s。
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn unavailable_udp_does_not_delay_main_connection() -> anyhow::Result<()> {
  let backend_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
  let backend_address = backend_tcp_listener.local_addr()?;
  let backend_udp_socket = UdpSocket::bind(backend_address).await?;
  let proxy = QomtTestProxy::start(backend_address).await?;
  proxy.set_udp_forwarding(false);

  let [mut server_config, mut client_config] = get_quiche_configs().await?;
  let [server_udp_config, client_udp_config] = get_udp_quiche_configs().await?;

  let ((listener, server), client) = timeout(Duration::from_secs(5), async {
    tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(
          backend_tcp_listener,
          Some(backend_udp_socket),
        );
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;
        anyhow::Ok((listener, connection))
      },
      async {
        qomt_connect(
          &mut client_config,
          Some(client_udp_config),
          proxy.address,
          1,
        )
        .await
      },
    )
  })
  .await
  .context("main QomT connection establishment timed out")??;

  assert_eq!(
    server.udp_state(),
    QomtUdpState::Connecting,
    "qomt_accept must return while the unavailable UDP path is still timing out in the background",
  );

  // 保持 listener 存活并验证主 reliable stream 确实可立即使用。
  let _listener = listener;
  let _proxy = proxy;
  timeout(Duration::from_secs(2), async {
    let mut client_stream = client.open_stream();
    client_stream.write_all(b"main-path").await?;
    client_stream.shutdown().await?;

    let mut server_stream = server
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing main-path stream"))?;
    let mut payload = Vec::new();
    server_stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"main-path");

    anyhow::Ok(())
  })
  .await
  .context("main QomT stream was delayed by unavailable UDP")??;

  Ok(())
}

/// 服务端未开启 UDP listener 时，握手直接协商禁用 UDP 旁路并进入 Disabled。
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn disabled_udp_listener_negotiates_disabled_state_immediately() -> anyhow::Result<()> {
  let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
  let address = tcp_listener.local_addr()?;
  let [mut server_config, mut client_config] = get_quiche_configs().await?;
  let [server_udp_config, client_udp_config] = get_udp_quiche_configs().await?;

  let ((listener, server), client) = timeout(Duration::from_secs(5), async {
    tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, None);
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;
        anyhow::Ok((listener, connection))
      },
      async { qomt_connect(&mut client_config, Some(client_udp_config), address, 1).await },
    )
  })
  .await
  .context("main QomT connection establishment timed out")??;

  assert_eq!(server.udp_state(), QomtUdpState::Disabled);
  assert_eq!(client.udp_state(), QomtUdpState::Disabled);

  let _listener = listener;
  let mut client_stream = client.open_stream();
  client_stream.write_all(b"no-udp").await?;
  client_stream.shutdown().await?;

  let mut server_stream = server
    .accept_stream()
    .await?
    .ok_or_else(|| anyhow::anyhow!("missing no-udp stream"))?;
  let mut payload = Vec::new();
  server_stream.read_to_end(&mut payload).await?;
  assert_eq!(payload, b"no-udp");

  Ok(())
}

/// mTCP 帧格式（u32 大端长度 + 载荷）的往返与边界。
#[tokio::test]
#[test_log::test]
async fn test_packet_frame_roundtrip() -> anyhow::Result<()> {
  let (mut left_write, mut right_read) = duplex(MAX_DATAGRAM_SIZE * 2);

  let payload = vec![0xab; MAX_DATAGRAM_SIZE - 8];

  QuicBytesPacket::write_packet(&mut left_write, payload.clone().into()).await?;
  QuicBytesPacket::write_packet(&mut left_write, vec![].into()).await?;

  // 关闭写端，让读端在缓冲排空后收到 EOF。
  drop(left_write);

  let packet = QuicBytesPacket::read_next_packet(&mut right_read)
    .await?
    .ok_or_else(|| anyhow::anyhow!("missing first packet"))?;

  assert_eq!(&*packet, &payload[..]);

  let empty = QuicBytesPacket::read_next_packet(&mut right_read)
    .await?
    .ok_or_else(|| anyhow::anyhow!("missing empty packet"))?;

  assert!(empty.is_empty());

  // EOF 之后返回 None。
  assert!(
    QuicBytesPacket::read_next_packet(&mut right_read)
      .await?
      .is_none()
  );

  Ok(())
}

/// 超过 MAX_DATAGRAM_SIZE 的帧必须被拒绝，而不是分配大缓冲区。
#[tokio::test]
#[test_log::test]
async fn test_packet_frame_rejects_oversized_length() -> anyhow::Result<()> {
  let (mut left_write, mut right_read) = duplex(MAX_DATAGRAM_SIZE * 2);

  left_write.write_u32((MAX_DATAGRAM_SIZE + 1) as u32).await?;

  let error = QuicBytesPacket::read_next_packet(&mut right_read)
    .await
    .expect_err("oversized frame must be rejected");

  assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

  Ok(())
}

#[tokio::test]
async fn test_packet_frame_rejects_oversized_write() {
  let error = QuicBytesPacket::write_packet(&mut sink(), vec![0; MAX_DATAGRAM_SIZE + 1].into())
    .await
    .expect_err("oversized outgoing frame must be rejected");

  assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn test_packet_frame_reports_truncated_frames() -> anyhow::Result<()> {
  let (mut prefix_writer, mut prefix_reader) = duplex(8);
  prefix_writer.write_all(&[0, 0]).await?;
  drop(prefix_writer);

  let prefix_error = QuicBytesPacket::read_next_packet(&mut prefix_reader)
    .await
    .expect_err("partial length prefix must be rejected");
  assert_eq!(prefix_error.kind(), std::io::ErrorKind::UnexpectedEof);

  let (mut body_writer, mut body_reader) = duplex(8);
  body_writer.write_u32(4).await?;
  body_writer.write_all(&[1, 2]).await?;
  drop(body_writer);

  let body_error = QuicBytesPacket::read_next_packet(&mut body_reader)
    .await
    .expect_err("partial packet body must be rejected");
  assert_eq!(body_error.kind(), std::io::ErrorKind::UnexpectedEof);

  Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn multi_ip_tiered_tcp_and_udp_overflow_and_shared_budget() -> anyhow::Result<()> {
  use crate::{
    mt_connections::{MtListenerBinding, TunnelInterfaceConfig, build_local_interfaces},
    utils::net::{bind_tcp_listener, bind_udp_socket},
  };

  timeout(Duration::from_secs(15), async {
    let server_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1"},
        {"address": "127.0.0.2", "metered": true}
      ]"#,
    )?;
    let server_raw_ifs = build_local_interfaces(server_configs, Some("0.0.0.0:0".parse()?))?;
    let mut bindings = Vec::with_capacity(server_raw_ifs.len());
    let mut bootstrap_addresses = Vec::with_capacity(server_raw_ifs.len());

    for iface in server_raw_ifs {
      let bind_addr = iface.listen_address.unwrap();
      let tcp_listener = bind_tcp_listener(bind_addr, None)?;
      let listen_addr = tcp_listener.local_addr()?;
      let udp_socket = bind_udp_socket(listen_addr, None)?;
      bootstrap_addresses.push(listen_addr);
      bindings.push(MtListenerBinding {
        interface_id: iface.id,
        local_interface: iface.with_resolved_port(listen_addr.port()),
        tcp_listener,
        udp_socket: Some(udp_socket),
      });
    }

    let client_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1", "bandwidth": {"out": "120KB/s"}, "connections_limit": 2},
        {"address": "127.0.0.2", "metered": true, "connections_limit": 2}
      ]"#,
    )?;
    let client_interfaces = build_local_interfaces(client_configs, None)?;
    let tier0_out_limiter = client_interfaces[0]
      .out_limiter
      .clone()
      .ok_or_else(|| anyhow::anyhow!("missing Tier 0 out limiter"))?;

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [server_udp_config, client_udp_config] = get_udp_quiche_configs().await?;

    let ((listener, server), client) = tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::from_bindings(bindings);
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;
        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection = crate::qomt::qomt_connect_with_options(
          &mut client_config,
          Some(client_udp_config),
          &bootstrap_addresses,
          &client_interfaces,
          2,
          QomtUdpReconnectPolicy::default(),
        )
        .await?;
        anyhow::Ok(Arc::new(connection))
      },
    )?;
    let _listener = listener;

    tokio::try_join!(
      wait_for_udp_established(&server),
      wait_for_udp_established(&client),
    )?;
    timeout(Duration::from_secs(5), async {
      loop {
        if client.active_udp_tier_count() == 2 && server.active_udp_tier_count() == 2 {
          return;
        }
        sleep(Duration::from_millis(10)).await;
      }
    })
    .await
    .context("timed out waiting for both UDP tiers to establish")?;
    let _ = wait_for_datagram_payload_len(&client).await?;

    // Send a burst of large (>= UDP_LARGE_PACKET_THRESHOLD) UDP datagrams exceeding Tier 0's
    // 120 KB/s burst (18 KB): early packets charge Tier 0's shared out_limiter and excess
    // overflows to Tier 1 UDP.
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    let expected_packets: Vec<Vec<u8>> = (0..28u8)
      .map(large_test_packet)
      .collect::<anyhow::Result<_>>()?;
    for packet in &expected_packets {
      let outcome = client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?;
      assert_eq!(outcome, QomtPacketSendOutcome::DatagramQueued);
    }

    assert!(
      !tier0_out_limiter.has_budget(std::time::Instant::now()),
      "UDP datagram traffic must debit Tier 0's shared out_limiter",
    );

    let mut received_packets = Vec::with_capacity(expected_packets.len());
    while received_packets.len() < expected_packets.len() {
      let packet = timeout(Duration::from_secs(4), server_packets.next())
        .await
        .context("timed out receiving multi-IP UDP burst")?
        .ok_or_else(|| anyhow::anyhow!("server packet stream closed early"))?;
      received_packets.push(packet);
    }
    received_packets.sort();
    assert_eq!(received_packets, expected_packets);
    assert!(client.udp_datagram_stats().sent >= expected_packets.len() as u64);

    // Send 1.5 MiB over reliable stream; Tier 0 (120 KB/s) alone would take >12s,
    // so completing inside 4s confirms automatic TCP overflow onto metered Tier 1.
    let bulk_payload = vec![0x55u8; 1_536 * 1024];
    let server_recv = server.clone();
    let client_send = client.clone();
    let expected_len = bulk_payload.len();

    let (_, received_bulk) = timeout(Duration::from_secs(4), async {
      tokio::try_join!(
        async move {
          let mut stream = client_send.open_stream();
          stream.write_all(&bulk_payload).await?;
          stream.shutdown().await?;
          anyhow::Ok(())
        },
        async move {
          let mut stream = server_recv
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing bulk reliable stream"))?;
          let mut received = Vec::with_capacity(expected_len);
          stream.read_to_end(&mut received).await?;
          anyhow::Ok(received)
        },
      )
    })
    .await
    .context("bulk multi-IP transfer did not overflow onto Tier 1 in time")??;

    assert_eq!(received_bulk.len(), expected_len);
    assert!(received_bulk.iter().all(|&byte| byte == 0x55));

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn multi_ip_bootstrap_falls_back_when_primary_address_unreachable() -> anyhow::Result<()> {
  use crate::{
    mt_connections::{MtListenerBinding, TunnelInterfaceConfig, build_local_interfaces},
    utils::net::bind_tcp_listener,
  };

  timeout(Duration::from_secs(8), async {
    let dead_listener = TcpListener::bind("127.0.0.1:0").await?;
    let dead_addr = dead_listener.local_addr()?;
    drop(dead_listener);

    let live_configs: Vec<TunnelInterfaceConfig> =
      serde_json::from_str(r#"[{"address": "127.0.0.2", "metered": true}]"#)?;
    let live_ifs = build_local_interfaces(live_configs, Some("0.0.0.0:0".parse()?))?;
    let live_tcp = bind_tcp_listener(live_ifs[0].listen_address.unwrap(), None)?;
    let live_addr = live_tcp.local_addr()?;

    let mut listener =
      MtConnectionsListener::<QuicBytesPacket>::from_bindings(vec![MtListenerBinding {
        interface_id: live_ifs[0].id,
        local_interface: live_ifs[0].with_resolved_port(live_addr.port()),
        tcp_listener: live_tcp,
        udp_socket: None,
      }]);

    let client_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1"},
        {"address": "127.0.0.2", "metered": true}
      ]"#,
    )?;
    let client_interfaces = build_local_interfaces(client_configs, None)?;
    let [mut server_config, mut client_config] = get_quiche_configs().await?;

    let bootstrap_addrs = [dead_addr, live_addr];
    let (server, client) = tokio::try_join!(
      async {
        let mt_connections = listener.accept().await?;
        qomt_accept(&mut server_config, None, mt_connections).await
      },
      crate::qomt::qomt_connect_with_options(
        &mut client_config,
        None,
        &bootstrap_addrs,
        &client_interfaces,
        1,
        QomtUdpReconnectPolicy::default(),
      ),
    )?;

    let mut client_stream = client.open_stream();
    client_stream.write_all(b"fallback-ok").await?;
    client_stream.shutdown().await?;

    let mut server_stream = server
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing fallback stream"))?;
    let mut payload = Vec::new();
    server_stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"fallback-ok");

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn steady_sub_rate_traffic_does_not_spill_to_metered_tier() -> anyhow::Result<()> {
  use crate::{
    mt_connections::{MtListenerBinding, TunnelInterfaceConfig, build_local_interfaces},
    utils::net::bind_tcp_listener,
  };

  timeout(Duration::from_secs(10), async {
    let server_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1"},
        {"address": "127.0.0.2", "metered": true}
      ]"#,
    )?;
    let server_raw_ifs = build_local_interfaces(server_configs, Some("0.0.0.0:0".parse()?))?;
    let mut bindings = Vec::with_capacity(server_raw_ifs.len());
    let mut bootstrap_addresses = Vec::with_capacity(server_raw_ifs.len());

    for iface in server_raw_ifs {
      let tcp_listener = bind_tcp_listener(iface.listen_address.unwrap(), None)?;
      let listen_addr = tcp_listener.local_addr()?;
      bootstrap_addresses.push(listen_addr);
      bindings.push(MtListenerBinding {
        interface_id: iface.id,
        local_interface: iface.with_resolved_port(listen_addr.port()),
        tcp_listener,
        udp_socket: None,
      });
    }

    let client_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1", "bandwidth": {"out": "200KB/s"}, "connections_limit": 2},
        {"address": "127.0.0.2", "metered": true, "connections_limit": 2}
      ]"#,
    )?;
    let client_interfaces = build_local_interfaces(client_configs, None)?;
    let [mut server_config, mut client_config] = get_quiche_configs().await?;

    let mut listener = MtConnectionsListener::<QuicBytesPacket>::from_bindings(bindings);
    let (server, client) = tokio::try_join!(
      async {
        let mt_connections = listener.accept().await?;
        qomt_accept(&mut server_config, None, mt_connections).await
      },
      crate::qomt::qomt_connect_with_options(
        &mut client_config,
        None,
        &bootstrap_addresses,
        &client_interfaces,
        2,
        QomtUdpReconnectPolicy::default(),
      ),
    )?;

    // Let Tier 0 bucket be full and send 6 x 8 KiB (~100 KB/s, below 200 KB/s limit).
    let client = Arc::new(client);
    let server = Arc::new(server);
    let server_recv = server.clone();
    let client_send = client.clone();

    let ((), received) = tokio::try_join!(
      async move {
        let mut stream = client_send.open_stream();
        for chunk_idx in 0..6u8 {
          stream.write_all(&[chunk_idx; 8 * 1024]).await?;
          sleep(Duration::from_millis(80)).await;
        }
        stream.shutdown().await?;
        anyhow::Ok(())
      },
      async move {
        let mut stream = server_recv
          .accept_stream()
          .await?
          .ok_or_else(|| anyhow::anyhow!("missing sub-rate stream"))?;
        let mut buf = Vec::with_capacity(48 * 1024);
        stream.read_to_end(&mut buf).await?;
        anyhow::Ok(buf)
      },
    )?;

    assert_eq!(received.len(), 48 * 1024);
    assert!(client.underlay_group_enqueued_bytes(0) > 48_000);
    assert_eq!(
      client.underlay_group_enqueued_bytes(1),
      0,
      "sub-rate traffic within Tier 0 bandwidth must never spill onto Metered Tier 1",
    );

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn bootstrap_fallback_path_retires_after_negotiated_pair_connects() -> anyhow::Result<()> {
  use crate::{
    mt_connections::{
      BOOTSTRAP_FALLBACK_GROUP_ID, MtListenerBinding, TunnelInterfaceConfig, build_local_interfaces,
    },
    utils::net::bind_tcp_listener,
  };

  timeout(Duration::from_secs(10), async {
    let server_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1", "connections_limit": 2},
        {"address": "127.0.0.2", "metered": true, "connections_limit": 2}
      ]"#,
    )?;
    let server_raw_ifs = build_local_interfaces(server_configs, Some("0.0.0.0:0".parse()?))?;
    let mut bindings = Vec::with_capacity(server_raw_ifs.len());
    let mut server_addrs = Vec::with_capacity(server_raw_ifs.len());

    for iface in server_raw_ifs {
      let tcp_listener = bind_tcp_listener(iface.listen_address.unwrap(), None)?;
      let listen_addr = tcp_listener.local_addr()?;
      server_addrs.push(listen_addr);
      bindings.push(MtListenerBinding {
        interface_id: iface.id,
        local_interface: iface.with_resolved_port(listen_addr.port()),
        tcp_listener,
        udp_socket: None,
      });
    }

    let client_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1", "connections_limit": 2},
        {"address": "127.0.0.2", "metered": true, "connections_limit": 2}
      ]"#,
    )?;
    let client_interfaces = build_local_interfaces(client_configs, None)?;
    let [mut server_config, mut client_config] = get_quiche_configs().await?;

    let mut listener = MtConnectionsListener::<QuicBytesPacket>::from_bindings(bindings);
    // Dial ONLY server[1] (metered) during bootstrap while client[0] is unmetered first:
    // bootstrap lands on (c0 -> s1), which is outside negotiated pairs [(c0->s0), (c1->s1)],
    // so bootstrap_pair_id == None and fallback path 0 must retire once Extend connects.
    let metered_only_bootstrap = [server_addrs[1]];
    let (server, client) = tokio::try_join!(
      async {
        let mt_connections = listener.accept().await?;
        qomt_accept(&mut server_config, None, mt_connections).await
      },
      crate::qomt::qomt_connect_with_options(
        &mut client_config,
        None,
        &metered_only_bootstrap,
        &client_interfaces,
        2,
        QomtUdpReconnectPolicy::default(),
      ),
    )?;

    let underlay = client
      .underlay_metrics
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("missing client underlay metrics"))?
      .clone();

    timeout(Duration::from_secs(5), async {
      loop {
        if underlay.available_path_count_in_group(0) >= 1
          && underlay.available_path_count_in_group(BOOTSTRAP_FALLBACK_GROUP_ID) == 0
        {
          return;
        }
        sleep(Duration::from_millis(10)).await;
      }
    })
    .await
    .context("bootstrap fallback path did not retire after negotiated pair connected")?;

    let mut client_stream = client.open_stream();
    client_stream.write_all(b"after-fallback-retire").await?;
    client_stream.shutdown().await?;

    let mut server_stream = server
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing stream after fallback retirement"))?;
    let mut payload = Vec::new();
    server_stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"after-fallback-retire");

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn asymmetric_udp_config_negotiates_disabled_cleanly() -> anyhow::Result<()> {
  for client_has_udp in [false, true] {
    let server_has_udp = !client_has_udp;
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp_listener.local_addr()?;
    let udp_socket = if server_has_udp {
      Some(UdpSocket::bind(address).await?)
    } else {
      None
    };

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [server_udp_cfg, client_udp_cfg] = get_udp_quiche_configs().await?;

    let ((_listener, server), client) = timeout(Duration::from_secs(5), async {
      tokio::try_join!(
        async {
          let mut listener =
            MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, udp_socket);
          let mt_connections = listener.accept().await?;
          let connection = qomt_accept(
            &mut server_config,
            server_has_udp.then_some(server_udp_cfg),
            mt_connections,
          )
          .await?;
          anyhow::Ok((listener, connection))
        },
        async {
          qomt_connect(
            &mut client_config,
            client_has_udp.then_some(client_udp_cfg),
            address,
            1,
          )
          .await
        },
      )
    })
    .await??;

    assert_eq!(server.udp_state(), QomtUdpState::Disabled);
    assert_eq!(client.udp_state(), QomtUdpState::Disabled);
  }

  Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn dual_stack_client_against_implicit_ipv4_server_creates_no_v6_mismatch()
-> anyhow::Result<()> {
  use crate::mt_connections::{TunnelInterfaceConfig, build_local_interfaces};

  timeout(Duration::from_secs(8), async {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp_listener.local_addr()?;
    let udp_socket = UdpSocket::bind(address).await?;

    let client_configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1"},
        {"address": "::1"}
      ]"#,
    )?;
    let client_interfaces = build_local_interfaces(client_configs, None)?;

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [server_udp_config, client_udp_config] = get_udp_quiche_configs().await?;

    let bootstrap = [address];
    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener =
          MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, Some(udp_socket));
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;
        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection = crate::qomt::qomt_connect_with_options(
          &mut client_config,
          Some(client_udp_config),
          &bootstrap,
          &client_interfaces,
          2,
          QomtUdpReconnectPolicy::default(),
        )
        .await?;
        anyhow::Ok(Arc::new(connection))
      },
    )?;

    tokio::try_join!(
      wait_for_udp_established(&server),
      wait_for_udp_established(&client),
    )?;

    let mut client_stream = client.open_stream();
    client_stream.write_all(b"v4-only-server").await?;
    client_stream.shutdown().await?;

    let mut server_stream = server
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing v4-only stream"))?;
    let mut payload = Vec::new();
    server_stream.read_to_end(&mut payload).await?;
    assert_eq!(payload, b"v4-only-server");

    anyhow::Ok(())
  })
  .await?
}

/// Regression test for the production QomT send wedge (`cid=0642344cd5f6` /
/// `cid=97445826450b`): over multi-TCP reliable transport (`set_reliable_transport(true)`),
/// mixing bidirectional bulk streams with bursty small interactive streams must
/// never invert QUIC packet numbers within any TCP connection's `ReliableRecv`
/// domain, drop packets silently, or wedge `cwnd` / `uncreated_streams`.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn multipath_reliable_qomt_mixed_bulk_and_interactive_streams_never_wedge()
-> anyhow::Result<()> {
  timeout(Duration::from_secs(15), async {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    let mut _proxy_tasks = JoinSet::new();
    _proxy_tasks.spawn(async move {
      let mut relay_set = JoinSet::new();

      while let Ok((inbound, _)) = proxy_listener.accept().await {
        let Ok(outbound) = TcpStream::connect(backend_addr).await else {
          break;
        };
        let _ = inbound.set_nodelay(true);
        let _ = outbound.set_nodelay(true);

        let (in_r, in_w) = inbound.into_split();
        let (out_r, out_w) = outbound.into_split();

        let pace_copy = |mut reader: tokio::net::tcp::OwnedReadHalf,
                         mut writer: tokio::net::tcp::OwnedWriteHalf| async move {
          let mut buf = vec![0u8; 8192];

          loop {
            let Ok(n) = reader.read(&mut buf).await else {
              break;
            };
            if n == 0 {
              let _ = writer.shutdown().await;
              break;
            }
            if n >= 4096 {
              sleep(Duration::from_millis(2)).await;
            }
            if writer.write_all(&buf[..n]).await.is_err() {
              break;
            }
          }
        };

        relay_set.spawn(pace_copy(in_r, out_w));
        relay_set.spawn(pace_copy(out_r, in_w));
      }
    });

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    server_config.set_reliable_transport(true);
    client_config.set_reliable_transport(true);

    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(backend_listener, None);
        let mt_connections = listener.accept().await?;
        let connection = qomt_accept(&mut server_config, None, mt_connections).await?;

        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection = qomt_connect(&mut client_config, None, proxy_addr, 4).await?;

        anyhow::Ok(Arc::new(connection))
      },
    )?;

    sleep(Duration::from_millis(80)).await;

    const UPSTREAM_BULK_STREAMS: usize = 2;
    const DOWNSTREAM_BULK_STREAMS: usize = 2;
    const BULK_BYTES_PER_STREAM: usize = 512 * 1024;
    const INTERACTIVE_STREAMS: usize = 32;
    const TOTAL_EXPECTED_STREAMS: usize =
      UPSTREAM_BULK_STREAMS + DOWNSTREAM_BULK_STREAMS + INTERACTIVE_STREAMS;

    let server_driver = {
      let server = server.clone();

      tokio::spawn(async move {
        let mut handlers = JoinSet::new();

        for _ in 0..TOTAL_EXPECTED_STREAMS {
          let mut stream = server
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("server closed before accepting all streams"))?;

          handlers.spawn(async move {
            let tag = stream.read_u8().await?;

            match tag {
              b'U' => {
                let mut total = 0usize;
                let mut buf = vec![0u8; 16 * 1024];
                while total < BULK_BYTES_PER_STREAM {
                  let n = stream.read(&mut buf).await?;
                  anyhow::ensure!(n > 0, "upstream bulk stream truncated at {total} bytes");
                  total += n;
                }
                stream.write_all(b"OK-UP").await?;
                stream.shutdown().await?;
              }
              b'D' => {
                let seed = stream.read_u8().await?;
                let chunk = vec![seed; 16 * 1024];
                let mut sent = 0usize;
                while sent < BULK_BYTES_PER_STREAM {
                  let to_send = (BULK_BYTES_PER_STREAM - sent).min(chunk.len());
                  stream.write_all(&chunk[..to_send]).await?;
                  sent += to_send;
                }
                stream.shutdown().await?;
              }
              b'I' => {
                let seq = stream.read_u32().await?;
                let mut req = [0u8; 128];
                stream.read_exact(&mut req).await?;
                stream.write_u32(seq).await?;
                stream.write_all(&req[..32]).await?;
                stream.shutdown().await?;
              }
              other => anyhow::bail!("unexpected stream tag: {other}"),
            }

            anyhow::Ok(())
          });
        }

        while let Some(res) = handlers.join_next().await {
          res??;
        }

        anyhow::Ok(())
      })
    };

    let bulk_driver = {
      let client = client.clone();

      async move {
        let mut set = JoinSet::new();

        for stream_idx in 0..UPSTREAM_BULK_STREAMS {
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            stream.write_u8(b'U').await?;
            let chunk = vec![(stream_idx as u8).wrapping_add(0x30); 16 * 1024];
            let mut sent = 0usize;
            while sent < BULK_BYTES_PER_STREAM {
              let to_send = (BULK_BYTES_PER_STREAM - sent).min(chunk.len());
              stream.write_all(&chunk[..to_send]).await?;
              sent += to_send;
            }
            stream.shutdown().await?;

            let mut ack = [0u8; 5];
            stream.read_exact(&mut ack).await?;
            anyhow::ensure!(&ack == b"OK-UP");
            anyhow::Ok(())
          });
        }

        for stream_idx in 0..DOWNSTREAM_BULK_STREAMS {
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            let seed = (stream_idx as u8).wrapping_add(0x60);
            stream.write_u8(b'D').await?;
            stream.write_u8(seed).await?;
            stream.shutdown().await?;

            let mut total = 0usize;
            let mut buf = vec![0u8; 16 * 1024];
            while total < BULK_BYTES_PER_STREAM {
              let n = stream.read(&mut buf).await?;
              anyhow::ensure!(n > 0, "downstream bulk stream truncated at {total} bytes");
              anyhow::ensure!(buf[..n].iter().all(|&b| b == seed));
              total += n;
            }
            anyhow::Ok(())
          });
        }

        while let Some(res) = set.join_next().await {
          res??;
        }

        anyhow::Ok(())
      }
    };

    let interactive_driver = {
      let client = client.clone();

      async move {
        let mut set = JoinSet::new();

        for seq in 0..(INTERACTIVE_STREAMS as u32) {
          sleep(Duration::from_millis(4)).await;
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            stream.write_u8(b'I').await?;
            stream.write_u32(seq).await?;
            let payload = [seq as u8 ^ 0x5a; 128];
            stream.write_all(&payload).await?;
            stream.shutdown().await?;

            let echoed_seq = stream.read_u32().await?;
            let mut echoed = [0u8; 32];
            stream.read_exact(&mut echoed).await?;
            anyhow::ensure!(echoed_seq == seq);
            anyhow::ensure!(echoed == payload[..32]);
            anyhow::Ok(())
          });
        }

        while let Some(res) = set.join_next().await {
          res??;
        }

        anyhow::Ok(())
      }
    };

    let workload_result = timeout(Duration::from_secs(8), async {
      let (_, _) = tokio::try_join!(bulk_driver, interactive_driver)?;
      server_driver.await??;
      anyhow::Ok(())
    })
    .await;

    let client_diag = client.diagnostics();
    let server_diag = server.diagnostics();
    if let Err(err) = workload_result {
      anyhow::bail!(
        "mixed workload wedged ({err});\n  client={client_diag}\n  server={server_diag}"
      );
    }

    for (label, diag) in [("client", &client_diag), ("server", &server_diag)] {
      anyhow::ensure!(
        diag.contains("uncreated_streams=0 ")
          && diag.contains("quic_lost_packets=0 ")
          && diag.contains("quic_retrans_packets=0 "),
        "{label} experienced unexpected loss or uncreated streams: {diag}",
      );
    }

    anyhow::Ok(())
  })
  .await?
}

/// Verifies that if a sibling TCP connection drops mid-transfer while out-of-order
/// express packets and bulk packets are concurrently in flight, `MtConnections`
/// fails any stranded reliable packets and `QuicConnection` recovers cleanly
/// without wedging.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn multipath_reliable_qomt_recovers_when_sibling_tcp_drops_mid_reorder()
-> anyhow::Result<()> {
  timeout(Duration::from_secs(15), async {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy_listener.local_addr()?;

    let accepted_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dropped_paths = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut _proxy_tasks = JoinSet::new();
    _proxy_tasks.spawn({
      let accepted_count = accepted_count.clone();
      let dropped_paths = dropped_paths.clone();

      async move {
        let mut relay_set = JoinSet::new();

        while let Ok((inbound, _)) = proxy_listener.accept().await {
          let Ok(outbound) = TcpStream::connect(backend_addr).await else {
            break;
          };
          let _ = inbound.set_nodelay(true);
          let _ = outbound.set_nodelay(true);

          let path_num = accepted_count.fetch_add(1, Ordering::AcqRel);
          let dropped_paths = dropped_paths.clone();
          let (mut in_r, mut in_w) = inbound.into_split();
          let (mut out_r, mut out_w) = outbound.into_split();

          relay_set.spawn(async move {
            let mut buf = vec![0u8; 8192];
            let mut forwarded = 0usize;

            loop {
              let Ok(n) = in_r.read(&mut buf).await else {
                break;
              };
              if n == 0 {
                let _ = out_w.shutdown().await;
                break;
              }
              if n >= 4096 {
                sleep(Duration::from_millis(3)).await;
              }
              forwarded += n;
              // Abruptly drop two bulk mTCP paths mid-transfer while mixed packets queue.
              if path_num < 4 && forwarded > 128 * 1024 {
                let mut current = dropped_paths.load(Ordering::Acquire);
                let mut claimed = false;
                while current < 2 {
                  match dropped_paths.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                  ) {
                    Ok(_) => {
                      claimed = true;
                      break;
                    }
                    Err(actual) => current = actual,
                  }
                }
                if claimed {
                  break;
                }
              }
              if out_w.write_all(&buf[..n]).await.is_err() {
                break;
              }
            }
          });

          relay_set.spawn(async move {
            let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
            let _ = in_w.shutdown().await;
          });
        }
      }
    });

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    server_config.set_reliable_transport(true);
    client_config.set_reliable_transport(true);

    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(backend_listener, None);
        let mt_connections = listener.accept().await?;
        let connection = qomt_accept(&mut server_config, None, mt_connections).await?;

        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection = qomt_connect(&mut client_config, None, proxy_addr, 4).await?;

        anyhow::Ok(Arc::new(connection))
      },
    )?;

    sleep(Duration::from_millis(80)).await;

    const BULK_STREAMS: usize = 3;
    const BULK_BYTES: usize = 384 * 1024;
    const INTERACTIVE_STREAMS: usize = 24;

    let server_driver = {
      let server = server.clone();

      tokio::spawn(async move {
        let mut handlers = JoinSet::new();

        for _ in 0..(BULK_STREAMS + INTERACTIVE_STREAMS) {
          let mut stream = server
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("server closed prematurely"))?;

          handlers.spawn(async move {
            match stream.read_u8().await? {
              b'B' => {
                let mut total = 0usize;
                let mut buf = vec![0u8; 16 * 1024];
                while total < BULK_BYTES {
                  let n = stream.read(&mut buf).await?;
                  anyhow::ensure!(n > 0, "bulk truncated at {total}");
                  total += n;
                }
                stream.write_all(b"DONE").await?;
                stream.shutdown().await?;
              }
              b'I' => {
                let id = stream.read_u32().await?;
                stream.write_u32(id ^ 0xa5a5_5a5a).await?;
                stream.shutdown().await?;
              }
              other => anyhow::bail!("unexpected tag {other}"),
            }

            anyhow::Ok(())
          });
        }

        while let Some(res) = handlers.join_next().await {
          res??;
        }

        anyhow::Ok(())
      })
    };

    let client_work = async {
      let bulk = async {
        let mut set = JoinSet::new();
        for idx in 0..BULK_STREAMS {
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            stream.write_u8(b'B').await?;
            let chunk = vec![0x41 + idx as u8; 16 * 1024];
            let mut sent = 0usize;
            while sent < BULK_BYTES {
              let n = (BULK_BYTES - sent).min(chunk.len());
              stream.write_all(&chunk[..n]).await?;
              sent += n;
            }
            stream.shutdown().await?;
            let mut done = [0u8; 4];
            stream.read_exact(&mut done).await?;
            anyhow::ensure!(&done == b"DONE");
            anyhow::Ok(())
          });
        }
        while let Some(res) = set.join_next().await {
          res??;
        }
        anyhow::Ok(())
      };

      let interactive = async {
        let mut set = JoinSet::new();
        for id in 0..(INTERACTIVE_STREAMS as u32) {
          sleep(Duration::from_millis(5)).await;
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            stream.write_u8(b'I').await?;
            stream.write_u32(id).await?;
            stream.shutdown().await?;
            let reply = stream.read_u32().await?;
            anyhow::ensure!(reply == (id ^ 0xa5a5_5a5a));
            anyhow::Ok(())
          });
        }
        while let Some(res) = set.join_next().await {
          res??;
        }
        anyhow::Ok(())
      };

      let (_, _) = tokio::try_join!(bulk, interactive)?;
      server_driver.await??;
      anyhow::Ok(())
    };

    timeout(Duration::from_secs(10), client_work)
      .await
      .with_context(|| {
        format!(
          "recovery wedged after sibling TCP drop;\n  client={}\n  server={}",
          client.diagnostics(),
          server.diagnostics()
        )
      })??;

    let client_diag = client.diagnostics();
    anyhow::ensure!(
      dropped_paths.load(Ordering::Acquire) == 2,
      "expected both victim TCP paths to drop mid-flight",
    );
    anyhow::ensure!(
      !client_diag.contains("quic_lost_packets=0 ") && client_diag.contains("uncreated_streams=0 "),
      "expected reliable loss recovery with zero wedged streams: {client_diag}",
    );

    anyhow::Ok(())
  })
  .await?
}

/// Reproduces the `meian-hub -> LA` residential uplink saturation scenario:
/// 5 mTCP connections share a single `~4 Mbps` (`512 KiB/s`) upstream bottleneck
/// saturated by continuous bulk uploads (starting cold with `small_activity == 0`
/// and queue ages exceeding `HEADROOM_STALL_FALLBACK = 100ms`). Interactive
/// `RESOLVE`-sized (`48 B`) bidirectional streams must cut ahead on the clean
/// express path (`rank = 0`) without multi-hundred-millisecond HOL queueing.
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn multipath_qomt_preserves_express_lane_under_saturated_low_bandwidth_uplink()
-> anyhow::Result<()> {
  timeout(Duration::from_secs(20), async {
    const UPLINK_BYTES_PER_SEC: f64 = 512.0 * 1024.0;
    const PROXY_CHUNK_BYTES: usize = 4096;

    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_listener.local_addr()?;

    let proxy_sock = socket2::Socket::new(
      socket2::Domain::IPV4,
      socket2::Type::STREAM,
      Some(socket2::Protocol::TCP),
    )?;
    proxy_sock.set_nonblocking(true)?;
    proxy_sock.set_recv_buffer_size(4096)?;
    proxy_sock.bind(&"127.0.0.1:0".parse::< std::net::SocketAddr >()?.into())?;
    proxy_sock.listen(128)?;
    let proxy_listener = TcpListener::from_std(proxy_sock.into())?;
    let proxy_addr = proxy_listener.local_addr()?;

    let uplink_gate = Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let mut _proxy_tasks = JoinSet::new();
    _proxy_tasks.spawn({
      let uplink_gate = uplink_gate.clone();

      async move {
        let mut relay_set = JoinSet::new();

        while let Ok((inbound, _)) = proxy_listener.accept().await {
          let Ok(outbound) = TcpStream::connect(backend_addr).await else {
            break;
          };
          let _ = inbound.set_nodelay(true);
          let _ = outbound.set_nodelay(true);
          let sock = socket2::SockRef::from(&inbound);
          let _ = sock.set_recv_buffer_size(4096);

          let uplink_gate = uplink_gate.clone();
          let (mut in_r, mut in_w) = inbound.into_split();
          let (mut out_r, mut out_w) = outbound.into_split();

          relay_set.spawn(async move {
            let mut buf = vec![0u8; PROXY_CHUNK_BYTES];

            loop {
              let Ok(n) = in_r.read(&mut buf).await else {
                break;
              };
              if n == 0 {
                let _ = out_w.shutdown().await;
                break;
              }

              {
                let mut next_free = uplink_gate.lock().await;
                let now = Instant::now();
                if *next_free > now {
                  tokio::time::sleep_until(*next_free).await;
                }
                let wire_time = Duration::from_secs_f64((n as f64) / UPLINK_BYTES_PER_SEC);
                *next_free = Instant::now() + wire_time;
              }

              if out_w.write_all(&buf[..n]).await.is_err() {
                break;
              }
            }
          });

          relay_set.spawn(async move {
            let _ = tokio::io::copy(&mut out_r, &mut in_w).await;
            let _ = in_w.shutdown().await;
          });
        }
      }
    });

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    server_config.set_reliable_transport(true);
    client_config.set_reliable_transport(true);

    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(backend_listener, None);
        let mt_connections = listener.accept().await?;
        let connection = qomt_accept(&mut server_config, None, mt_connections).await?;

        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection = qomt_connect(&mut client_config, None, proxy_addr, 5).await?;

        anyhow::Ok(Arc::new(connection))
      },
    )?;

    sleep(Duration::from_millis(100)).await;

    const BULK_STREAMS: usize = 3;
    const BULK_BYTES_PER_STREAM: usize = 384 * 1024;
    const INTERACTIVE_PROBES: usize = 16;

    let test_epoch = std::time::Instant::now();
    let srv_arrivals = Arc::new(Mutex::new(vec![0.0_f64; INTERACTIVE_PROBES]));
    let server_driver = {
      let server = server.clone();
      let srv_arrivals = srv_arrivals.clone();

      tokio::spawn(async move {
        let mut handlers = JoinSet::new();

        for _ in 0..(BULK_STREAMS + INTERACTIVE_PROBES) {
          let mut stream = server
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("server closed before accepting all streams"))?;
          let srv_arrivals = srv_arrivals.clone();

          handlers.spawn(async move {
            match stream.read_u8().await? {
              b'B' => {
                let mut total = 0usize;
                let mut buf = vec![0u8; 16 * 1024];
                while total < BULK_BYTES_PER_STREAM {
                  let n = stream.read(&mut buf).await?;
                  anyhow::ensure!(n > 0, "bulk stream truncated at {total}");
                  total += n;
                }
                stream.write_all(b"OK").await?;
                stream.shutdown().await?;
              }
              b'R' => {
                let id = stream.read_u32().await?;
                let mut query = [0u8; 43];
                stream.read_exact(&mut query).await?;
                srv_arrivals.lock().unwrap()[id as usize] =
                  test_epoch.elapsed().as_secs_f64() * 1000.0;
                stream.write_u32(id).await?;
                stream.write_all(&query[..16]).await?;
                stream.shutdown().await?;
              }
              other => anyhow::bail!("unexpected stream tag {other}"),
            }

            anyhow::Ok(())
          });
        }

        while let Some(res) = handlers.join_next().await {
          res??;
        }

        anyhow::Ok(())
      })
    };

    let bulk_driver = {
      let client = client.clone();

      async move {
        let mut set = JoinSet::new();
        for idx in 0..BULK_STREAMS {
          let client = client.clone();
          set.spawn(async move {
            let mut stream = client.open_stream();
            stream.write_u8(b'B').await?;
            let chunk = vec![0x30 + idx as u8; 16 * 1024];
            let mut sent = 0usize;
            while sent < BULK_BYTES_PER_STREAM {
              let n = (BULK_BYTES_PER_STREAM - sent).min(chunk.len());
              stream.write_all(&chunk[..n]).await?;
              sent += n;
            }
            stream.shutdown().await?;
            let mut ok = [0u8; 2];
            stream.read_exact(&mut ok).await?;
            anyhow::ensure!(&ok == b"OK");
            anyhow::Ok(())
          });
        }

        while let Some(res) = set.join_next().await {
          res??;
        }
        anyhow::Ok(())
      }
    };

    let interactive_driver = {
      let client = client.clone();

      async move {
        // Let pure bulk saturate the 512 KiB/s uplink for 350ms (> 3x HEADROOM_STALL_FALLBACK)
        // with zero prior interactive activity (cold start).
        sleep(Duration::from_millis(350)).await;

        let mut rtts_ms = Vec::with_capacity(INTERACTIVE_PROBES);
        let mut traces = Vec::with_capacity(INTERACTIVE_PROBES);
        for probe_id in 0..(INTERACTIVE_PROBES as u32) {
          if probe_id % 4 == 0 && probe_id > 0 {
            sleep(Duration::from_millis(60)).await;
          }
          let t0_ms = test_epoch.elapsed().as_secs_f64() * 1000.0;
          let started = std::time::Instant::now();
          let mut stream = client.open_stream();
          stream.write_u8(b'R').await?;
          stream.write_u32(probe_id).await?;
          let query = [probe_id as u8 ^ 0x3c; 43];
          stream.write_all(&query).await?;
          stream.shutdown().await?;
          let write_ms = started.elapsed().as_secs_f64() * 1000.0;

          let echoed_id = stream.read_u32().await?;
          let mut answer = [0u8; 16];
          stream.read_exact(&mut answer).await?;
          anyhow::ensure!(echoed_id == probe_id);
          anyhow::ensure!(answer == query[..16]);
          let total_ms = started.elapsed().as_secs_f64() * 1000.0;
          let up_ms = srv_arrivals.lock().unwrap()[probe_id as usize] - t0_ms;
          traces.push(format!(
            "#{probe_id}:w={write_ms:.1}/up={up_ms:.1}/tot={total_ms:.1}"
          ));
          rtts_ms.push(total_ms);
        }

        rtts_ms.sort_by(f64::total_cmp);
        let median_ms = rtts_ms[rtts_ms.len() / 2];
        let p90_ms = rtts_ms[(rtts_ms.len() * 9) / 10];
        let max_ms = *rtts_ms.last().unwrap();

        anyhow::ensure!(
          median_ms < 80.0 && p90_ms < 150.0 && max_ms < 250.0,
          "interactive RESOLVE probes suffered upstream HOL bloat on saturated 4 Mbps uplink: \
           median={median_ms:.1}ms p90={p90_ms:.1}ms max={max_ms:.1}ms traces={traces:?}",
        );

        anyhow::Ok(())
      }
    };

    let (_, _) = tokio::try_join!(bulk_driver, interactive_driver)?;
    server_driver.await??;

    for (label, diag) in [("client", client.diagnostics()), ("server", server.diagnostics())] {
      anyhow::ensure!(
        diag.contains("uncreated_streams=0 "),
        "{label} reported uncreated_streams in diagnostics: {diag}",
      );
    }

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn udp_bypass_carries_negotiated_resolve_streams_with_legacy_and_blackhole_fallback()
-> anyhow::Result<()> {
  use crate::{
    node::{NodeMessageToOut, NodeOutDispatcher, NodeResolveAnswers, OutDispatcher, ResolveQuery},
    primitives::{OutExit, OutExits},
    utils::postcard::postcard_read_stream,
  };

  timeout(Duration::from_secs(12), async {
    // 1. Legacy server (`p2p` ALPN only) still establishes QomT UDP for datagrams,
    //    while `try_open_udp_stream()` cleanly declines UDP streams.
    {
      let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
      let address = tcp_listener.local_addr()?;
      let udp_socket = UdpSocket::bind(address).await?;
      let [mut server_config, mut client_config] = get_quiche_configs().await?;
      let [mut legacy_server_udp_cfg, client_udp_cfg] = get_udp_quiche_configs().await?;
      legacy_server_udp_cfg.set_application_protos(&[b"p2p"])?;

      let ((_listener, _server), client) = tokio::try_join!(
        async {
          let mut listener =
            MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, Some(udp_socket));
          let mt_connections = listener.accept().await?;
          let connection =
            qomt_accept(&mut server_config, Some(legacy_server_udp_cfg), mt_connections).await?;
          anyhow::Ok((listener, connection))
        },
        qomt_connect(&mut client_config, Some(client_udp_cfg), address, 2),
      )?;

      timeout(Duration::from_secs(3), async {
        while client.udp_state() != QomtUdpState::Established {
          sleep(Duration::from_millis(10)).await;
        }
      })
      .await?;
      assert!(client.try_open_udp_stream().is_none());
    }

    // 2. Upgraded peers (`p2p-s`) route `NodeOutDispatcher::resolve` over QomT UDP
    //    with zero mTCP bytes, and fall back to mTCP if UDP silently blackholes.
    let backend_tcp = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_tcp.local_addr()?;
    let backend_udp = UdpSocket::bind(backend_addr).await?;
    let proxy = QomtTestProxy::start(backend_addr).await?;

    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [server_udp_cfg, client_udp_cfg] = get_udp_quiche_configs().await?;

    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener =
          MtConnectionsListener::<QuicBytesPacket>::new(backend_tcp, Some(backend_udp));
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_cfg), mt_connections).await?;
        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection =
          qomt_connect(&mut client_config, Some(client_udp_cfg), proxy.address, 2).await?;
        anyhow::Ok(Arc::new(connection))
      },
    )?;

    timeout(Duration::from_secs(3), async {
      while client.udp_state() != QomtUdpState::Established
        || server.udp_state() != QomtUdpState::Established
      {
        sleep(Duration::from_millis(10)).await;
      }
    })
    .await?;

    let seen_udp_flags = Arc::new(Mutex::new(Vec::<bool>::new()));
    let server_task = tokio::spawn({
      let server = server.clone();
      let seen_udp_flags = seen_udp_flags.clone();
      async move {
        while let Ok(Some(mut stream)) = server.accept_stream().await {
          let seen_udp_flags = seen_udp_flags.clone();
          tokio::spawn(async move {
            let is_udp = stream.is_udp_bypass();
            let Ok(NodeMessageToOut::Resolve(_, query)) =
              postcard_read_stream::<NodeMessageToOut>(&mut stream).await
            else {
              return;
            };
            seen_udp_flags.lock().unwrap().push(is_udp);
            let answer = NodeResolveAnswers::Success(query.name.into_bytes());
            let _ = stream
              .write_all(&postcard::to_allocvec(&answer).unwrap())
              .await;
            let _ = stream.shutdown().await;
          });
        }
      }
    });

    let exits = OutExits::new([OutExit::Proxy, OutExit::from("us")]);
    let dispatcher = NodeOutDispatcher::new(exits, client.clone());
    let query = ResolveQuery {
      name: "api.x.com.".to_owned(),
      record_type: 1,
    };

    let mtcp_bytes_before = client.underlay_group_enqueued_bytes(0);
    let answer1 = dispatcher
      .resolve(OutExit::from("us"), &query)
      .await?;
    assert!(matches!(
      answer1,
      NodeResolveAnswers::Success(ref bytes) if bytes == b"api.x.com."
    ));
    assert_eq!(
      client.underlay_group_enqueued_bytes(0),
      mtcp_bytes_before,
      "RESOLVE over Established QomT UDP must enqueue 0 bytes on mTCP",
    );
    assert_eq!(&*seen_udp_flags.lock().unwrap(), &[true]);

    // Silently blackhole UDP mid-session (before QOMT_UDP_IDLE_TIMEOUT expires):
    // next RESOLVE must time out its UDP attempt and succeed over mTCP!
    proxy.forward_client_udp.store(false, Ordering::Release);
    let fallback_query = ResolveQuery {
      name: "youtubei.googleapis.com.".to_owned(),
      record_type: 1,
    };
    let answer2 = dispatcher
      .resolve(OutExit::from("us"), &fallback_query)
      .await?;
    assert!(matches!(
      answer2,
      NodeResolveAnswers::Success(ref bytes) if bytes == b"youtubei.googleapis.com."
    ));
    assert!(client.underlay_group_enqueued_bytes(0) > mtcp_bytes_before);
    assert_eq!(&*seen_udp_flags.lock().unwrap(), &[true, false]);

    server_task.abort();
    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn high_burst_best_effort_datagrams_deliver_without_internal_queue_drops()
-> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let max_payload = wait_for_datagram_payload_len(&client).await?;

    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    const BURST_PACKETS: usize = 200;
    let mut expected = Vec::with_capacity(BURST_PACKETS);

    // Queue an entire 200-packet (~240 KiB) video-chunk-style burst before
    // draining the receiver stream: initial packets fit within QomT UDP's safe
    // headroom while excess packets proactively spill onto mTCP without queue
    // bloat or dropped packets.
    let mut datagram_count = 0_usize;
    let mut reliable_count = 0_usize;
    for index in 0..BURST_PACKETS {
      let mut packet = large_test_packet((index & 0xff) as u8)?;
      packet[0..2].copy_from_slice(&(index as u16).to_be_bytes());
      assert!(postcard::to_allocvec(&packet)?.len() <= max_payload);

      match client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?
      {
        QomtPacketSendOutcome::DatagramQueued => datagram_count += 1,
        QomtPacketSendOutcome::ReliableQueued => reliable_count += 1,
        other => anyhow::bail!("unexpected packet send outcome: {other:?}"),
      }
      expected.push(packet);
    }

    assert!(datagram_count > 0);
    assert!(
      reliable_count > 0,
      "240 KiB synchronous burst must spill excess onto mTCP rather than stuffing UDP queue",
    );

    let mut received = Vec::with_capacity(BURST_PACKETS);
    while received.len() < BURST_PACKETS {
      let packet = timeout(Duration::from_secs(5), server_packets.next())
        .await
        .context("timed out draining 200-packet QomT burst")?
        .ok_or_else(|| anyhow::anyhow!("server packet stream closed early"))?;
      received.push(packet);
    }

    received.sort();
    expected.sort();
    assert_eq!(received, expected);

    let client_stream_stats = client_packets.stats();
    let server_stream_stats = server_packets.stats();
    let server_dgram_stats = server.udp_datagram_stats();

    assert_eq!(client_stream_stats.dropped_udp_queue_full, 0);
    assert_eq!(client_stream_stats.dropped_reliable_queue_full, 0);
    assert_eq!(server_stream_stats.dropped_incoming_datagram_queue_full, 0);
    assert_eq!(server_dgram_stats.dropped_receive_queue_full, 0);
    assert_eq!(
      server_stream_stats.received_datagram + server_stream_stats.received_reliable,
      BURST_PACKETS as u64,
    );

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn mixed_size_best_effort_packets_stay_coherent_and_offload_to_mtcp_when_udp_bottlenecks()
-> anyhow::Result<()> {
  timeout(Duration::from_secs(12), async {
    let backend_tcp = TcpListener::bind("127.0.0.1:0").await?;
    let backend_addr = backend_tcp.local_addr()?;
    let backend_udp = UdpSocket::bind(backend_addr).await?;
    let proxy = QomtTestProxy::start(backend_addr).await?;
    let [mut server_config, mut client_config] = get_quiche_configs().await?;
    let [server_udp_config, mut client_udp_config] = get_udp_quiche_configs().await?;
    client_udp_config.enable_dgram(true, 1024, 2);

    let ((_listener, server), client) = tokio::try_join!(
      async {
        let mut listener =
          MtConnectionsListener::<QuicBytesPacket>::new(backend_tcp, Some(backend_udp));
        let mt_connections = listener.accept().await?;
        let connection =
          qomt_accept(&mut server_config, Some(server_udp_config), mt_connections).await?;
        anyhow::Ok((listener, Arc::new(connection)))
      },
      async {
        let connection =
          qomt_connect(&mut client_config, Some(client_udp_config), proxy.address, 2).await?;
        anyhow::Ok(Arc::new(connection))
      },
    )?;

    let _ = wait_for_datagram_payload_len(&client).await?;
    let (mut client_packets, mut server_packets) =
      open_test_packet_stream_pair(client.clone(), server.clone()).await?;

    // 1. Healthy UDP within safe headroom: both `< 1024 B` (0-RTT-sized) and
    //    `>= 1024 B` (Initial-sized) packets stay on the same QomT UDP lane.
    let small_packet = vec![0x11; 160];
    let large_packet = large_test_packet(0x22)?;
    assert_eq!(
      client_packets
        .send_packet(large_packet.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );
    assert_eq!(
      client_packets
        .send_packet(small_packet.clone(), QomtPacketDelivery::BestEffort)
        .await?,
      QomtPacketSendOutcome::DatagramQueued,
    );

    let mut initial_pair = vec![
      timeout(Duration::from_secs(2), server_packets.next())
        .await?
        .unwrap(),
      timeout(Duration::from_secs(2), server_packets.next())
        .await?
        .unwrap(),
    ];
    initial_pair.sort();
    let mut expected_pair = vec![small_packet, large_packet];
    expected_pair.sort();
    assert_eq!(initial_pair, expected_pair);
    assert_eq!(client_packets.stats().reliable_queued, 0);

    // 2. Simulate ISP UDP QoS stall: once safe headroom / send queue saturates,
    //    excess `< 1024 B` and `>= 1024 B` packets offload seamlessly onto mTCP!
    proxy.set_udp_forwarding(false);
    let mut expected_offloaded = Vec::new();
    for index in 0..32_usize {
      let mut packet = if index < 24 || index % 2 == 1 {
        large_test_packet(0x44)?
      } else {
        vec![0x33; 180]
      };
      packet[0..2].copy_from_slice(&(index as u16).to_be_bytes());
      let outcome = client_packets
        .send_packet(packet.clone(), QomtPacketDelivery::BestEffort)
        .await?;
      if outcome == QomtPacketSendOutcome::ReliableQueued {
        expected_offloaded.push(packet);
      }
      tokio::task::yield_now().await;
    }

    assert!(
      !expected_offloaded.is_empty(),
      "expected UDP bottleneck to offload packets onto mTCP reliable stream",
    );
    assert!(client.udp_datagram_stats().offloaded_bottlenecked > 0);
    assert_eq!(
      client_packets.stats().dropped_udp_queue_full,
      0,
      "UDP queue saturation must spill onto mTCP rather than dropping packets",
    );

    let mut received_offloaded = Vec::with_capacity(expected_offloaded.len());
    while received_offloaded.len() < expected_offloaded.len() {
      received_offloaded.push(
        timeout(Duration::from_secs(3), server_packets.next())
          .await?
          .ok_or_else(|| anyhow::anyhow!("server packet stream closed early"))?,
      );
    }
    assert_eq!(received_offloaded, expected_offloaded);
    assert_eq!(
      server_packets.stats().received_reliable,
      expected_offloaded.len() as u64,
    );

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn bursty_http3_flow_pins_to_mtcp_while_concurrent_game_flow_stays_on_udp()
-> anyhow::Result<()> {
  use crate::{
    node::NodeId,
    qomt::QomtPacketStream,
    udp_forwarder::{IncomingUdpPacket, OutgoingUdpPacket, UdpPacketSource},
  };

  timeout(Duration::from_secs(12), async {
    let (_listener, server, client) = connect_real_qomt_pair(true).await?;
    let _ = wait_for_datagram_payload_len(&server).await?;

    let (_, mut out_sender) = tokio::try_join!(
      async {
        let mut stream = client.open_stream();
        stream.write_u8(1).await?;
        let mut ps = QomtPacketStream::<OutgoingUdpPacket, IncomingUdpPacket>::connect(
          client.clone(),
          stream,
        )
        .await?;
        tokio::spawn(async move {
          while ps.next().await.is_some() {}
        });
        anyhow::Ok(())
      },
      async {
        let mut stream = server
          .accept_stream()
          .await?
          .ok_or_else(|| anyhow::anyhow!("missing packet stream"))?;
        let _ = stream.read_u8().await?;
        let ps = QomtPacketStream::<IncomingUdpPacket, OutgoingUdpPacket>::accept(
          server.clone(),
          stream,
        )
        .await?;
        anyhow::Ok(ps)
      },
    )?;

    let client_source = UdpPacketSource {
      via: vec![NodeId::new()],
      address: "100.69.178.77:61601".parse()?,
    };
    let yt_dest: std::net::SocketAddr = "142.251.218.14:443".parse()?;
    let game_dest: std::net::SocketAddr = "103.28.54.185:27017".parse()?;

    // 1. Heavy YouTube HTTP/3 flow bursts > 16 KiB -> promotes & pins to mTCP.
    let mut yt_pinned = false;
    for seq in 0..24_u8 {
      let outcome = out_sender
        .send_packet(
          IncomingUdpPacket {
            source: client_source.clone(),
            destination: yt_dest,
            payload: vec![seq; 1100],
          },
          QomtPacketDelivery::BestEffort,
        )
        .await?;
      if outcome == QomtPacketSendOutcome::ReliableQueued {
        yt_pinned = true;
      }
    }
    assert!(yt_pinned, "heavy HTTP/3 flow must promote onto mTCP");

    // 2. Even after pausing 300ms (when UDP token bucket refills!), the pinned
    //    YouTube flow MUST stay on mTCP (zero oscillation back to UDP), while a
    //    concurrent :27017 game flow stays cleanly on QomT UDP!
    sleep(Duration::from_millis(300)).await;

    let yt_followup = out_sender
      .send_packet(
        IncomingUdpPacket {
          source: client_source.clone(),
          destination: yt_dest,
          payload: vec![0xaa; 900],
        },
        QomtPacketDelivery::BestEffort,
      )
      .await?;
    assert_eq!(
      yt_followup,
      QomtPacketSendOutcome::ReliableQueued,
      "pinned HTTP/3 flow must stay on mTCP instead of oscillating back to UDP",
    );

    let game_outcome = out_sender
      .send_packet(
        IncomingUdpPacket {
          source: client_source,
          destination: game_dest,
          payload: vec![0x55; 84],
        },
        QomtPacketDelivery::BestEffort,
      )
      .await?;
    assert_eq!(
      game_outcome,
      QomtPacketSendOutcome::DatagramQueued,
      "lightweight game UDP flow must remain on low-latency QomT UDP",
    );

    anyhow::Ok(())
  })
  .await?
}
