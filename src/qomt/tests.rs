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
  mt_connections::{
    MtConnectionsListener, MtConnectionsPacket, MtConnectionsPacketMode, decode_udp_frame,
  },
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

/// 对端没有 UDP listener 时，后台旁路失败不能把本地主连接返回拖到 2s。
#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn unavailable_udp_does_not_delay_main_connection() -> anyhow::Result<()> {
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

  assert_eq!(
    server.udp_state(),
    QomtUdpState::Connecting,
    "qomt_accept must return while the unavailable UDP path is still timing out in the background",
  );

  // 保持 listener 存活并验证主 reliable stream 确实可立即使用。
  let _listener = listener;
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

/// mTCP 帧格式（u32 大端长度 + 载荷）的往返与边界。
#[tokio::test]
#[test_log::test]
async fn test_packet_frame_roundtrip() -> anyhow::Result<()> {
  let (mut left_write, mut right_read) = duplex(MAX_DATAGRAM_SIZE * 2);

  let payload = vec![0xab; MAX_DATAGRAM_SIZE - 8];

  QuicBytesPacket::write_packet(&mut left_write, None, payload.clone().into()).await?;
  QuicBytesPacket::write_packet(&mut left_write, None, vec![].into()).await?;

  // 关闭写端，让读端在缓冲排空后收到 EOF。
  drop(left_write);

  let (sequence, packet) =
    QuicBytesPacket::read_next_packet(&mut right_read, MtConnectionsPacketMode::Legacy)
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing first packet"))?;

  assert_eq!(sequence, None);
  assert_eq!(&*packet, &payload[..]);

  let (_, empty) =
    QuicBytesPacket::read_next_packet(&mut right_read, MtConnectionsPacketMode::Legacy)
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing empty packet"))?;

  assert!(empty.is_empty());

  // EOF 之后返回 None。
  assert!(
    QuicBytesPacket::read_next_packet(&mut right_read, MtConnectionsPacketMode::Legacy)
      .await?
      .is_none()
  );

  Ok(())
}

#[tokio::test]
async fn test_sequenced_packet_frame_roundtrip() -> anyhow::Result<()> {
  let (mut left_write, mut right_read) = duplex(MAX_DATAGRAM_SIZE * 2);
  let payload = vec![0xcd; MAX_DATAGRAM_SIZE - 8];

  QuicBytesPacket::write_packet(&mut left_write, Some(42), payload.clone().into()).await?;
  let (sequence, packet) =
    QuicBytesPacket::read_next_packet(&mut right_read, MtConnectionsPacketMode::Sequenced)
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing sequenced packet"))?;

  assert_eq!(sequence, Some(42));
  assert_eq!(&*packet, &payload[..]);
  Ok(())
}

/// 超过 MAX_DATAGRAM_SIZE 的帧必须被拒绝，而不是分配大缓冲区。
#[tokio::test]
#[test_log::test]
async fn test_packet_frame_rejects_oversized_length() -> anyhow::Result<()> {
  let (mut left_write, mut right_read) = duplex(MAX_DATAGRAM_SIZE * 2);

  left_write.write_u32((MAX_DATAGRAM_SIZE + 1) as u32).await?;

  let error = QuicBytesPacket::read_next_packet(&mut right_read, MtConnectionsPacketMode::Legacy)
    .await
    .expect_err("oversized frame must be rejected");

  assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

  Ok(())
}

#[tokio::test]
async fn test_packet_frame_rejects_oversized_write() {
  let error =
    QuicBytesPacket::write_packet(&mut sink(), None, vec![0; MAX_DATAGRAM_SIZE + 1].into())
      .await
      .expect_err("oversized outgoing frame must be rejected");

  assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn test_packet_frame_reports_truncated_frames() -> anyhow::Result<()> {
  let (mut prefix_writer, mut prefix_reader) = duplex(8);
  prefix_writer.write_all(&[0, 0]).await?;
  drop(prefix_writer);

  let prefix_error =
    QuicBytesPacket::read_next_packet(&mut prefix_reader, MtConnectionsPacketMode::Legacy)
      .await
      .expect_err("partial length prefix must be rejected");
  assert_eq!(prefix_error.kind(), std::io::ErrorKind::UnexpectedEof);

  let (mut body_writer, mut body_reader) = duplex(8);
  body_writer.write_u32(4).await?;
  body_writer.write_all(&[1, 2]).await?;
  drop(body_writer);

  let body_error =
    QuicBytesPacket::read_next_packet(&mut body_reader, MtConnectionsPacketMode::Legacy)
      .await
      .expect_err("partial packet body must be rejected");
  assert_eq!(body_error.kind(), std::io::ErrorKind::UnexpectedEof);

  Ok(())
}
