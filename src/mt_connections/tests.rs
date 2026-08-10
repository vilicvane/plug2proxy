use std::{
  sync::{Arc, LazyLock},
  time::{Duration, Instant},
};

use futures::{SinkExt, StreamExt};
use lits::duration;
use lowkit::SelfWrapExt;
use rand::Rng;
use socket2::SockRef;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
  net::{TcpListener, TcpStream, UdpSocket},
  sync::{mpsc, oneshot},
  task::AbortHandle,
  time::{sleep, timeout},
};

use crate::primitives::ConnectionSide;
use crate::quic_connection::{MAX_DATAGRAM_SIZE, QuicBytesPacket};
use crate::utils::postcard::postcard_read_stream;

use super::*;

static RANDOM_DATA_1: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; MAX_DATAGRAM_SIZE];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

static RANDOM_DATA_2: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; MAX_DATAGRAM_SIZE];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

#[tokio::test]
async fn sequenced_delivery_restores_order_beyond_quic_receive_window() -> anyhow::Result<()> {
  const PACKETS: u64 = 512;
  let (received_packet_sender, received_packet_receiver) = mpsc::unbounded_channel();
  let (packet_sender, packet_receiver) = flume::bounded::<QuicBytesPacket>(0);
  let diagnostics = Arc::new(MtConnectionsDiagnostics::new());

  let delivery = tokio::spawn(deliver_mt_packets(
    received_packet_receiver,
    packet_sender,
    diagnostics,
    ConnectionSide::Client,
    "127.0.0.1:1122".parse()?,
  ));
  let collect = tokio::spawn(async move {
    let mut delivered = Vec::new();
    while let Ok(packet) = packet_receiver.recv_async().await {
      delivered.push(u64::from_be_bytes(packet[..].try_into().unwrap()));
    }
    delivered
  });

  let send_packet = |sequence| {
    received_packet_sender
      .send(MtConnectionsReceivedPacket {
        sequence: Some(sequence),
        packet: sequence.to_be_bytes().to_vec().into(),
      })
      .unwrap();
  };

  send_packet(0);
  for sequence in 2..PACKETS {
    send_packet(sequence);
  }
  sleep(duration!("100ms")).await;
  send_packet(1);
  drop(received_packet_sender);

  let delivered = timeout(duration!("5s"), collect).await??;
  delivery.await?;
  assert_eq!(delivered, (0..PACKETS).collect::<Vec<_>>());

  Ok(())
}

#[tokio::test]
async fn new_listener_accepts_legacy_client_framing() -> anyhow::Result<()> {
  let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
  let address = tcp_listener.local_addr()?;
  let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(tcp_listener, None);
  let payload = b"legacy client".to_vec();

  timeout(duration!("5s"), async {
    tokio::try_join!(
      async {
        let mut mt_connections = listener.accept().await?;
        let packet = mt_connections
          .next()
          .await
          .ok_or_else(|| anyhow::anyhow!("legacy client did not deliver a packet"))?;
        anyhow::ensure!(&packet[..] == payload);
        anyhow::Ok(())
      },
      async {
        let mut stream = TcpStream::connect(address).await?;
        let request = postcard::to_allocvec(&MtConnectionsRequestHead {
          magic: MtConnectionsMagic,
          data: MtConnectionsRequestHeadData::Create,
        })?;
        stream.write_all(&request).await?;
        let response = postcard_read_stream::<MtConnectionsResponseHead>(&mut stream).await?;
        anyhow::ensure!(matches!(
          response.data,
          MtConnectionsResponseHeadData::Created(_)
        ));
        stream.write_u32(payload.len() as u32).await?;
        stream.write_all(&payload).await?;
        anyhow::Ok(())
      },
    )?;
    anyhow::Ok(())
  })
  .await??;

  Ok(())
}

#[tokio::test]
async fn new_connector_falls_back_to_legacy_server_framing() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let address = listener.local_addr()?;
  let payload = b"legacy server".to_vec();

  timeout(duration!("5s"), async {
    tokio::try_join!(
      async {
        let (mut unsupported_stream, _) = listener.accept().await?;
        let unsupported =
          postcard_read_stream::<MtConnectionsRequestHead>(&mut unsupported_stream).await?;
        anyhow::ensure!(unsupported.data == MtConnectionsRequestHeadData::CreateSequenced);
        drop(unsupported_stream);

        let (mut legacy_stream, _) = listener.accept().await?;
        let legacy = postcard_read_stream::<MtConnectionsRequestHead>(&mut legacy_stream).await?;
        anyhow::ensure!(legacy.data == MtConnectionsRequestHeadData::Create);
        let id = MtConnectionsId::new();
        let response = postcard::to_allocvec(&MtConnectionsResponseHead {
          magic: MtConnectionsMagic,
          data: MtConnectionsResponseHeadData::Created(id),
        })?;
        legacy_stream.write_all(&response).await?;

        let encoded_length = legacy_stream.read_u32().await?;
        anyhow::ensure!(encoded_length as usize == payload.len());
        let mut received = vec![0; encoded_length as usize];
        legacy_stream.read_exact(&mut received).await?;
        anyhow::ensure!(received == payload);
        anyhow::Ok(())
      },
      async {
        let (mut mt_connections, _extend) =
          mt_connections_connect::<QuicBytesPacket>(address, 1).await?;
        mt_connections.send(payload.clone().into()).await?;
        anyhow::Ok(())
      },
    )?;
    anyhow::Ok(())
  })
  .await??;

  Ok(())
}

#[test]
fn tcp_info_loss_floor_tracks_current_ack_stall() {
  let metrics = MtConnectionsUnderlayMetrics::default();
  let path_id = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let now = Instant::now();
  let info = MtTcpInfo {
    rtt: Duration::from_millis(100),
    rttvar: Duration::from_millis(20),
    rto: Duration::from_millis(250),
    unacked: 1,
    retrans: 1,
    total_retrans: 3,
    last_ack_recv: Duration::from_millis(300),
  };

  metrics.update_path(path_id, info, now - Duration::from_millis(300));
  metrics.update_path(path_id, info, now);

  let snapshot = metrics.snapshot();
  assert_eq!(snapshot.paths, 1);
  assert_eq!(snapshot.sampled_paths, 1);
  assert_eq!(snapshot.loss_delay_floor, Duration::from_millis(550));
  assert_eq!(snapshot.max_rtt, Duration::from_millis(100));
  assert_eq!(snapshot.max_rttvar, Duration::from_millis(20));
  assert_eq!(snapshot.max_rto, Duration::from_millis(250));
  assert_eq!(snapshot.max_ack_stall, Duration::from_millis(300));
  assert_eq!(snapshot.quorum_ack_stall, Duration::from_millis(300));
  assert_eq!(snapshot.total_unacked, 1);
  assert_eq!(snapshot.retransmitting_paths, 1);
  assert_eq!(snapshot.total_retrans, 3);

  metrics.remove_path(path_id);
  assert_eq!(metrics.snapshot().paths, 0);
}

#[test]
fn tcp_info_loss_floor_requires_a_path_quorum() {
  let metrics = MtConnectionsUnderlayMetrics::default();
  let now = Instant::now();
  let mut path_ids = Vec::new();

  for stall in [
    Duration::from_millis(900),
    Duration::from_millis(400),
    Duration::from_millis(20),
    Duration::ZERO,
  ] {
    let path_id = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
    let info = MtTcpInfo {
      rtt: Duration::from_millis(100),
      rttvar: Duration::from_millis(20),
      rto: Duration::from_millis(250),
      unacked: u32::from(!stall.is_zero()),
      retrans: 0,
      total_retrans: 0,
      last_ack_recv: stall,
    };
    metrics.update_path(path_id, info, now - stall);
    metrics.update_path(path_id, info, now);
    path_ids.push(path_id);
  }

  let snapshot = metrics.snapshot();
  assert_eq!(snapshot.sampled_paths, 4);
  assert_eq!(snapshot.loss_delay_floor, Duration::from_millis(650));
  assert_eq!(snapshot.max_ack_stall, Duration::from_millis(900));
  assert_eq!(snapshot.quorum_ack_stall, Duration::from_millis(400));

  metrics.remove_path(path_ids[1]);
  metrics.remove_path(path_ids[2]);
  metrics.remove_path(path_ids[3]);
  let snapshot = metrics.snapshot();
  assert_eq!(snapshot.sampled_paths, 1);
  assert_eq!(snapshot.loss_delay_floor, Duration::from_millis(1150));
  assert_eq!(snapshot.quorum_ack_stall, Duration::from_millis(900));
}

#[tokio::test]
async fn configures_mt_tcp_stream_options() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let address = listener.local_addr()?;

  let connect = TcpStream::connect(address);
  let accept = listener.accept();
  let (client_stream, _) = tokio::try_join!(connect, accept)?;

  configure_mt_tcp_stream(&client_stream)?;

  let socket = SockRef::from(&client_stream);

  #[cfg(target_os = "linux")]
  if std::fs::read_to_string("/proc/sys/net/ipv4/tcp_available_congestion_control")?
    .split_ascii_whitespace()
    .any(|algorithm| algorithm == "bbr")
  {
    assert_eq!(socket.tcp_congestion()?, b"bbr");
  }

  #[cfg(any(target_os = "android", target_os = "linux"))]
  assert_eq!(
    socket.tcp_notsent_lowat()?,
    MT_CONNECTIONS_TCP_NOTSENT_LOWAT
  );

  assert!(socket.keepalive()?);
  assert_eq!(socket.tcp_keepalive_time()?, MT_CONNECTIONS_KEEPALIVE_TIME);
  assert_eq!(
    socket.tcp_keepalive_interval()?,
    MT_CONNECTIONS_KEEPALIVE_INTERVAL
  );
  assert_eq!(
    socket.tcp_keepalive_retries()?,
    MT_CONNECTIONS_KEEPALIVE_RETRIES
  );

  #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
  assert_eq!(
    socket.tcp_user_timeout()?,
    Some(MT_CONNECTIONS_TCP_USER_TIMEOUT)
  );

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_mt_connections() -> anyhow::Result<()> {
  let (listener_ready_sender, listener_ready_receiver) = oneshot::channel();
  let (complete_sender, complete_receiver) = oneshot::channel();

  let instant = None.mutex();

  tokio::try_join!(
    async {
      let listener = TcpListener::bind("127.0.0.1:0").await?;

      let address = listener.local_addr()?;

      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(listener, None);

      listener_ready_sender.send(address).unwrap();

      let mut mt_connections = listener.accept().await?;

      let main_future = async {
        instant.lock().unwrap().replace(Instant::now());

        mt_connections.send(RANDOM_DATA_1.clone().into()).await?;
        mt_connections.send(RANDOM_DATA_2.clone().into()).await?;

        let packet_1 = mt_connections.next().await.unwrap();
        let packet_2 = mt_connections.next().await.unwrap();

        assert!(*packet_1 == *RANDOM_DATA_1 || *packet_1 == *RANDOM_DATA_2);
        assert!(*packet_2 == *RANDOM_DATA_1 || *packet_2 == *RANDOM_DATA_2);

        complete_sender.send(()).unwrap();

        anyhow::Ok(())
      };

      let listener_future = async {
        listener.accept().await?;

        anyhow::bail!("only meant to poll the listener");

        #[allow(unreachable_code)]
        anyhow::Ok(())
      };

      tokio::select!(
        result = main_future => result,
        result = listener_future => result.and_then(|_| Err(anyhow::anyhow!("Listener future completed"))),
      )?;

      anyhow::Ok(())
    },
    async {
      let address = listener_ready_receiver.await?;

      let (mut mt_connections, extend_signal_sender) =
        mt_connections_connect::<QuicBytesPacket>(address, 2).await?;

      let packet_1 = mt_connections.next().await.unwrap();

      log::debug!(
        "packet 1 received after {:?}",
        instant.lock().unwrap().unwrap().elapsed()
      );

      let packet_2 = mt_connections.next().await.unwrap();

      assert!(*packet_1 == *RANDOM_DATA_1 || *packet_1 == *RANDOM_DATA_2);
      assert!(*packet_2 == *RANDOM_DATA_1 || *packet_2 == *RANDOM_DATA_2);

      extend_signal_sender.send(()).unwrap();

      sleep(duration!("100ms")).await;

      assert_eq!(mt_connections.connection_count(), 2);

      mt_connections.send(RANDOM_DATA_1.clone().into()).await?;
      mt_connections.send(RANDOM_DATA_2.clone().into()).await?;

      complete_receiver.await?;

      anyhow::Ok(())
    },
  )?;

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn reconnects_a_dropped_tcp_connection() -> anyhow::Result<()> {
  timeout(duration!("10s"), async {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
    let backend_address = backend_listener.local_addr()?;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_address = proxy_listener.local_addr()?;

    let (relay_sender, mut relay_receiver) = mpsc::unbounded_channel::<AbortHandle>();

    let proxy_task = tokio::spawn(async move {
      loop {
        let (mut client_stream, _) = proxy_listener.accept().await?;
        let mut server_stream = TcpStream::connect(backend_address).await?;

        let relay_task =
          tokio::spawn(
            async move { copy_bidirectional(&mut client_stream, &mut server_stream).await },
          );

        if relay_sender.send(relay_task.abort_handle()).is_err() {
          break;
        }
      }

      anyhow::Ok(())
    });

    let server_future = async {
      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(backend_listener, None);
      let mt_connections = listener.accept().await?;

      anyhow::Ok((listener, mt_connections))
    };

    let client_future = async {
      mt_connections_connect::<QuicBytesPacket>(proxy_address, 2)
        .await
        .map_err(anyhow::Error::from)
    };

    let ((mut listener, mut server_connections), (mut client_connections, extend_sender)) =
      tokio::try_join!(server_future, client_future)?;

    let listener_task = tokio::spawn(async move {
      let _unexpected_connection = listener.accept().await?;
      anyhow::Result::<()>::Err(anyhow::anyhow!("unexpected new mTCP connection group"))
    });

    extend_sender
      .send(())
      .map_err(|_| anyhow::anyhow!("failed to extend mTCP connections"))?;

    let _initial_relay = relay_receiver
      .recv()
      .await
      .ok_or_else(|| anyhow::anyhow!("missing initial TCP relay"))?;
    let relay_to_drop = relay_receiver
      .recv()
      .await
      .ok_or_else(|| anyhow::anyhow!("missing extended TCP relay"))?;

    timeout(duration!("2s"), async {
      while client_connections.connection_count() != 2 {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    relay_to_drop.abort();

    let _replacement_relay = timeout(duration!("5s"), relay_receiver.recv())
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing replacement TCP relay"))?;

    timeout(duration!("2s"), async {
      while client_connections.connection_count() != 2 {
        tokio::task::yield_now().await;
      }
    })
    .await?;

    let packet = b"connection recovered".to_vec();
    client_connections.send(packet.clone().into()).await?;

    let received = timeout(duration!("2s"), server_connections.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("server mTCP connections closed"))?;

    assert_eq!(*received, packet);

    listener_task.abort();
    proxy_task.abort();

    anyhow::Ok(())
  })
  .await?
}

/// listener 全局 UDP socket 按 MtConnectionsId 分发：connect 侧与 listener 侧
/// 各自 take 到 UDP duplex 后双向互发互收。
#[tokio::test]
#[test_log::test]
async fn udp_side_channel_is_delivered_between_sides() -> anyhow::Result<()> {
  timeout(duration!("10s"), async {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;

    let udp_socket = UdpSocket::bind(listener.local_addr()?).await.ok();

    let mut mt_connections_listener =
      MtConnectionsListener::<QuicBytesPacket>::new(listener, udp_socket);

    // listener 留在测试作用域，UDP 分发循环存活至测试结束（Drop 会 abort 它）。
    let client_task =
      tokio::spawn(async move { mt_connections_connect::<QuicBytesPacket>(address, 1).await });

    let server_connections = mt_connections_listener.accept().await?;

    let (client_connections, _extend_signal_sender) = client_task.await??;

    assert_eq!(mt_connections_listener.udp_dispatch_count(), 1);

    let mut client_udp_duplex =
      MtConnectionsSideUdpDuplex::<QuicBytesPacket>::connect_side(address, client_connections.id())
        .await?;

    let client_packet = vec![0x01, 0x02, 0x03];
    let server_packet = vec![0x04, 0x05];

    // 首包既触发 route/duplex 创建，也必须进入有界队列，不能依赖 QUIC
    // 重传来掩盖 dispatcher 的调度窗口。
    client_udp_duplex.send(client_packet.clone().into()).await?;

    // listener 侧 duplex 由分发循环在首个 UDP 包到达时创建，轮询等待。
    let mut server_udp_duplex = loop {
      if let Some(duplex) = server_connections.take_udp_duplex() {
        break duplex;
      }

      tokio::task::yield_now().await;
    };

    let received_by_server = timeout(duration!("2s"), server_udp_duplex.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("server UDP duplex closed"))?;

    // route 固定到第一个有效来源地址；同 IP 不同端口不能注入同 ID。
    let attacker = UdpSocket::bind("127.0.0.1:0").await?;
    let injected_packet: QuicBytesPacket = vec![0x99].into();
    let injected_frame = encode_udp_frame(&client_udp_duplex.id(), &injected_packet).unwrap();
    attacker.send_to(&injected_frame, address).await?;

    assert!(
      timeout(duration!("100ms"), server_udp_duplex.next())
        .await
        .is_err(),
      "packet from a different UDP source must be dropped",
    );

    // 负向 timeout 之后再用合法来源发 sentinel；如果注入包被误投递，
    // 它会排在 sentinel 前并让这个正向断言失败。
    let source_sentinel = vec![0x7a, 0x7b];
    client_udp_duplex
      .send(source_sentinel.clone().into())
      .await?;

    let received_sentinel = timeout(duration!("2s"), server_udp_duplex.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("server UDP duplex closed before source sentinel"))?;

    assert_eq!(&*received_sentinel, &source_sentinel);

    let received_by_client = {
      let receive = client_udp_duplex.next();
      tokio::pin!(receive);

      server_udp_duplex.send(server_packet.clone().into()).await?;

      timeout(duration!("2s"), &mut receive)
        .await?
        .ok_or_else(|| anyhow::anyhow!("client UDP duplex closed"))?
    };

    assert_eq!(&*received_by_server, &client_packet[..]);
    assert_eq!(&*received_by_client, &server_packet[..]);

    // Ending one UDP generation must retain the stable MtConnectionsId route.
    // Keep the old client socket open so the replacement is guaranteed to use
    // a different source port, matching a real reconnect.
    let first_client_address = client_udp_duplex.local_addr()?;
    drop(server_udp_duplex);
    let mut replacement_client_udp =
      MtConnectionsSideUdpDuplex::<QuicBytesPacket>::connect_side(address, client_connections.id())
        .await?;
    assert_ne!(replacement_client_udp.local_addr()?, first_client_address);

    let replacement_packet = vec![0x42, 0x43, 0x44];
    replacement_client_udp
      .send(replacement_packet.clone().into())
      .await?;
    let mut replacement_server_udp = timeout(duration!("2s"), server_connections.wait_udp_duplex())
      .await?
      .ok_or_else(|| anyhow::anyhow!("replacement server UDP duplex missing"))?;
    let received_replacement = timeout(duration!("2s"), replacement_server_udp.next())
      .await?
      .ok_or_else(|| anyhow::anyhow!("replacement server UDP duplex closed"))?;

    assert_eq!(&*received_replacement, &replacement_packet);
    assert_eq!(
      mt_connections_listener.udp_dispatch_count(),
      1,
      "UDP generation replacement must retain one stable dispatch route",
    );

    drop(client_udp_duplex);
    drop(replacement_server_udp);
    drop(replacement_client_udp);
    drop(server_connections);
    drop(client_connections);

    assert_eq!(
      mt_connections_listener.udp_dispatch_count(),
      0,
      "dropping MtConnections must unregister its UDP route",
    );

    anyhow::Ok(())
  })
  .await?
}
