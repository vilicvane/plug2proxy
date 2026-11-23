use std::{
  sync::LazyLock,
  time::{Duration, Instant},
};

use futures::{SinkExt, StreamExt};
use lits::duration;
use lowkit::SelfWrapExt;
use rand::Rng;
use socket2::SockRef;
use tokio::{
  io::copy_bidirectional,
  net::{TcpListener, TcpStream, UdpSocket},
  sync::{mpsc, oneshot},
  task::AbortHandle,
  time::{sleep, timeout},
};

use crate::quic_connection::{MAX_DATAGRAM_SIZE, QuicBytesPacket};

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

fn tcp_info(bytes_acked: u64) -> MtTcpInfo {
  MtTcpInfo {
    ca_state: 0,
    probes: 0,
    backoff: 0,
    rtt: Duration::from_millis(100),
    rttvar: Duration::from_millis(20),
    rto: Duration::from_millis(250),
    snd_mss: 1448,
    unacked: 0,
    notsent_bytes: 0,
    retrans: 0,
    total_retrans: 0,
    data_segs_out: 0,
    bytes_acked,
    delivered: bytes_acked as u32,
  }
}

#[test]
fn rotation_uses_the_window_minimum_and_preserves_the_target_count() {
  let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
  let now = Instant::now();
  let mut paths = Vec::new();
  for milliseconds in [80, 90, 70] {
    let path = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
    let mut info = tcp_info(1);
    info.rtt = Duration::from_millis(milliseconds);
    metrics.update_path(path, info, now);
    paths.push(path);
  }

  // A high latest RTT does not change this path's better five-minute minimum.
  let mut spike = tcp_info(2);
  spike.rtt = Duration::from_millis(300);
  metrics.update_path(paths[0], spike, now + Duration::from_secs(60));
  assert_eq!(
    metrics.retire_worst_path(2, now + Duration::from_secs(60)),
    Some(paths[1])
  );
  assert_eq!(metrics.available_path_count(), 2);
  assert_eq!(metrics.snapshot().paths, 3);
  assert_eq!(
    metrics.retire_worst_path(2, now + Duration::from_secs(60)),
    None
  );
}

#[test]
fn rotation_expires_old_minima_and_ignores_stale_tcp_info() {
  let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
  let now = Instant::now();
  let oldest = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let stale = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let other = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let mut initial = tcp_info(1);
  initial.rtt = Duration::from_millis(10);
  metrics.update_path(oldest, initial, now);
  initial.rtt = Duration::from_millis(200);
  metrics.update_path(stale, initial, now);
  let later = now + Duration::from_secs(301);
  let mut recent = tcp_info(2);
  recent.rtt = Duration::from_millis(120);
  metrics.update_path(oldest, recent, later);
  recent.rtt = Duration::from_millis(80);
  metrics.update_path(other, recent, later);
  // Re-reading an unchanged counter cannot renew an expired RTT sample.
  metrics.update_path(stale, initial, later);
  assert_eq!(metrics.retire_worst_path(2, later), Some(oldest));
}

#[cfg(target_os = "linux")]
async fn wait_for_tcp_path_count(
  client: &MtConnections<QuicBytesPacket>,
  server: &MtConnections<QuicBytesPacket>,
  expected: usize,
) -> anyhow::Result<()> {
  timeout(Duration::from_secs(2), async {
    while client.connection_count() != expected || server.connection_count() != expected {
      tokio::task::yield_now().await;
    }
  })
  .await?;
  Ok(())
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn rotation_adds_a_spare_then_replaces_one_path_after_it_drains() -> anyhow::Result<()> {
  // The two explicit scheduler advances consume ten minutes of virtual time.
  timeout(Duration::from_secs(610), async {
    let socket = TcpListener::bind("127.0.0.1:0").await?;
    let address = socket.local_addr()?;
    let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(socket, None);
    let ((mut client, extend), mut server) = tokio::try_join!(
      async {
        mt_connections_connect::<QuicBytesPacket>(address, 4)
          .await
          .map_err(anyhow::Error::from)
      },
      async { listener.accept().await.map_err(anyhow::Error::from) },
    )?;
    let listener_task = tokio::spawn(async move { listener.accept().await });
    let listener_guard = lowkit::DropCallback::new(move || listener_task.abort());
    extend
      .send(())
      .map_err(|_| anyhow::anyhow!("extension task stopped"))?;
    wait_for_tcp_path_count(&client, &server, 4).await?;
    sleep(Duration::from_millis(100)).await;

    // Advance only the scheduler clock. Real socket I/O runs with time resumed.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(300)).await;
    tokio::time::resume();
    wait_for_tcp_path_count(&client, &server, 5).await?;
    sleep(Duration::from_millis(100)).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(300)).await;
    tokio::time::resume();
    wait_for_tcp_path_count(&client, &server, 4).await?;

    client.send(b"during replacement".to_vec().into()).await?;
    assert_eq!(
      server.next().await.unwrap().as_slice(),
      b"during replacement"
    );
    wait_for_tcp_path_count(&client, &server, 5).await?;
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
      client.connection_count(),
      5,
      "retirement caused a duplicate replacement"
    );
    server.send(b"after replacement".to_vec().into()).await?;
    assert_eq!(
      client.next().await.unwrap().as_slice(),
      b"after replacement"
    );
    drop(listener_guard);
    anyhow::Ok(())
  })
  .await?
}

#[test]
fn three_state_tcp_health_distinguishes_sack_stalling_from_dead_blackhole() {
  let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
  let path = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let other = metrics.register_path(None, "127.0.0.1:1123".parse().unwrap());
  let now = Instant::now();

  metrics.update_path(path, tcp_info(1), now);
  metrics.update_path(other, tcp_info(1), now);

  // Idle paths (`unacked == 0 && notsent_bytes == 0`) remain Clean indefinitely
  // without sending keepalive probe frames.
  let idle_later = now + Duration::from_secs(30);
  metrics.update_path(path, tcp_info(1), idle_later);
  metrics.update_path(other, tcp_info(1), idle_later);
  assert_eq!(metrics.snapshot().active_paths, 2);
  assert_eq!(metrics.snapshot().stalling_paths, 0);

  let mut packet: QuicBytesPacket = vec![1].into();
  let delivery = quiche::ReliablePacket::default();
  packet.delivery = Some(delivery.clone());
  assert!(metrics.bind_packet(path, &packet));
  assert!(!delivery.is_lost());

  // State 2 (`Stalling`): cumulative `bytes_acked` is frozen behind a lost
  // segment for >1s and even hits backoff=2, while SACK (`tcpi_delivered`) keeps
  // advancing. Assignment pauses on `path`, but `delivery` MUST NOT be marked lost!
  let sack_hole_time = idle_later + Duration::from_millis(1500);
  let mut sack_recovering = tcp_info(1);
  sack_recovering.ca_state = MT_TCP_CA_RECOVERY;
  sack_recovering.unacked = 12;
  sack_recovering.retrans = 1;
  sack_recovering.delivered = 25;
  metrics.update_path(path, sack_recovering, sack_hole_time);
  metrics.update_path(other, tcp_info(10), sack_hole_time);
  assert_eq!(metrics.snapshot().active_paths, 1);
  assert_eq!(metrics.snapshot().stalling_paths, 1);
  assert!(!delivery.is_lost());

  // Even after 5 seconds of head-of-line delay, continuous `tcpi_delivered`
  // progress (SACKs arriving) proves the uplink is alive and prevents `Dead`.
  let mut ongoing_sack = sack_recovering;
  ongoing_sack.backoff = 3;
  ongoing_sack.delivered = 40;
  let five_sec = sack_hole_time + Duration::from_secs(4);
  metrics.update_path(path, ongoing_sack, five_sec);
  assert!(!delivery.is_lost());

  // Kernel patches the hole (`bytes_acked` advances, `backoff == 0`, `ca_state == Open`):
  // `path` returns to Clean on the exact same unbroken ReliableTransport generation!
  let mut healed = tcp_info(50_000);
  healed.delivered = 42;
  let healed_at = five_sec + Duration::from_millis(100);
  metrics.update_path(path, healed, healed_at);
  assert_eq!(metrics.snapshot().active_paths, 2);
  assert_eq!(metrics.snapshot().stalling_paths, 0);
  assert!(!delivery.is_lost());

  // State 3 (`Dead`): uplink blackhole with `unacked > 0`, ZERO `delivered` and
  // ZERO `bytes_acked` progress across `>= 3s` and `backoff >= 3` (even if RTO grows).
  let mut blackholed = healed;
  blackholed.ca_state = MT_TCP_CA_LOSS;
  blackholed.unacked = 6;
  blackholed.backoff = 1;
  blackholed.rto = Duration::from_secs(2);
  metrics.update_path(path, blackholed, healed_at + Duration::from_millis(500));
  assert_eq!(metrics.snapshot().active_paths, 1);
  assert_eq!(metrics.snapshot().stalling_paths, 1);
  assert!(!delivery.is_lost());

  blackholed.backoff = MT_TCP_DEAD_BACKOFF;
  blackholed.rto = Duration::from_secs(8);
  metrics.update_path(path, blackholed, healed_at + Duration::from_millis(3600));
  assert!(delivery.is_lost());
  // With `other` alive (`live_paths == 2`), `path` is immediately marked dead (`!is_live()`).
  assert_eq!(metrics.available_path_count(), 1);
}

#[test]
fn sole_dead_path_waits_for_replacement_before_closing_socket() {
  let metrics = MtConnectionsUnderlayMetrics::<QuicBytesPacket>::default();
  let sole = metrics.register_path(None, "127.0.0.1:1122".parse().unwrap());
  let now = Instant::now();
  metrics.update_path(sole, tcp_info(1), now);

  let mut packet: QuicBytesPacket = vec![1].into();
  let delivery = quiche::ReliablePacket::default();
  packet.delivery = Some(delivery.clone());
  assert!(metrics.bind_packet(sole, &packet));

  let mut blackholed = tcp_info(1);
  blackholed.ca_state = MT_TCP_CA_LOSS;
  blackholed.unacked = 4;
  blackholed.backoff = MT_TCP_DEAD_BACKOFF;
  metrics.update_path(sole, blackholed, now + Duration::from_secs(4));

  // Unacked generation fails immediately, while the sole socket stays open until
  // either TCP_USER_TIMEOUT or a replacement path registers.
  assert!(delivery.is_lost());
  assert_eq!(metrics.available_path_count(), 1);
  let mut raced_packet: QuicBytesPacket = vec![2].into();
  let raced_delivery = quiche::ReliablePacket::default();
  raced_packet.delivery = Some(raced_delivery.clone());
  assert!(!metrics.bind_packet(sole, &raced_packet));
  assert!(raced_delivery.is_lost());

  // Registering a replacement path immediately reaps the pending dead path.
  let _replacement = metrics.register_path(None, "127.0.0.1:1123".parse().unwrap());
  assert_eq!(metrics.available_path_count(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn idle_tcp_paths_remain_clean_without_probe_frames() -> anyhow::Result<()> {
  timeout(Duration::from_secs(8), async {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (client, (server, _)) = tokio::try_join!(TcpStream::connect(address), listener.accept())?;
    let id = MtConnectionsId::new();
    let (mut left, _left_sender, _) =
      MtConnections::<QuicBytesPacket>::new(client, crate::primitives::ConnectionSide::Client, id);
    let (mut right, _right_sender, _) =
      MtConnections::<QuicBytesPacket>::new(server, crate::primitives::ConnectionSide::Server, id);
    sleep(Duration::from_millis(2300)).await;
    assert_eq!(left.underlay_metrics().snapshot().active_paths, 1);
    assert_eq!(right.underlay_metrics().snapshot().active_paths, 1);
    assert!(
      timeout(Duration::from_millis(100), left.next())
        .await
        .is_err()
    );
    left.send(vec![1, 2, 3].into()).await?;
    assert_eq!(right.next().await.unwrap().as_slice(), &[1, 2, 3]);
    anyhow::Ok(())
  })
  .await?
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

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn rejects_invalid_extend_token_and_wrong_binding() -> anyhow::Result<()> {
  use crate::utils::{net::bind_tcp_listener, postcard::postcard_read_stream};
  use std::collections::HashMap;
  use tokio::io::AsyncWriteExt;

  timeout(duration!("10s"), async {
    let configs: Vec<TunnelInterfaceConfig> = serde_json::from_str(
      r#"[
        {"address": "127.0.0.1"},
        {"address": "127.0.0.2", "metered": true}
      ]"#,
    )?;
    let local_interfaces = build_local_interfaces(configs, Some("0.0.0.0:0".parse()?))?;
    let tcp0 = bind_tcp_listener(local_interfaces[0].listen_address.unwrap(), None)?;
    let tcp1 = bind_tcp_listener(local_interfaces[1].listen_address.unwrap(), None)?;
    let addr0 = tcp0.local_addr()?;
    let addr1 = tcp1.local_addr()?;

    let mut listener = MtConnectionsListener::<QuicBytesPacket>::from_bindings(vec![
      MtListenerBinding {
        interface_id: local_interfaces[0].id,
        local_interface: local_interfaces[0].with_resolved_port(addr0.port()),
        tcp_listener: tcp0,
        udp_socket: None,
      },
      MtListenerBinding {
        interface_id: local_interfaces[1].id,
        local_interface: local_interfaces[1].with_resolved_port(addr1.port()),
        tcp_listener: tcp1,
        udp_socket: None,
      },
    ]);

    let (client_mt, _plan_sender, _, _) =
      mt_connections_connect_multi::<QuicBytesPacket>(vec![MtDialTarget {
        local_interface: LocalInterface::default_implicit(),
        remote_address: addr0,
      }])
      .await?;

    let mut server_mt = listener.accept().await?;
    let session_handle = server_mt
      .take_listener_handle()
      .ok_or_else(|| anyhow::anyhow!("missing server session handle"))?;
    let server_metrics = server_mt.underlay_metrics();
    let token = [0x42u8; 32];
    session_handle.install_extend_plan(
      token,
      HashMap::from([(0, 0)]),
      HashMap::from([(0, 2)]),
      &server_metrics,
    );

    let probe_extend = |target: std::net::SocketAddr,
                        id: MtConnectionsId,
                        pair_id: u16,
                        extend_token: [u8; 32]| async move {
      let mut stream = TcpStream::connect(target).await?;
      let head =
        postcard::to_vec::<_, MT_CONNECTIONS_REQUEST_HEAD_BUFFER_SIZE>(&MtConnectionsRequestHead {
          magic: MtConnectionsMagic,
          data: MtConnectionsRequestHeadData::Extend {
            id,
            pair_id,
            token: extend_token,
          },
        })
        .unwrap();
      stream.write_all(&head).await?;
      let response = postcard_read_stream::<MtConnectionsResponseHead>(&mut stream).await?;
      anyhow::Ok((response.data, stream))
    };

    assert_eq!(
      probe_extend(addr0, client_mt.id(), 0, [0x99u8; 32])
        .await?
        .0,
      MtConnectionsResponseHeadData::AlreadyClosed,
      "invalid extend token must be rejected",
    );
    assert_eq!(
      probe_extend(addr1, client_mt.id(), 0, token).await?.0,
      MtConnectionsResponseHeadData::AlreadyClosed,
      "valid extend token on wrong server interface binding must be rejected",
    );
    let (valid_extend, _held_extend_stream) = probe_extend(addr0, client_mt.id(), 0, token).await?;
    assert_eq!(
      valid_extend,
      MtConnectionsResponseHeadData::Extended,
      "matching extend token on assigned server interface binding must succeed",
    );

    timeout(duration!("3s"), async {
      while server_metrics.available_path_count_in_group(0) < 2 {
        sleep(duration!("10ms")).await;
      }
    })
    .await?;

    assert_eq!(
      probe_extend(addr0, client_mt.id(), 0, token).await?.0,
      MtConnectionsResponseHeadData::AlreadyClosed,
      "extend beyond server per-pair max paths must be rejected",
    );

    let _client = client_mt;
    Ok(())
  })
  .await?
}

#[test]
fn bbr_capability_and_policer_loss_detector_only_trigger_on_sustained_bbrv1_loss() {
  use super::mt_connections::{
    PolicerLossDetector, PolicerLossTrigger, congestion_control_needs_policer_guard,
    is_bbr_module_version_loss_aware,
  };

  assert!(!is_bbr_module_version_loss_aware(None));
  assert!(!is_bbr_module_version_loss_aware(Some("")));
  assert!(!is_bbr_module_version_loss_aware(Some("1\n")));
  assert!(!is_bbr_module_version_loss_aware(Some("1.0")));
  assert!(is_bbr_module_version_loss_aware(Some("2\n")));
  assert!(is_bbr_module_version_loss_aware(Some("3")));
  assert!(is_bbr_module_version_loss_aware(Some("3.1-custom\n")));

  assert!(congestion_control_needs_policer_guard("bbr", false));
  assert!(!congestion_control_needs_policer_guard("bbr", true));
  assert!(!congestion_control_needs_policer_guard("bbr2", false));
  assert!(!congestion_control_needs_policer_guard("cubic", false));

  let mut detector = PolicerLossDetector::default();
  // Baseline sample (even with non-zero pre-established counters) never evaluates a window.
  assert_eq!(detector.observe(10, 5), None);

  // Sub-window traffic (< 250 data segments) waits without triggering.
  assert_eq!(detector.observe(259, 60), None);

  // Two high-loss windows (16% and 12%) followed by a normal WAN window (3.2%) reset cleanly.
  assert_eq!(detector.observe(260, 45), None); // delta = (250, 40) -> 16% (1/3)
  assert_eq!(detector.observe(510, 75), None); // delta = (250, 30) -> 12% (2/3)
  assert_eq!(detector.observe(760, 83), None); // delta = (250, 8)  -> 3.2% -> reset to 0/3!

  // Continuous 4% WAN loss across many windows never triggers.
  for step in 1..=6 {
    assert_eq!(detector.observe(760 + step * 300, 83 + step * 12), None);
  }

  // Three consecutive >= 250-segment windows with >= 10% retransmission rate (including u32 wrap)
  // trigger once and never re-trigger afterwards.
  let mut wrap_detector = PolicerLossDetector::default();
  let start_segs = u32::MAX - 100;
  let start_retrans = u32::MAX - 20;
  assert_eq!(wrap_detector.observe(start_segs, start_retrans), None);
  assert_eq!(
    wrap_detector.observe(start_segs.wrapping_add(250), start_retrans.wrapping_add(25)),
    None,
  );
  assert_eq!(
    wrap_detector.observe(start_segs.wrapping_add(550), start_retrans.wrapping_add(85)),
    None,
  );
  assert_eq!(
    wrap_detector.observe(start_segs.wrapping_add(850), start_retrans.wrapping_add(130)),
    Some(PolicerLossTrigger {
      window_data_segs: 300,
      window_retrans: 45,
    }),
  );
  assert_eq!(
    wrap_detector.observe(
      start_segs.wrapping_add(1_200),
      start_retrans.wrapping_add(250)
    ),
    None,
  );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn live_socket_switches_congestion_control_to_cubic_and_tracks_data_segs_out()
-> anyhow::Result<()> {
  use std::os::fd::AsRawFd;
  use tokio::io::{AsyncReadExt, AsyncWriteExt};

  use super::mt_connections::{
    read_mt_tcp_congestion, read_mt_tcp_info, set_mt_tcp_congestion,
  };

  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let addr = listener.local_addr()?;
  let (mut client, (mut server, _)) = tokio::try_join!(TcpStream::connect(addr), listener.accept())?;

  configure_mt_tcp_stream(&client)?;
  let client_fd = client.as_raw_fd();
  let initial_cc = read_mt_tcp_congestion(client_fd)?;
  assert!(!initial_cc.is_empty());

  set_mt_tcp_congestion(client_fd, b"cubic")?;
  assert_eq!(read_mt_tcp_congestion(client_fd)?, "cubic");

  let before = read_mt_tcp_info(client_fd)?;
  client.write_all(&[0x5au8; 8_192]).await?;
  let mut sink = [0u8; 8_192];
  server.read_exact(&mut sink).await?;

  let after = read_mt_tcp_info(client_fd)?;
  assert!(
    after.data_segs_out > before.data_segs_out,
    "TCP_INFO data_segs_out must advance after sending payload (before={}, after={})",
    before.data_segs_out,
    after.data_segs_out,
  );

  Ok(())
}
