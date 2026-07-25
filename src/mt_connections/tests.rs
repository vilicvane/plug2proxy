use std::{sync::LazyLock, time::Instant};

use futures::{SinkExt, StreamExt};
use lits::duration;
use lowkit::SelfWrapExt;
use rand::Rng;
use socket2::SockRef;
use tokio::{
  io::copy_bidirectional,
  net::{TcpListener, TcpStream},
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

#[tokio::test]
async fn configures_tcp_liveness_detection() -> anyhow::Result<()> {
  let listener = TcpListener::bind("127.0.0.1:0").await?;
  let address = listener.local_addr()?;

  let connect = TcpStream::connect(address);
  let accept = listener.accept();
  let (client_stream, _) = tokio::try_join!(connect, accept)?;

  configure_mt_tcp_stream(&client_stream)?;

  let socket = SockRef::from(&client_stream);
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

      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(listener);

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
      let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(backend_listener);
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
