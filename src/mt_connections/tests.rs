use std::{sync::LazyLock, time::Instant};

use futures::{SinkExt, StreamExt};
use lits::{bytes, duration};
use lowkit::SelfWrapExt;
use rand::Rng;
use tokio::{net::TcpListener, sync::oneshot, time::sleep};

use super::*;

static RANDOM_DATA_1: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; bytes!("8 MiB") as usize];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

static RANDOM_DATA_2: LazyLock<Vec<u8>> = LazyLock::new(|| {
  let mut random_data = vec![0u8; bytes!("8 MiB") as usize];
  rand::rng().fill(&mut random_data[..]);
  random_data
});

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

      let mut listener = MtConnectionsListener::<MtBytesPacket>::new(listener);

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
        mt_connections_connect::<MtBytesPacket>(address, 2).await?;

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
