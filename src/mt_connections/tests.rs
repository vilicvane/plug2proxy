use std::time::Instant;

use futures::{SinkExt, StreamExt};
use lits::duration;
use lowkit::SelfWrapExt;
use tokio::{net::TcpListener, sync::oneshot, time::sleep};

use super::*;

#[tokio::test]
#[test_log::test]
async fn test_mt_connections() -> anyhow::Result<()> {
  let (listener_ready_sender, listener_ready_receiver) = oneshot::channel();

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

        mt_connections
          .send(b"hello from listener".to_vec().into())
          .await?;

        let packets = mt_connections.collect::<Vec<_>>().await;

        assert_eq!(*packets[0], b"hello from connect 1");
        assert_eq!(*packets[1], b"hello from connect 2");

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

      let packet = mt_connections.next().await.unwrap();

      log::debug!(
        "packet 1 received after {:?}",
        instant.lock().unwrap().unwrap().elapsed()
      );

      assert_eq!(*packet, b"hello from listener");

      extend_signal_sender.send(()).unwrap();

      sleep(duration!("100ms")).await;

      assert_eq!(mt_connections.connection_count(), 2);

      mt_connections
        .send(b"hello from connect 1".to_vec().into())
        .await?;

      mt_connections
        .send(b"hello from connect 2".to_vec().into())
        .await?;

      anyhow::Ok(())
    },
  )?;

  Ok(())
}
