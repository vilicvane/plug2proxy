#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use lits::duration;
  use tokio::{net::TcpListener, sync::oneshot, task::JoinSet, time::sleep};

  use crate::qomt_tunnel::{bytes_packet::BytesPacket, *};

  #[tokio::test]
  #[test_log::test]
  async fn test_mt_connections_connect() -> anyhow::Result<()> {
    let (listener_ready_sender, listener_ready_receiver) = oneshot::channel();

    tokio::try_join!(
      async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;

        let address = listener.local_addr()?;

        let mut listener = MtConnectionsListener::<BytesPacket>::new(listener);

        listener_ready_sender.send(address).unwrap();

        let mut mt_connections = listener.accept().await?;

        let mut join_set = JoinSet::new();

        join_set.spawn(async {
          mt_connections
            .send(b"hello from listener".to_vec().into())
            .await?;

          let packets = mt_connections.collect::<Vec<_>>().await;

          assert_eq!(*packets[0], b"hello from connect 1");
          assert_eq!(*packets[1], b"hello from connect 2");

          anyhow::Ok(())
        });

        join_set.spawn(async move {
          listener.accept().await?;

          anyhow::bail!("only meant to poll the listener");
        });

        join_set.join_next().await.unwrap()??;

        anyhow::Ok(())
      },
      async {
        let address = listener_ready_receiver.await?;

        let (mut mt_connections, extend_signal_sender) =
          mt_connections_connect::<BytesPacket>(address, 2).await?;

        let packet = mt_connections.next().await.unwrap();

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
}
