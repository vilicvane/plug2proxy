#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use lits::duration;
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
      TcpListener,
      tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::oneshot,
    task::JoinSet,
    time::sleep,
  };

  use crate::qomt_tunnel::*;

  #[tokio::test]
  #[test_log::test]
  async fn test_mt_connections_connect() -> anyhow::Result<()> {
    let (listener_ready_sender, listener_ready_receiver) = oneshot::channel();

    tokio::try_join!(
      async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;

        let address = listener.local_addr()?;

        let mut listener = MtConnectionsListener::<TestPacket>::new(listener);

        listener_ready_sender.send(address).unwrap();

        let mut mt_connections = listener.accept().await?;

        let mut join_set = JoinSet::new();

        join_set.spawn(async {
          mt_connections
            .send(TestPacket(b"hello from listener".to_vec()))
            .await?;

          let packets = mt_connections.collect::<Vec<_>>().await;

          assert_eq!(&packets[0].0, b"hello from connect 1");
          assert_eq!(&packets[1].0, b"hello from connect 2");

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
          mt_connections_connect::<TestPacket>(address, 2).await?;

        let packet = mt_connections.next().await.unwrap();

        assert_eq!(&packet.0, b"hello from listener");

        extend_signal_sender.send(()).unwrap();

        sleep(duration!("100ms")).await;

        assert_eq!(mt_connections.connection_count(), 2);

        mt_connections
          .send(TestPacket(b"hello from connect 1".to_vec()))
          .await?;

        mt_connections
          .send(TestPacket(b"hello from connect 2".to_vec()))
          .await?;

        anyhow::Ok(())
      },
    )?;

    Ok(())
  }

  #[derive(Debug)]
  struct TestPacket(Vec<u8>);

  impl MtConnectionsPacket for TestPacket {
    async fn read_next_packet(stream: &mut OwnedReadHalf) -> Result<Option<Self>, std::io::Error> {
      async {
        let length = stream.read_u32().await?;
        let mut buffer = vec![0; length as usize];
        stream.read_exact(&mut buffer).await?;

        Ok(Some(Self(buffer)))
      }
      .await
      .or_else(|error: std::io::Error| match error.kind() {
        std::io::ErrorKind::UnexpectedEof => Ok(None),
        _ => Err(error),
      })
    }

    async fn write_packet(stream: &mut OwnedWriteHalf, packet: Self) -> Result<(), std::io::Error> {
      stream.write_u32(packet.0.len() as u32).await?;
      stream.write_all(&packet.0).await?;
      Ok(())
    }
  }
}
