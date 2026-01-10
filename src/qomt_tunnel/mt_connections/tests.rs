#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
      TcpListener,
      tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::oneshot,
  };

  use crate::qomt_tunnel::*;

  #[tokio::test]
  async fn test_mt_connections_connect() -> anyhow::Result<()> {
    let (listener_ready_sender, listener_ready_receiver) = oneshot::channel();

    tokio::try_join!(
      async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;

        let address = listener.local_addr()?;

        let mut listener = MtConnectionsListener::<TestPacket>::new(listener);

        listener_ready_sender.send(address).unwrap();

        let mut mt_connections = listener.accept().await?;

        mt_connections
          .send(TestPacket(b"hello from listener".to_vec()))
          .await?;

        let packet = mt_connections.next().await.unwrap();

        assert_eq!(&packet.0, b"hello from connect");

        anyhow::Ok(())
      },
      async {
        let address = listener_ready_receiver.await?;

        let (mut mt_connections, _) = mt_connections_connect::<TestPacket>(address, 2).await?;

        let packet = mt_connections.next().await.unwrap();

        assert_eq!(&packet.0, b"hello from listener");

        mt_connections
          .send(TestPacket(b"hello from connect".to_vec()))
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
      let length = stream.read_u32().await?;
      let mut buffer = vec![0; length as usize];
      stream.read_exact(&mut buffer).await?;
      Ok(Some(Self(buffer)))
    }

    async fn write_packet(stream: &mut OwnedWriteHalf, packet: Self) -> Result<(), std::io::Error> {
      stream.write_u32(packet.0.len() as u32).await?;
      stream.write_all(&packet.0).await?;
      Ok(())
    }
  }
}
