#[cfg(test)]
mod tests {
  use futures::{SinkExt, StreamExt};
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
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

        let mut listener = MtConnectionsListener::new(listener);

        listener_ready_sender.send(address).unwrap();

        let mut mt_connections = listener.accept().await?;

        mt_connections.send(b"hello from listener".to_vec()).await?;

        let packet = mt_connections.next().await.unwrap();

        println!("listener packet: {:?}", packet);

        assert_eq!(&packet, b"hello from connect");

        anyhow::Ok(())
      },
      async {
        let address = listener_ready_receiver.await?;

        let (mut mt_connections, _) = mt_connections_connect(address, 2).await?;

        let packet = mt_connections.next().await.unwrap();

        println!("connect packet: {:?}", packet);

        assert_eq!(&packet, b"hello from listener");

        mt_connections.send(b"hello from connect".to_vec()).await?;

        anyhow::Ok(())
      },
    )?;

    Ok(())
  }
}
