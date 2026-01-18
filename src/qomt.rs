use std::ops::Deref;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{mt_connections::MtConnectionsPacket, quic_connection::QuicBytesPacket};

impl MtConnectionsPacket for QuicBytesPacket {
  fn len(&self) -> usize {
    self.deref().len()
  }

  async fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> Result<Option<Self>, std::io::Error> {
    async {
      let length = stream.read_u32().await?;
      let mut buffer = vec![0; length as usize];
      stream.read_exact(&mut buffer).await?;

      Ok(Some(buffer.into()))
    }
    .await
    .or_else(|error: std::io::Error| match error.kind() {
      std::io::ErrorKind::UnexpectedEof => Ok(None),
      _ => Err(error),
    })
  }

  async fn write_packet(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    packet: Self,
  ) -> Result<(), std::io::Error> {
    stream.write_u32(packet.len() as u32).await?;
    stream.write_all(packet.deref()).await?;
    Ok(())
  }
}
