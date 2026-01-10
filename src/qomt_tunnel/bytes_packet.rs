use std::ops::{Deref, DerefMut};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::qomt_tunnel::MtConnectionsPacket;

#[derive(Debug)]
pub struct BytesPacket(Vec<u8>);

impl From<Vec<u8>> for BytesPacket {
  fn from(value: Vec<u8>) -> Self {
    Self(value)
  }
}

impl Deref for BytesPacket {
  type Target = Vec<u8>;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl DerefMut for BytesPacket {
  fn deref_mut(&mut self) -> &mut Self::Target {
    &mut self.0
  }
}

impl MtConnectionsPacket for BytesPacket {
  async fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> Result<Option<Self>, std::io::Error> {
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

  async fn write_packet(
    stream: &mut (dyn AsyncWrite + Unpin + Send),
    packet: Self,
  ) -> Result<(), std::io::Error> {
    stream.write_u32(packet.0.len() as u32).await?;
    stream.write_all(&packet.0).await?;
    Ok(())
  }
}
