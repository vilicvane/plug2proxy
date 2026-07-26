use std::{net::SocketAddr, ops::Deref};

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use tokio::{
  io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
  time::timeout,
};

use crate::{
  mt_connections::{
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT, MtConnections, MtConnectionsPacket, mt_connections_connect,
  },
  quic_connection::{MAX_DATAGRAM_SIZE, QuicBytesPacket, QuicConnection},
};

pub const MAX_PENDING_QOMT_HANDSHAKES: usize = 64;

impl MtConnectionsPacket for QuicBytesPacket {
  fn len(&self) -> usize {
    self.deref().len()
  }

  async fn read_next_packet(
    stream: &mut (dyn AsyncRead + Unpin + Send),
  ) -> Result<Option<Self>, std::io::Error> {
    async {
      let length = stream.read_u32().await? as usize;

      if length > MAX_DATAGRAM_SIZE {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          format!("QUIC packet length {length} exceeds maximum"),
        ));
      }

      let mut buffer = vec![0; length];
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

pub async fn qomt_connect(
  quiche_config: &mut quiche::Config,
  address: SocketAddr,
  connections: usize,
) -> anyhow::Result<QuicConnection> {
  let (mut mt_connections, extend_signal_sender) =
    mt_connections_connect::<QuicBytesPacket>(address, connections)
      .await
      .context("failed to create mTCP connections.")?;

  let connection_id = QuicConnection::generate_connection_id();

  mt_connections.send(connection_id.to_vec().into()).await?;

  let qomt_connection = QuicConnection::connect(&connection_id, quiche_config, mt_connections);

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    qomt_connection.established(),
  )
  .await
  .context("timed out establishing QUIC connection")??;

  extend_signal_sender.send(()).ok();

  Ok(qomt_connection)
}

pub async fn qomt_accept(
  quiche_config: &mut quiche::Config,
  mut mt_connections: MtConnections<QuicBytesPacket>,
) -> anyhow::Result<QuicConnection> {
  let first_packet = timeout(MT_CONNECTIONS_HANDSHAKE_TIMEOUT, mt_connections.next())
    .await
    .context("timed out waiting for QUIC connection ID")?
    .ok_or_else(|| anyhow::anyhow!("missing first packet (QUIC connection ID)"))?;

  anyhow::ensure!(
    first_packet.len() == quiche::MAX_CONN_ID_LEN,
    "invalid QUIC connection ID length: expected {}, got {}",
    quiche::MAX_CONN_ID_LEN,
    first_packet.len()
  );

  let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());
  let qomt_connection = QuicConnection::accept(&connection_id, quiche_config, mt_connections);

  timeout(
    MT_CONNECTIONS_HANDSHAKE_TIMEOUT,
    qomt_connection.established(),
  )
  .await
  .context("timed out establishing QUIC connection")??;

  Ok(qomt_connection)
}
