use std::{path::PathBuf, sync::LazyLock};

use futures::{SinkExt, StreamExt};
use lits::bytes;
use rand::Rng;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
  sync::oneshot,
};

use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  mt_connections::{MtBytesPacket, MtConnectionsListener, mt_connections_connect},
  test::test_dir,
};

use super::*;

// Cache generated cert paths to avoid regenerating across tests.
static QUICHE_CERT_PATHS: tokio::sync::OnceCell<(PathBuf, PathBuf, PathBuf)> =
  tokio::sync::OnceCell::const_new();

async fn get_quiche_configs() -> anyhow::Result<[quiche::Config; 2]> {
  let (ca_pem_file_path, hub_pem_file_path, out_pem_file_path) = QUICHE_CERT_PATHS
    .get_or_try_init(|| async {
      let test_dir = test_dir();

      let ca_pem_file_path = generate_ca_pem_file(&test_dir).await?;

      let hub_pem_file_path = generate_node_pem_file(&test_dir, "hub").await?;
      let out_pem_file_path = generate_node_pem_file(&test_dir, "out").await?;

      anyhow::Ok((ca_pem_file_path, hub_pem_file_path, out_pem_file_path))
    })
    .await?
    .clone();

  Ok([
    create_quiche_config(&hub_pem_file_path, &ca_pem_file_path)?,
    create_quiche_config(&out_pem_file_path, &ca_pem_file_path)?,
  ])
}

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

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn test_init() -> anyhow::Result<()> {
  // Avoid confusing test duration as it takes some time.

  let _ = get_quiche_configs().await?;

  let _ = *RANDOM_DATA_1;
  let _ = *RANDOM_DATA_2;

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_quic_connection() -> anyhow::Result<()> {
  let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<MtBytesPacket>(0);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<MtBytesPacket>(0);

  let connection_id = QuicConnection::generate_connection_id();

  let mut out_quic_connection = QuicConnection::connect_with_sink_and_stream(
    &connection_id,
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    hub_to_out_packet_receiver.into_stream(),
  );

  let mut hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
    out_quic_connection.id(),
    &mut hub_quiche_config,
    hub_to_out_packet_sender.into_sink(),
    out_to_hub_packet_receiver.into_stream(),
  );

  tokio::try_join!(
    async {
      out_quic_connection.established().await;

      {
        let mut stream = out_quic_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_2);
      }

      {
        let mut stream = out_quic_connection.accept_stream().await.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;
      }

      anyhow::Ok(())
    },
    async {
      hub_quic_connection.established().await;

      {
        let mut stream = hub_quic_connection.accept_stream().await.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;
      }

      {
        let mut stream = hub_quic_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_2);
      }

      anyhow::Ok(())
    },
  )?;

  Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn test_qomt_connection() -> anyhow::Result<()> {
  let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

  let listener = TcpListener::bind("127.0.0.1:0").await?;

  let address = listener.local_addr()?;

  let (read_complete_sender, read_complete_receiver) = oneshot::channel();

  tokio::try_join!(
    async {
      let mut hub_mt_connections_listener = MtConnectionsListener::<MtBytesPacket>::new(listener);

      let mut hub_mt_connections = hub_mt_connections_listener.accept().await?;

      let main_future = async {
        let first_packet = hub_mt_connections
          .next()
          .await
          .ok_or(anyhow::anyhow!("No packet"))?;

        let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

        let mut hub_qomt_connection =
          QuicConnection::accept(&connection_id, &mut hub_quiche_config, hub_mt_connections);

        hub_qomt_connection.established().await;

        {
          let mut stream = hub_qomt_connection.accept_stream().await.unwrap();

          let mut data = Vec::new();

          stream.read_to_end(&mut data).await?;

          assert!(data == *RANDOM_DATA_1);

          stream.write_all(&RANDOM_DATA_2).await?;
          stream.shutdown().await?;
        }

        log::debug!("hub accept stream ended");

        {
          let mut stream = hub_qomt_connection.open_stream();

          stream.write_all(&RANDOM_DATA_1).await?;
          stream.shutdown().await?;

          let mut data = Vec::new();

          stream.read_to_end(&mut data).await?;

          assert!(data == *RANDOM_DATA_2);
        }

        read_complete_sender.send(()).unwrap();

        log::debug!("hub open stream ended");

        anyhow::Ok(())
      };

      let listener_future = async {
        hub_mt_connections_listener.accept().await?;

        anyhow::Ok(())
      };

      tokio::select!(
        result = main_future => result,
        result = listener_future => result.and_then(|_| Err(anyhow::anyhow!("Listener future completed"))),
      )?;

      anyhow::Ok(())
    },
    async {
      let (mut out_mt_connections, extend_signal_sender) =
        mt_connections_connect::<MtBytesPacket>(address, 4).await?;

      extend_signal_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("Error sending extend signal"))?;

      let connection_id = QuicConnection::generate_connection_id();

      out_mt_connections
        .send(connection_id.to_vec().into())
        .await?;

      let mut out_qomt_connection =
        QuicConnection::connect(&connection_id, &mut out_quiche_config, out_mt_connections);

      out_qomt_connection.established().await;

      {
        let mut stream = out_qomt_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_2);
      }

      log::debug!("out open stream ended");

      {
        let mut stream = out_qomt_connection.accept_stream().await.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;

        read_complete_receiver.await?;
      }

      log::debug!("out accept stream ended");

      anyhow::Ok(())
    },
  )?;

  Ok(())
}
