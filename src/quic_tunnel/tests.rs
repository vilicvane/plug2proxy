use futures::{SinkExt, StreamExt};
use lits::{bytes, duration};
use lowkit::SelfWrapExt;
use rand::Rng;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
  time::sleep,
};

use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  mt_connections::{MtBytesPacket, MtConnectionsListener, mt_connections_connect},
  test::test_dir,
};

use super::*;

#[tokio::test]
#[test_log::test]
async fn test_quic_connection() -> anyhow::Result<()> {
  let test_dir = test_dir();

  let ca_pem_file_path = generate_ca_pem_file(&test_dir).await?;

  let hub_pem_file_path = generate_node_pem_file(&test_dir, "hub").await?;
  let out_pem_file_path = generate_node_pem_file(&test_dir, "out").await?;

  let mut hub_quiche_config = create_quiche_config(&hub_pem_file_path, &ca_pem_file_path)?;
  let mut out_quiche_config = create_quiche_config(&out_pem_file_path, &ca_pem_file_path)?;

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<MtBytesPacket>(16);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<MtBytesPacket>(16);

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

  let mut random_data_1 = vec![0u8; bytes!("8 MiB") as usize];
  let mut random_data_2 = vec![0u8; bytes!("8 MiB") as usize];

  rand::rng().fill(&mut random_data_1[..]);
  rand::rng().fill(&mut random_data_2[..]);

  tokio::try_join!(
    async {
      out_quic_connection.established().await;

      {
        let mut stream = out_quic_connection.open_stream();

        stream.write_all(&random_data_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, random_data_2);
      }

      {
        let mut stream = out_quic_connection.accept_stream().await.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, random_data_1);

        stream.write_all(&random_data_2).await?;
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

        assert_eq!(data, random_data_1);

        stream.write_all(&random_data_2).await?;
        stream.shutdown().await?;
      }

      {
        let mut stream = hub_quic_connection.open_stream();

        stream.write_all(&random_data_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, random_data_2);
      }

      anyhow::Ok(())
    },
  )?;

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_qomt_connection() -> anyhow::Result<()> {
  let test_dir = test_dir();

  let ca_pem_file_path = generate_ca_pem_file(&test_dir).await?;

  let hub_pem_file_path = generate_node_pem_file(&test_dir, "hub").await?;
  let out_pem_file_path = generate_node_pem_file(&test_dir, "out").await?;

  let mut hub_quiche_config = create_quiche_config(&hub_pem_file_path, &ca_pem_file_path)?;
  let mut out_quiche_config = create_quiche_config(&out_pem_file_path, &ca_pem_file_path)?;

  let mut random_data_1 = vec![0u8; bytes!("1 KiB") as usize];
  let mut random_data_2 = vec![0u8; bytes!("1 KiB") as usize];

  rand::rng().fill(&mut random_data_1[..]);
  rand::rng().fill(&mut random_data_2[..]);

  let random_data_1 = random_data_1.arc();
  let random_data_2 = random_data_2.arc();

  let listener = TcpListener::bind("127.0.0.1:0").await?;

  let address = listener.local_addr()?;

  tokio::try_join!(
    async {
      let random_data_1 = random_data_1.clone();
      let random_data_2 = random_data_2.clone();

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

          assert_eq!(data, *random_data_1);

          stream.write_all(&random_data_2).await?;
          stream.shutdown().await?;
        }

        {
          let mut stream = hub_qomt_connection.open_stream();

          stream.write_all(&random_data_1).await?;
          stream.shutdown().await?;

          let mut data = Vec::new();

          stream.read_to_end(&mut data).await?;

          assert_eq!(data, *random_data_2);
        }

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
        mt_connections_connect::<MtBytesPacket>(address, 2).await?;

      let connection_id = quiche::ConnectionId::from_vec(rand::random::<[u8; 20]>().to_vec());

      out_mt_connections
        .send(connection_id.to_vec().into())
        .await?;

      let mut out_qomt_connection =
        QuicConnection::connect(&connection_id, &mut out_quiche_config, out_mt_connections);

      out_qomt_connection.established().await;

      {
        let mut stream = out_qomt_connection.open_stream();

        stream.write_all(&random_data_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *random_data_2);
      }

      extend_signal_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("Error sending extend signal"))?;

      {
        let mut stream = out_qomt_connection.accept_stream().await.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert_eq!(data, *random_data_1);

        stream.write_all(&random_data_2).await?;
        stream.shutdown().await?;
      }

      sleep(duration!("100ms")).await;

      anyhow::Ok(())
    },
  )?;

  Ok(())
}
