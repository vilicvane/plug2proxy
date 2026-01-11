use lits::bytes;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  qomt_tunnel::bytes_packet::BytesPacket,
  test::test_dir,
};

use super::*;

#[tokio::test]
#[test_log::test]
async fn test_qomt_connection() -> anyhow::Result<()> {
  let test_dir = test_dir();

  let ca_pem_file_path = generate_ca_pem_file(&test_dir).await?;

  let hub_pem_file_path = generate_node_pem_file(&test_dir, "hub").await?;
  let out_pem_file_path = generate_node_pem_file(&test_dir, "out").await?;

  let mut hub_quiche_config = create_quiche_config(&hub_pem_file_path, &ca_pem_file_path)?;
  let mut out_quiche_config = create_quiche_config(&out_pem_file_path, &ca_pem_file_path)?;

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<BytesPacket>(16);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<BytesPacket>(16);

  let mut out_qomt_connection = QomtConnection::connect(
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    hub_to_out_packet_receiver.into_stream(),
  );

  let mut hub_qomt_connection = QomtConnection::accept(
    out_qomt_connection.id(),
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
      out_qomt_connection.established().await;

      let mut stream = out_qomt_connection.open_stream();

      stream.write_all(&random_data_1).await?;
      stream.shutdown().await?;

      let mut data = Vec::new();

      stream.read_to_end(&mut data).await?;

      assert_eq!(data, random_data_2);

      anyhow::Ok(())
    },
    async {
      hub_qomt_connection.established().await;

      let mut stream = hub_qomt_connection.accept_stream().await.unwrap();

      let mut data = Vec::new();

      stream.read_to_end(&mut data).await?;

      assert_eq!(data, random_data_1);

      stream.write_all(&random_data_2).await?;
      stream.shutdown().await?;

      anyhow::Ok(())
    },
  )?;

  Ok(())
}
