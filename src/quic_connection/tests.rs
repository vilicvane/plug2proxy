use std::{
  path::PathBuf,
  sync::{
    Arc, LazyLock,
    atomic::{self, AtomicUsize},
  },
};

use futures::{SinkExt, StreamExt};
use lits::{bytes, duration};
use lowkit::SelfWrapExt;
use rand::Rng;
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
  sync::oneshot,
  task::JoinSet,
  time::{sleep, timeout},
};

use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  mt_connections::{MtConnectionsListener, mt_connections_connect},
  quic_connection::{
    MAX_UDP_DATAGRAM_SIZE, QuicBytesPacket, QuicConnection, QuicConnectionError,
    QuicDatagramSendError, create_quiche_config, create_udp_quiche_config,
  },
  test::test_dir,
};

static QUICHE_CERT_PATHS: tokio::sync::OnceCell<[PathBuf; 2]> = tokio::sync::OnceCell::const_new();

async fn get_quiche_cert_paths() -> anyhow::Result<[PathBuf; 2]> {
  QUICHE_CERT_PATHS
    .get_or_try_init(|| async {
      let test_dir = test_dir();

      generate_ca_pem_file(&test_dir).await?;

      let hub_pem_file_path = generate_node_pem_file(&test_dir, "hub", true).await?;
      let out_pem_file_path = generate_node_pem_file(&test_dir, "out", true).await?;

      anyhow::Ok([hub_pem_file_path, out_pem_file_path])
    })
    .await?
    .clone()
    .wrap_ok()
}

pub(crate) async fn get_quiche_configs() -> anyhow::Result<[quiche::Config; 2]> {
  let [hub_pem_file_path, out_pem_file_path] = get_quiche_cert_paths().await?;

  Ok([
    create_quiche_config(&hub_pem_file_path)?,
    create_quiche_config(&out_pem_file_path)?,
  ])
}

pub(crate) async fn get_udp_quiche_configs() -> anyhow::Result<[quiche::Config; 2]> {
  let [hub_pem_file_path, out_pem_file_path] = get_quiche_cert_paths().await?;

  Ok([
    create_udp_quiche_config(&hub_pem_file_path)?,
    create_udp_quiche_config(&out_pem_file_path)?,
  ])
}

static WRONG_CERT_PATH: tokio::sync::OnceCell<PathBuf> = tokio::sync::OnceCell::const_new();

async fn get_wrong_cert_path() -> anyhow::Result<PathBuf> {
  WRONG_CERT_PATH
    .get_or_try_init(|| async {
      let test_dir = test_dir().join("wrong");

      generate_ca_pem_file(&test_dir).await?;

      generate_node_pem_file(&test_dir, "node", true).await
    })
    .await?
    .clone()
    .wrap_ok()
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

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);

  let connection_id = QuicConnection::generate_connection_id();

  let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
    &connection_id,
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    hub_to_out_packet_receiver.into_stream(),
  );

  let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
    out_quic_connection.id(),
    &mut hub_quiche_config,
    hub_to_out_packet_sender.into_sink(),
    out_to_hub_packet_receiver.into_stream(),
  );

  tokio::try_join!(
    async {
      out_quic_connection.established().await?;

      {
        let mut stream = out_quic_connection.open_stream();

        stream.write_all(&RANDOM_DATA_1).await?;
        stream.shutdown().await?;

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_2);
      }

      {
        let mut stream = out_quic_connection.accept_stream().await?.unwrap();

        let mut data = Vec::new();

        stream.read_to_end(&mut data).await?;

        assert!(data == *RANDOM_DATA_1);

        stream.write_all(&RANDOM_DATA_2).await?;
        stream.shutdown().await?;
      }

      anyhow::Ok(())
    },
    async {
      hub_quic_connection.established().await?;

      {
        let mut stream = hub_quic_connection.accept_stream().await?.unwrap();

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
async fn quic_datagrams_are_negotiated_and_flow_bidirectionally() -> anyhow::Result<()> {
  timeout(duration!("5s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_udp_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(64);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(64);

    let connection_id = QuicConnection::generate_connection_id();
    let out_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );
    let hub_connection = QuicConnection::accept_with_sink_and_stream(
      out_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(out_connection.established(), hub_connection.established())?;

    let out_datagrams = out_connection.datagram_socket();
    let hub_datagrams = hub_connection.datagram_socket();
    let out_max = out_datagrams
      .max_writable_len()
      .ok_or_else(|| anyhow::anyhow!("client did not negotiate QUIC DATAGRAM"))?;
    let hub_max = hub_datagrams
      .max_writable_len()
      .ok_or_else(|| anyhow::anyhow!("server did not negotiate QUIC DATAGRAM"))?;

    assert!(out_max > 0 && out_max < MAX_UDP_DATAGRAM_SIZE);
    assert!(hub_max > 0 && hub_max < MAX_UDP_DATAGRAM_SIZE);

    let out_to_hub = vec![0xa5; out_max];
    let hub_to_out = b"hub-to-out-datagram".to_vec();
    out_datagrams.try_send(&out_to_hub)?;
    hub_datagrams.try_send(&hub_to_out)?;

    let (received_by_hub, received_by_out) = tokio::try_join!(
      async {
        timeout(duration!("1s"), hub_datagrams.recv())
          .await
          .map_err(|_| anyhow::anyhow!("server did not receive client DATAGRAM"))?
          .ok_or_else(|| anyhow::anyhow!("server DATAGRAM socket closed"))
      },
      async {
        timeout(duration!("1s"), out_datagrams.recv())
          .await
          .map_err(|_| anyhow::anyhow!("client did not receive server DATAGRAM"))?
          .ok_or_else(|| anyhow::anyhow!("client DATAGRAM socket closed"))
      },
    )?;

    assert_eq!(received_by_hub, out_to_hub);
    assert_eq!(received_by_out, hub_to_out);

    let out_metrics = out_datagrams.path_metrics().unwrap();
    let hub_metrics = hub_datagrams.path_metrics().unwrap();
    assert!(out_metrics.dgram_sent >= 1 && out_metrics.dgram_recv >= 1);
    assert!(hub_metrics.dgram_sent >= 1 && hub_metrics.dgram_recv >= 1);

    assert!(matches!(
      out_datagrams.try_send(&vec![0; out_max + 1]),
      Err(QuicDatagramSendError::TooLarge {
        length,
        maximum: Some(maximum),
      }) if length == out_max + 1 && maximum == out_max
    ));

    drop(out_connection);
    assert_eq!(out_datagrams.max_writable_len(), None);
    assert_eq!(out_datagrams.path_metrics(), None);
    assert!(matches!(
      out_datagrams.try_send(b"after-owner-drop"),
      Err(QuicDatagramSendError::Unavailable),
    ));
    assert_eq!(
      timeout(duration!("100ms"), out_datagrams.recv()).await?,
      None,
    );

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn main_quic_config_does_not_negotiate_datagrams() -> anyhow::Result<()> {
  timeout(duration!("5s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(64);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(64);

    let connection_id = QuicConnection::generate_connection_id();
    let out_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );
    let hub_connection = QuicConnection::accept_with_sink_and_stream(
      out_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(out_connection.established(), hub_connection.established())?;

    let out_datagrams = out_connection.datagram_socket();
    let hub_datagrams = hub_connection.datagram_socket();
    assert_eq!(out_datagrams.max_writable_len(), None);
    assert_eq!(hub_datagrams.max_writable_len(), None);
    assert!(matches!(
      out_datagrams.try_send(b"disabled"),
      Err(QuicDatagramSendError::Unavailable)
    ));
    assert!(matches!(
      hub_datagrams.try_send(b"disabled"),
      Err(QuicDatagramSendError::Unavailable)
    ));

    anyhow::Ok(())
  })
  .await?
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
      let mut hub_mt_connections_listener =
        MtConnectionsListener::<QuicBytesPacket>::new(listener, None);

      let mut hub_mt_connections = hub_mt_connections_listener.accept().await?;

      let main_future = async {
        let first_packet = hub_mt_connections
          .next()
          .await
          .ok_or(anyhow::anyhow!("No packet"))?;

        let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

        let hub_qomt_connection =
          QuicConnection::accept(&connection_id, &mut hub_quiche_config, hub_mt_connections);

        hub_qomt_connection.established().await?;

        {
          let mut stream = hub_qomt_connection.accept_stream().await?.unwrap();

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
        mt_connections_connect::<QuicBytesPacket>(address, 4).await?;

      extend_signal_sender
        .send(())
        .map_err(|_| anyhow::anyhow!("Error sending extend signal"))?;

      let connection_id = QuicConnection::generate_connection_id();

      out_mt_connections
        .send(connection_id.to_vec().into())
        .await?;

      let out_qomt_connection =
        QuicConnection::connect(&connection_id, &mut out_quiche_config, out_mt_connections);

      out_qomt_connection.established().await?;

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
        let mut stream = out_qomt_connection.accept_stream().await?.unwrap();

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

#[tokio::test]
#[test_log::test]
async fn test_client_verification() -> anyhow::Result<()> {
  let [mut hub_quiche_config, _] = get_quiche_configs().await?;

  let mut out_quiche_config = {
    let node_pem_file_path = get_wrong_cert_path().await?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.set_application_protos(&[b"p2p"])?;
    config.load_cert_chain_from_pem_file(node_pem_file_path.to_str().unwrap())?;
    config.load_priv_key_from_pem_file(node_pem_file_path.to_str().unwrap())?;
    config
  };

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);

  let connection_id = QuicConnection::generate_connection_id();

  let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
    &connection_id,
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    hub_to_out_packet_receiver.into_stream(),
  );

  let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
    out_quic_connection.id(),
    &mut hub_quiche_config,
    hub_to_out_packet_sender.into_sink(),
    out_to_hub_packet_receiver.into_stream(),
  );

  let (hub_rejected_sender, hub_rejected_receiver) = oneshot::channel();

  tokio::try_join!(
    async {
      let error = hub_quic_connection
        .established()
        .await
        .expect_err("Should fail to establish connection");

      assert!(matches!(
        error,
        QuicConnectionError::QuicheConnectionLocal(quiche::ConnectionError {
          is_app: false,
          error_code: 0x0133, // 0x0100 CRYPTO_ERROR + 0x33 certificate_unknown
          ..
        })
      ));

      hub_rejected_sender.send(()).unwrap();

      anyhow::Ok(())
    },
    async {
      let established_result = out_quic_connection.established().await;

      hub_rejected_receiver.await?;

      let error = match established_result {
        Err(error) => error,
        Ok(()) => out_quic_connection
          .accept_stream()
          .await
          .expect_err("peer certificate rejection should close the connection"),
      };

      assert!(matches!(
        error,
        QuicConnectionError::QuicheConnectionPeer(quiche::ConnectionError {
          is_app: false,
          error_code: 0x0133,
          ..
        })
      ));

      anyhow::Ok(())
    },
  )?;

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn transport_close_wakes_stream_waiters() -> anyhow::Result<()> {
  timeout(duration!("5s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );

    let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(
      out_quic_connection.established(),
      hub_quic_connection.established()
    )?;

    let mut out_stream = out_quic_connection.open_stream();
    out_stream.write_u8(1).await?;

    let mut hub_stream = hub_quic_connection
      .accept_stream()
      .await?
      .expect("test stream should arrive");
    assert_eq!(hub_stream.read_u8().await?, 1);

    drop(hub_quic_connection);

    timeout(duration!("1s"), out_stream.read_u8())
      .await
      .map_err(|_| anyhow::anyhow!("existing stream waiter was not woken after transport close"))?
      .expect_err("transport close should end the existing stream");

    let error = timeout(duration!("1s"), out_quic_connection.accept_stream())
      .await
      .map_err(|_| anyhow::anyhow!("stream waiter was not woken after transport close"))?
      .expect_err("transport close should be reported as an error");

    assert!(matches!(
      error,
      QuicConnectionError::UnderlyingTransportClosed
    ));

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test]
#[test_log::test]
async fn locally_opened_stream_can_wait_before_first_send() -> anyhow::Result<()> {
  timeout(duration!("5s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );

    let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(
      async {
        out_quic_connection.established().await?;

        let mut stream = out_quic_connection.open_stream();

        // Let the receive task run before stream_send() creates the stream in
        // quiche. This used to race into InvalidStreamState or a lost wakeup.
        tokio::task::yield_now().await;

        stream.write_all(b"request").await?;
        stream.shutdown().await?;

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        assert_eq!(response, b"response");

        anyhow::Ok(())
      },
      async {
        hub_quic_connection.established().await?;

        let mut stream = hub_quic_connection
          .accept_stream()
          .await?
          .ok_or_else(|| anyhow::anyhow!("missing peer stream"))?;

        let mut request = Vec::new();
        stream.read_to_end(&mut request).await?;
        assert_eq!(request, b"request");

        sleep(duration!("20ms")).await;
        stream.write_all(b"response").await?;
        stream.shutdown().await?;

        anyhow::Ok(())
      },
    )?;

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn dropped_stream_tasks_are_reaped() -> anyhow::Result<()> {
  timeout(duration!("10s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );

    let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(
      out_quic_connection.established(),
      hub_quic_connection.established()
    )?;

    for index in 0..32 {
      let mut stream = out_quic_connection.open_stream();

      if index % 2 == 0 {
        stream.write_all(b"request").await?;
      }

      drop(stream);
    }

    timeout(duration!("2s"), async {
      loop {
        if out_quic_connection.diagnostics().contains("streams=0 ") {
          break;
        }

        sleep(duration!("20ms")).await;
      }
    })
    .await
    .map_err(|_| {
      anyhow::anyhow!(
        "dropped stream tasks were not reaped: out=[{}] hub=[{}]",
        out_quic_connection.diagnostics(),
        hub_quic_connection.diagnostics(),
      )
    })?;

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn dropped_request_response_stream_tasks_are_reaped() -> anyhow::Result<()> {
  timeout(duration!("10s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    );

    let hub_quic_connection = QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    );

    tokio::try_join!(
      out_quic_connection.established(),
      hub_quic_connection.established()
    )?;

    let mut out_stream = out_quic_connection.open_stream();
    out_stream.write_all(b"request").await?;

    let mut hub_stream = hub_quic_connection
      .accept_stream()
      .await?
      .ok_or_else(|| anyhow::anyhow!("missing request stream"))?;
    let mut request = [0; 7];
    hub_stream.read_exact(&mut request).await?;
    assert_eq!(&request, b"request");

    hub_stream.write_all(b"response").await?;
    hub_stream.shutdown().await?;

    let hub_stream_task = tokio::spawn(async move {
      let mut request_tail = Vec::new();
      hub_stream.read_to_end(&mut request_tail).await?;
      anyhow::ensure!(request_tail.is_empty());

      anyhow::Ok(())
    });

    let mut response = Vec::new();
    out_stream.read_to_end(&mut response).await?;
    assert_eq!(response, b"response");
    drop(out_stream);
    hub_stream_task.await??;

    timeout(duration!("2s"), async {
      loop {
        if out_quic_connection.diagnostics().contains("streams=0 ")
          && hub_quic_connection.diagnostics().contains("streams=0 ")
        {
          break;
        }

        sleep(duration!("20ms")).await;
      }
    })
    .await
    .map_err(|_| {
      anyhow::anyhow!(
        "dropped request/response tasks were not reaped: out=[{}] hub=[{}]",
        out_quic_connection.diagnostics(),
        hub_quic_connection.diagnostics(),
      )
    })?;

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn concurrent_dropped_request_response_stream_tasks_are_reaped() -> anyhow::Result<()> {
  const STREAM_COUNT: usize = 256;

  timeout(duration!("20s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = Arc::new(QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      hub_to_out_packet_receiver.into_stream(),
    ));

    let hub_quic_connection = Arc::new(QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      out_to_hub_packet_receiver.into_stream(),
    ));

    tokio::try_join!(
      out_quic_connection.established(),
      hub_quic_connection.established()
    )?;

    tokio::try_join!(
      async {
        let mut tasks = JoinSet::new();

        for _ in 0..STREAM_COUNT {
          let connection = out_quic_connection.clone();

          tasks.spawn(async move {
            let mut stream = connection.open_stream();
            stream.write_all(b"request").await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            anyhow::ensure!(response == b"response");

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
      async {
        let mut tasks = JoinSet::new();

        for _ in 0..STREAM_COUNT {
          let connection = hub_quic_connection.clone();

          tasks.spawn(async move {
            let mut stream = connection
              .accept_stream()
              .await?
              .ok_or_else(|| anyhow::anyhow!("missing request stream"))?;
            let mut request = [0; 7];
            stream.read_exact(&mut request).await?;
            anyhow::ensure!(&request == b"request");
            stream.write_all(b"response").await?;

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
    )?;

    timeout(duration!("5s"), async {
      loop {
        if out_quic_connection.diagnostics().contains("streams=0 ")
          && hub_quic_connection.diagnostics().contains("streams=0 ")
        {
          break;
        }

        sleep(duration!("20ms")).await;
      }
    })
    .await
    .map_err(|_| {
      anyhow::anyhow!(
        "concurrent dropped request/response tasks were not reaped: out=[{}] hub=[{}]",
        out_quic_connection.diagnostics(),
        hub_quic_connection.diagnostics(),
      )
    })?;

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn concurrent_stream_fins_survive_delayed_transport() -> anyhow::Result<()> {
  const STREAM_COUNT: u8 = 32;

  timeout(duration!("30s"), async {
    let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

    let (hub_to_out_packet_sender, hub_to_out_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);
    let (out_to_hub_packet_sender, out_to_hub_packet_receiver) =
      flume::bounded::<QuicBytesPacket>(0);

    let delayed_hub_packets = hub_to_out_packet_receiver
      .into_stream()
      .then(|packet| async move {
        sleep(duration!("20ms")).await;
        packet
      });
    let delayed_out_packets = out_to_hub_packet_receiver
      .into_stream()
      .then(|packet| async move {
        sleep(duration!("20ms")).await;
        packet
      });

    let connection_id = QuicConnection::generate_connection_id();

    let out_quic_connection = Arc::new(QuicConnection::connect_with_sink_and_stream(
      &connection_id,
      &mut out_quiche_config,
      out_to_hub_packet_sender.into_sink(),
      Box::pin(delayed_hub_packets),
    ));

    let hub_quic_connection = Arc::new(QuicConnection::accept_with_sink_and_stream(
      out_quic_connection.id(),
      &mut hub_quiche_config,
      hub_to_out_packet_sender.into_sink(),
      Box::pin(delayed_out_packets),
    ));

    tokio::try_join!(
      out_quic_connection.established(),
      hub_quic_connection.established()
    )?;

    tokio::try_join!(
      async {
        let mut tasks = JoinSet::new();

        for value in 0..STREAM_COUNT {
          let connection = out_quic_connection.clone();

          tasks.spawn(async move {
            let mut stream = connection.open_stream();
            stream.write_all(&[value]).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            anyhow::ensure!(response == vec![value; 32]);

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
      async {
        let mut tasks = JoinSet::new();

        for _ in 0..STREAM_COUNT {
          let mut stream = hub_quic_connection
            .accept_stream()
            .await?
            .ok_or_else(|| anyhow::anyhow!("missing peer stream"))?;

          tasks.spawn(async move {
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;
            anyhow::ensure!(request.len() == 1);

            stream.write_all(&vec![request[0]; 32]).await?;
            stream.shutdown().await?;

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
    )?;

    anyhow::Ok(())
  })
  .await?
}

#[tokio::test(flavor = "multi_thread")]
#[test_log::test]
async fn concurrent_bulk_streams_survive_lossy_transport() -> anyhow::Result<()> {
  const BULK_STREAM_COUNT: usize = 1;
  const DROPPED_STREAM_COUNT: usize = 64;

  let [mut hub_quiche_config, mut out_quiche_config] = get_quiche_configs().await?;

  // Shrink flow-control windows so bulk streams congest and senders block
  // mid-transfer, matching production QOMT pressure.
  for config in [&mut hub_quiche_config, &mut out_quiche_config] {
    config.set_initial_max_data(bytes!("64 MiB"));
    config.set_initial_max_stream_data_bidi_local(bytes!("256 KiB"));
    config.set_initial_max_stream_data_bidi_remote(bytes!("256 KiB"));
    config.set_initial_max_stream_data_uni(bytes!("256 KiB"));
  }

  let (hub_to_out_packet_sender, hub_to_out_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);
  let (out_to_hub_packet_sender, out_to_hub_packet_receiver) = flume::bounded::<QuicBytesPacket>(0);

  // Deterministic 2% packet loss in both directions to exercise QUIC loss
  // recovery on multiplexed bulk streams.
  let lossy_transport = |receiver: flume::Receiver<QuicBytesPacket>| {
    let mut rng_state = 0x9e37_79b9_7f4a_7c15u64;

    Box::pin(receiver.into_stream().filter_map(move |packet| {
      rng_state ^= rng_state << 13;
      rng_state ^= rng_state >> 7;
      rng_state ^= rng_state << 17;

      let keep = rng_state % 50 != 0;

      async move { keep.then_some(packet) }
    }))
  };

  let lossy_hub_packets = lossy_transport(hub_to_out_packet_receiver);
  let lossy_out_packets = lossy_transport(out_to_hub_packet_receiver);

  let connection_id = QuicConnection::generate_connection_id();

  let out_quic_connection = Arc::new(QuicConnection::connect_with_sink_and_stream(
    &connection_id,
    &mut out_quiche_config,
    out_to_hub_packet_sender.into_sink(),
    lossy_hub_packets,
  ));

  let hub_quic_connection = Arc::new(QuicConnection::accept_with_sink_and_stream(
    out_quic_connection.id(),
    &mut hub_quiche_config,
    hub_to_out_packet_sender.into_sink(),
    lossy_out_packets,
  ));

  tokio::try_join!(
    out_quic_connection.established(),
    hub_quic_connection.established()
  )?;

  let bulk_completed = Arc::new(AtomicUsize::new(0));
  let server_completed = Arc::new(AtomicUsize::new(0));

  let work = async {
    tokio::try_join!(
      async {
        let mut tasks = JoinSet::new();

        // Bulk streams must transfer intact despite loss and churn.
        for _ in 0..BULK_STREAM_COUNT {
          let connection = out_quic_connection.clone();
          let bulk_completed = bulk_completed.clone();

          tasks.spawn(async move {
            let mut stream = connection.open_stream();
            stream.write_all(&RANDOM_DATA_1).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            anyhow::ensure!(response == *RANDOM_DATA_2);

            bulk_completed.fetch_add(1, atomic::Ordering::Relaxed);

            anyhow::Ok(())
          });
        }

        // Churn streams are dropped mid-transfer without shutdown, exercising
        // the drain/rearm/reap paths next to the bulk streams.
        for _ in 0..DROPPED_STREAM_COUNT {
          let connection = out_quic_connection.clone();

          tasks.spawn(async move {
            let mut stream = connection.open_stream();
            stream
              .write_all(&RANDOM_DATA_1[..bytes!("8 KiB") as usize])
              .await?;
            drop(stream);

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
      async {
        let mut tasks = JoinSet::new();

        for _ in 0..BULK_STREAM_COUNT + DROPPED_STREAM_COUNT {
          let connection = hub_quic_connection.clone();
          let server_completed = server_completed.clone();

          tasks.spawn(async move {
            let mut stream = connection
              .accept_stream()
              .await?
              .ok_or_else(|| anyhow::anyhow!("missing request stream"))?;

            let mut request = Vec::new();
            stream.read_to_end(&mut request).await?;

            if request == *RANDOM_DATA_1 {
              stream.write_all(&RANDOM_DATA_2).await?;
              stream.shutdown().await?;
            } else {
              // Dropped churn streams may already be stopped by the peer.
              _ = stream.write_all(&RANDOM_DATA_2).await;
            }

            server_completed.fetch_add(1, atomic::Ordering::Relaxed);

            anyhow::Ok(())
          });
        }

        while let Some(result) = tasks.join_next().await {
          result??;
        }

        anyhow::Ok(())
      },
    )
  };

  let progress = async {
    loop {
      sleep(duration!("15s")).await;

      eprintln!(
        "progress: bulk={}/{BULK_STREAM_COUNT} server={}/{}\n  out=[{}]\n  hub=[{}]",
        bulk_completed.load(atomic::Ordering::Relaxed),
        server_completed.load(atomic::Ordering::Relaxed),
        BULK_STREAM_COUNT + DROPPED_STREAM_COUNT,
        out_quic_connection.diagnostics(),
        hub_quic_connection.diagnostics(),
      );
    }
  };

  let work_result = tokio::select! {
    result = work => Some(result),
    _ = timeout(duration!("105s"), progress) => None,
  };

  let work_completed = work_result.is_some();

  if let Some(work_result) = work_result {
    work_result?;
  }

  let reap_result = timeout(duration!("10s"), async {
    loop {
      if out_quic_connection.diagnostics().contains("streams=0 ")
        && hub_quic_connection.diagnostics().contains("streams=0 ")
      {
        break;
      }

      sleep(duration!("20ms")).await;
    }
  })
  .await;

  anyhow::ensure!(
    work_completed && reap_result.is_ok(),
    "bulk lossy transport wedged: bulk={}/{BULK_STREAM_COUNT} server={}/{} out=[{}] hub=[{}]",
    bulk_completed.load(atomic::Ordering::Relaxed),
    server_completed.load(atomic::Ordering::Relaxed),
    BULK_STREAM_COUNT + DROPPED_STREAM_COUNT,
    out_quic_connection.diagnostics(),
    hub_quic_connection.diagnostics(),
  );

  Ok(())
}
