use std::{net::SocketAddr, path::PathBuf, time::Instant};

use anyhow::Context;
use clap::{Parser, Subcommand};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use plug2proxy::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  mt_connections::{MtConnectionsListener, mt_connections_connect},
  quic_connection::{QuicBytesPacket, QuicConnection, create_quiche_config},
};

#[derive(Parser, Debug)]
#[command(name = "qomt_connection_test")]
#[command(about = "QUIC-over-mTCP (MtConnections) upload/download throughput test")]
struct Cli {
  #[command(subcommand)]
  command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
  Server {
    #[arg(long, default_value = "127.0.0.1:1122")]
    listen: SocketAddr,
  },
  Client {
    #[arg(long)]
    connect: SocketAddr,
    #[arg(long, default_value_t = 4)]
    connections: usize,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    upload_bytes: u64,
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    download_bytes: u64,
    #[arg(long, default_value_t = 64 * 1024)]
    chunk_bytes: usize,
  },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
  env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

  let cli = Cli::parse();

  match cli.command {
    Command::Server { listen } => run_server(listen).await,
    Command::Client {
      connect,
      connections,
      upload_bytes,
      download_bytes,
      chunk_bytes,
    } => {
      run_client(ClientArgs {
        connect,
        connections,
        upload_bytes,
        download_bytes,
        chunk_bytes,
      })
      .await
    }
  }
}

#[derive(Debug, Clone)]
struct ClientArgs {
  connect: SocketAddr,
  connections: usize,
  upload_bytes: u64,
  download_bytes: u64,
  chunk_bytes: usize,
}

async fn run_server(listen: SocketAddr) -> anyhow::Result<()> {
  log::info!("qomt server listening on {}", listen);

  let listener = tokio::net::TcpListener::bind(listen)
    .await
    .context("bind server listener")?;

  let mut listener = MtConnectionsListener::<QuicBytesPacket>::new(listener);

  loop {
    let mt_connections = listener.accept().await.context("accept MtConnections")?;
    handle_server_connection(mt_connections).await?;
  }
}

async fn handle_server_connection(
  mut mt_connections: plug2proxy::mt_connections::MtConnections<QuicBytesPacket>,
) -> anyhow::Result<()> {
  let first_packet = mt_connections
    .next()
    .await
    .ok_or_else(|| anyhow::anyhow!("no first packet (connection_id)"))?;

  let connection_id = quiche::ConnectionId::from_vec(first_packet.to_vec());

  let mut quiche_config = create_test_quiche_config("qomt-server").await?;
  let quic_connection = QuicConnection::accept(&connection_id, &mut quiche_config, mt_connections);

  quic_connection
    .established()
    .await
    .context("wait server QUIC established")?;

  log::info!("server QUIC established");

  loop {
    let Some(mut stream) = quic_connection.accept_stream().await? else {
      break;
    };

    // The client runs upload then download sequentially, so sequential handling is fine.
    handle_server_stream(&mut stream).await?;
  }

  Ok(())
}

async fn handle_server_stream(
  stream: &mut plug2proxy::quic_connection::QuicStream,
) -> anyhow::Result<()> {
  let mut kind = [0u8; 1];
  stream.read_exact(&mut kind).await?;

  match kind[0] {
    // upload test: client -> server, then server acks with received bytes
    b'U' => {
      let total = read_u64_be(stream).await?;
      let mut remaining = total;
      let mut buf = vec![0u8; 64 * 1024];

      while remaining > 0 {
        let to_read = (remaining as usize).min(buf.len());
        let n = stream.read(&mut buf[..to_read]).await?;
        if n == 0 {
          break;
        }
        remaining -= n as u64;
      }

      let received = total - remaining;

      stream.write_all(b"A").await?;
      write_u64_be(stream, received).await?;
      stream.shutdown().await?;
    }

    // download test: client requests N bytes, server sends them
    b'D' => {
      let total = read_u64_be(stream).await?;
      let chunk = read_u32_be(stream).await? as usize;
      let mut remaining = total;

      let chunk = chunk.clamp(1, 1024 * 1024);
      let buf = vec![0u8; chunk];

      while remaining > 0 {
        let to_send = (remaining as usize).min(buf.len());
        stream.write_all(&buf[..to_send]).await?;
        remaining -= to_send as u64;
      }

      stream.shutdown().await?;
    }
    _ => {
      stream.shutdown().await?;
    }
  }

  Ok(())
}

async fn run_client(args: ClientArgs) -> anyhow::Result<()> {
  log::info!(
    "qomt client connecting to {} (mtcp connections={})",
    args.connect,
    args.connections
  );

  let (mut mt_connections, extend_signal_sender) =
    mt_connections_connect::<QuicBytesPacket>(args.connect, args.connections)
      .await
      .context("mt_connections_connect")?;

  // Extend to target connections immediately (best effort).
  extend_signal_sender.send(()).ok();

  let connection_id = QuicConnection::generate_connection_id();
  mt_connections
    .send(connection_id.to_vec().into())
    .await
    .context("send connection_id")?;

  let mut quiche_config = create_test_quiche_config("qomt-client").await?;
  let mut quic_connection =
    QuicConnection::connect(&connection_id, &mut quiche_config, mt_connections);

  quic_connection
    .established()
    .await
    .context("wait client QUIC established")?;

  client_outln(format_args!("connected: {}", args.connect))?;
  client_outln(format_args!("mtcp connections: {}", args.connections))?;

  let upload = run_upload_test(&mut quic_connection, args.upload_bytes, args.chunk_bytes).await?;
  print_stats("upload", &upload);

  let download =
    run_download_test(&mut quic_connection, args.download_bytes, args.chunk_bytes).await?;
  print_stats("download", &download);

  Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Stats {
  bytes: u64,
  duration_secs: f64,
}

async fn run_upload_test(
  quic_connection: &mut QuicConnection,
  total_bytes: u64,
  chunk_bytes: usize,
) -> anyhow::Result<Stats> {
  let mut stream = quic_connection.open_stream();

  stream.write_all(b"U").await?;
  write_u64_be(&mut stream, total_bytes).await?;

  let chunk_bytes = chunk_bytes.clamp(1, 1024 * 1024);
  let buf = vec![0u8; chunk_bytes];

  let start = Instant::now();
  let mut remaining = total_bytes;

  while remaining > 0 {
    let to_send = (remaining as usize).min(buf.len());
    stream.write_all(&buf[..to_send]).await?;
    remaining -= to_send as u64;
  }

  stream.shutdown().await?;

  let mut ack = [0u8; 1];
  stream.read_exact(&mut ack).await?;
  if ack[0] != b'A' {
    anyhow::bail!("bad upload ack");
  }
  let received = read_u64_be(&mut stream).await?;
  let duration = start.elapsed().as_secs_f64();

  if received != total_bytes {
    anyhow::bail!("server reported {received} bytes received, expected {total_bytes}");
  }

  Ok(Stats {
    bytes: total_bytes,
    duration_secs: duration,
  })
}

async fn run_download_test(
  quic_connection: &mut QuicConnection,
  total_bytes: u64,
  chunk_bytes: usize,
) -> anyhow::Result<Stats> {
  let mut stream = quic_connection.open_stream();

  stream.write_all(b"D").await?;
  write_u64_be(&mut stream, total_bytes).await?;
  write_u32_be(&mut stream, chunk_bytes as u32).await?;

  let start = Instant::now();
  let mut received = 0u64;
  let mut buf = vec![0u8; 64 * 1024];

  while received < total_bytes {
    let n = stream.read(&mut buf).await?;
    if n == 0 {
      break;
    }
    received += n as u64;
  }

  let duration = start.elapsed().as_secs_f64();

  if received != total_bytes {
    anyhow::bail!("download ended early: received {received}, expected {total_bytes}");
  }

  Ok(Stats {
    bytes: total_bytes,
    duration_secs: duration,
  })
}

fn print_stats(label: &str, stats: &Stats) {
  let mbps = (stats.bytes as f64 * 8.0) / stats.duration_secs / 1_000_000.0;
  client_outln(format_args!(
    "{label}: bytes={} duration={:.3}s throughput={:.2} Mbps",
    stats.bytes, stats.duration_secs, mbps
  ))
  .ok();
}

fn client_outln(args: std::fmt::Arguments<'_>) -> std::io::Result<()> {
  use std::io::Write;

  let mut stdout = std::io::stdout().lock();
  stdout.write_fmt(args)?;
  stdout.write_all(b"\n")?;
  stdout.flush()?;
  Ok(())
}

async fn create_test_quiche_config(common_name: &str) -> anyhow::Result<quiche::Config> {
  let dir = create_ephemeral_cert_dir(common_name);

  generate_ca_pem_file(&dir)
    .await
    .with_context(|| format!("generate CA pem in {}", dir.display()))?;

  let node_pem_file_path = generate_node_pem_file(&dir, common_name, true)
    .await
    .with_context(|| format!("generate node pem in {}", dir.display()))?;

  // Use the project's canonical QUIC settings (no duplicated constants),
  // but disable verification so client/server don't need to share a CA dir.
  let mut config = create_quiche_config(&node_pem_file_path)?;
  config.verify_peer(false);

  Ok(config)
}

fn create_ephemeral_cert_dir(common_name: &str) -> PathBuf {
  std::env::temp_dir().join(format!(
    "plug2proxy-qomt-test/{common_name}-{}",
    uuid::Uuid::new_v4()
  ))
}

async fn read_u64_be<TRead>(stream: &mut TRead) -> anyhow::Result<u64>
where
  TRead: tokio::io::AsyncRead + Unpin + Send,
{
  let mut buf = [0u8; 8];
  stream.read_exact(&mut buf).await?;
  Ok(u64::from_be_bytes(buf))
}

async fn write_u64_be<TWrite>(stream: &mut TWrite, value: u64) -> anyhow::Result<()>
where
  TWrite: tokio::io::AsyncWrite + Unpin + Send,
{
  stream.write_all(&value.to_be_bytes()).await?;
  Ok(())
}

async fn read_u32_be<TRead>(stream: &mut TRead) -> anyhow::Result<u32>
where
  TRead: tokio::io::AsyncRead + Unpin + Send,
{
  let mut buf = [0u8; 4];
  stream.read_exact(&mut buf).await?;
  Ok(u32::from_be_bytes(buf))
}

async fn write_u32_be<TWrite>(stream: &mut TWrite, value: u32) -> anyhow::Result<()>
where
  TWrite: tokio::io::AsyncWrite + Unpin + Send,
{
  stream.write_all(&value.to_be_bytes()).await?;
  Ok(())
}
