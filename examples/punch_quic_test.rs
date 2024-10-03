use clap::Parser;
use plug2proxy::{
    punch_quic::{
        redis_match_server::{RedisInMatchServer, RedisOutMatchServer},
        PunchQuicInTunnelConfig, PunchQuicInTunnelProvider, PunchQuicOutTunnelConfig,
        PunchQuicOutTunnelProvider,
    },
    tunnel::TransportType,
    tunnel_provider::{InTunnelProvider, OutTunnelProvider},
    utils::io::copy_bidirectional,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const STUN_SERVER_ADDR: &str = "stun.l.google.com:19302";

#[derive(clap::Parser, Debug)]
struct Cli {
    #[clap(long)]
    server: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    color_backtrace::install();

    rustls::crypto::ring::default_provider()
        .install_default()
        .unwrap();

    let cli = Cli::parse();

    let redis_url = std::env::var("REDIS_URL")?;

    let redis = redis::Client::open(format!("{redis_url}?protocol=resp3"))?;

    if cli.server {
        let match_server = Box::new(RedisOutMatchServer::new(redis, vec![]).await?);

        let provider = PunchQuicOutTunnelProvider::new(
            match_server,
            PunchQuicOutTunnelConfig {
                stun_server_address: STUN_SERVER_ADDR.to_string(),
            },
        );

        let tunnel = provider.accept().await?;

        let (typ, remote_addr, (tunnel_recv_stream, tunnel_send_stream)) = tunnel.accept().await?;

        println!("accept {typ:?} connection to {remote_addr}");

        let (remote_recv_stream, remote_send_stream) = tokio::net::TcpStream::connect(remote_addr)
            .await?
            .into_split();

        println!("connected to {}", remote_addr);

        copy_bidirectional(
            (tunnel_recv_stream, remote_send_stream),
            (remote_recv_stream, tunnel_send_stream),
        )
        .await?;

        tokio::signal::ctrl_c().await?;
    } else {
        let match_server = Box::new(RedisInMatchServer::new(redis));

        let provider = PunchQuicInTunnelProvider::new(
            match_server,
            PunchQuicInTunnelConfig {
                stun_server_address: STUN_SERVER_ADDR.to_string(),
            },
        );

        let tunnel = provider.accept().await?;

        let (mut recv_stream, mut send_stream) = tunnel
            .connect(TransportType::Tcp, "39.156.66.10:80".parse()?)
            .await?;

        send_stream
            .write_all("GET / HTTP/1.1\r\nHost: baidu.com\r\n\r\n".as_bytes())
            .await?;

        send_stream.shutdown().await?;

        let mut content = String::new();

        recv_stream.read_to_string(&mut content).await?;

        println!("{}", content);
    }

    Ok(())
}
