use clap::Parser;
use plug2proxy::{
    match_server::MatchPeerId,
    punch_quic_tunnel_provider::{
        PunchQuicClientTunnelConfig, PunchQuicClientTunnelProvider, PunchQuicServerTunnelConfig,
        PunchQuicServerTunnelProvider,
    },
    redis_match_server::RedisMatchServer,
    tunnel::TransportType,
    tunnel_provider::{ClientTunnelProvider, ServerTunnelProvider},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const STUN_SERVER_ADDR: &'static str = "stun.l.google.com:19302";

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

    let match_server = RedisMatchServer::new(redis);

    if cli.server {
        let provider = PunchQuicServerTunnelProvider::new(
            MatchPeerId("test_server".to_owned()),
            match_server,
            PunchQuicServerTunnelConfig {
                stun_server_addr: STUN_SERVER_ADDR.to_string(),
            },
        );

        let tunnel = provider.accept().await?;

        let (typ, remote_addr, (_, mut recv_stream)) = tunnel.accept().await?;

        println!("accept {typ:?} connection to {remote_addr:?}");

        let mut content = String::new();

        recv_stream.read_to_string(&mut content).await?;

        println!("{}", content);

        tokio::signal::ctrl_c().await?;
    } else {
        let provider = PunchQuicClientTunnelProvider::new(
            MatchPeerId("test_client".to_owned()),
            match_server,
            PunchQuicClientTunnelConfig {
                stun_server_addr: STUN_SERVER_ADDR.to_string(),
            },
        );

        let tunnel = provider.accept().await?;

        let (mut send_stream, _) = tunnel
            .connect(TransportType::Tcp, "127.0.0.1:8080".parse()?)
            .await?;

        send_stream.write_all(b"hello world\n").await?;
        send_stream.shutdown().await?;

        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}
