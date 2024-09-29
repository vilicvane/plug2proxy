use clap::Parser;
use plug2proxy::{
    punch_quic::{
        match_server::MatchPeerId, redis_match_server::RedisMatchServer,
        PunchQuicClientTunnelConfig, PunchQuicClientTunnelProvider, PunchQuicServerTunnelConfig,
        PunchQuicServerTunnelProvider,
    },
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

        let (typ, remote_addr, (mut tunnel_send_stream, mut tunnel_recv_stream)) =
            tunnel.accept().await?;

        println!("accept {typ:?} connection to {remote_addr}");

        let (mut remote_recv_stream, mut remote_send_stream) =
            tokio::net::TcpStream::connect(remote_addr)
                .await?
                .into_split();

        println!("connected to {}", remote_addr);

        tokio::try_join!(
            async {
                tokio::io::copy(&mut tunnel_recv_stream, &mut remote_send_stream).await?;

                println!("tunnel_recv_stream EOF");

                remote_send_stream.shutdown().await?;

                anyhow::Ok(())
            },
            async {
                tokio::io::copy(&mut remote_recv_stream, &mut tunnel_send_stream).await?;

                println!("remote_recv_stream EOF");

                tunnel_send_stream.shutdown().await?;

                anyhow::Ok(())
            },
        )?;

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

        let (mut send_stream, mut recv_stream) = tunnel
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
