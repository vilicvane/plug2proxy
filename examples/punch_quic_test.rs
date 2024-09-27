use clap::Parser;
use plug2proxy::{
    punch_quic_tunnel_provider::{
        PunchQuicClientTunnelConfig, PunchQuicClientTunnelProvider, PunchQuicServerTunnelConfig,
        PunchQuicServerTunnelProvider,
    },
    tunnel::TransportType,
    tunnel_provider::{ClientTunnelProvider, ServerTunnelProvider},
};

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

    if cli.server {
        let provider = PunchQuicServerTunnelProvider::new(PunchQuicServerTunnelConfig {
            stun_server_addr: STUN_SERVER_ADDR.to_string(),
        });

        let tunnel = provider.accept().await?;

        let (typ, remote_addr, mut stream) = tunnel.accept().await?;

        println!("accept {typ:?} connection to {remote_addr:?}");

        tokio::signal::ctrl_c().await?;
    } else {
        let provider = PunchQuicClientTunnelProvider::new(PunchQuicClientTunnelConfig {
            stun_server_addr: STUN_SERVER_ADDR.to_string(),
        });

        let tunnel = provider.accept().await?;

        let stream = tunnel
            .connect(TransportType::Tcp, "127.0.0.1:8080".parse()?)
            .await?;

        tokio::signal::ctrl_c().await?;
    }

    Ok(())
}
