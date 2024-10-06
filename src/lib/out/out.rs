use std::net::{SocketAddr, ToSocketAddrs as _};

use itertools::Itertools as _;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    punch_quic::{PunchQuicOutTunnelConfig, PunchQuicOutTunnelProvider},
    routing::config::OutRuleConfig,
    tunnel::OutTunnel,
    tunnel_provider::OutTunnelProvider as _,
    utils::io::copy_bidirectional,
};

pub struct Options {
    pub labels: Vec<String>,
    pub priority: i64,
    pub stun_server_addresses: Vec<String>,
    pub match_server_config: MatchServerConfig,
    pub routing_rules: Vec<OutRuleConfig>,
}

pub async fn up(
    Options {
        labels,
        priority,
        stun_server_addresses,
        match_server_config,
        routing_rules,
    }: Options,
) -> anyhow::Result<()> {
    log::info!("starting OUT...");

    let match_server = match_server_config.new_out_match_server(labels).await?;

    let stun_server_addresses = stun_server_addresses
        .iter()
        .flat_map(|address| address.to_socket_addrs().unwrap_or_default())
        .collect_vec();

    let tunnel_provider = PunchQuicOutTunnelProvider::new(
        match_server,
        PunchQuicOutTunnelConfig {
            priority,
            stun_server_addresses,
            routing_rules,
        },
    );

    loop {
        match tunnel_provider.accept().await {
            Ok(tunnel) => {
                log::info!("tunnel {} established.", tunnel.id());

                tokio::spawn(handle_tunnel(tunnel));
            }
            Err(error) => {
                log::error!("error accepting tunnel: {:?}", error);
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

async fn handle_tunnel(tunnel: Box<dyn OutTunnel>) -> anyhow::Result<()> {
    loop {
        match tunnel.accept().await {
            Ok((
                (destination_address, destination_name),
                (tunnel_recv_stream, tunnel_send_stream),
            )) => {
                log::info!(
                    "accepted connection to {}.",
                    get_destination_string(destination_address, &destination_name)
                );

                tokio::spawn(handle_tcp_stream(
                    destination_address,
                    destination_name,
                    tunnel_recv_stream,
                    tunnel_send_stream,
                ));
            }
            Err(error) => {
                log::warn!("error accepting connection: {error}");

                if tunnel.is_closed() {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_tcp_stream(
    destination_address: SocketAddr,
    destination_name: Option<String>,
    tunnel_recv_stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    tunnel_send_stream: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
) -> anyhow::Result<()> {
    let stream = if let Some(destination_name) = destination_name {
        tokio::net::TcpStream::connect(format!("{destination_name}:{}", destination_address.port()))
            .await?
    } else {
        tokio::net::TcpStream::connect(destination_address).await?
    };

    let (remote_recv_stream, remote_send_stream) = stream.into_split();

    copy_bidirectional(
        (tunnel_recv_stream, remote_send_stream),
        (remote_recv_stream, tunnel_send_stream),
    )
    .await?;

    Ok(())
}
