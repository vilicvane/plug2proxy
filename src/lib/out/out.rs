use std::net::ToSocketAddrs as _;

use itertools::Itertools as _;

use crate::{
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
                r#type,
                (remote_hostname, remote_port),
                (tunnel_recv_stream, tunnel_send_stream),
            )) => {
                log::info!(
                    "accepted {} connection to {remote_hostname}:{remote_port}",
                    r#type
                );

                match r#type {
                    crate::tunnel::TransportType::Udp => tokio::spawn(handle_udp_stream(
                        remote_hostname,
                        remote_port,
                        tunnel_recv_stream,
                        tunnel_send_stream,
                    )),
                    crate::tunnel::TransportType::Tcp => tokio::spawn(handle_tcp_stream(
                        remote_hostname,
                        remote_port,
                        tunnel_recv_stream,
                        tunnel_send_stream,
                    )),
                };
            }
            Err(error) => {
                eprintln!("error accepting connection: {:?}", error);

                if tunnel.is_closed() {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn handle_udp_stream(
    remote_hostname: String,
    remote_port: u16,
    tunnel_recv_stream: Box<dyn tokio::io::AsyncRead + Send>,
    tunnel_send_stream: Box<dyn tokio::io::AsyncWrite + Send>,
) -> anyhow::Result<()> {
    unimplemented!()
}

async fn handle_tcp_stream(
    remote_hostname: String,
    remote_port: u16,
    tunnel_recv_stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    tunnel_send_stream: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
) -> anyhow::Result<()> {
    let stream = tokio::net::TcpStream::connect(format!("{remote_hostname}:{remote_port}")).await?;

    let (remote_recv_stream, remote_send_stream) = stream.into_split();

    copy_bidirectional(
        (tunnel_recv_stream, remote_send_stream),
        (remote_recv_stream, tunnel_send_stream),
    )
    .await?;

    Ok(())
}
