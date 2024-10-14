use std::{
    net::{SocketAddr, ToSocketAddrs as _},
    sync::Arc,
};

use futures::future::join_all;
use itertools::Itertools as _;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    route::config::OutRuleConfig,
    tunnel::{
        http2::{Http2OutTunnelConfig, Http2OutTunnelProvider},
        punch_quic::{PunchQuicOutTunnelConfig, PunchQuicOutTunnelProvider},
        OutTunnel, OutTunnelProvider,
    },
    utils::io::copy_bidirectional,
};

pub struct Options {
    pub labels: Vec<String>,
    pub stun_server_addresses: Vec<String>,
    pub match_server_config: MatchServerConfig,
    pub tcp_priority: Option<i64>,
    pub udp_priority: Option<i64>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
}

pub async fn up(
    Options {
        labels,
        stun_server_addresses,
        match_server_config,
        tcp_priority,
        udp_priority,
        routing_rules,
        routing_priority,
    }: Options,
) -> anyhow::Result<()> {
    log::info!("starting OUT...");

    let match_server = Arc::new(match_server_config.new_out_match_server(labels).await?);

    let stun_server_addresses = stun_server_addresses
        .iter()
        .flat_map(|address| address.to_socket_addrs().unwrap_or_default())
        .collect_vec();

    let tunnel_providers: Vec<Box<dyn OutTunnelProvider>> = vec![
        Box::new(Http2OutTunnelProvider::new(
            match_server.clone(),
            Http2OutTunnelConfig {
                stun_server_addresses: stun_server_addresses.clone(),
                priority: tcp_priority,
                routing_priority,
                routing_rules: routing_rules.clone(),
            },
        )),
        Box::new(PunchQuicOutTunnelProvider::new(
            match_server.clone(),
            PunchQuicOutTunnelConfig {
                stun_server_addresses,
                priority: udp_priority,
                routing_priority,
                routing_rules,
            },
        )),
    ];

    let tunneling_tasks = tunnel_providers
        .into_iter()
        .map(|tunnel_provider| async move {
            loop {
                match tunnel_provider.accept().await {
                    Ok(tunnel) => {
                        tokio::spawn(handle_tunnel(tunnel));

                        // tokio::task::spawn_blocking(|| {
                        //     tokio::runtime::Builder::new_current_thread()
                        //         .enable_all()
                        //         .build()
                        //         .unwrap()
                        //         .block_on(handle_tunnel(tunnel));
                        // });
                    }
                    Err(error) => {
                        log::error!("error accepting tunnel: {:?}", error);
                    }
                }
            }
        })
        .collect_vec();

    join_all(tunneling_tasks).await;

    #[allow(unreachable_code)]
    Ok(())
}

async fn handle_tunnel(tunnel: Box<dyn OutTunnel>) {
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
                    log::info!("tunnel {tunnel} closed.");

                    break;
                }
            }
        }
    }
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

    stream.set_nodelay(true)?;

    let (remote_recv_stream, remote_send_stream) = stream.into_split();

    copy_bidirectional(
        (tunnel_recv_stream, remote_send_stream),
        (remote_recv_stream, tunnel_send_stream),
    )
    .await?;

    Ok(())
}
