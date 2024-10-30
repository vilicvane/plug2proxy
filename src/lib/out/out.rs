use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs as _},
    sync::Arc,
};

use futures::future::join_all;
use itertools::Itertools as _;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    out::direct_output::DirectOutput,
    route::{
        config::{OutOutputConfig, OutRuleConfig},
        rule::Label,
    },
    tunnel::{
        http2::{Http2OutTunnelConfig, Http2OutTunnelProvider},
        quic::{QuicOutTunnelConfig, QuicOutTunnelProvider},
        OutTunnel, OutTunnelProvider,
    },
    utils::io::copy_bidirectional,
};

use super::output::{AnyOutput, Output as _};

pub struct Options {
    pub labels: Vec<Label>,
    pub stun_server_addresses: Vec<String>,
    pub match_server_config: MatchServerConfig,
    pub tcp_priority: Option<i64>,
    pub udp_priority: Option<i64>,
    pub routing_rules: Vec<OutRuleConfig>,
    pub routing_priority: i64,
    pub output_configs: Vec<OutOutputConfig>,
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
        output_configs,
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
        Box::new(QuicOutTunnelProvider::new(
            match_server.clone(),
            QuicOutTunnelConfig {
                stun_server_addresses,
                priority: udp_priority,
                routing_priority,
                routing_rules,
            },
        )),
    ];

    let output_map = Arc::new(
        output_configs
            .into_iter()
            .map(|config| (config.tag().to_owned(), Arc::new(config.into_output())))
            .collect::<HashMap<_, _>>(),
    );

    let direct_output = Arc::new(AnyOutput::Direct(DirectOutput::new()));

    let tunneling_tasks = tunnel_providers
        .into_iter()
        .map(|tunnel_provider| {
            let output_map = output_map.clone();
            let direct_output = direct_output.clone();

            async move {
                loop {
                    match tunnel_provider.accept().await {
                        Ok(tunnel) => {
                            tokio::spawn(handle_tunnel(
                                tunnel,
                                output_map.clone(),
                                direct_output.clone(),
                            ));

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
            }
        })
        .collect_vec();

    join_all(tunneling_tasks).await;

    #[allow(unreachable_code)]
    Ok(())
}

async fn handle_tunnel(
    tunnel: Box<dyn OutTunnel>,
    output_map: Arc<HashMap<String, Arc<AnyOutput>>>,
    direct_output: Arc<AnyOutput>,
) {
    loop {
        match tunnel.accept().await {
            Ok((
                (destination_address, destination_name, tag),
                (tunnel_read_stream, tunnel_write_stream),
            )) => {
                log::info!(
                    "accepted connection to {}.",
                    get_destination_string(destination_address, &destination_name)
                );

                let output = tag
                    .and_then(|tag| output_map.get(&tag))
                    .unwrap_or(&direct_output);

                tokio::spawn(handle_tcp_stream(
                    destination_address,
                    destination_name,
                    output.clone(),
                    tunnel_read_stream,
                    tunnel_write_stream,
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
    output: Arc<AnyOutput>,
    tunnel_read_stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    tunnel_write_stream: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
) -> anyhow::Result<()> {
    let address = if let Some(destination_name) = destination_name {
        tokio::net::lookup_host(format!("{destination_name}:{}", destination_address.port()))
            .await?
            .next()
            .unwrap_or(destination_address)
    } else {
        destination_address
    };

    let (read_stream, write_stream) = output.connect(address).await?;

    copy_bidirectional(
        (tunnel_read_stream, write_stream),
        (read_stream, tunnel_write_stream),
    )
    .await?;

    Ok(())
}
