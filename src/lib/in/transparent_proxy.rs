use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use futures::{future::try_join_all, TryFutureExt};
use itertools::Itertools;
use tokio::io::AsyncWriteExt;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    r#in::{
        dns_resolver::convert_to_socket_addresses,
        fake_ip_dns::FakeIpResolver,
        udp_forwarder::{UdpForwarder, UDP_BUFFER_SIZE},
    },
    route::{config::InRuleConfig, geolite2::GeoLite2, router::Router},
    tunnel::{
        http2::{Http2InTunnelConfig, Http2InTunnelProvider},
        punch_quic::{PunchQuicInTunnelConfig, PunchQuicInTunnelProvider},
        InTunnelLike as _, InTunnelProvider,
    },
    utils::{
        io::copy_bidirectional,
        net::socket::{get_socket_original_destination, IpFamily},
    },
};

use super::tunnel_manager::TunnelManager;

pub struct Options<'a> {
    pub listen_address: SocketAddr,
    pub traffic_mark: u32,
    pub fake_ip_dns_db_path: &'a PathBuf,
    pub fake_ipv4_net: ipnet::Ipv4Net,
    pub fake_ipv6_net: ipnet::Ipv6Net,
    pub stun_server_addresses: Vec<String>,
    pub match_server_config: MatchServerConfig,
    pub tunneling_tcp_enabled: bool,
    pub tunneling_tcp_connections: usize,
    pub tunneling_tcp_priority: Option<i64>,
    pub tunneling_tcp_priority_default: i64,
    pub tunneling_udp_enabled: bool,
    pub tunneling_udp_priority: Option<i64>,
    pub tunneling_udp_priority_default: i64,
    pub routing_rules: Vec<InRuleConfig>,
    pub geolite2_cache_path: &'a PathBuf,
    pub geolite2_url: String,
    pub geolite2_update_interval: Duration,
}

pub async fn up(
    dns_resolver: Arc<hickory_resolver::TokioAsyncResolver>,
    Options {
        listen_address,
        traffic_mark,
        fake_ip_dns_db_path,
        fake_ipv4_net,
        fake_ipv6_net,
        stun_server_addresses,
        match_server_config,
        tunneling_tcp_enabled,
        tunneling_tcp_connections,
        tunneling_tcp_priority,
        tunneling_tcp_priority_default,
        tunneling_udp_enabled,
        tunneling_udp_priority,
        tunneling_udp_priority_default,
        routing_rules,
        geolite2_cache_path,
        geolite2_url,
        geolite2_update_interval,
    }: Options<'_>,
) -> anyhow::Result<()> {
    log::info!("starting IN transparent proxy...");

    let tunnel_providers = {
        let match_server = Arc::new(match_server_config.new_in_match_server()?);

        let stun_server_addresses = {
            let mut resolved_addresses = Vec::new();

            for address in stun_server_addresses {
                resolved_addresses
                    .extend(convert_to_socket_addresses(address, &dns_resolver, None).await?);
            }

            resolved_addresses
        };

        let mut tunnel_providers = Vec::<Box<dyn InTunnelProvider + Send>>::new();

        if tunneling_tcp_enabled {
            let config = Http2InTunnelConfig {
                connections: tunneling_tcp_connections,
                priority: tunneling_tcp_priority,
                priority_default: tunneling_tcp_priority_default,
                traffic_mark,
            };

            tunnel_providers.push(Box::new(
                Http2InTunnelProvider::new(match_server.clone(), config).await?,
            ));
        }

        if tunneling_udp_enabled {
            let config = PunchQuicInTunnelConfig {
                priority: tunneling_udp_priority,
                priority_default: tunneling_udp_priority_default,
                stun_server_addresses: stun_server_addresses.clone(),
                traffic_mark,
            };

            tunnel_providers.push(Box::new(PunchQuicInTunnelProvider::new(
                match_server.clone(),
                config,
            )));
        }

        tunnel_providers
    };

    let router = Arc::new(Router::new(routing_rules));

    let tunnel_manager = Arc::new(TunnelManager::new(
        tunnel_providers,
        router.clone(),
        traffic_mark,
    ));

    let tunnel_task = {
        let tunnel_manager = Arc::clone(&tunnel_manager);

        async move {
            let accept_handles = tunnel_manager
                .accept_handles
                .lock()
                .unwrap()
                .take()
                .unwrap();

            try_join_all(accept_handles).await?;

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    let fake_ip_resolver = Arc::new(FakeIpResolver::new(
        fake_ip_dns_db_path,
        fake_ipv4_net,
        fake_ipv6_net,
    ));

    let geolite2 = Arc::new(GeoLite2::new(
        geolite2_cache_path,
        geolite2_url,
        geolite2_update_interval,
    ));

    let listen_tcp_task = {
        let fake_ip_resolver = fake_ip_resolver.clone();
        let geolite2 = geolite2.clone();
        let router = router.clone();

        let tunnel_manager = tunnel_manager.clone();

        async move {
            let tcp_listener = {
                let socket = tokio::net::TcpSocket::new_v4()?;

                nix::sys::socket::setsockopt(
                    &socket,
                    nix::sys::socket::sockopt::IpTransparent,
                    &true,
                )?;

                nix::sys::socket::setsockopt(
                    &socket,
                    nix::sys::socket::sockopt::IpFreebind,
                    &true,
                )?;

                socket.set_reuseport(true)?;
                socket.set_nodelay(true)?;

                socket.bind(listen_address)?;

                socket.listen(64)?
            };

            while let Ok((stream, source)) = tcp_listener.accept().await {
                let destination = get_socket_original_destination(&stream, IpFamily::V4)
                    .unwrap_or_else(|_| stream.local_addr().unwrap());

                let (destination, name, labels_groups) =
                    resolve_destination(destination, &fake_ip_resolver, &geolite2, &router);

                handle_in_tcp_stream(
                    stream,
                    source,
                    destination,
                    name,
                    labels_groups,
                    &tunnel_manager,
                )
                .await?;
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    let listen_udp_task = async move {
        let udp_forwarder = UdpForwarder::new(listen_address, traffic_mark)?;

        let mut buffer = [0u8; UDP_BUFFER_SIZE];

        while let Ok((length, source, original_destination)) =
            udp_forwarder.receive(&mut buffer).await
        {
            let real_destination = udp_forwarder
                .get_associated_destination(&source, &original_destination)
                .await
                .unwrap_or_else(|| {
                    let (real_destination, name, _) = resolve_destination(
                        original_destination,
                        &fake_ip_resolver,
                        &geolite2,
                        &router,
                    );

                    let destination_string = get_destination_string(real_destination, &name);

                    log::info!("redirect datagrams from {source} to {destination_string}...");

                    real_destination
                });

            udp_forwarder
                .send(
                    source,
                    original_destination,
                    real_destination,
                    &buffer[..length],
                )
                .await?;
        }

        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    log::info!("transparent proxy listening on {listen_address}...");

    tokio::try_join!(tunnel_task, listen_tcp_task, listen_udp_task)?;

    Ok(())
}

fn resolve_destination(
    destination: SocketAddr,
    fake_ip_resolver: &FakeIpResolver,
    geolite2: &GeoLite2,
    router: &Router,
) -> (SocketAddr, Option<String>, Vec<Vec<String>>) {
    if let Some((real_ip, name)) = fake_ip_resolver.resolve(&destination.ip()) {
        let real_destination = SocketAddr::new(real_ip, destination.port());

        let region_codes = geolite2.lookup(real_ip);

        let labels_groups = router.r#match(real_destination, &name, &region_codes);

        (real_destination, name, labels_groups)
    } else {
        (destination, None, Vec::new())
    }
}

async fn handle_in_tcp_stream(
    mut stream: tokio::net::TcpStream,
    source: SocketAddr,
    destination: SocketAddr,
    name: Option<String>,
    labels_groups: Vec<Vec<String>>,
    tunnel_manager: &TunnelManager,
) -> anyhow::Result<()> {
    let destination_string = get_destination_string(destination, &name);

    log::debug!(
        "route connection from {source} to {destination_string} with labels {}...",
        stringify_labels_groups(&labels_groups)
    );

    let Some(tunnel) = tunnel_manager.select_tunnel(&labels_groups).await else {
        log::warn!(
            "connection from {source} to {destination_string} via {} rejected cause no matching tunnel.",
            stringify_labels_groups(&labels_groups)
        );

        stream.shutdown().await?;

        return Ok(());
    };

    log::info!("connect {source} to {destination_string} via {tunnel}...");

    let (mut in_recv_stream, mut in_send_stream) = stream.into_split();

    tokio::spawn({
        async move {
            let (mut tunnel_recv_stream, mut tunnel_send_stream) =
                tunnel.connect(destination, name).await?;

            copy_bidirectional(
                (&mut in_recv_stream, &mut tunnel_send_stream),
                (&mut tunnel_recv_stream, &mut in_send_stream),
            )
            .await?;

            anyhow::Ok(())
        }
        .inspect_err(move |error| {
            log::debug!("connection from {source} to {destination_string} errored: {error}",)
        })
    });

    Ok(())
}

fn stringify_labels_groups(labels_groups: &[Vec<String>]) -> String {
    labels_groups
        .iter()
        .map(|labels| labels.join(","))
        .join(";")
}
