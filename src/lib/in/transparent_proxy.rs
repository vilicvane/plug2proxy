use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use futures::{future::try_join_all, TryFutureExt};
use itertools::Itertools;
use rusqlite::OptionalExtension;
use tokio::io::AsyncWriteExt;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    r#in::dns_resolver::convert_to_socket_addresses,
    route::{config::InRuleConfig, geolite2::GeoLite2, router::Router},
    tunnel::{
        punch_quic::{PunchQuicInTunnelConfig, PunchQuicInTunnelProvider},
        yamux::{YamuxInTunnelConfig, YamuxInTunnelProvider},
        InTunnelLike as _, InTunnelProvider,
    },
    utils::{
        io::copy_bidirectional,
        net::{get_tokio_tcp_stream_original_destination, IpFamily},
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
    pub tunneling_tcp_priority: Option<i64>,
    pub tunneling_tcp_priority_default: i64,
    pub tunneling_tcp_connections: usize,
    pub tunneling_udp_priority: Option<i64>,
    pub tunneling_udp_priority_default: i64,
    pub tunneling_udp_connections: usize,
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
        tunneling_tcp_priority,
        tunneling_tcp_priority_default,
        tunneling_tcp_connections,
        tunneling_udp_priority,
        tunneling_udp_priority_default,
        tunneling_udp_connections,
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

        (0..tunneling_tcp_connections)
            .map(|index| {
                Box::new(YamuxInTunnelProvider::new(
                    match_server.clone(),
                    YamuxInTunnelConfig {
                        priority: tunneling_tcp_priority,
                        priority_default: tunneling_tcp_priority_default,
                        traffic_mark,
                    },
                    index,
                )) as Box<dyn InTunnelProvider + Send>
            })
            .chain((0..tunneling_udp_connections).map(|_| {
                Box::new(PunchQuicInTunnelProvider::new(
                    match_server.clone(),
                    PunchQuicInTunnelConfig {
                        priority: tunneling_udp_priority,
                        priority_default: tunneling_udp_priority_default,
                        stun_server_addresses: stun_server_addresses.clone(),
                        traffic_mark,
                    },
                )) as Box<dyn InTunnelProvider + Send>
            }))
            .collect_vec()
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

    let listen_task = {
        let sqlite_connection = rusqlite::Connection::open_with_flags(
            fake_ip_dns_db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();

        let geolite2 =
            GeoLite2::new(geolite2_cache_path, geolite2_url, geolite2_update_interval).await;

        let tunnel_manager = Arc::clone(&tunnel_manager);

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

                socket.bind(listen_address)?;

                socket.listen(64)?
            };

            log::info!("transparent proxy listening on {listen_address}...");

            while let Ok((stream, _)) = tcp_listener.accept().await {
                let destination = get_tokio_tcp_stream_original_destination(&stream, IpFamily::V4)
                    .unwrap_or_else(|_| stream.local_addr().unwrap());

                handle_in_tcp_stream(
                    stream,
                    destination,
                    &tunnel_manager,
                    &fake_ipv4_net,
                    &fake_ipv6_net,
                    &sqlite_connection,
                    &geolite2,
                    &router,
                )
                .await?;
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    tokio::select! {
        _ = tunnel_task => Err(anyhow::anyhow!("unexpected completion of tunnel task.")),
        result = listen_task => {
            result?;
            Err(anyhow::anyhow!("listening ended unexpectedly."))
        },
    }?;

    Ok(())
}

async fn handle_in_tcp_stream(
    mut stream: tokio::net::TcpStream,
    destination: SocketAddr,
    tunnel_manager: &TunnelManager,
    fake_ipv4_net: &ipnet::Ipv4Net,
    fake_ipv6_net: &ipnet::Ipv6Net,
    sqlite_connection: &rusqlite::Connection,
    geolite2: &GeoLite2,
    router: &Router,
) -> anyhow::Result<()> {
    let fake_ip_type_and_id = match destination.ip() {
        IpAddr::V4(ipv4) => {
            if fake_ipv4_net.contains(&ipv4) {
                Some((
                    hickory_client::rr::RecordType::A,
                    (ipv4.to_bits() - fake_ipv4_net.network().to_bits()) as i64,
                ))
            } else {
                None
            }
        }
        IpAddr::V6(ipv6) => {
            if fake_ipv6_net.contains(&ipv6) {
                Some((
                    hickory_client::rr::RecordType::AAAA,
                    (ipv6.to_bits() - fake_ipv6_net.network().to_bits()) as i64,
                ))
            } else {
                None
            }
        }
    };

    let (destination, name, labels_groups) = if let Some((r#type, id)) = fake_ip_type_and_id {
        let record: Option<(String, Vec<u8>)> = sqlite_connection
            .query_row(
                "SELECT name, real_ip FROM records WHERE type = ? AND id = ?",
                rusqlite::params![r#type.to_string(), id],
                |row| Ok((row.get("name")?, row.get("real_ip")?)),
            )
            .optional()
            .unwrap();

        if let Some((name, real_ip)) = record {
            let name = name.trim_end_matches(".").to_owned();

            let real_ip = match r#type {
                hickory_client::rr::RecordType::A => IpAddr::V4(Ipv4Addr::from_bits(
                    u32::from_be_bytes(real_ip.try_into().unwrap()),
                )),
                hickory_client::rr::RecordType::AAAA => IpAddr::V6(Ipv6Addr::from_bits(
                    u128::from_be_bytes(real_ip.try_into().unwrap()),
                )),
                _ => unreachable!(),
            };

            log::debug!(
                "fake ip {} translated to {} ({}).",
                destination.ip(),
                real_ip,
                name
            );

            let real_destination = SocketAddr::new(real_ip, destination.port());

            let domain = Some(name);

            let region_codes = geolite2.lookup(real_ip).await;

            let labels_groups = router
                .r#match(real_destination, &domain, &region_codes)
                .await;

            (real_destination, domain, labels_groups)
        } else {
            log::warn!("fake ip {} not found.", destination.ip());

            (destination, None, Vec::new())
        }
    } else {
        let region_codes = geolite2.lookup(destination.ip()).await;

        let labels_groups = router.r#match(destination, &None, &region_codes).await;

        (destination, None, labels_groups)
    };

    let destination_string = get_destination_string(destination, &name);

    log::debug!(
        "route {destination_string} with labels {}...",
        stringify_labels_groups(&labels_groups)
    );

    let Some(tunnel) = tunnel_manager.select_tunnel(&labels_groups).await else {
        log::warn!(
            "connection to {destination_string} via {} rejected cause no matching tunnel.",
            stringify_labels_groups(&labels_groups)
        );

        stream.shutdown().await?;

        return Ok(());
    };

    log::info!("connect {destination_string} via {tunnel}...");

    let (mut in_recv_stream, mut in_send_stream) = stream.into_split();

    tokio::spawn({
        async move {
            let (mut tunnel_recv_stream, mut tunnel_send_stream) =
                tunnel.connect(destination, name).await?;

            // println!("connected to {destination} via {tunnel}.");

            copy_bidirectional(
                (&mut in_recv_stream, &mut tunnel_send_stream),
                (&mut tunnel_recv_stream, &mut in_send_stream),
            )
            .await?;

            anyhow::Ok(())
        }
        .inspect_err(move |error| {
            log::debug!("connection to {destination_string} errored: {error}",)
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
