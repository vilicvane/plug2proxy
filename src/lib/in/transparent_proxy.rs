use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use futures::TryFutureExt;
use itertools::Itertools;
use rusqlite::OptionalExtension;
use tokio::io::AsyncWriteExt;

use crate::{
    config::MatchServerConfig,
    punch_quic::{PunchQuicInTunnelConfig, PunchQuicInTunnelProvider},
    routing::{config::InRuleConfig, geolite2::GeoLite2, router::Router},
    utils::{io::copy_bidirectional, net::get_tokio_tcp_stream_original_dst},
};

use super::tunnel_manager::TunnelManager;

pub struct Options<'a> {
    pub listen_address: SocketAddr,
    pub fake_ip_dns_db_path: &'a PathBuf,
    pub fake_ipv4_net: ipnet::Ipv4Net,
    pub fake_ipv6_net: ipnet::Ipv6Net,
    pub stun_server_address: String,
    pub match_server_config: MatchServerConfig,
    pub routing_rules: Vec<InRuleConfig>,
    pub geolite2_cache_path: &'a PathBuf,
    pub geolite2_url: String,
    pub geolite2_update_interval: Duration,
}

pub async fn up(
    Options {
        listen_address,
        fake_ip_dns_db_path,
        fake_ipv4_net,
        fake_ipv6_net,
        stun_server_address,
        match_server_config,
        routing_rules,
        geolite2_cache_path,
        geolite2_url,
        geolite2_update_interval,
    }: Options<'_>,
) -> anyhow::Result<()> {
    let sqlite_connection = rusqlite::Connection::open_with_flags(
        fake_ip_dns_db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();

    let match_server = match_server_config.new_in_match_server()?;

    let tunnel_provider = PunchQuicInTunnelProvider::new(
        match_server,
        PunchQuicInTunnelConfig {
            stun_server_address,
        },
    );

    let router = Arc::new(Router::new(routing_rules));

    let tunnel_manager = Arc::new(TunnelManager::new(
        Box::new(tunnel_provider),
        router.clone(),
    ));

    let geolite2 = GeoLite2::new(geolite2_cache_path, geolite2_url, geolite2_update_interval).await;

    let tunnel_task = {
        let tunnel_manager = Arc::clone(&tunnel_manager);

        async move {
            let join_handle = tunnel_manager.accept_handle.lock().unwrap().take().unwrap();

            join_handle.await?;

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    let listen_task = {
        let tunnel_manager = Arc::clone(&tunnel_manager);

        async move {
            let tcp_listener = socket2::Socket::new(
                socket2::Domain::for_address(listen_address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            tcp_listener.set_ip_transparent(true)?;

            tcp_listener.bind(&socket2::SockAddr::from(listen_address))?;
            tcp_listener.listen(1024)?;

            let tcp_listener = std::net::TcpListener::from(tcp_listener);

            tcp_listener.set_nonblocking(true)?;

            let tcp_listener = tokio::net::TcpListener::from_std(tcp_listener)?;

            while let Ok((stream, _)) = tcp_listener.accept().await {
                handle_in_tcp_stream(
                    stream,
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
        _ = tunnel_task => panic!("unexpected completion of tunnel task."),
        _ = listen_task => Err(anyhow::anyhow!("listening ended unexpectedly.")),
    }?;

    Ok(())
}

async fn handle_in_tcp_stream(
    mut stream: tokio::net::TcpStream,
    tunnel_manager: &TunnelManager,
    fake_ipv4_net: &ipnet::Ipv4Net,
    fake_ipv6_net: &ipnet::Ipv6Net,
    sqlite_connection: &rusqlite::Connection,
    geolite2: &GeoLite2,
    router: &Router,
) -> anyhow::Result<()> {
    let destination = get_tokio_tcp_stream_original_dst(&stream)?;

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

    let (destination, name, labels) = if let Some((r#type, id)) = fake_ip_type_and_id {
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

            let real_address = SocketAddr::new(real_ip, destination.port());

            let region = geolite2.lookup(real_ip).await;

            let labels = router
                .r#match(real_address, Some(name.clone()), region)
                .await
                .into_iter()
                .collect_vec();

            (real_address, Some(name), labels)
        } else {
            log::warn!("fake ip {} not found.", destination.ip());

            (destination, None, Vec::new())
        }
    } else {
        let region = geolite2.lookup(destination.ip()).await;

        let labels = router
            .r#match(destination, None, region)
            .await
            .into_iter()
            .collect_vec();

        (destination, None, labels)
    };

    log::debug!(
        "routing {}{} with labels {}...",
        destination,
        name.map_or_else(|| "".to_owned(), |name| format!(" ({})", name)),
        labels.join(",")
    );

    let Some(tunnel) = tunnel_manager.select_tunnel(&labels).await else {
        log::warn!("no tunnel available.");

        stream.shutdown().await?;

        return Ok(());
    };

    let (mut in_recv_stream, mut in_send_stream) = stream.into_split();

    tokio::spawn({
        let tunnel = Arc::clone(&tunnel);

        async move {
            let (mut tunnel_recv_stream, mut tunnel_send_stream) = tunnel
                .connect(crate::tunnel::TransportType::Tcp, destination)
                .await?;

            copy_bidirectional(
                (&mut in_recv_stream, &mut tunnel_send_stream),
                (&mut tunnel_recv_stream, &mut in_send_stream),
            )
            .await?;

            anyhow::Ok(())
        }
        .inspect_err(|error| log::error!("tunnel error: {:?}", error))
    });

    Ok(())
}
