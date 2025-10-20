use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use futures::future::try_join_all;
use itertools::Itertools;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    r#in::{dns_resolver::convert_to_socket_addresses, fake_ip_dns::FakeIpResolver},
    route::{config::InRuleConfig, geolite2::GeoLite2, router::Router, rule::Label},
    tunnel::{
        http2::{Http2InTunnelConfig, Http2InTunnelProvider},
        quic::{QuicInTunnelConfig, QuicInTunnelProvider},
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
    pub tunneling_http2_enabled: bool,
    pub tunneling_http2_connections: usize,
    pub tunneling_http2_priority: Option<i64>,
    pub tunneling_http2_priority_default: i64,
    pub tunneling_quic_enabled: bool,
    pub tunneling_quic_priority: Option<i64>,
    pub tunneling_quic_priority_default: i64,
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
        tunneling_http2_enabled,
        tunneling_http2_connections,
        tunneling_http2_priority,
        tunneling_http2_priority_default,
        tunneling_quic_enabled,
        tunneling_quic_priority,
        tunneling_quic_priority_default,
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

        if tunneling_http2_enabled {
            let config = Http2InTunnelConfig {
                connections: tunneling_http2_connections,
                priority: tunneling_http2_priority,
                priority_default: tunneling_http2_priority_default,
                traffic_mark,
            };

            tunnel_providers.push(Box::new(
                Http2InTunnelProvider::new(match_server.clone(), config).await?,
            ));
        }

        if tunneling_quic_enabled {
            let config = QuicInTunnelConfig {
                priority: tunneling_quic_priority,
                priority_default: tunneling_quic_priority_default,
                stun_server_addresses: stun_server_addresses.clone(),
                traffic_mark,
            };

            tunnel_providers.push(Box::new(QuicInTunnelProvider::new(
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
                socket.set_keepalive(true)?;

                socket.bind(listen_address)?;

                socket.listen(1024)?
            };

            while let Ok((mut stream, source)) = tcp_listener.accept().await {
                let destination = get_socket_original_destination(&stream, IpFamily::V4)
                    .unwrap_or_else(|_| stream.local_addr().unwrap());

                let fake_ip_resolver = fake_ip_resolver.clone();
                let geolite2 = geolite2.clone();
                let router = router.clone();
                let tunnel_manager = tunnel_manager.clone();

                tokio::spawn(async move {
                    let (resolved_destination, name, labels_groups, sniff_buffer) =
                        resolve_destination(
                            destination,
                            &fake_ip_resolver,
                            &mut stream,
                            &geolite2,
                            &router,
                        )
                        .await;

                    let Some(resolved_destination) = resolved_destination else {
                        let _ = stream.shutdown().await;
                        return;
                    };

                    handle_in_tcp_stream(
                        stream,
                        sniff_buffer,
                        source,
                        resolved_destination,
                        name,
                        labels_groups,
                        tunnel_manager,
                    )
                    .await;
                });
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    log::info!("transparent proxy listening on {listen_address}...");

    tokio::try_join!(tunnel_task, listen_tcp_task)?;

    Ok(())
}

async fn resolve_destination(
    destination: SocketAddr,
    fake_ip_resolver: &FakeIpResolver,
    stream: &mut tokio::net::TcpStream,
    geolite2: &GeoLite2,
    router: &Router,
) -> (
    Option<SocketAddr>,
    Option<String>,
    Vec<Vec<(Label, Option<String>)>>,
    Vec<u8>,
) {
    let mut sniff_buffer = Vec::new();

    let Some((real_ip, mut name)) = fake_ip_resolver.resolve(&destination.ip()) else {
        return (None, None, Vec::new(), sniff_buffer);
    };

    if name.is_none() {
        const READ_BUFFER_SIZE: usize = 4096;

        let mut read_buffer = [0; READ_BUFFER_SIZE];

        loop {
            match stream.read(&mut read_buffer).await {
                Ok(read_length) => {
                    sniff_buffer.extend_from_slice(&read_buffer[..read_length]);

                    match extract_sni_hostname(&sniff_buffer) {
                        Some(hostname) => {
                            name = hostname;
                            break;
                        }
                        None => {
                            continue;
                        }
                    }
                }
                Err(error) => {
                    log::warn!("connection to {real_ip} errored: {error}");
                    break;
                }
            }
        }
    }

    let real_destination = SocketAddr::new(real_ip, destination.port());

    let region_codes = geolite2.lookup(real_ip);

    let labels_groups = router.r#match(real_destination, &name, &region_codes);

    (Some(real_destination), name, labels_groups, sniff_buffer)
}

fn extract_sni_hostname(buffer: &[u8]) -> Option<Option<String>> {
    let plaintext = match tls_parser::parse_tls_plaintext(buffer) {
        Ok((_, plaintext)) => plaintext,
        Err(error) => {
            if error.is_incomplete() {
                return None;
            } else {
                return Some(None);
            }
        }
    };

    for message in plaintext.msg {
        if let tls_parser::TlsMessage::Handshake(tls_parser::TlsMessageHandshake::ClientHello(
            hello,
        )) = message
        {
            let (_, extensions) = tls_parser::parse_tls_client_hello_extensions(hello.ext?).ok()?;
            for extension in extensions {
                if let tls_parser::TlsExtension::SNI(names) = extension {
                    for (sni_type, name_bytes) in names {
                        if sni_type == tls_parser::SNIType::HostName {
                            return Some(String::from_utf8(name_bytes.to_vec()).ok());
                        }
                    }
                }
            }
        }
    }

    Some(None)
}

async fn handle_in_tcp_stream(
    mut stream: tokio::net::TcpStream,
    sniff_buffer: Vec<u8>,
    source: SocketAddr,
    destination: SocketAddr,
    name: Option<String>,
    labels_groups: Vec<Vec<(Label, Option<String>)>>,
    tunnel_manager: Arc<TunnelManager>,
) {
    let destination_string = get_destination_string(destination, &name);

    log::debug!(
        "route connection from {source} to {destination_string} with labels {}...",
        stringify_labels_groups(&labels_groups)
    );

    let Some((tunnel, tag)) = tunnel_manager.select_tunnel(&labels_groups).await else {
        log::warn!(
            "connection from {source} to {destination_string} via {} rejected cause no matching tunnel.",
            stringify_labels_groups(&labels_groups)
        );

        let _ = stream.shutdown().await;

        return;
    };

    log::info!(
        "connect {source} to {destination_string} via {tunnel}{tagged}...",
        tagged = tag
            .as_deref()
            .map_or_else(|| "".to_owned(), |tag| format!(" ({tag})"))
    );

    if let Err(error) = {
        let destination_string = destination_string.clone();

        async move {
            let (mut tunnel_read_stream, mut tunnel_write_stream, stream_closed_sender) =
                tunnel.connect(destination, name, tag).await?;

            let (mut read_stream, mut write_stream) = stream.into_split();

            tunnel_write_stream.write_all(&sniff_buffer).await?;

            let copy_result = copy_bidirectional(
                &destination_string,
                (&mut read_stream, &mut tunnel_write_stream),
                (&mut tunnel_read_stream, &mut write_stream),
            )
            .await;

            stream_closed_sender.send(()).ok();

            copy_result?;

            anyhow::Ok(())
        }
    }
    .await
    {
        log::warn!("connection from {source} to {destination_string} errored: {error}");
    }
}

fn stringify_labels_groups(labels_groups: &[Vec<(Label, Option<String>)>]) -> String {
    labels_groups
        .iter()
        .map(|labels| labels.iter().map(|(label, _)| label).join(","))
        .join(";")
}
