use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use futures::future::try_join_all;
use itertools::Itertools;
use lits::duration;
use tokio::io::AsyncWriteExt;

use crate::{
    common::get_destination_string,
    config::MatchServerConfig,
    r#in::{
        dns_resolver::convert_to_socket_addresses,
        fake_ip_dns::FakeIpResolver,
        udp_forwarder::{UdpForwarder, UDP_BUFFER_SIZE},
    },
    route::{config::InRuleConfig, geolite2::GeoLite2, router::Router, rule::Label},
    tunnel::{
        http2::{
            Http2InTunnelConfig, Http2InTunnelProvider, PlugHttp2InTunnelConfig,
            PlugHttp2InTunnelProvider,
        },
        quic::{QuicInTunnelConfig, QuicInTunnelProvider},
        InTunnelLike as _, InTunnelProvider,
    },
    utils::{
        io::copy_bidirectional,
        net::socket::{get_socket_original_destination, set_keepalive_options, IpFamily},
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
    pub tunneling_plug_http2_enabled: bool,
    pub tunneling_plug_http2_listen_address: SocketAddr,
    pub tunneling_plug_http2_external_port: Option<u16>,
    pub tunneling_plug_http2_connections: usize,
    pub tunneling_plug_http2_priority: Option<i64>,
    pub tunneling_plug_http2_priority_default: i64,
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
        tunneling_plug_http2_enabled,
        tunneling_plug_http2_listen_address,
        tunneling_plug_http2_external_port,
        tunneling_plug_http2_connections,
        tunneling_plug_http2_priority,
        tunneling_plug_http2_priority_default,
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

        if tunneling_plug_http2_enabled {
            let config = PlugHttp2InTunnelConfig {
                listen_address: tunneling_plug_http2_listen_address,
                external_port: tunneling_plug_http2_external_port,
                connections: tunneling_plug_http2_connections,
                priority: tunneling_plug_http2_priority,
                priority_default: tunneling_plug_http2_priority_default,
                stun_server_addresses: stun_server_addresses.clone(),
                traffic_mark,
            };

            tunnel_providers.push(Box::new(
                PlugHttp2InTunnelProvider::new(match_server.clone(), config).await?,
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

                socket.set_reuseaddr(true)?;
                socket.set_nodelay(true)?;

                set_keepalive_options(&socket, 60, 10, 5)?;

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
                    let (resolved_destination, name, labels_groups, sniff_buffer, end) =
                        resolve_tcp_destination(
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
                        end,
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

    let listen_udp_task = async move {
        let udp_forwarder = UdpForwarder::new(listen_address, traffic_mark)?;

        let mut buffer = [0u8; UDP_BUFFER_SIZE];

        while let Ok((length, source, original_destination)) =
            udp_forwarder.receive(&mut buffer).await
        {
            let real_destination = udp_forwarder
                .get_associated_destination(&source, &original_destination)
                .await
                .or_else(|| {
                    let (real_destination, name, _) = resolve_udp_destination(
                        original_destination,
                        &fake_ip_resolver,
                        &geolite2,
                        &router,
                    );

                    real_destination.inspect(|&real_destination| {
                        let destination_string = get_destination_string(real_destination, &name);

                        log::info!("redirect datagrams from {source} to {destination_string}...");
                    })
                });

            if let Some(real_destination) = real_destination {
                udp_forwarder
                    .send(
                        source,
                        original_destination,
                        real_destination,
                        &buffer[..length],
                    )
                    .await?;
            }
        }

        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    log::info!("transparent proxy listening on {listen_address}...");

    tokio::try_join!(tunnel_task, listen_tcp_task, listen_udp_task)?;

    Ok(())
}

async fn resolve_tcp_destination(
    destination: SocketAddr,
    fake_ip_resolver: &FakeIpResolver,
    stream: &mut tokio::net::TcpStream,
    geolite2: &GeoLite2,
    router: &Router,
) -> (
    Option<SocketAddr>,
    Option<String>,
    Vec<Vec<(Label, Option<String>)>>,
    Option<Vec<u8>>,
    bool,
) {
    let Some((real_ip, mut name)) = fake_ip_resolver.resolve(&destination.ip()) else {
        return (None, None, Vec::new(), None, false);
    };

    let mut sniff_buffer = Vec::new();
    let mut end = false;

    if name.is_none() {
        const READ_BUFFER_SIZE: usize = 4096;

        let mut read_buffer = [0; READ_BUFFER_SIZE];

        const READ_ATTEMPTS_LIMIT: usize = 5;
        const READ_ATTEMPTS_INTERVAL: Duration = duration!("100ms");

        let mut read_attempts = 0;

        let mut determined = false;

        loop {
            match stream.try_read(&mut read_buffer) {
                Ok(read_length) => {
                    if read_length == 0 {
                        end = true;
                        break;
                    }

                    sniff_buffer.extend_from_slice(&read_buffer[..read_length]);

                    if determined {
                        // 已经确定，但是尝试把 buffer 读完。
                        continue;
                    }

                    let sniff_buffer_length = sniff_buffer.len();

                    #[allow(unused_assignments)]
                    if sniff_buffer_length >= 1 && sniff_buffer[0] != 0x16
                        || sniff_buffer_length >= 2 && sniff_buffer[1] != 0x03
                    {
                        determined = true;
                        break;
                    }

                    #[allow(unused_assignments)]
                    if let Some(hostname) = extract_sni_hostname(&sniff_buffer) {
                        name = hostname;
                        determined = true;
                        break;
                    }
                }
                Err(error) => {
                    if error.kind() == std::io::ErrorKind::WouldBlock {
                        if determined {
                            break;
                        }

                        if read_attempts < READ_ATTEMPTS_LIMIT {
                            tokio::time::sleep(READ_ATTEMPTS_INTERVAL).await;

                            read_attempts += 1;

                            continue;
                        }
                    } else {
                        log::warn!("connection to {real_ip} read errored: {error}");
                    }

                    break;
                }
            }

            tokio::time::sleep(READ_ATTEMPTS_INTERVAL).await;
        }
    }

    let real_destination = SocketAddr::new(real_ip, destination.port());

    let region_codes = geolite2.lookup(real_ip);

    let labels_groups = router.r#match(real_destination, &name, &region_codes);

    (
        Some(real_destination),
        name,
        labels_groups,
        if sniff_buffer.is_empty() {
            None
        } else {
            Some(sniff_buffer)
        },
        end,
    )
}

fn resolve_udp_destination(
    destination: SocketAddr,
    fake_ip_resolver: &FakeIpResolver,
    geolite2: &GeoLite2,
    router: &Router,
) -> (
    Option<SocketAddr>,
    Option<String>,
    Vec<Vec<(Label, Option<String>)>>,
) {
    if let Some((real_ip, name)) = fake_ip_resolver.resolve(&destination.ip()) {
        let real_destination = SocketAddr::new(real_ip, destination.port());

        let region_codes = geolite2.lookup(real_ip);

        let labels_groups = router.r#match(real_destination, &name, &region_codes);

        (Some(real_destination), name, labels_groups)
    } else {
        (None, None, Vec::new())
    }
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
    sniff_buffer: Option<Vec<u8>>,
    end: bool,
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
                tunnel.connect(destination, name, tag, sniff_buffer).await?;

            let (mut read_stream, mut write_stream) = stream.into_split();

            let copy_result = copy_bidirectional(
                &destination_string,
                (&mut read_stream, &mut tunnel_write_stream, end),
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
