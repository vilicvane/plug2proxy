use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use futures::TryFutureExt;
use rusqlite::OptionalExtension;
use tokio::io::AsyncWriteExt;

use crate::{
    config::MatchServerConfig,
    punch_quic::{PunchQuicInTunnelConfig, PunchQuicInTunnelProvider},
    tunnel::{InTunnel, TunnelId},
    tunnel_provider::InTunnelProvider as _,
    utils::{io::copy_bidirectional, net::get_tokio_tcp_stream_original_dst},
};

pub struct Options {
    pub listen_address: SocketAddr,
    pub fake_ip_dns_db_path: PathBuf,
    pub fake_ipv4_net: ipnet::Ipv4Net,
    pub fake_ipv6_net: ipnet::Ipv6Net,
    pub stun_server_address: String,
    pub match_server_config: MatchServerConfig,
}

pub async fn up(
    Options {
        listen_address,
        fake_ip_dns_db_path,
        fake_ipv4_net,
        fake_ipv6_net,
        stun_server_address,
        match_server_config,
    }: Options,
) -> anyhow::Result<()> {
    let sqlite_connection = rusqlite::Connection::open_with_flags(
        &fake_ip_dns_db_path,
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

    let tunnel_map = Arc::new(tokio::sync::Mutex::new(HashMap::<
        TunnelId,
        Arc<Box<dyn InTunnel>>,
    >::new()));

    let tunnel_task = {
        let tunnel_set = Arc::clone(&tunnel_map);

        async move {
            loop {
                if let Ok(tunnel) = tunnel_provider.accept().await {
                    tunnel_set
                        .lock()
                        .await
                        .insert(tunnel.get_id(), Arc::new(tunnel));
                }
            }

            #[allow(unreachable_code)]
            anyhow::Ok(())
        }
    };

    let listen_task = {
        let tunnel_map = Arc::clone(&tunnel_map);

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

            while let Ok((mut stream, _)) = tcp_listener.accept().await {
                let destination = get_tokio_tcp_stream_original_dst(&stream)?;

                let destination_ip = destination.ip();

                let fake_ip_type_and_id = match destination_ip {
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

                let destination = if let Some((type_, id)) = fake_ip_type_and_id {
                    let record: Option<(String, Vec<u8>)> = sqlite_connection
                        .query_row(
                            "SELECT name, real_ip FROM records WHERE type = ? AND id = ?",
                            rusqlite::params![type_.to_string(), id],
                            |row| Ok((row.get("name")?, row.get("real_ip")?)),
                        )
                        .optional()
                        .unwrap();

                    println!("record: {:?}", record);

                    if let Some((name, real_ip)) = record {
                        // TODO: routing

                        let real_ip = match type_ {
                            hickory_client::rr::RecordType::A => IpAddr::V4(Ipv4Addr::from_bits(
                                u32::from_be_bytes(real_ip.try_into().unwrap()),
                            )),
                            hickory_client::rr::RecordType::AAAA => {
                                IpAddr::V6(Ipv6Addr::from_bits(u128::from_be_bytes(
                                    real_ip.try_into().unwrap(),
                                )))
                            }
                            _ => unreachable!(),
                        };

                        println!("real ip {}", real_ip);

                        SocketAddr::new(real_ip, destination.port())
                    } else {
                        destination
                    }
                } else {
                    destination
                };

                let tunnel_map = tunnel_map.lock().await;

                let Some(tunnel) = tunnel_map.values().next() else {
                    stream.shutdown().await?;
                    continue;
                };

                let (mut client_recv_stream, mut client_send_stream) = stream.into_split();

                tokio::spawn({
                    let tunnel = Arc::clone(tunnel);

                    async move {
                        let (mut tunnel_recv_stream, mut tunnel_send_stream) = tunnel
                            .connect(crate::tunnel::TransportType::Tcp, destination)
                            .await?;

                        copy_bidirectional(
                            (&mut client_recv_stream, &mut tunnel_send_stream),
                            (&mut tunnel_recv_stream, &mut client_send_stream),
                        )
                        .await?;

                        anyhow::Ok(())
                    }
                    .inspect_err(|error| log::error!("tunnel error: {:?}", error))
                });
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
