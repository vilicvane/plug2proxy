use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use futures::TryFutureExt;
use tokio::io::AsyncWriteExt;

use crate::{
    punch_quic::{PunchQuicClientTunnelConfig, PunchQuicClientTunnelProvider},
    tunnel::{ClientTunnel, TunnelId},
    tunnel_provider::ClientTunnelProvider as _,
    utils::{io::copy_bidirectional, net::get_tokio_tcp_stream_original_dst},
};

use super::config::Config;

pub async fn up(config: Config) -> anyhow::Result<()> {
    let match_server = config.matcher.new_client_side_matcher()?;

    let tunnel_provider = PunchQuicClientTunnelProvider::new(
        match_server,
        PunchQuicClientTunnelConfig {
            stun_server_addr: config.stun_server,
        },
    );

    let tunnel_map = Arc::new(tokio::sync::Mutex::new(HashMap::<
        TunnelId,
        Arc<Box<dyn ClientTunnel>>,
    >::new()));

    let tunnel_task = {
        let tunnel_set = Arc::clone(&tunnel_map);

        async move {
            loop {
                if let Ok(tunnel) = tunnel_provider.accept().await {
                    println!("tunnel accepted: {}", tunnel.get_id());

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
            let tcp_server_address = "0.0.0.0:12345".parse::<SocketAddr>()?;

            let tcp_listener = socket2::Socket::new(
                socket2::Domain::for_address(tcp_server_address),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            tcp_listener.set_ip_transparent(true)?;

            tcp_listener.bind(&socket2::SockAddr::from(tcp_server_address))?;
            tcp_listener.listen(1024)?;

            let tcp_listener = std::net::TcpListener::from(tcp_listener);

            tcp_listener.set_nonblocking(true)?;

            let tcp_listener = tokio::net::TcpListener::from_std(tcp_listener)?;

            while let Ok((mut stream, _)) = tcp_listener.accept().await {
                let destination = get_tokio_tcp_stream_original_dst(&stream)?;

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
