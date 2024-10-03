use std::sync::Arc;

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
    pub stun_server_address: String,
    pub match_server_config: MatchServerConfig,
    pub routing_rules: Vec<OutRuleConfig>,
}

pub async fn up(
    Options {
        labels,
        priority,
        stun_server_address,
        match_server_config,
        routing_rules,
    }: Options,
) -> anyhow::Result<()> {
    let match_server = match_server_config.new_out_match_server(labels).await?;

    let tunnel_provider = PunchQuicOutTunnelProvider::new(
        match_server,
        PunchQuicOutTunnelConfig {
            priority,
            stun_server_address,
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
    println!("tunnel accepted: {}", tunnel.id());

    loop {
        match tunnel.accept().await {
            Ok((typ, remote_addr, (tunnel_recv_stream, tunnel_send_stream))) => {
                println!("accept {} connection to {}", typ, remote_addr);

                match typ {
                    crate::tunnel::TransportType::Udp => tokio::spawn(handle_udp_stream(
                        remote_addr,
                        tunnel_recv_stream,
                        tunnel_send_stream,
                    )),
                    crate::tunnel::TransportType::Tcp => tokio::spawn(handle_tcp_stream(
                        remote_addr,
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
    remote_addr: std::net::SocketAddr,
    tunnel_recv_stream: Box<dyn tokio::io::AsyncRead + Send>,
    tunnel_send_stream: Box<dyn tokio::io::AsyncWrite + Send>,
) -> anyhow::Result<()> {
    let socket = tokio::net::UdpSocket::bind("0:0").await?;

    socket.connect(remote_addr).await?;

    let socket = Arc::new(socket);

    unimplemented!();

    Ok(())
}

async fn handle_tcp_stream(
    remote_addr: std::net::SocketAddr,
    tunnel_recv_stream: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    tunnel_send_stream: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
) -> anyhow::Result<()> {
    let stream = tokio::net::TcpStream::connect(remote_addr).await?;

    let (remote_recv_stream, remote_send_stream) = stream.into_split();

    copy_bidirectional(
        (tunnel_recv_stream, remote_send_stream),
        (remote_recv_stream, tunnel_send_stream),
    )
    .await?;

    Ok(())
}