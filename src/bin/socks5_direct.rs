//! Simple direct SOCKS5 proxy for testing socks5-server usage.
//! This bypasses all tunnel logic and connects directly to targets.

use std::net::SocketAddr;
use std::sync::Arc;

use socks5_server::{
    AssociatedUdpSocket, Command, IncomingConnection, Server,
    proto::{Address, Reply},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let bind_addr: SocketAddr = "127.0.0.1:1080".parse()?;

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let auth = Arc::new(socks5_server::auth::NoAuth);
    let server = Server::new(listener, auth);

    tracing::info!("Direct SOCKS5 proxy listening on {}", bind_addr);

    loop {
        match server.accept().await {
            Ok((conn, addr)) => {
                tracing::debug!("accepted connection from {}", addr);

                let bind_addr_clone = bind_addr;
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(conn, bind_addr_clone).await {
                        tracing::error!("client {} error: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("accept error: {}", e);
            }
        }
    }
}

async fn handle_connection<A>(
    conn: IncomingConnection<A, socks5_server::connection::state::NeedAuthenticate>,
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (conn, _) = conn.authenticate().await.map_err(|(e, _)| e)?;

    match conn.wait().await.map_err(|(e, _)| e)? {
        Command::Connect(connect, addr) => {
            let target = address_to_string(&addr);
            tracing::info!("CONNECT to {}", target);
            handle_connect(connect, &target).await
        }
        Command::Bind(_, _) => {
            tracing::warn!("BIND not supported");
            Ok(())
        }
        Command::Associate(associate, addr) => {
            tracing::info!("UDP ASSOCIATE from {}", addr);
            handle_udp_associate(associate, server_addr).await
        }
    }
}

async fn handle_connect(
    connect: socks5_server::Connect<socks5_server::connection::connect::state::NeedReply>,
    target: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Connect directly to target
    let target_stream = match TcpStream::connect(target).await {
        Ok(s) => {
            s.set_nodelay(true)?;
            s
        }
        Err(e) => {
            tracing::error!("failed to connect to {}: {}", target, e);
            let _ = connect
                .reply(Reply::GeneralFailure, Address::unspecified())
                .await;
            return Err(e.into());
        }
    };

    tracing::info!("connected to {}", target);

    // Send success reply
    let mut client = connect
        .reply(Reply::Succeeded, Address::unspecified())
        .await
        .map_err(|(e, _)| e)?;

    // Simple bidirectional relay
    let (mut target_read, mut target_write) = target_stream.into_split();

    let mut client_buf = vec![0u8; 16384];
    let mut target_buf = vec![0u8; 16384];

    loop {
        tokio::select! {
            // Client -> Target
            result = client.read(&mut client_buf) => {
                match result {
                    Ok(0) => {
                        tracing::debug!("client closed");
                        break;
                    }
                    Ok(n) => {
                        tracing::trace!("client -> target: {} bytes", n);
                        target_write.write_all(&client_buf[..n]).await?;
                    }
                    Err(e) => {
                        tracing::debug!("client read error: {}", e);
                        break;
                    }
                }
            }

            // Target -> Client
            result = target_read.read(&mut target_buf) => {
                match result {
                    Ok(0) => {
                        tracing::debug!("target closed");
                        break;
                    }
                    Ok(n) => {
                        tracing::trace!("target -> client: {} bytes", n);
                        client.write_all(&target_buf[..n]).await?;
                    }
                    Err(e) => {
                        tracing::debug!("target read error: {}", e);
                        break;
                    }
                }
            }
        }
    }

    tracing::debug!("relay completed");
    Ok(())
}

async fn handle_udp_associate(
    associate: socks5_server::Associate<socks5_server::connection::associate::state::NeedReply>,
    server_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Bind UDP relay socket
    let bind_addr = if server_addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let relay_socket = UdpSocket::bind(bind_addr).await?;
    let relay_local_addr = relay_socket.local_addr()?;

    tracing::info!("UDP relay socket bound to {}", relay_local_addr);

    // Build reply address
    let reply_ip = if server_addr.ip().is_loopback() {
        if server_addr.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
    } else {
        server_addr.ip()
    };
    let reply_addr = SocketAddr::new(reply_ip, relay_local_addr.port());

    tracing::info!("UDP ASSOCIATE: relay address {} sent to client", reply_addr);

    // Send success reply
    let mut associate = associate
        .reply(Reply::Succeeded, Address::SocketAddress(reply_addr))
        .await
        .map_err(|(e, _)| e)?;

    // Wrap relay socket with SOCKS5 UDP handling
    let associated_socket = AssociatedUdpSocket::new(relay_socket, 65535);

    // Spawn UDP relay task
    let relay_task = tokio::spawn(async move {
        if let Err(e) = run_udp_relay(associated_socket).await {
            tracing::error!("UDP relay error: {:?}", e);
        }
    });

    // Wait for TCP control connection to close
    if let Err(e) = associate.wait_close().await {
        tracing::debug!("TCP control connection closed: {}", e);
    }

    tracing::info!("UDP ASSOCIATE: TCP control connection closed, stopping relay");
    relay_task.abort();

    Ok(())
}

async fn run_udp_relay(
    socket: AssociatedUdpSocket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Create a single outbound socket for forwarding
    let outbound = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    tracing::info!("UDP outbound socket bound to {}", outbound.local_addr()?);

    let socket = Arc::new(socket);

    // Track client address for responses
    let client_addr: Arc<tokio::sync::RwLock<Option<SocketAddr>>> =
        Arc::new(tokio::sync::RwLock::new(None));

    // Task: Client -> Destination
    let socket_recv = Arc::clone(&socket);
    let outbound_send = Arc::clone(&outbound);
    let client_addr_write = Arc::clone(&client_addr);
    let client_to_dest = tokio::spawn(async move {
        loop {
            match socket_recv.recv_from().await {
                Ok((data, header, from_addr)) => {
                    let dest_addr = match header.address {
                        Address::SocketAddress(addr) => addr,
                        Address::DomainAddress(domain, port) => {
                            let domain_str = String::from_utf8_lossy(&domain);
                            tracing::warn!("UDP domain not supported: {}:{}", domain_str, port);
                            continue;
                        }
                    };

                    tracing::debug!("UDP: {} -> {} ({} bytes)", from_addr, dest_addr, data.len());

                    // Remember client address for responses
                    {
                        let mut addr = client_addr_write.write().await;
                        *addr = Some(from_addr);
                    }

                    // Forward to destination
                    if let Err(e) = outbound_send.send_to(&data, dest_addr).await {
                        tracing::warn!("UDP forward error: {}", e);
                    }
                }
                Err((e, _)) => {
                    tracing::error!("UDP recv error: {:?}", e);
                    break;
                }
            }
        }
    });

    // Task: Destination -> Client
    let socket_send = socket;
    let outbound_recv = outbound;
    let client_addr_read = client_addr;
    let dest_to_client = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match outbound_recv.recv_from(&mut buf).await {
                Ok((len, from_addr)) => {
                    let client = {
                        let addr = client_addr_read.read().await;
                        *addr
                    };

                    if let Some(client) = client {
                        tracing::debug!("UDP: {} <- {} ({} bytes)", client, from_addr, len);

                        let header = socks5_server::proto::UdpHeader {
                            frag: 0,
                            address: Address::SocketAddress(from_addr),
                        };

                        if let Err(e) = socket_send.send_to(&buf[..len], &header, client).await {
                            tracing::warn!("UDP send to client error: {}", e);
                        }
                    } else {
                        tracing::warn!("UDP response but no client address known");
                    }
                }
                Err(e) => {
                    tracing::error!("UDP outbound recv error: {}", e);
                    break;
                }
            }
        }
    });

    tokio::select! {
        _ = client_to_dest => {
            tracing::debug!("UDP client->dest task ended");
        }
        _ = dest_to_client => {
            tracing::debug!("UDP dest->client task ended");
        }
    }

    Ok(())
}

fn address_to_string(addr: &Address) -> String {
    match addr {
        Address::SocketAddress(addr) => addr.to_string(),
        Address::DomainAddress(domain, port) => {
            let domain_str = String::from_utf8_lossy(domain);
            format!("{}:{}", domain_str, port)
        }
    }
}
