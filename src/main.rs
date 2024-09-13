use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
};

mod tproxy_socket;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let tcp_server_address = "0.0.0.0:11223".parse::<SocketAddr>()?;

    let tcp_server = socket2::Socket::new(
        socket2::Domain::for_address(tcp_server_address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    tcp_server.set_ip_transparent(true)?;

    tcp_server.bind(&socket2::SockAddr::from(tcp_server_address))?;
    tcp_server.listen(1024)?;

    let (socket, source_address) = tcp_server.accept()?;

    println!("Accepted connection from: {:?}", source_address.as_socket());
    println!("{:?}", socket.original_dst()?.as_socket());

    tokio::signal::ctrl_c().await?;

    Ok(())
}
