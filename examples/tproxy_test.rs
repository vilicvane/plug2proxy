use std::{
    mem,
    net::SocketAddr,
    os::fd::{AsFd as _, AsRawFd as _},
};

use anyhow::Ok;
use plug2proxy::utils::net::{get_tokio_tcp_stream_original_destination, IpFamily};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let listen_address = "[::]:12346".parse::<SocketAddr>().unwrap();

    let socket = tokio::net::TcpSocket::new_v6()?;

    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::IpTransparent, &true)?;
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::IpFreebind, &true)?;

    socket.set_reuseport(true)?;

    socket.bind(listen_address)?;

    let listener = socket.listen(64)?;

    while let Result::Ok((stream, _)) = listener.accept().await {
        let original_dst = get_tokio_tcp_stream_original_destination(&stream, IpFamily::V6)?;

        println!(
            "accept new connection, peer[{}]->local[{}], {}",
            stream.peer_addr()?,
            stream.local_addr()?,
            original_dst,
        );
    }

    Ok(())
}
