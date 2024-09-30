use std::{
    mem::forget,
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd, FromRawFd},
};

pub fn get_tokio_tcp_stream_original_dst(
    stream: &tokio::net::TcpStream,
) -> anyhow::Result<SocketAddr> {
    let raw_fd = stream.as_fd().as_raw_fd();

    let socket = unsafe { socket2::Socket::from_raw_fd(raw_fd) };

    let original_dst = socket.original_dst()?.as_socket().unwrap();

    forget(socket);

    Ok(original_dst)
}
