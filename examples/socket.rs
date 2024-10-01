use std::net::SocketAddr;

use plug2proxy::utils::net::get_tokio_tcp_stream_original_dst;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let tcp_server_address = "0.0.0.0:12233".parse::<SocketAddr>()?;

    let tcp_listener = socket2::Socket::new(
        socket2::Domain::for_address(tcp_server_address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    tcp_listener.set_ip_transparent(true)?;

    tcp_listener.bind(&socket2::SockAddr::from(tcp_server_address))?;
    tcp_listener.listen(1024)?;

    // let (socket, source_address) = tcp_listener.accept()?;

    // let original_destination = socket.original_dst();

    // let mut socket = tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))?;

    // println!("Accepted connection from: {:?}", source_address.as_socket());
    // println!("{:?}", original_destination?.as_socket());

    let tcp_listener =
        tokio::net::TcpListener::from_std(std::net::TcpListener::from(tcp_listener))?;

    let (mut stream, _) = tcp_listener.accept().await?;

    println!("{:?}", get_tokio_tcp_stream_original_dst(&stream)?);

    stream.write_all("hello world\n".as_bytes()).await?;

    loop {
        let mut buffer = [0; 8];

        let length = stream.read(&mut buffer).await?;

        if length == 0 {
            break;
        }

        println!("Received: {:?}", &buffer[..length]);
    }

    Ok(())
}
