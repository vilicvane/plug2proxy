async fn test_socket() -> anyhow::Result<()> {
    let tcp_server_address = "0.0.0.0:12233".parse::<SocketAddr>()?;

    let tcp_server = socket2::Socket::new(
        socket2::Domain::for_address(tcp_server_address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    tcp_server.set_ip_transparent(true)?;

    tcp_server.bind(&socket2::SockAddr::from(tcp_server_address))?;
    tcp_server.listen(1024)?;

    let (socket, source_address) = tcp_server.accept()?;

    let original_destination = socket.original_dst();

    let mut socket = tokio::net::TcpStream::from_std(std::net::TcpStream::from(socket))?;

    println!("Accepted connection from: {:?}", source_address.as_socket());
    println!("{:?}", original_destination?.as_socket());

    socket.write("hello world\n".as_bytes()).await?;

    loop {
        let mut buffer = [0; 8];

        let length = socket.read(&mut buffer).await?;

        if length == 0 {
            break;
        }

        println!("Received: {:?}", &buffer[..length]);
    }

    Ok(())
}
