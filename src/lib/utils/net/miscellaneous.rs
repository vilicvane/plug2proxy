use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

pub fn bind_tcp_listener_reuseaddr(address: SocketAddr) -> anyhow::Result<tokio::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    // Must be set before bind() (esp. on Windows semantics; harmless on Unix).
    socket.set_reuse_address(true)?;

    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;

    let listener = tokio::net::TcpListener::from_std(socket.into())?;

    Ok(listener)
}

pub const ANY_ADDRESS_IPV4: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

pub const ANY_ADDRESS_IPV6: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0));

pub fn get_any_address(address: &SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => ANY_ADDRESS_IPV4,
        SocketAddr::V6(_) => ANY_ADDRESS_IPV6,
    }
}

pub fn get_any_port_address(ip: &IpAddr) -> SocketAddr {
    match ip {
        IpAddr::V4(ip) => SocketAddr::V4(SocketAddrV4::new(*ip, 0)),
        IpAddr::V6(ip) => SocketAddr::V6(SocketAddrV6::new(*ip, 0, 0, 0)),
    }
}

pub fn parse_ip_net(ip_net: &str) -> anyhow::Result<ipnet::IpNet> {
    ip_net.parse().or_else(|_| {
        let ip = ip_net.parse::<IpAddr>()?;
        let prefix_length = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        anyhow::Ok(ipnet::IpNet::new(ip, prefix_length)?)
    })
}
