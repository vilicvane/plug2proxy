use std::net::{IpAddr, SocketAddr};

pub enum IpFamily {
    V4,
    V6,
}

pub fn get_tokio_tcp_stream_original_destination(
    stream: &tokio::net::TcpStream,
    family: IpFamily,
) -> anyhow::Result<SocketAddr> {
    match family {
        IpFamily::V4 => {
            let address =
                nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::OriginalDst)?;
            let ip = IpAddr::V4(address.sin_addr.s_addr.to_be().into());
            Ok(SocketAddr::new(ip, address.sin_port.to_be()))
        }
        IpFamily::V6 => {
            let address =
                nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::Ip6tOriginalDst)?;
            let ip = IpAddr::V6(address.sin6_addr.s6_addr.into());
            Ok(SocketAddr::new(ip, address.sin6_port.to_be()))
        }
    }
}

pub fn parse_ip_net(ip_net: &str) -> anyhow::Result<ipnet::IpNet> {
    ip_net
        .parse()
        .or_else(|_| {
            let ip = ip_net.parse::<IpAddr>()?;
            let prefix_length = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };

            anyhow::Ok(ipnet::IpNet::new(ip, prefix_length)?)
        })
        .map_err(Into::into)
}
