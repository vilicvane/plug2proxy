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
