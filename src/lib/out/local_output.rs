use std::net::{IpAddr, SocketAddr};

use crate::utils::net::socket::set_keepalive_options;

use super::output::Output;

pub enum LocalIpOrInterface {
    Ip(IpAddr),
    Interface(String),
}

impl<'de> serde::Deserialize<'de> for LocalIpOrInterface {
    fn deserialize<T>(deserializer: T) -> Result<Self, T::Error>
    where
        T: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;

        if let Ok(ip) = value.parse::<IpAddr>() {
            Ok(LocalIpOrInterface::Ip(ip))
        } else {
            Ok(LocalIpOrInterface::Interface(value))
        }
    }
}

pub struct LocalOutput {
    ip_or_interface: Option<LocalIpOrInterface>,
}

impl LocalOutput {
    pub fn new(ip_or_interface: Option<LocalIpOrInterface>) -> Self {
        Self { ip_or_interface }
    }
}

impl Default for LocalOutput {
    fn default() -> Self {
        Self::new(None)
    }
}

#[async_trait::async_trait]
impl Output for LocalOutput {
    async fn connect(
        &self,
        address: SocketAddr,
    ) -> anyhow::Result<(
        Box<dyn tokio::io::AsyncRead + Send + Unpin>,
        Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
    )> {
        let socket = match address {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
        }?;

        socket.set_nodelay(true)?;

        set_keepalive_options(&socket, 60, 10, 5)?;

        match &self.ip_or_interface {
            Some(LocalIpOrInterface::Ip(ip)) => {
                socket.bind(SocketAddr::new(*ip, 0))?;
            }
            Some(LocalIpOrInterface::Interface(interface)) => {
                socket.bind_device(Some(interface.as_bytes()))?;
            }
            None => {}
        }

        let stream = socket.connect(address).await?;

        let (read_stream, write_stream) = stream.into_split();

        Ok((Box::new(read_stream), Box::new(write_stream)))
    }
}
