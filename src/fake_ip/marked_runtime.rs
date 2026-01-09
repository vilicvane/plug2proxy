use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use hickory_resolver::proto::{
    ProtoError,
    runtime::{RuntimeProvider, Spawn, Time, iocompat::AsyncIoTokioAsStd},
};
use tokio::net::TcpSocket;

use crate::util::set_socket_mark;

/// A RuntimeProvider that sets SO_MARK on all created sockets.
/// This is needed for TPROXY to avoid intercepting the fake-ip DNS server's
/// upstream queries.
#[derive(Clone)]
pub struct MarkedRuntimeProvider {
    mark: Option<u32>,
    handle: tokio::runtime::Handle,
}

impl MarkedRuntimeProvider {
    pub fn new(mark: Option<u32>) -> Self {
        Self {
            mark,
            handle: tokio::runtime::Handle::current(),
        }
    }
}

impl Default for MarkedRuntimeProvider {
    fn default() -> Self {
        Self::new(None)
    }
}

impl RuntimeProvider for MarkedRuntimeProvider {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = tokio::net::UdpSocket;
    type Tcp = AsyncIoTokioAsStd<tokio::net::TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        TokioHandle(self.handle.clone())
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        let mark = self.mark;
        Box::pin(async move {
            let socket = match server_addr {
                SocketAddr::V4(_) => TcpSocket::new_v4(),
                SocketAddr::V6(_) => TcpSocket::new_v6(),
            }?;

            // Set mark before bind/connect
            if let Some(m) = mark {
                set_socket_mark(&socket, m)?;
            }

            if let Some(bind_addr) = bind_addr {
                socket.bind(bind_addr)?;
            }

            let connect = socket.connect(server_addr);
            let tcp = match wait_for {
                Some(wait_for) => {
                    tokio::time::timeout(wait_for, connect)
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "connection timed out")
                        })??
                }
                None => connect.await?,
            };

            Ok(AsyncIoTokioAsStd(tcp))
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        let mark = self.mark;
        Box::pin(async move {
            // Use socket2 to create the socket so we can set SO_MARK before binding
            let domain = match local_addr {
                SocketAddr::V4(_) => socket2::Domain::IPV4,
                SocketAddr::V6(_) => socket2::Domain::IPV6,
            };

            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

            // Set mark before bind
            if let Some(m) = mark {
                set_socket_mark(&socket, m)?;
            }

            socket.set_nonblocking(true)?;
            socket.bind(&local_addr.into())?;

            let std_socket: std::net::UdpSocket = socket.into();
            tokio::net::UdpSocket::from_std(std_socket)
        })
    }
}

/// Tokio-based handle for spawning futures.
#[derive(Clone)]
pub struct TokioHandle(tokio::runtime::Handle);

impl Spawn for TokioHandle {
    fn spawn_bg<F>(&mut self, future: F)
    where
        F: Future<Output = Result<(), ProtoError>> + Send + 'static,
    {
        let _join = self.0.spawn(future);
    }
}

/// Tokio-based timer implementation.
#[derive(Clone, Copy, Default)]
pub struct TokioTime;

#[async_trait::async_trait]
impl Time for TokioTime {
    async fn delay_for(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    async fn timeout<F: 'static + Future + Send>(
        duration: Duration,
        future: F,
    ) -> io::Result<F::Output> {
        tokio::time::timeout(duration, future)
            .await
            .map_err(move |_| io::Error::new(io::ErrorKind::TimedOut, "operation timed out"))
    }
}
