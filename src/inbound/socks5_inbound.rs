use std::{
  net::SocketAddr,
  pin::Pin,
  task::{Context, Poll},
};

use async_trait::async_trait;
use futures::{Sink, Stream};
use lowkit::{SelfWrapExt, tokio_join_set};
use socks5_server::{
  Command, Connect, IncomingConnection, Server,
  auth::NoAuth,
  connection::{connect::state::Ready, state::NeedAuthenticate},
  proto::{Address, Reply},
};
use tokio::{
  io::{AsyncRead, AsyncWrite, ReadBuf},
  net::{TcpListener, ToSocketAddrs},
  sync::mpsc,
  task::JoinSet,
};

use crate::{
  inbound::{Inbound, InboundError},
  primitives::{Destination, DestinationAddress},
  udp::UdpPacket,
};

pub struct Socks5Inbound {
  listen_address: SocketAddr,
  tcp_connect_receiver: tokio::sync::Mutex<mpsc::UnboundedReceiver<(Destination, Socks5TcpStream)>>,
  _join_set: JoinSet<()>,
}

impl Socks5Inbound {
  pub async fn new(listen_address: impl ToSocketAddrs) -> Result<Self, InboundError> {
    let tcp_listener = TcpListener::bind(listen_address).await?;

    let listen_address = tcp_listener.local_addr()?;

    let server = Server::new(tcp_listener, NoAuth.arc());

    let (tcp_connect_sender, tcp_connect_receiver) = mpsc::unbounded_channel();

    Self {
      listen_address,
      tcp_connect_receiver: tokio::sync::Mutex::new(tcp_connect_receiver),
      _join_set: tokio_join_set!(async move {
        loop {
          let (connection, _) = server.accept().await.unwrap();

          let tcp_connect_sender = tcp_connect_sender.clone();

          tokio::spawn(async {
            handle_incoming_connection(connection, tcp_connect_sender)
              .await
              .inspect_err(|error| {
                log::error!("error handling incoming connection: {}", error);
              })
              .ok();
          });
        }
      }),
    }
    .wrap_ok()
  }

  pub fn listen_address(&self) -> SocketAddr {
    self.listen_address
  }
}

#[async_trait]
impl Inbound for Socks5Inbound {
  type TcpStream = Socks5TcpStream;
  type UdpPacketStream = Socks5UdpPacketStream;

  async fn accept_tcp_connect(&self) -> Result<(Destination, Self::TcpStream), InboundError> {
    let mut tcp_connect_receiver = self.tcp_connect_receiver.lock().await;

    tcp_connect_receiver
      .recv()
      .await
      .ok_or(InboundError::Closed)
  }

  async fn get_udp_packet_stream(&self) -> Result<Self::UdpPacketStream, InboundError> {
    todo!()
  }
}

pub struct Socks5TcpStream {
  stream: Connect<Ready>,
}

impl AsyncRead for Socks5TcpStream {
  fn poll_read(
    mut self: Pin<&mut Self>,
    context: &mut Context,
    buffer: &mut ReadBuf,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_read(context, buffer)
  }
}

impl AsyncWrite for Socks5TcpStream {
  fn poll_write(
    mut self: Pin<&mut Self>,
    context: &mut Context,
    buffer: &[u8],
  ) -> Poll<Result<usize, std::io::Error>> {
    Pin::new(&mut self.stream).poll_write(context, buffer)
  }

  fn poll_flush(
    mut self: Pin<&mut Self>,
    context: &mut Context,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_flush(context)
  }

  fn poll_shutdown(
    mut self: Pin<&mut Self>,
    context: &mut Context,
  ) -> Poll<Result<(), std::io::Error>> {
    Pin::new(&mut self.stream).poll_shutdown(context)
  }
}

pub struct Socks5UdpPacketStream {}

impl Sink<UdpPacket> for Socks5UdpPacketStream {
  type Error = InboundError;

  fn poll_ready(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    todo!()
  }

  fn start_send(self: Pin<&mut Self>, packet: UdpPacket) -> Result<(), Self::Error> {
    todo!()
  }

  fn poll_flush(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    todo!()
  }

  fn poll_close(self: Pin<&mut Self>, context: &mut Context) -> Poll<Result<(), Self::Error>> {
    todo!()
  }
}

impl Stream for Socks5UdpPacketStream {
  type Item = UdpPacket;

  fn poll_next(self: Pin<&mut Self>, context: &mut Context) -> Poll<Option<Self::Item>> {
    todo!()
  }
}

async fn handle_incoming_connection(
  connection: IncomingConnection<(), NeedAuthenticate>,
  tcp_connect_sender: mpsc::UnboundedSender<(Destination, Socks5TcpStream)>,
) -> Result<(), InboundError> {
  let (connection, _) = connection.authenticate().await?;

  match connection.wait().await? {
    Command::Connect(connect_command, address) => {
      let connect = connect_command
        .reply(Reply::Succeeded, Address::unspecified())
        .await?;

      tcp_connect_sender
        .send((address.into(), Socks5TcpStream { stream: connect }))
        .unwrap()
    }
    Command::Bind(bind_command, _address) => {
      bind_command
        .reply(Reply::CommandNotSupported, Address::unspecified())
        .await?;
    }
    Command::Associate(associate_command, _address) => {
      associate_command
        .reply(Reply::CommandNotSupported, Address::unspecified())
        .await?;
    }
  }

  Ok(())
}

impl From<socks5_server::proto::Address> for Destination {
  fn from(address: socks5_server::proto::Address) -> Self {
    match address {
      socks5_server::proto::Address::DomainAddress(domain, port) => Destination {
        address: DestinationAddress::DomainName(String::from_utf8_lossy(&domain).into_owned()),
        port,
      },
      socks5_server::proto::Address::SocketAddress(socket_address) => Destination {
        address: DestinationAddress::IpAddress(socket_address.ip()),
        port: socket_address.port(),
      },
    }
  }
}

impl<T> From<(std::io::Error, T)> for InboundError {
  fn from((error, _): (std::io::Error, T)) -> Self {
    InboundError::Io(error)
  }
}

impl<T> From<(socks5_server::proto::Error, T)> for InboundError {
  fn from((error, _): (socks5_server::proto::Error, T)) -> Self {
    InboundError::Io(error.into())
  }
}

#[cfg(test)]
mod tests {
  use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
  };

  use crate::{
    inbound::{Inbound, Socks5Inbound},
    primitives::{Destination, DestinationAddress},
  };

  #[tokio::test]
  async fn accept_tcp_connect_returns_destination_and_stream() -> anyhow::Result<()> {
    let inbound = Socks5Inbound::new("127.0.0.1:0").await?;
    let listen_address = inbound.listen_address();
    let (accept_result_sender, accept_result_receiver) = oneshot::channel();

    tokio::spawn(async move {
      let accept_result = async {
        let (destination, mut tcp_stream) = inbound
          .accept_tcp_connect()
          .await
          .map_err(std::io::Error::other)?;
        let mut received_payload = [0u8; 4];
        tcp_stream.read_exact(&mut received_payload).await?;
        tcp_stream.write_all(b"pong").await?;
        Ok::<_, std::io::Error>((destination, received_payload))
      }
      .await;

      let _ = accept_result_sender.send(accept_result);
    });

    let mut client_stream = TcpStream::connect(listen_address).await?;

    let handshake_request = socks5_server::proto::handshake::Request::new(vec![
      socks5_server::proto::handshake::Method::NONE,
    ]);
    handshake_request.write_to(&mut client_stream).await?;

    let handshake_response =
      socks5_server::proto::handshake::Response::read_from(&mut client_stream).await?;
    assert!(matches!(
      handshake_response.method,
      socks5_server::proto::handshake::Method::NONE
    ));

    let destination_address =
      socks5_server::proto::Address::DomainAddress(b"example.com".to_vec(), 443);
    let connect_request = socks5_server::proto::Request::new(
      socks5_server::proto::Command::Connect,
      destination_address,
    );
    connect_request.write_to(&mut client_stream).await?;

    let connect_response = socks5_server::proto::Response::read_from(&mut client_stream).await?;
    assert!(matches!(
      connect_response.reply,
      socks5_server::proto::Reply::Succeeded
    ));

    client_stream.write_all(b"ping").await?;
    let mut client_receive_buffer = [0u8; 4];
    client_stream.read_exact(&mut client_receive_buffer).await?;
    assert_eq!(&client_receive_buffer, b"pong");

    let (destination, received_payload) = accept_result_receiver.await??;

    assert_eq!(&received_payload, b"ping");
    assert_destination(destination, "example.com", 443);

    Ok(())
  }

  fn assert_destination(destination: Destination, domain: &str, port: u16) {
    assert_eq!(destination.port, port);
    match destination.address {
      DestinationAddress::DomainName(domain_name) => assert_eq!(domain_name, domain),
      DestinationAddress::IpAddress(_) => panic!("expected domain destination"),
    }
  }
}
