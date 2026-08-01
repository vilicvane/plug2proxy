use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  hub::{Hub, HubOptions},
  r#in::{In, InHubOptions, InOptions},
  inbound::{Socks5Inbound, Socks5InboundOptions},
  node::{DefaultLocalExit, LocalOutDispatcher},
  out::{Out, OutHubOptions, OutOptions},
  primitives::OutExit,
  route::{AddressRule, Router},
  test::{get_free_local_tcp_address, test_dir},
};
use lits::duration;
use lowkit::{SelfWrapExt, UserInterruptExt, user_interrupt};
use socks5_server::{
  AssociatedUdpSocket,
  proto::{Address, Reply, UdpHeader},
};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::{TcpListener, TcpStream, UdpSocket},
  time::{sleep, timeout},
};

#[tokio::test]
#[test_log::test]
async fn test_hub_out() -> anyhow::Result<()> {
  let test_dir = test_dir().join("hub_out");

  let hub_dir = test_dir.join("hub");
  let in_dir = test_dir.join("in");
  let out_dir = test_dir.join("out");

  generate_ca_pem_file(&test_dir).await?;

  generate_node_pem_file(&test_dir, "hub", true).await?;
  generate_node_pem_file(&test_dir, "in", true).await?;
  generate_node_pem_file(&test_dir, "out", true).await?;

  let hub_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;

  let hub_address = hub_tcp_listener.local_addr()?;

  let http_listener = TcpListener::bind("127.0.0.1:0").await?;
  let http_address = http_listener.local_addr()?;
  let udp_echo_socket = UdpSocket::bind(http_address).await?;

  let socks5_listen_address = get_free_local_tcp_address();

  let socks5_inbound = Socks5Inbound::new(Socks5InboundOptions {
    listen: socks5_listen_address,
    sniff: true,
  })
  .await?;

  tokio::try_join!(
    async {
      let router = Router::new(&hub_dir);

      router.register_local_rules(vec![
        AddressRule {
          match_ips: None,
          match_ports: Some(vec![http_address.port()]),
          priority: 0,
          negate: false,
          exits: vec![OutExit::from("system")],
        }
        .into(),
      ]);

      let udp_socket = UdpSocket::bind(hub_tcp_listener.local_addr()?).await.ok();

      let hub = Hub::new(
        hub_tcp_listener,
        udp_socket,
        vec![],
        router,
        HubOptions {
          local_out_dispatchers: vec![LocalOutDispatcher::new_default(DefaultLocalExit::Private)],
          context_dir: hub_dir,
        },
      );

      hub.run().await?;

      anyhow::Ok(())
    },
    async {
      let router = Router::new(&in_dir);
      let in_node = In::new(
        vec![socks5_inbound.into()],
        router,
        InOptions {
          context_dir: in_dir,
          hub: InHubOptions {
            address: hub_address,
            connections: 2,
          },
        },
      );

      in_node.run().await?;

      anyhow::Ok(())
    },
    async {
      // Force the IN to consume an initial snapshot without provider exits,
      // then verify the later OUT update enables the tagged local exit.
      sleep(duration!("500ms")).await;

      let out = Out::new(OutOptions {
        local_out_dispatchers: vec![LocalOutDispatcher::new_default(
          DefaultLocalExit::Advertised {
            tags: vec!["system".into()],
          },
        )],
        listen: None,
        advertise: None,
        context_dir: out_dir,
        hub: OutHubOptions {
          address: hub_address,
          connections: 2,
        },
      });

      out.run().await?;

      anyhow::Ok(())
    },
    async {
      let http_server = tokio::spawn(async move {
        let (mut stream, _) = http_listener.accept().await?;
        let mut request = Vec::new();
        let mut buffer = [0; 1024];

        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
          let length = stream.read(&mut buffer).await?;

          if length == 0 {
            anyhow::bail!("HTTP client closed before completing its request");
          }

          request.extend_from_slice(&buffer[..length]);
        }

        stream
          .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied")
          .await?;

        anyhow::Ok(())
      });

      let proxy = reqwest::Proxy::all(format!("socks5://{}", socks5_listen_address))?;

      let client = reqwest::Client::builder().proxy(proxy).build()?;

      let response = timeout(duration!("5s"), async {
        loop {
          match client.get(format!("http://{http_address}/")).send().await {
            Ok(response) => break anyhow::Ok(response),
            Err(_) => sleep(duration!("50ms")).await,
          }
        }
      })
      .await
      .map_err(|_| anyhow::anyhow!("timed out waiting for OUT provider registration"))??
      .error_for_status()?;

      let body = response.text().await?;

      assert_eq!(body, "proxied");

      http_server.await??;

      let udp_echo_server = tokio::spawn(async move {
        let mut buffer = [0; 1500];
        let (length, source) = udp_echo_socket.recv_from(&mut buffer).await?;
        udp_echo_socket.send_to(&buffer[..length], source).await?;

        std::io::Result::Ok(())
      });
      let mut control_stream = TcpStream::connect(socks5_listen_address).await?;
      let handshake_request = socks5_server::proto::handshake::Request::new(vec![
        socks5_server::proto::handshake::Method::NONE,
      ]);
      handshake_request.write_to(&mut control_stream).await?;
      socks5_server::proto::handshake::Response::read_from(&mut control_stream).await?;
      let udp_socket = UdpSocket::bind("127.0.0.1:0").await?;
      let associate_request = socks5_server::proto::Request::new(
        socks5_server::proto::Command::Associate,
        Address::SocketAddress(udp_socket.local_addr()?),
      );
      associate_request.write_to(&mut control_stream).await?;
      let associate_response =
        socks5_server::proto::Response::read_from(&mut control_stream).await?;
      assert!(matches!(associate_response.reply, Reply::Succeeded));
      let Address::SocketAddress(udp_relay_address) = associate_response.address else {
        anyhow::bail!("expected SOCKS5 UDP relay socket address");
      };
      let udp_socket = AssociatedUdpSocket::new(udp_socket, u16::MAX as usize);

      udp_socket
        .send_to(
          b"udp proxied",
          &UdpHeader::new(0, Address::SocketAddress(http_address)),
          udp_relay_address,
        )
        .await?;

      let (payload, header, _) = timeout(duration!("5s"), udp_socket.recv_from())
        .await?
        .map_err(|(error, _)| std::io::Error::from(error))?;
      assert_eq!(&payload[..], b"udp proxied");
      assert_eq!(header.address, Address::SocketAddress(http_address));
      udp_echo_server.await??;

      user_interrupt()?;

      anyhow::Ok(())
    }
  )
  .user_interrupt_ok()?;

  Ok(())
}

#[tokio::test]
#[test_log::test]
async fn test_hub_out_resolve() -> anyhow::Result<()> {
  use hickory_resolver::proto::{op::Message, rr::RData};
  use std::net::Ipv4Addr;

  use crate::{
    node::{Node, NodeResolveAnswers, ResolveQuery},
    route::RouteMatch,
  };

  let test_dir = test_dir().join("hub_out_resolve");

  let hub_dir = test_dir.join("hub");
  let in_dir = test_dir.join("in");
  let out_dir = test_dir.join("out");

  generate_ca_pem_file(&test_dir).await?;

  generate_node_pem_file(&test_dir, "hub", true).await?;
  generate_node_pem_file(&test_dir, "in", true).await?;
  generate_node_pem_file(&test_dir, "out", true).await?;

  let hub_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
  let hub_address = hub_tcp_listener.local_addr()?;

  let udp_socket = UdpSocket::bind(hub_tcp_listener.local_addr()?).await.ok();

  let hub = Hub::new(
    hub_tcp_listener,
    udp_socket,
    vec![],
    Router::new(&hub_dir),
    HubOptions {
      local_out_dispatchers: vec![LocalOutDispatcher::new_default(DefaultLocalExit::Private)],
      context_dir: hub_dir,
    },
  )
  .arc();

  let in_node = In::new(
    vec![],
    Router::new(&in_dir),
    InOptions {
      context_dir: in_dir,
      hub: InHubOptions {
        address: hub_address,
        connections: 2,
      },
    },
  )
  .arc();

  tokio::try_join!(
    hub.clone().run_shared(),
    in_node.clone().run_shared(),
    async {
      sleep(duration!("500ms")).await;

      let out = Out::new(OutOptions {
        local_out_dispatchers: vec![LocalOutDispatcher::new_default(
          DefaultLocalExit::Advertised {
            tags: vec!["system".into()],
          },
        )],
        listen: None,
        advertise: None,
        context_dir: out_dir,
        hub: OutHubOptions {
          address: hub_address,
          connections: 2,
        },
      });

      out.run().await
    },
    async {
      let query = ResolveQuery {
        name: "localhost".to_owned(),
        record_type: 1,
      };

      // IN -> HUB -> OUT("system") 全链路解析，等 OUT 注册完成后应成功。
      let bytes = timeout(duration!("10s"), async {
        loop {
          match in_node
            .resolve_routes(vec![RouteMatch::fixed(OutExit::from("system"))], &query)
            .await
          {
            Ok(NodeResolveAnswers::Success(bytes)) => break bytes,
            _ => sleep(duration!("50ms")).await,
          }
        }
      })
      .await
      .map_err(|_| anyhow::anyhow!("timed out waiting for remote DNS resolve"))?;

      let message = Message::from_vec(&bytes)?;
      assert!(
        message
          .answers
          .iter()
          .any(|record| matches!(&record.data, RData::A(a) if a.0 == Ipv4Addr::LOCALHOST)),
        "unexpected answers: {:?}",
        message.answers
      );

      // DIRECT 出口在 IN 本机解析。
      let NodeResolveAnswers::Success(bytes) = in_node
        .resolve_routes(vec![RouteMatch::fixed(OutExit::Direct)], &query)
        .await?
      else {
        anyhow::bail!("expected direct local resolve to succeed");
      };

      let message = Message::from_vec(&bytes)?;
      assert!(
        message
          .answers
          .iter()
          .any(|record| matches!(&record.data, RData::A(a) if a.0 == Ipv4Addr::LOCALHOST)),
        "unexpected answers: {:?}",
        message.answers
      );

      user_interrupt()?;

      anyhow::Ok(())
    }
  )
  .user_interrupt_ok()?;

  Ok(())
}
