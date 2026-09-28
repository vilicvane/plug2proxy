use std::{net::SocketAddr, path::Path, sync::Arc};

use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  hub::{Hub, HubOptions},
  r#in::{In, InHubOptions, InOptions},
  inbound::{Socks5Inbound, Socks5InboundOptions},
  node::{DefaultLocalExit, LocalOutDispatcher, Node, OutDispatcher},
  out::{Out, OutHubOptions, OutOptions},
  primitives::{BidiStream, OutExit, SocketDestination, SocketDestinationHost},
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
  net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
  task::JoinSet,
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
      // Require the advertised OUT from the first request. Otherwise the
      // pre-snapshot DIRECT fallback can make HTTP appear ready before OUT
      // registration, and the subsequent one-shot UDP packet has no provider.
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
        hubs: vec![OutHubOptions {
          address: hub_address,
          connections: 2,
        }],
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
        hubs: vec![OutHubOptions {
          address: hub_address,
          connections: 2,
        }],
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

#[tokio::test]
#[test_log::test]
async fn out_serves_multiple_hubs_and_recovers_one_independently() -> anyhow::Result<()> {
  timeout(duration!("30s"), async {
    let test_dir = test_dir().join(format!("multiple_hubs_{}", uuid::Uuid::new_v4()));
    generate_ca_pem_file(&test_dir).await?;
    for name in ["hub_a", "hub_b", "out"] {
      generate_node_pem_file(&test_dir, name, true).await?;
    }

    let first_listener = TcpListener::bind("127.0.0.1:0").await?;
    let first_address = first_listener.local_addr()?;
    // Reserve the second address without listening: its initial connections
    // fail while the first HUB must remain usable.
    let second_socket = TcpSocket::new_v4()?;
    second_socket.set_reuseaddr(true)?;
    second_socket.bind("127.0.0.1:0".parse()?)?;
    let second_address = second_socket.local_addr()?;
    let first_hub = multi_hub_test_node(first_listener, &test_dir.join("hub_a"));
    let mut tasks = JoinSet::new();
    tasks.spawn(first_hub.clone().run_shared());
    tasks.spawn(
      Out::new(OutOptions {
        local_out_dispatchers: vec![LocalOutDispatcher::new_default(
          DefaultLocalExit::Advertised {
            tags: vec!["system".into()],
          },
        )],
        listen: None,
        advertise: None,
        hubs: vec![
          OutHubOptions {
            address: second_address,
            connections: 2,
          },
          OutHubOptions {
            address: first_address,
            connections: 2,
          },
        ],
        context_dir: test_dir.join("out"),
      })
      .run(),
    );

    let first_dispatcher = wait_for_hub_provider(&first_hub).await?;
    assert_hub_tcp_udp_dns(&first_hub).await?;

    // Keep a first-HUB TCP flow open across the other HUB's full lifecycle.
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let mut stable_stream = first_dispatcher
      .connect(
        OutExit::from("system"),
        test_destination(target_listener.local_addr()?),
      )
      .await?;
    let (mut target_stream, _) = target_listener.accept().await?;
    assert_tcp_echo(&mut *stable_stream, &mut target_stream).await?;

    let second_hub = multi_hub_test_node(second_socket.listen(128)?, &test_dir.join("hub_b"));
    let second_task = tasks.spawn(second_hub.clone().run_shared());
    wait_for_hub_provider(&second_hub).await?;
    tokio::try_join!(
      assert_hub_tcp_udp_dns(&first_hub),
      assert_hub_tcp_udp_dns(&second_hub),
    )?;

    second_task.abort();
    let stopped = tasks.join_next().await.expect("second HUB task missing");
    assert!(stopped.is_err_and(|error| error.is_cancelled()));
    drop(second_hub);
    assert_tcp_echo(&mut *stable_stream, &mut target_stream).await?;
    assert_hub_tcp_udp_dns(&first_hub).await?;

    // Session cleanup releases its listener asynchronously.
    let restarted_listener = loop {
      match TcpListener::bind(second_address).await {
        Ok(listener) => break listener,
        Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
          sleep(duration!("20ms")).await;
        }
        Err(error) => return Err(error.into()),
      }
    };
    let restarted_hub = multi_hub_test_node(restarted_listener, &test_dir.join("hub_b"));
    tasks.spawn(restarted_hub.clone().run_shared());
    wait_for_hub_provider(&restarted_hub).await?;
    tokio::try_join!(
      assert_hub_tcp_udp_dns(&first_hub),
      assert_hub_tcp_udp_dns(&restarted_hub),
    )?;
    assert_tcp_echo(&mut *stable_stream, &mut target_stream).await?;

    anyhow::Ok(())
  })
  .await?
}

fn multi_hub_test_node(listener: TcpListener, context_dir: &Path) -> Arc<Hub> {
  Hub::new(
    listener,
    None,
    vec![],
    Router::new(context_dir),
    HubOptions {
      local_out_dispatchers: vec![LocalOutDispatcher::new_default(DefaultLocalExit::Private)],
      context_dir: context_dir.to_owned(),
    },
  )
  .arc()
}

async fn wait_for_hub_provider(hub: &Hub) -> anyhow::Result<Arc<dyn OutDispatcher>> {
  timeout(duration!("10s"), async {
    loop {
      if let Some(dispatcher) = hub
        .get_out_dispatchers()
        .into_iter()
        .find(|dispatcher| dispatcher.match_exit(&OutExit::from("system")).is_some())
      {
        return dispatcher;
      }
      sleep(duration!("20ms")).await;
    }
  })
  .await
  .map_err(|_| anyhow::anyhow!("timed out waiting for HUB provider"))
}

fn test_destination(address: SocketAddr) -> SocketDestination {
  SocketDestination {
    host: SocketDestinationHost::IpAddress(address.ip()),
    port: address.port(),
    routing_domain: None,
    routing_protocol: None,
  }
}

async fn assert_tcp_echo(
  stream: &mut dyn BidiStream,
  target: &mut TcpStream,
) -> anyhow::Result<()> {
  stream.write_all(b"ping").await?;
  let mut request = [0; 4];
  target.read_exact(&mut request).await?;
  assert_eq!(&request, b"ping");
  target.write_all(b"pong").await?;
  let mut response = [0; 4];
  stream.read_exact(&mut response).await?;
  assert_eq!(&response, b"pong");
  Ok(())
}

async fn assert_hub_tcp_udp_dns(hub: &Hub) -> anyhow::Result<()> {
  use futures::{SinkExt, StreamExt};
  use hickory_resolver::proto::{op::Message, rr::RData};
  use std::net::Ipv4Addr;

  use crate::{
    node::{NodeResolveAnswers, ResolveQuery},
    route::RouteMatch,
    udp_forwarder::{OutgoingUdpPacket, UdpPacketSource},
  };

  timeout(duration!("5s"), async {
    let dispatcher = wait_for_hub_provider(hub).await?;
    let exit = OutExit::from("system");
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = tcp_listener.local_addr()?;
    let mut stream = dispatcher
      .connect(exit.clone(), test_destination(address))
      .await?;
    let (mut target, _) = tcp_listener.accept().await?;
    assert_tcp_echo(&mut *stream, &mut target).await?;

    let udp_socket = UdpSocket::bind(address).await?;
    let mut packets = dispatcher.associate(exit.clone()).await?;
    let source = UdpPacketSource {
      via: vec![hub.id()],
      address: "127.0.0.1:12345".parse()?,
    };
    packets
      .send(OutgoingUdpPacket {
        source: source.clone(),
        destination: test_destination(address),
        response_destination: None,
        payload: b"udp ping".to_vec(),
      })
      .await?;
    let mut buffer = [0; 32];
    let (length, sender) = udp_socket.recv_from(&mut buffer).await?;
    assert_eq!(&buffer[..length], b"udp ping");
    udp_socket.send_to(b"udp pong", sender).await?;
    let response = packets.next().await.expect("UDP association closed");
    assert_eq!(response.source, source);
    assert_eq!(response.destination, address);
    assert_eq!(response.payload, b"udp pong");

    let query = ResolveQuery {
      name: "localhost".to_owned(),
      record_type: 1,
    };
    let NodeResolveAnswers::Success(bytes) = hub
      .resolve_routes(vec![RouteMatch::fixed(exit)], &query)
      .await?
    else {
      anyhow::bail!("expected remote DNS resolution to succeed");
    };
    assert!(Message::from_vec(&bytes)?.answers.iter().any(|record| {
      matches!(&record.data, RData::A(address) if address.0 == Ipv4Addr::LOCALHOST)
    }));

    anyhow::Ok(())
  })
  .await?
}
