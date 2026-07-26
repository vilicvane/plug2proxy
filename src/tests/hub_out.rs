use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  hub::{Hub, HubOptions},
  r#in::{In, InHubOptions, InOptions},
  inbound::{Socks5Inbound, Socks5InboundOptions},
  node::{DefaultLocalExit, LocalOutDispatcher},
  out::{Out, OutHubOptions, OutOptions},
  primitives::OutExit,
  route::{AddressRule, GeoLite2, Router},
  test::{get_free_local_tcp_address, test_dir},
};
use lits::duration;
use lowkit::{UserInterruptExt, user_interrupt};
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpListener,
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

  let socks5_listen_address = get_free_local_tcp_address();

  let socks5_inbound = Socks5Inbound::new(Socks5InboundOptions {
    listen: socks5_listen_address,
  })
  .await?;

  tokio::try_join!(
    async {
      let router = Router::new(GeoLite2::new(&hub_dir));

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

      let hub = Hub::new(
        hub_tcp_listener,
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
      let router = Router::new(GeoLite2::new(&in_dir));
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

      user_interrupt()?;

      anyhow::Ok(())
    }
  )
  .user_interrupt_ok()?;

  Ok(())
}
