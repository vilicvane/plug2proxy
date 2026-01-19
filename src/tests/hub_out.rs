use crate::{
  cert::{generate_ca_pem_file, generate_node_pem_file},
  hub::{Hub, HubOptions},
  inbound::{Socks5Inbound, Socks5InboundOptions},
  out::{Out, OutHubOptions, OutOptions},
  test::{get_free_local_tcp_address, test_dir},
};
use tokio::net::TcpListener;

#[tokio::test]
#[test_log::test]
async fn test_hub_out() -> anyhow::Result<()> {
  let test_dir = test_dir();

  let hub_dir = test_dir.join("hub");
  let out_dir = test_dir.join("out");

  generate_ca_pem_file(&test_dir).await?;

  generate_node_pem_file(&test_dir, "hub").await?;
  generate_node_pem_file(&test_dir, "out").await?;

  let hub_tcp_listener = TcpListener::bind("127.0.0.1:0").await?;

  let hub_address = hub_tcp_listener.local_addr()?;

  let socks5_listen_address = get_free_local_tcp_address();

  let socks5_inbound = Socks5Inbound::new(Socks5InboundOptions {
    listen: socks5_listen_address,
  })
  .await?;

  tokio::try_join!(
    async {
      let inbounds = vec![socks5_inbound.into()];

      let hub = Hub::new(
        hub_tcp_listener,
        inbounds,
        HubOptions {
          tags: None,
          context_dir: hub_dir,
        },
      );

      hub.run().await?;

      anyhow::Ok(())
    },
    async {
      let out = Out::new(OutOptions {
        tags: vec![],
        context_dir: out_dir,
        hub: OutHubOptions {
          address: hub_address,
          connections: 2,
        },
      });

      out.run().await?;

      anyhow::Ok(())
    }
  )?;

  Ok(())
}
