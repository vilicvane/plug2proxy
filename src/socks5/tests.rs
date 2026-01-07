/// Simple test to verify SOCKS5 integration compiles and basic flow works
#[cfg(test)]
mod socks5_integration_tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use crate::node::{Hub, HubConfig, InNode};
    use crate::socks5::Socks5Server;

    #[tokio::test]
    async fn test_socks5_server_creation() {
        // This test just verifies that we can create all the components
        let in_node = Arc::new(InNode::new("test_in".to_string()));
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let _socks5_server = Socks5Server::new(in_node, bind_addr);

        // If we got here, the API is correct
        assert!(true);
    }

    #[tokio::test]
    async fn test_hub_and_in_connection() -> Result<(), Box<dyn std::error::Error>> {
        // Start a HUB
        let hub_addr: SocketAddr = "127.0.0.1:0".parse()?;
        let listener = tokio::net::TcpListener::bind(hub_addr).await?;
        let hub_addr = listener.local_addr()?;
        drop(listener);

        let hub: Arc<Hub> = Arc::new(Hub::new(HubConfig {
            cert_path: "certs/cert.pem".to_string(),
            key_path: "certs/key.pem".to_string(),
        }));

        let hub_clone: Arc<Hub> = Arc::clone(&hub);
        tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Connect IN node
        let mut in_node = InNode::new("test_in".to_string());
        let result: Result<(), _> = in_node.connect_hub(hub_addr).await;

        // We expect this to succeed
        assert!(result.is_ok(), "IN node should connect to HUB");

        Ok(())
    }
}
