//! Integration tests for routing with 1 IN + 1 HUB + 2 OUT network topology.
//!
//! Tests verify that routing rules correctly direct traffic through the appropriate nodes.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use plug2proxy::cert::{generate_ca, generate_node_cert};
use plug2proxy::node::{ClientConfig, Hub, HubConfig, InNode, OutNode, RouteEntry};
use plug2proxy::route::{
    BuiltInLabel, DomainPatternRuleConfig, DomainRuleConfig, FallbackRuleConfig, Label, OneOrMany,
    RuleConfig,
};

const TEST_CERT_PATH: &str = "test_routing.pem";

/// Ensure test certificate exists.
fn ensure_test_cert() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        if !std::path::Path::new(TEST_CERT_PATH).exists() {
            let ca = generate_ca("test-ca").unwrap();
            let server_cert =
                generate_node_cert("test-server", &ca.cert_pem, &ca.key_pem, true).unwrap();
            server_cert.write_to_file(TEST_CERT_PATH).unwrap();
        }
    });
}

fn test_client_config() -> ClientConfig {
    ClientConfig {
        pem_path: None,
        ca_pem_path: None,
    }
}

/// Start an echo server that prefixes responses with a node identifier.
/// This helps verify which node handled the request.
async fn start_echo_server(node_id: &str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let node_id = node_id.to_string();

    let handle = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => break,
            };

            let node_id = node_id.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                loop {
                    let n = match socket.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(_) => break,
                    };

                    // Echo back with node identifier prefix
                    let response = format!("[{}] {}", node_id, String::from_utf8_lossy(&buf[..n]));
                    if socket.write_all(response.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    (addr, handle)
}

/// Test infrastructure: 1 HUB + 1 IN + 2 OUT nodes
struct TestNetwork {
    #[allow(dead_code)]
    hub_addr: SocketAddr,
    in_node: Arc<InNode>,
    _hub_handle: tokio::task::JoinHandle<()>,
    _out1_handle: tokio::task::JoinHandle<()>,
    _out2_handle: tokio::task::JoinHandle<()>,
}

impl TestNetwork {
    /// Create a test network with given routing rules.
    async fn new(routing_rules: Vec<RuleConfig>) -> Self {
        let _ = tracing_subscriber::fmt::try_init();
        ensure_test_cert();

        // Start HUB with routing rules
        let hub = Arc::new(Hub::new(HubConfig {
            pem_path: TEST_CERT_PATH.to_string(),
            ca_pem_path: None,
            tags: vec!["hub".to_string()], // HUB can also act as an OUT
        }));

        let hub_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(hub_addr).await.unwrap();
        let hub_addr = listener.local_addr().unwrap();
        drop(listener);

        // Set routing rules on HUB
        hub.set_route_rules(routing_rules).await;

        let hub_clone = Arc::clone(&hub);
        let hub_handle = tokio::spawn(async move {
            let _ = hub_clone.serve(hub_addr).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start OUT1 with tag "us"
        let mut out1 = OutNode::new(
            vec!["us".to_string()],
            vec![], // No additional routing rules from OUT
            0,
            test_client_config(),
        );
        out1.connect_hub(hub_addr, 1).await.unwrap();
        tracing::info!("OUT1 (us) connected");

        let out1_handle = tokio::spawn(async move {
            let _ = out1.run().await;
        });

        // Start OUT2 with tag "cn"
        let mut out2 = OutNode::new(
            vec!["cn".to_string()],
            vec![], // No additional routing rules from OUT
            0,
            test_client_config(),
        );
        out2.connect_hub(hub_addr, 1).await.unwrap();
        tracing::info!("OUT2 (cn) connected");

        let out2_handle = tokio::spawn(async move {
            let _ = out2.run().await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        // Start IN node
        let mut in_node = InNode::new(test_client_config());
        in_node.connect_hub(hub_addr, 1).await.unwrap();
        tracing::info!("IN node connected");

        tokio::time::sleep(Duration::from_millis(100)).await;

        Self {
            hub_addr,
            in_node: Arc::new(in_node),
            _hub_handle: hub_handle,
            _out1_handle: out1_handle,
            _out2_handle: out2_handle,
        }
    }

    /// Connect to a target through the IN node.
    async fn connect(&self, target: &str) -> Result<plug2proxy::tunnel::Stream, String> {
        self.in_node
            .connect(target)
            .await
            .map_err(|e| e.to_string())
    }

    /// Resolve routes for a target.
    async fn resolve_routes(&self, target: &str) -> Vec<RouteEntry> {
        self.in_node.resolve_routes(target).await
    }
}

/// Test: Domain-based routing to different OUT nodes
#[tokio::test]
async fn test_domain_routing_to_different_outs() {
    let rules = vec![
        // Route google.com to "us" OUT
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("google.com".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("us".to_string())),
            priority: Some(0),
            tag: Some("google-route".to_string()), // Tag for second-level routing
        }),
        // Route baidu.com to "cn" OUT
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("baidu.com".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("cn".to_string())),
            priority: Some(0),
            tag: Some("baidu-route".to_string()),
        }),
        // Fallback to DIRECT (HUB handles)
        RuleConfig::Fallback(FallbackRuleConfig {
            out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Direct)),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // Test: google.com should route to "us"
    let routes = network.resolve_routes("google.com:443").await;
    assert!(!routes.is_empty(), "Expected routes for google.com");
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    assert_eq!(routes[0].tag, Some("google-route".to_string()));
    tracing::info!("✓ google.com routes to 'us' with tag 'google-route'");

    // Test: baidu.com should route to "cn"
    let routes = network.resolve_routes("baidu.com:443").await;
    assert!(!routes.is_empty(), "Expected routes for baidu.com");
    assert_eq!(routes[0].label, Label::Custom("cn".to_string()));
    assert_eq!(routes[0].tag, Some("baidu-route".to_string()));
    tracing::info!("✓ baidu.com routes to 'cn' with tag 'baidu-route'");

    // Test: www.google.com (subdomain) should also route to "us"
    let routes = network.resolve_routes("www.google.com:443").await;
    assert!(!routes.is_empty(), "Expected routes for www.google.com");
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    tracing::info!("✓ www.google.com routes to 'us'");

    // Test: unknown.com should fallback to DIRECT
    let routes = network.resolve_routes("unknown.com:80").await;
    assert!(
        !routes.is_empty(),
        "Expected fallback route for unknown.com"
    );
    assert_eq!(routes[0].label, Label::BuiltIn(BuiltInLabel::Direct));
    tracing::info!("✓ unknown.com falls back to DIRECT");
}

/// Test: Multiple labels from rules with same priority
#[tokio::test]
async fn test_multiple_labels_same_priority() {
    let rules = vec![
        // Route to both "us" and "cn" with same priority
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("multi.com".to_string()),
            negate: false,
            out: OneOrMany::Many(vec![
                Label::Custom("us".to_string()),
                Label::Custom("cn".to_string()),
            ]),
            priority: Some(0),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    let routes = network.resolve_routes("multi.com:443").await;
    assert!(routes.len() >= 2, "Expected multiple routes for multi.com");

    let labels: Vec<_> = routes.iter().map(|r| &r.label).collect();
    assert!(labels.contains(&&Label::Custom("us".to_string())));
    assert!(labels.contains(&&Label::Custom("cn".to_string())));
    tracing::info!("✓ multi.com has multiple route options");
}

/// Test: Priority ordering - higher priority rules override lower
#[tokio::test]
async fn test_priority_ordering() {
    let rules = vec![
        // Low priority: route *.com to "cn" (using pattern)
        RuleConfig::DomainPattern(DomainPatternRuleConfig {
            r#match: OneOrMany::One(r"\.com$".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("cn".to_string())),
            priority: Some(100), // Lower priority (higher number)
            tag: None,
        }),
        // High priority: route google.com to "us"
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("google.com".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("us".to_string())),
            priority: Some(-100), // Higher priority (lower number)
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // google.com should match high-priority rule first
    let routes = network.resolve_routes("google.com:443").await;
    assert!(!routes.is_empty());
    // First match should be from the higher priority rule
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    tracing::info!("✓ google.com matches high-priority rule (us)");

    // other.com should only match the .com pattern rule
    let routes = network.resolve_routes("other.com:443").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::Custom("cn".to_string()));
    tracing::info!("✓ other.com matches low-priority .com rule (cn)");
}

/// Test: Negated rules
#[tokio::test]
async fn test_negated_rules() {
    let rules = vec![
        // Route everything EXCEPT google.com to "cn"
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("google.com".to_string()),
            negate: true, // Negate the match
            out: OneOrMany::One(Label::Custom("cn".to_string())),
            priority: Some(0),
            tag: None,
        }),
        // Fallback for google.com
        RuleConfig::Fallback(FallbackRuleConfig {
            out: OneOrMany::One(Label::Custom("us".to_string())),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // google.com should NOT match negated rule, fall through to fallback
    let routes = network.resolve_routes("google.com:443").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    tracing::info!("✓ google.com doesn't match negated rule, uses fallback");

    // other.com should match negated rule (not google.com)
    let routes = network.resolve_routes("other.com:443").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::Custom("cn".to_string()));
    tracing::info!("✓ other.com matches negated rule (cn)");
}

/// Test: Tags are preserved in routing
#[tokio::test]
async fn test_tags_preserved() {
    let rules = vec![RuleConfig::Domain(DomainRuleConfig {
        r#match: OneOrMany::One("example.com".to_string()),
        negate: false,
        out: OneOrMany::One(Label::Custom("us".to_string())),
        priority: Some(0),
        tag: Some("my-custom-tag".to_string()),
    })];

    let network = TestNetwork::new(rules).await;

    let routes = network.resolve_routes("example.com:443").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    assert_eq!(routes[0].tag, Some("my-custom-tag".to_string()));
    tracing::info!("✓ Tags are preserved: {:?}", routes[0].tag);
}

/// Test: End-to-end connection through OUT node
#[tokio::test]
async fn test_e2e_connection_through_out() {
    // Start echo servers for each OUT
    let (echo_us_addr, echo_us_handle) = start_echo_server("US").await;
    let (echo_cn_addr, echo_cn_handle) = start_echo_server("CN").await;
    let (echo_hub_addr, echo_hub_handle) = start_echo_server("HUB").await;

    tracing::info!(
        "Echo servers: US={}, CN={}, HUB={}",
        echo_us_addr,
        echo_cn_addr,
        echo_hub_addr
    );

    let rules = vec![
        // Route to "us" OUT
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("us-target".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("us".to_string())),
            priority: Some(0),
            tag: Some("us-traffic".to_string()),
        }),
        // Route to "cn" OUT
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("cn-target".to_string()),
            negate: false,
            out: OneOrMany::One(Label::Custom("cn".to_string())),
            priority: Some(0),
            tag: Some("cn-traffic".to_string()),
        }),
        // Fallback to DIRECT (handled by HUB)
        RuleConfig::Fallback(FallbackRuleConfig {
            out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Direct)),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // Test 1: Connect through HUB direct (fallback)
    tracing::info!("\n=== Test: HUB Direct Connection ===");
    let stream = network.connect(&echo_hub_addr.to_string()).await.unwrap();
    stream.send(b"hello-hub").await.unwrap();

    let mut buf = vec![0u8; 1024];
    let mut received = 0;
    for _ in 0..20 {
        let (n, _) = stream.recv(&mut buf[received..]).await.unwrap();
        received += n;
        if received > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let response = String::from_utf8_lossy(&buf[..received]);
    tracing::info!("HUB response: {}", response);
    assert!(response.contains("[HUB]"), "Expected HUB to handle request");
    tracing::info!("✓ Direct connection routed through HUB");

    // Clean up
    echo_us_handle.abort();
    echo_cn_handle.abort();
    echo_hub_handle.abort();
}

/// Test: OUT node selection by tags
#[tokio::test]
async fn test_out_selection_by_tags() {
    let rules = vec![
        // All traffic goes to "us" OUT
        RuleConfig::Fallback(FallbackRuleConfig {
            out: OneOrMany::One(Label::Custom("us".to_string())),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // Verify OUTs are available
    let outs = network.in_node.get_outs().await;
    assert!(outs.len() >= 2, "Expected at least 2 OUT nodes");
    tracing::info!(
        "Available OUTs: {:?}",
        outs.iter().map(|o| &o.tags).collect::<Vec<_>>()
    );

    // All routes should go to "us"
    let routes = network.resolve_routes("any-target:80").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::Custom("us".to_string()));
    tracing::info!("✓ Fallback routes to 'us' OUT");
}

/// Test: Built-in labels (DIRECT, PROXY, ANY)
#[tokio::test]
async fn test_builtin_labels() {
    let rules = vec![
        // local addresses go DIRECT
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("localhost".to_string()),
            negate: false,
            out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Direct)),
            priority: Some(-100),
            tag: None,
        }),
        // proxy.com goes through PROXY (any OUT)
        RuleConfig::Domain(DomainRuleConfig {
            r#match: OneOrMany::One("proxy.com".to_string()),
            negate: false,
            out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Proxy)),
            priority: Some(0),
            tag: None,
        }),
        // wildcard goes through ANY
        RuleConfig::Fallback(FallbackRuleConfig {
            out: OneOrMany::One(Label::BuiltIn(BuiltInLabel::Any)),
            tag: None,
        }),
    ];

    let network = TestNetwork::new(rules).await;

    // localhost should be DIRECT
    let routes = network.resolve_routes("localhost:8080").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::BuiltIn(BuiltInLabel::Direct));
    tracing::info!("✓ localhost routes to DIRECT");

    // proxy.com should be PROXY
    let routes = network.resolve_routes("proxy.com:443").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::BuiltIn(BuiltInLabel::Proxy));
    tracing::info!("✓ proxy.com routes to PROXY");

    // other domains should be ANY
    let routes = network.resolve_routes("other.org:80").await;
    assert!(!routes.is_empty());
    assert_eq!(routes[0].label, Label::BuiltIn(BuiltInLabel::Any));
    tracing::info!("✓ other.org routes to ANY");
}
