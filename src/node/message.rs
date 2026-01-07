use serde::{Deserialize, Serialize};

/// Node role identifier sent during registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    In,
    Out,
}

/// Connect request sent on a data stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    /// Target address (e.g., "example.com:443").
    pub target: String,
    /// Routing tag (determined by IN).
    pub tag: Option<String>,
}

/// Messages from node to HUB.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeMessage {
    /// Register this node with HUB.
    Register {
        role: NodeRole,
        /// Node identifier.
        id: String,
        /// Tags this node provides (for OUT) or empty (for IN).
        tags: Vec<String>,
    },
}

/// Messages from HUB to node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubMessage {
    /// Registration acknowledged.
    Registered,
    /// Routing configuration (sent to IN).
    RouteConfig { rules: Vec<RouteRule> },
    /// OUT node availability update (sent to IN).
    OutUpdate { outs: Vec<OutInfo> },
}

/// A routing rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRule {
    /// Pattern to match (e.g., domain pattern).
    pub pattern: String,
    /// Tag to route to.
    pub tag: String,
}

/// Information about an OUT node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutInfo {
    pub id: String,
    pub tags: Vec<String>,
    /// Connection info for direct connection (if applicable).
    pub direct_addr: Option<String>,
}
