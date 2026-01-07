use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Default TTL for NAT mappings (5 minutes).
const DEFAULT_MAPPING_TTL: Duration = Duration::from_secs(300);

/// A NAT mapping entry for full-cone semantics.
///
/// In full-cone NAT:
/// - When an internal client sends a packet to any external address, a mapping is created.
/// - Once mapped, ANY external host can send packets to the mapped port, and they will be
///   forwarded to the internal client.
#[derive(Debug, Clone)]
pub struct NatMapping {
    /// The internal client address (where responses should be sent).
    pub internal_addr: SocketAddr,
    /// The original destination that created this mapping.
    pub original_dest: SocketAddr,
    /// When this mapping was last used.
    pub last_used: Instant,
    /// Time-to-live for this mapping.
    pub ttl: Duration,
}

impl NatMapping {
    pub fn new(internal_addr: SocketAddr, original_dest: SocketAddr) -> Self {
        Self {
            internal_addr,
            original_dest,
            last_used: Instant::now(),
            ttl: DEFAULT_MAPPING_TTL,
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Check if this mapping has expired.
    pub fn is_expired(&self) -> bool {
        self.last_used.elapsed() > self.ttl
    }

    /// Touch this mapping to refresh its last-used time.
    pub fn touch(&mut self) {
        self.last_used = Instant::now();
    }
}

/// A thread-safe NAT mapping table.
///
/// Maps external port numbers to internal client addresses. This implements full-cone
/// NAT semantics where any external host can send to a mapped port.
#[derive(Clone)]
pub struct NatMappingTable {
    /// Maps external port → mapping entry.
    /// Using port as the key since in full-cone NAT, any source can send to the mapped port.
    mappings_by_port: Arc<RwLock<HashMap<u16, NatMapping>>>,

    /// Reverse mapping: internal_addr → external_port.
    /// Used to find existing mappings for a client.
    port_by_internal: Arc<RwLock<HashMap<SocketAddr, u16>>>,

    /// The next port to allocate.
    next_port: Arc<RwLock<u16>>,

    /// Port range for allocation.
    port_range: (u16, u16),

    /// TTL for new mappings.
    mapping_ttl: Duration,
}

impl NatMappingTable {
    /// Create a new mapping table with the specified port range.
    pub fn new(port_range: (u16, u16)) -> Self {
        Self {
            mappings_by_port: Arc::new(RwLock::new(HashMap::new())),
            port_by_internal: Arc::new(RwLock::new(HashMap::new())),
            next_port: Arc::new(RwLock::new(port_range.0)),
            port_range,
            mapping_ttl: DEFAULT_MAPPING_TTL,
        }
    }

    /// Set the TTL for new mappings.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.mapping_ttl = ttl;
        self
    }

    /// Get or create a mapping for an internal client.
    ///
    /// If a mapping already exists for the client, it's refreshed and returned.
    /// Otherwise, a new mapping is created with a newly allocated port.
    pub async fn get_or_create(&self, internal_addr: SocketAddr, dest: SocketAddr) -> Option<u16> {
        // Check for existing mapping
        {
            let port_by_internal = self.port_by_internal.read().await;
            if let Some(&port) = port_by_internal.get(&internal_addr) {
                // Refresh the mapping
                let mut mappings = self.mappings_by_port.write().await;
                if let Some(mapping) = mappings.get_mut(&port) {
                    if !mapping.is_expired() {
                        mapping.touch();
                        return Some(port);
                    }
                    // Expired - will reallocate below
                }
            }
        }

        // Allocate a new port
        let port = self.allocate_port().await?;

        // Create the mapping
        let mapping = NatMapping::new(internal_addr, dest).with_ttl(self.mapping_ttl);

        {
            let mut mappings = self.mappings_by_port.write().await;
            mappings.insert(port, mapping);
        }

        {
            let mut port_by_internal = self.port_by_internal.write().await;
            port_by_internal.insert(internal_addr, port);
        }

        tracing::debug!(
            internal = %internal_addr,
            external_port = port,
            dest = %dest,
            "created NAT mapping"
        );

        Some(port)
    }

    /// Look up a mapping by external port.
    ///
    /// This is the core of full-cone NAT: any external source can look up by port alone.
    pub async fn lookup_by_port(&self, port: u16) -> Option<NatMapping> {
        let mappings = self.mappings_by_port.read().await;
        mappings.get(&port).filter(|m| !m.is_expired()).cloned()
    }

    /// Look up the external port for an internal address.
    pub async fn lookup_by_internal(&self, internal_addr: &SocketAddr) -> Option<u16> {
        let port_by_internal = self.port_by_internal.read().await;
        let port = *port_by_internal.get(internal_addr)?;

        // Verify the mapping is still valid
        let mappings = self.mappings_by_port.read().await;
        if mappings.get(&port).is_some_and(|m| !m.is_expired()) {
            Some(port)
        } else {
            None
        }
    }

    /// Touch a mapping to refresh its TTL.
    pub async fn touch(&self, port: u16) {
        let mut mappings = self.mappings_by_port.write().await;
        if let Some(mapping) = mappings.get_mut(&port) {
            mapping.touch();
        }
    }

    /// Remove expired mappings.
    pub async fn cleanup_expired(&self) {
        let expired_ports: Vec<u16> = {
            let mappings = self.mappings_by_port.read().await;
            mappings
                .iter()
                .filter(|(_, m)| m.is_expired())
                .map(|(&port, _)| port)
                .collect()
        };

        if expired_ports.is_empty() {
            return;
        }

        let mut mappings = self.mappings_by_port.write().await;
        let mut port_by_internal = self.port_by_internal.write().await;

        for port in expired_ports {
            if let Some(mapping) = mappings.remove(&port) {
                port_by_internal.remove(&mapping.internal_addr);
                tracing::debug!(
                    port,
                    internal = %mapping.internal_addr,
                    "removed expired NAT mapping"
                );
            }
        }
    }

    /// Remove a specific mapping.
    pub async fn remove(&self, port: u16) {
        let mut mappings = self.mappings_by_port.write().await;
        if let Some(mapping) = mappings.remove(&port) {
            let mut port_by_internal = self.port_by_internal.write().await;
            port_by_internal.remove(&mapping.internal_addr);
        }
    }

    /// Get the number of active mappings.
    pub async fn len(&self) -> usize {
        let mappings = self.mappings_by_port.read().await;
        mappings.values().filter(|m| !m.is_expired()).count()
    }

    /// Check if there are no active mappings.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }

    /// Allocate the next available port.
    async fn allocate_port(&self) -> Option<u16> {
        let mut next_port = self.next_port.write().await;
        let mappings = self.mappings_by_port.read().await;

        let range_size = self.port_range.1 - self.port_range.0 + 1;
        let start_port = *next_port;

        // Find an unused port
        for _ in 0..range_size {
            let port = *next_port;
            *next_port = if *next_port >= self.port_range.1 {
                self.port_range.0
            } else {
                *next_port + 1
            };

            if !mappings.contains_key(&port) {
                return Some(port);
            }

            // Also reclaim expired mappings
            if mappings.get(&port).is_some_and(|m| m.is_expired()) {
                return Some(port);
            }
        }

        tracing::warn!(
            start = self.port_range.0,
            end = self.port_range.1,
            attempted_start = start_port,
            "NAT port range exhausted"
        );
        None
    }
}

impl Default for NatMappingTable {
    fn default() -> Self {
        // Default port range: 49152-65535 (dynamic/private ports)
        Self::new((49152, 65535))
    }
}
