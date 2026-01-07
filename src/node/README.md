# Node Module

Proxy node implementation for plug2proxy.

## Architecture

```
IN ──┬── [QUIC-over-TCP] ──→ HUB ──→ [TCP] ──→ Target
     │                        ↓
     └── [QUIC-over-TCP] ──→ OUT ──→ [TCP] ──→ Target
```

## Components

| File | Description |
|------|-------------|
| `message.rs` | JSON messages: `NodeMessage`, `HubMessage`, `ConnectRequest` |
| `connection.rs` | `HubConnection` (node→HUB), `NodeConnection` (HUB→node) |
| `router.rs` | Tag-based routing with pattern matching |
| `in_like.rs` | `InLike` trait - frontend abstraction for creating connections |
| `out_like.rs` | `OutLike` trait - backend abstraction for exiting traffic |
| `connector.rs` | `InLike` implementations: `HubConnector`, `DirectOutConnector`, `LocalConnector` |
| `hub.rs` | HUB node with registration, config distribution, and data relay |
| `in_node.rs` | IN node with routing and `connect()` method |
| `out.rs` | OUT node (stub) |

## Implemented ✓

- **Node Registration**: IN/OUT register with HUB, receive ack
- **Config Distribution**: HUB pushes route rules and OUT list to IN
- **OUT Updates**: HUB broadcasts OUT changes to all INs
- **Data Flow (HUB exit)**: IN → HUB → Target → HUB → IN
- **Router**: Pattern matching (`*`, `*.domain.com`, exact match)
- **InLike/OutLike traits**: Abstractions defined

## Not Implemented

- **Routing Logic**: `InNode.connect()` always uses HUB; should pick connector based on tag
- **OUT Forwarding**: HUB → OUT → Target path not implemented
- **Direct IN-OUT**: Bypass HUB for direct connections
- **LocalConnector**: IN exits locally without forwarding
- **HUB as Aggregated OUT**: Route to specific OUTs based on tag within HUB
- **Connection Lifecycle**: Cleanup when nodes disconnect
- **Error Recovery**: Reconnection, retries

## Test Coverage

- `test_in_out_connect_to_hub` - Node registration flow
- `test_full_proxy_flow` - End-to-end: IN → HUB → echo server
- `test_router_*` - Router pattern matching
