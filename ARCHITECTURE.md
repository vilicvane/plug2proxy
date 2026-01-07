# plug2proxy Architecture

## Roles

- **IN**: Entry point for proxied traffic. Determines routing and forwards data.
- **OUT**: Exit point for proxied traffic.
- **HUB**: Central coordination node. Stores and distributes configs (including routing rules).

## Topology

- IN can also serve as HUB (combined node) or be separate.
- Multiple INs and OUTs supported; one HUB (for now).
- IN and OUT configs only contain HUB connection info.

## Data Path

- HUB can forward data by joining two QUIC-over-TCP tunnels.
- Direct IN-OUT tunnel can be established if it performs better.

## Routing

- Tag-based rules on HUB, routing decisions made by IN.
- IN exit paths: self, HUB (aggregated), or direct OUT.
- HUB as aggregated OUT: exits directly or relays to connected OUTs.
- HUB pushes OUT info to IN (initial + updates).

## Control Plane

- QUIC-over-TCP (single TCP initially, extends to forwarding tunnel if needed).
- JSON message serialization over QUIC streams.
