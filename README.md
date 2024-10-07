[![MIT License](https://img.shields.io/badge/license-MIT-0969da?style=flat-square)](./LICENSE)
[![Discord](https://img.shields.io/badge/chat-discord-5662f6?style=flat-square)](https://discord.com/invite/vanVrDwSkS)

# Plug2Proxy

> Checkout the original Node.js version at branch [nodejs](https://github.com/vilicvane/plug2proxy/tree/nodejs).

Plug2Proxy is a transparent proxy **currently in development** that:

-   Connects IN to OUT with punched UDP (QUIC) tunnels.
-   Utilizes a match server (currently only Redis server is supported) to discover peers.
-   Supports routing based on GeoLite2 and fake-IP DNS (no traffic sniffing).

Currently only IPv4 TCP is supported, will probably add UDP support soon and then IPv6 as well.

## Usage

> You'll need to compile it yourself for now, so make sure you have reasonably new Rust installed.
>
> The template is now available only for Ubuntu.

```sh
# install to IN server
./scripts/install-to-server.sh -m in -c common,ubuntu -d "in-server-address"
# install to OUT server
./scripts/install-to-server.sh -m out -c common,ubuntu -d "out-server-address"
```

## Configuration

The configuration file provided by the installation template is located at `/etc/plug2proxy/config.json`.

If you are using the binary directly, just do `plug2proxy config.json`.

Checkout [src/config.rs](src/config.rs) for the complete configuration options available.

### IN Server

```json
{
    "mode": "in",
    "tunneling": {
        "match_server": "redis://username:password@redis-server/"
    },
    "routing": {
        "rules": [
            {
                "type": "geoip",
                "match": "CN",
                "out": "DIRECT"
            },
            {
                "type": "fallback",
                "out": "ANY"
            }
        ]
    }
}
```

### OUT Server

```json
{
    "mode": "out",
    "tunneling": {
        "match_server": "redis://username:password@redis-server/"
    }
}
```

## License

MIT License.
