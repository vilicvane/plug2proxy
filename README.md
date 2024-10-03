# Plug2Proxy

```json
{
    "role": "in",
    "transparent_proxy": {
        "listen": "127.0.0.1:12345"
    },
    "fake_ip_dns": {
        "listen": "127.0.0.1:5353"
    },
    "tunneling": {
        "stun_server": "",
        "match_server": "redis://xxx/"
    },
    "routing": {
        "rules": [
            {
                "type": "geoip",
                "match": "CN",
                "out": "DIRECT"
            },
            {
                "type": "domain",
                "match": "\\.hk$",
                "out": ["hk", "DIRECT"]
            },
            {
                "type": "domain",
                "match": "(^|\\.)openai\\.com$",
                "out": "us"
            }
        ]
    }
}
```

```json
{
    "role": "out",
    "tunneling": {
        "label": "us",
        "priority": 100,
        "stun_server": "",
        "match_server": "redis://xxx/"
    },
    "routing": {
        "rules": [
            {
                "type": "geoip",
                "match": "CN",
                "negate": true
            },
            {
                "type": "domain",
                "match": "\\.hk$",
                "priority": 200
            },
            {
                "type": "domain",
                "match": "(^|\\.)openai\\.com$"
            }
        ]
    }
}
```
