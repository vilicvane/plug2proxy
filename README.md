# Plug2Proxy

```json
{
    "role": "in",
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
        "stun_server": "",
        "match_server": "redis://xxx/"
    },
    "routing": {
        "priority": 100,
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
