# Plug2Proxy

## Usage

```sh
plug2proxy
```

Config file `config.yaml` should be put in the current directory.

### Hub

Start Hub and generate `ca.pem` and `hub.pem` in the current directory if absent:

```sh
plug2proxy
```

### IN/OUT

Run with Hub (CA generated) and generate `<name>/node.pem` under the current directory:

```sh
plug2proxy --node-cert <name>
```
