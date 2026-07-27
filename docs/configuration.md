# Plug2Proxy 最简配置教程

本文只介绍 Plug2Proxy 本身，不涉及服务管理器、透明代理、DNS、Tailscale
或防火墙配置。

完成后得到一条最小链路：

```text
SOCKS5 client → IN → HUB → OUT → target
```

本例使用一个 HUB、一个 IN 和一个 OUT。所有流量经 HUB relay 到 OUT，
暂不启用 IN–OUT peer 直连。

## 约定

开始前准备：

- 三台机器使用相同版本的 `plug2proxy`；
- HUB 的 TCP `1122` 可被 IN 和 OUT 访问；
- 每台机器的工作目录均为 `/etc/plug2proxy`；
- 将文中的 `HUB_ADDRESS` 替换为 HUB 的实际 IP 或域名。

Plug2Proxy 从当前工作目录读取 `config.json` 和 `node.pem`。配置语法支持
`//`、`/* ... */` 注释和尾逗号。下文所有启动
命令都必须在 `/etc/plug2proxy` 中执行。

## 1. 配置并启动 HUB

在 HUB 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "hub",
  "listen": "0.0.0.0:1122"
}
```

启动 HUB：

```bash
cd /etc/plug2proxy
plug2proxy
```

首次启动会在当前目录生成：

```text
ca.pem
node.pem
```

保持 HUB 运行。`ca.pem` 包含 CA 私钥，只能留在 HUB，不得提交 Git
或复制到其他节点。

## 2. 为 IN 和 OUT 签发证书

在 HUB 的另一个终端中，以能够读取 `ca.pem` 的用户执行：

```bash
cd /etc/plug2proxy
plug2proxy --node-cert in
plug2proxy --node-cert out
```

生成结果：

```text
in/node.pem
out/node.pem
```

分别复制为：

```text
IN:  /etc/plug2proxy/node.pem
OUT: /etc/plug2proxy/node.pem
```

复制后保持文件仅对运行 Plug2Proxy 的用户可读，例如：

```bash
chmod 0600 /etc/plug2proxy/node.pem
```

每个节点只使用自己的 `node.pem`。该文件包含节点私钥，不得提交 Git。

## 3. 配置并启动 OUT

在 OUT 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "out",
  "hub": {
    "address": "HUB_ADDRESS:1122",
    "connections": 4
  },
  "exits": [
    {
      "type": "local",
      "tags": ["us"]
    }
  ]
}
```

这里的 `us` 是 exit tag，名称可以修改，但必须与 IN 路由中的 `exit`
完全一致。

启动 OUT：

```bash
cd /etc/plug2proxy
plug2proxy
```

该配置没有 `listen`，因此 OUT 只通过 HUB relay 提供出口。

## 4. 配置并启动 IN

在 IN 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "in",
  "hub": {
    "address": "HUB_ADDRESS:1122",
    "connections": 4
  },
  "route": {
    "rules": [
      {
        "type": "fallback",
        "exit": "us"
      }
    ]
  },
  "inbounds": {
    "socks5": {
      "listen": "127.0.0.1:1080"
    }
  }
}
```

`fallback` 让所有请求使用带 `us` tag 的 OUT。

启动 IN：

```bash
cd /etc/plug2proxy
plug2proxy
```

## 5. 验证

使用任意 SOCKS5 客户端连接：

```text
127.0.0.1:1080
```

通过该代理访问一个外部目标。成功时应同时满足：

- HUB 日志出现 `HUB is listening`；
- OUT 日志出现 `registered with HUB`；
- IN 日志出现 `connection to HUB established`；
- 请求经过时，IN 日志出现 `TCP <destination> -> us`；
- 目标看到的来源地址是 OUT 的公网地址。

如果出现 `no out dispatcher matched`，先检查 OUT 和 IN 中的 `us` 是否
完全一致。如果出现证书验证错误，确认 IN、OUT 的 `node.pem` 都由当前
HUB 的 `ca.pem` 签发。

到这里，Plug2Proxy 的最小代理链路已经完成。peer 直连、多个 OUT、
域名与 GeoIP 路由以及透明代理应在此链路稳定后再分别配置。
