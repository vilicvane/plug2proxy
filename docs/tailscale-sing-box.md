# 使用 Tailscale、sing-box 与 Plug2Proxy 建立最简 IPv4 exit node

本文假设：

- 已按[最简配置教程](configuration.md)跑通 Plug2Proxy；
- IN 已加入现有 tailnet；
- IN 使用 Linux、systemd 和 nftables；
- IN 已安装 sing-box `1.12.25`。

本文只覆盖 IPv4。完成后的路径：

```text
本机流量 ───────────────┐
                       ├→ sing-box TUN → Plug2Proxy IN → HUB / OUT
Tailscale 客户端流量 ───┘

tailscaled 外层连接 ─────→ 物理网络
```

## 1. 使用独立用户运行代理服务

Plug2Proxy 和 sing-box 自己的连接必须绕过 TUN。为 Plug2Proxy 创建独立
用户；用户已经存在时不要重复创建：

```bash
sudo useradd --system \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  plug2proxy
```

创建 `/etc/systemd/system/plug2proxy.service`：

```ini
[Unit]
Description=Plug2Proxy IN
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=plug2proxy
Group=plug2proxy
WorkingDirectory=/etc/plug2proxy
ExecStart=/usr/sbin/plug2proxy
Environment=RUST_LOG=info
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

确认 sing-box 也使用独立用户，并取得两个实际 UID：

```bash
systemctl show -p User --value sing-box
id -u sing-box
id -u plug2proxy
```

第一条命令应输出 `sing-box`，不能是空值或 `root`。确保
`/etc/plug2proxy` 中的配置、证书和 GeoLite2 数据库具有
`plug2proxy` 用户所需的读写权限。

## 2. 配置 sing-box

创建 `/etc/sing-box/config.json`。先把 `SING_BOX_UID` 和
`PLUG2PROXY_UID` 替换为上一步查询到的整数；占位符未经替换时配置应当
校验失败。

```jsonc
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "type": "udp",
        "tag": "cloudflare",
        "server": "1.1.1.1",
        "server_port": 53,
        // DNS 也通过 Plug2Proxy，避免使用 IN 所在网络的本地 DNS。
        "detour": "plug2proxy"
      }
    ],
    "final": "cloudflare",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "interface_name": "singtun0",
      "address": "172.19.0.1/30",
      "mtu": 9000,
      "auto_route": true,
      "auto_redirect": true,
      "auto_redirect_input_mark": "0x2023",
      "auto_redirect_output_mark": "0x2024",
      "stack": "system",
      "sniff": true,
      "sniff_override_destination": true,
      // 只排除两个代理服务，不排除 root。
      "exclude_uid": [
        SING_BOX_UID,
        PLUG2PROXY_UID
      ]
    }
  ],
  "outbounds": [
    {
      "type": "socks",
      "tag": "plug2proxy",
      "server": "127.0.0.1",
      "server_port": 1080,
      "version": "5"
    }
  ],
  "route": {
    "rules": [
      {
        "port": 53,
        "action": "hijack-dns"
      }
    ],
    "final": "plug2proxy"
  }
}
```

Plug2Proxy IN 的 SOCKS5 必须监听 `127.0.0.1:1080`。域名由 sing-box
嗅探后交给 Plug2Proxy，本教程不使用 FakeIP。

## 3. 绕过 tailscaled 外层连接

创建 `/etc/sing-box/plug2proxy-tun-bypass.nft`：

```nft
table inet plug2proxy_tun_bypass {
  chain output {
    type filter hook output priority mangle - 2; policy accept;

    meta mark & 0xff0000 == 0x80000 counter ct mark set 0x2024
  }
}
```

创建 `/usr/local/sbin/plug2proxy-tun-bypass`：

```sh
#!/bin/sh
set -eu

/usr/sbin/nft delete table inet plug2proxy_tun_bypass 2>/dev/null || true
exec /usr/sbin/nft -f /etc/sing-box/plug2proxy-tun-bypass.nft
```

```bash
sudo chown root:root /usr/local/sbin/plug2proxy-tun-bypass
sudo chmod 0755 /usr/local/sbin/plug2proxy-tun-bypass
```

创建
`/etc/systemd/system/sing-box.service.d/plug2proxy-tun.conf`：

```ini
[Service]
ExecStartPre=+/usr/local/sbin/plug2proxy-tun-bypass
```

这条规则只绕过 tailscaled 标记的控制、DERP 和 WireGuard 外层连接；
从 `tailscale0` 解密后的客户端流量仍会进入 sing-box。

## 4. 开启 IPv4 forwarding

创建 `/etc/sysctl.d/90-plug2proxy-exit-node.conf`：

```text
net.ipv4.ip_forward = 1
```

应用配置：

```bash
sudo sysctl --system
sudo tailscale set --accept-dns=false --netfilter-mode=on
```

## 5. 检查并启动

```bash
sudo sing-box check -c /etc/sing-box/config.json
sudo nft -c -f /etc/sing-box/plug2proxy-tun-bypass.nft
sudo systemctl daemon-reload
sudo systemctl enable --now plug2proxy
sudo systemctl restart sing-box
```

确认代理启动后 Tailscale 仍在线：

```bash
systemctl is-active plug2proxy sing-box tailscaled
sudo nft list table inet plug2proxy_tun_bypass
tailscale netcheck
```

然后声明 exit node：

```bash
sudo tailscale set --advertise-exit-node
```

在 tailnet 管理端批准该节点，并让一台客户端选择它。

## 6. 验证

先在 IN 上分别测试普通用户和 root：

```bash
curl -4 --max-time 15 https://cloudflare-quic.com/cdn-cgi/trace
sudo curl -4 --max-time 15 https://cloudflare-quic.com/cdn-cgi/trace
```

再从已选择该 exit node 的 Tailscale 客户端执行相同请求，并用支持 UDP
或 HTTP/3 的应用访问外部目标。

同时观察 IN：

```bash
journalctl -f -u sing-box -u plug2proxy
```

成功时：

- 普通用户、root 和 Tailscale 客户端都显示 Plug2Proxy OUT 的公网地址；
- Plug2Proxy 日志包含 TCP 和 UDP 流量；
- `tailscale netcheck` 仍显示 UDP 可用；
- nftables bypass 规则的 counter 会增长。

不要把 UID `0` 加入 `exclude_uid`，也不要为 `tailscale0` 添加宽泛的
绕过规则。

## 参考

- [Plug2Proxy 最简配置教程](configuration.md)
- [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [Tailscale exit node](https://tailscale.com/docs/features/exit-nodes)
- [Tailscale netfilter modes](https://tailscale.com/docs/reference/netfilter-modes)
