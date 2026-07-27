# 在 IN 上使用 sing-box 与 Tailscale 建立 IPv4 透明代理网关

本文记录一套已经完成实机验证的 Linux IN 部署方案：

- Plug2Proxy 提供本机 SOCKS5 TCP/UDP 入口。
- sing-box TUN 接管本机普通用户和 root 的流量，再转发给 Plug2Proxy。
- Tailscale 可以继续正常维护控制、DERP 和 WireGuard 外层连接。
- 将 IN 声明为 Tailscale exit node 后，来自 tailnet 客户端的流量也会进入
  sing-box 和 Plug2Proxy。

本文暂时只覆盖 IPv4。示例基于 sing-box `1.12.25`、systemd、
nftables 以及使用内核网络栈的 Tailscale。

这里固定使用 `1.12.25`，并保留该版本的
`sniff_override_destination`。实测 sing-box `1.13.14` 的 route
`sniff` action 虽能识别 TLS 域名，却仍会把原始 IP 传给 SOCKS
outbound；这与上游 [#4308](https://github.com/SagerNet/sing-box/issues/4308)
报告的回归一致。在上游确认修复前，不要直接把本示例迁移到
`1.13.14`。

## 数据路径

```text
普通用户与 root ──────────────┐
                             │
tailnet 客户端 → tailscale0 ─┼→ singtun0 → sing-box
                             │                │
                             │                ▼
                             │       127.0.0.1:1080
                             │                │
                             │                ▼
                             │           Plug2Proxy IN
                             │                │
                             │          HUB / peer OUT
                             │
tailscaled 外层连接 ── fwmark 0x80000 ─→ 物理网络
```

这里需要区分两类看起来都属于 Tailscale 的流量：

- tailscaled 自己建立的控制、DERP 和 WireGuard 外层连接必须绕过 TUN，
  否则会形成 Tailscale → sing-box → Plug2Proxy → Tailscale 的自环。
- 从 `tailscale0` 解密后进入内核的客户端流量不能绕过 TUN；它正是
  exit-node 需要代理的用户流量。

因此不能简单地排除 root，也不能按进程名整体绕过转发流量。

## 前置条件

开始前应确保：

- Plug2Proxy IN 已经可以连接 HUB，并能通过预期的 OUT 访问目标。
- IN 工作目录中存在 `config.yaml` 和 `node.pem`。
- sing-box 使用独立的非 root 用户，以及具有 TUN 和 nftables 权限的
  systemd 服务运行。
- Tailscale 使用 `netfilter-mode=on`。真实的 `tailscale0` 转发流量由
  Tailscale 创建的 `ts-forward` 规则双向放行，无需另加宽泛的
  `FORWARD ACCEPT` 规则。
- 系统安装了 `nft`、`iproute2`、`systemd-resolved` 和 `curl`。

本文示例使用以下路径和服务名，可按实际安装方式调整：

```text
/usr/local/bin/p2p
/etc/plug2proxy/config.yaml
/etc/plug2proxy/node.pem
/etc/plug2proxy/geolite2.mmdb
/etc/sing-box/config.json
plug2proxy.service
sing-box.service
tailscaled.service
```

## 1. 使用专用用户运行 Plug2Proxy

Plug2Proxy 的底层 HUB、OUT 和 `DIRECT` 连接必须绕过 sing-box，因此
应当使用专用系统用户运行：

```bash
sudo useradd --system \
  --home-dir /nonexistent \
  --shell /usr/sbin/nologin \
  plug2proxy
```

如果用户已经存在，保留现有 UID 即可。记录 sing-box 和 Plug2Proxy
在当前机器上的实际 UID：

```bash
id -u sing-box
id -u plug2proxy
```

后面的 `exclude_uid` 必须使用这里查询到的数字。UID 是机器本地状态，
不能从其他服务器的配置中照抄。

如果 `systemctl show -p User sing-box` 显示 sing-box 仍由 root 运行，
应先为它配置独立的非 root 用户，并保留原服务创建 TUN 所需的
capabilities。不要用 UID `0` 代替 sing-box UID，否则所有 root 流量
都会被排除。不同发行版的 sing-box unit 权限设置不同，应在修改后先用
`sing-box check` 和一次 TUN 启动测试确认。

Plug2Proxy 的 systemd unit 至少应包含：

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
ExecStart=/usr/local/bin/p2p
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

`config.yaml` 和 `node.pem` 只需对 `plug2proxy` 用户可读。

GeoLite2 数据库是一个例外：当前实现会每 24 小时尝试更新
`geolite2.mmdb`，所以该文件必须对 `plug2proxy` 用户可写。如果首次
启动时还没有数据库，工作目录也必须允许它创建该文件；更稳妥的做法是
预先放置数据库并把文件所有者设为 `plug2proxy`。

## 2. 配置 Plug2Proxy IN

以下示例让：

- `okx.com` 优先走带 `hk` tag 的出口。
- GeoIP 为 `CN` 的目标由 IN 本机 `DIRECT`。
- 明确为非 `CN` 的目标走 `us`。
- GeoIP 无法识别时也回退到 `us`。

```yaml
type: in

hub:
  address: HUB_ADDRESS:1122
  connections: 4

inbounds:
  socks5:
    listen: 127.0.0.1:1080

route:
  rules:
    - type: domain
      match: okx.com
      priority: 0
      exit: hk

    - type: geoip
      match: CN
      priority: 1000
      exit: DIRECT

    - type: geoip
      match: CN
      negate: true
      priority: 1000
      exit: us

    - type: fallback
      exit: us
```

`hk` 和 `us` 是示例 tag，必须与 HUB 下发的 OUT exit tag 一致。
普通 tag 使用小写；`DIRECT`、`PROXY` 和 `ANY` 是保留 selector，
保持大写。

这里的 `DIRECT` 表示由当前 IN 所在机器直接连接目标。由于 Plug2Proxy
使用专用 UID 且该 UID 会被 sing-box 排除，这些本地出口连接不会再次
进入 TUN。

SOCKS5 当前不提供认证。仅供本机 sing-box 使用时应监听
`127.0.0.1:1080`；如果还需要给局域网浏览器直接使用，必须配合防火墙，
不要把无认证 SOCKS5 暴露到公网。

## 3. 配置 sing-box TUN

下面是一份 IPv4 配置模板。请先把 `989` 和 `997` 分别替换为本机
`sing-box` 与 `plug2proxy` 的实际 UID，再启动服务。

```json
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
        "detour": "plug2proxy"
      },
      {
        "type": "fakeip",
        "tag": "fakeip",
        "inet4_range": "198.18.0.0/15"
      }
    ],
    "rules": [
      {
        "domain_suffix": [
          "okx.com",
          "youtube.com",
          "youtu.be",
          "googlevideo.com",
          "ytimg.com",
          "netflix.com",
          "nflxvideo.net"
        ],
        "query_type": [
          "A",
          "AAAA"
        ],
        "action": "route",
        "server": "fakeip"
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
      "exclude_uid": [
        989,
        997
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

不要把 UID `0` 加入 `exclude_uid`。root 的普通流量需要和普通用户一样
进入 TUN。

显式填写 `auto_redirect_input_mark` 和 `auto_redirect_output_mark` 是为了
让后面的 nftables 规则不依赖 sing-box 默认值。

### DNS 与 tag 匹配

DNS 请求由 sing-box 接管，并通过 Plug2Proxy 访问 `1.1.1.1`，避免
IN 所在网络的 DNS 污染。

示例只为当前需要 feature tag 的域名返回 FakeIP。配合 inbound 上的
`sniff_override_destination`：

- feature 域名即使没有可嗅探的 HTTP、TLS 或 QUIC 握手，也能作为域名
  传给 Plug2Proxy，匹配 `youtube`、`netflix` 或 `okx` 等 tag。
- 其他域名仍向客户端返回真实 IPv4；可嗅探连接会把恢复出的域名传给
  Plug2Proxy，无法嗅探的连接保留目标 IP。Plug2Proxy 两种情况下都可
  继续执行 GeoIP 规则。

不要无条件把所有域名都改成 FakeIP，否则 IN 可能只拿到域名而失去
基于目标 IP 的 GeoIP 判断条件。

使用 exit node 的 Tailscale 客户端默认会使用 exit node 解析 DNS。
应使用 `resolvectl status` 确认 `singtun0` 提供 `172.19.0.2`，并拥有
`~.` DNS domain：

```text
Link ... (singtun0)
    Current Scopes: DNS
Current DNS Server: 172.19.0.2
       DNS Servers: 172.19.0.2
        DNS Domain: ~.
```

如果客户端关闭 Tailscale DNS，或者应用自行使用加密 DoH，IN 可能只
看到连接 IP。此时 GeoIP 规则仍然有效，但依赖域名的 feature tag
不一定能够匹配。

## 4. 只绕过 tailscaled 的外层连接

在已验证的 Tailscale 内核模式中，tailscaled 为自己的物理、控制和
DERP 套接字设置 `0x80000` fwmark。可以在 sing-box output 规则之前，
把这些连接的 conntrack mark 设置为 sing-box 的 output/bypass mark
`0x2024`：

```nft
table inet plug2proxy_tun_bypass {
  chain output {
    type filter hook output priority mangle - 2; policy accept;

    meta mark & 0xff0000 == 0x80000 counter ct mark set 0x2024
  }
}
```

保存为：

```text
/etc/sing-box/plug2proxy-tun-bypass.nft
```

这条规则只修改 conntrack mark，不改写 Tailscale 原本的 packet mark，
因此 Tailscale 自己的 policy routing 仍然有效。

`0x80000` 是当前 Tailscale 实现细节，不应当被当成跨版本的稳定 API。
升级 Tailscale 后应先检查：

```bash
sudo ss -tunapoe | grep tailscaled
```

确认 tailscaled 的外层套接字仍显示 `fwmark:0x80000`。

创建一个幂等加载脚本 `/usr/local/sbin/plug2proxy-tun-bypass`：

```sh
#!/bin/sh
set -eu

/usr/sbin/nft delete table inet plug2proxy_tun_bypass 2>/dev/null || true
exec /usr/sbin/nft -f /etc/sing-box/plug2proxy-tun-bypass.nft
```

脚本应由 root 所有且不可由普通用户修改：

```bash
sudo chown root:root /usr/local/sbin/plug2proxy-tun-bypass
sudo chmod 0755 /usr/local/sbin/plug2proxy-tun-bypass
```

通过 sing-box systemd drop-in 在每次启动前加载：

```ini
[Service]
ExecStartPre=+/usr/local/sbin/plug2proxy-tun-bypass
```

保存为：

```text
/etc/systemd/system/sing-box.service.d/plug2proxy-tun.conf
```

然后检查配置并重启：

```bash
sudo sing-box check -c /etc/sing-box/config.json
sudo nft -c -f /etc/sing-box/plug2proxy-tun-bypass.nft
sudo systemctl daemon-reload
sudo systemctl restart plug2proxy
sudo systemctl restart sing-box
```

可用下面的命令确认绕行规则已经命中：

```bash
sudo nft list chain inet plug2proxy_tun_bypass output
tailscale netcheck
```

执行 `tailscale netcheck` 后，规则 counter 应当增加，且 Tailscale 的
UDP、控制连接和已有 peer 连接仍然可用。

## 5. 准备 Tailscale exit node

开启 IPv4 forwarding：

```text
# /etc/sysctl.d/90-plug2proxy-exit-node.conf
net.ipv4.ip_forward = 1
```

```bash
sudo sysctl --system
sudo tailscale set --netfilter-mode=on
```

本方案不需要为 `tailscale0` 单独添加 sing-box nftables 规则。
sing-box 的 prerouting 会接管外部接口上的 TCP 和 UDP；Tailscale
自己的 `ts-forward` 链则负责在系统 `FORWARD` policy 为 `DROP` 时
放行真实的 `tailscale0` 双向流量。

准备完毕后，可以选择声明 exit node：

```bash
sudo tailscale set --advertise-exit-node
```

如果已经设置了本机 operator，例如：

```bash
sudo tailscale set --operator=pi
```

那么 operator 用户可以不使用 `sudo` 执行 Tailscale 管理命令：

```bash
tailscale set --advertise-exit-node
```

`--operator` 只授予指定本机 Unix 用户操作 tailscaled 控制 socket 的
权限。它不会让 tailscaled 改为该用户运行，也不会让 exit-node 数据面
套接字带上该用户的 UID。tailscaled 通常仍由 root 运行，因此本文按
`fwmark` 绕过其外层连接的设计仍然必要。

随后还需要根据 tailnet 策略在 Tailscale 管理端批准该节点。客户端选择
该 exit node 后，其 IPv4 TCP、UDP 和 DNS 流量应按本文的数据路径进入
sing-box 和 Plug2Proxy。

如果现在只想准备环境而不对 tailnet 发布出口，不要执行
`--advertise-exit-node`。可用下面的命令检查当前是否已经声明：

```bash
tailscale status --json |
  jq '.Self.ExitNodeOption'
```

## 6. 验证

### 服务与路由

```bash
systemctl is-active plug2proxy sing-box tailscaled
ip -4 rule show
ip -4 route show table 2022
sudo nft list table inet sing-box
sudo nft list table inet plug2proxy_tun_bypass
```

sing-box 默认 mark 对应的策略路由应包含：

```text
fwmark 0x2024 ... bypass
fwmark 0x2023 lookup 2022
```

并且 table `2022` 的默认路由应指向 `singtun0`。

### root 与普通用户

分别执行：

```bash
curl -4 --max-time 15 https://cloudflare-quic.com/cdn-cgi/trace
sudo curl -4 --max-time 15 https://cloudflare-quic.com/cdn-cgi/trace
```

两次请求都应显示所选 Plug2Proxy OUT 的公网 IP。如果 root 显示 IN
本机公网 IP，首先检查 UID `0` 是否被错误加入了 `exclude_uid`。

### 直接测试 SOCKS5

```bash
curl -4 --max-time 15 \
  --socks5-hostname 127.0.0.1:1080 \
  https://cloudflare-quic.com/cdn-cgi/trace
```

### HTTP/3

如果系统安装了 `quiche-client`：

```bash
quiche-client \
  --wire-version 00000001 \
  --http-version HTTP/3 \
  --dump-json \
  https://cloudflare-quic.com/
```

同时观察：

```bash
journalctl -f -u sing-box -u plug2proxy
```

sing-box 应显示 `outbound packet connection` 经 `plug2proxy` SOCKS
outbound。

Plug2Proxy 会分别记录 UDP association 和 UDP flow：

- `UDP association opened` 在某个 exit 的长期 association 建立时输出。
- `UDP <source> -> <destination> via <exit>` 在新的来源、目标和 exit
  组合首次出现时输出。活跃 flow 不会逐包重复记录；空闲超过一分钟后再次
  出现会重新记录。

### 从 tailnet 客户端验证

启用 exit node 后，在另一台 Tailscale 客户端选择该 IN，并检查：

```bash
curl -4 --max-time 15 https://cloudflare-quic.com/cdn-cgi/trace
```

然后使用支持 HTTP/3 的浏览器或客户端访问同一目标。需要同时满足：

- 公网 IP 是预期 Plug2Proxy OUT。
- IN 上的 sing-box 能看到来自 TUN 的 TCP/UDP。
- Plug2Proxy 没有持续出现 `no out dispatcher matched`。
- `tailscale netcheck` 仍显示 UDP 可用。

## 常见问题

### 启动 sing-box 后 Tailscale 很快离线

依次检查：

1. tailscaled 外层套接字是否仍带 `fwmark:0x80000`。
2. `plug2proxy_tun_bypass` counter 是否增长。
3. sing-box 的 `auto_redirect_output_mark` 是否仍为 `0x2024`。
4. nftables bypass 表是否在 sing-box 启动前成功加载。

不要通过排除 root 来规避这个问题，否则 root 的普通网络流量也会绕过
透明代理。

### TCP 正常但 exit-node UDP 不通

检查 Tailscale 是否仍使用 `netfilter-mode=on`，以及 `ts-forward`
是否存在以下语义：

- 从 `tailscale0` 进入的包被标记并接受。
- 发往 `tailscale0` 的回程包被接受。

不要用普通 veth 直接模拟后就断定 UDP 不工作；系统 `FORWARD` policy
为 `DROP` 时，普通 veth 不会自动获得 Tailscale 的双向放行规则。

### 域名规则没有命中

先看 sing-box 的 `outbound/socks[plug2proxy]` 日志。对于普通 HTTP、
TLS 和 QUIC，请求目标应是域名；对 feature 规则，再确认客户端 DNS
是否经过 exit node 和 sing-box，以及目标域名是否位于 FakeIP 列表。
使用自带 DoH、ECH 或没有可识别握手的应用仍可能只留下目标 IP，此时
Plug2Proxy 只能按 IP 和 GeoIP 路由。

如果 sing-box 日志显示已经嗅探出域名，但 SOCKS outbound 仍使用 IP，
先检查是否误用了存在该回归的 `1.13.14`，不要通过无限扩大 FakeIP
列表掩盖版本问题。

### GeoIP 规则长期失效

检查：

```bash
ls -l /etc/plug2proxy/geolite2.mmdb
journalctl -u plug2proxy | grep -i geolite
```

确保运行 Plug2Proxy 的专用用户能够更新该文件。

## 上游参考

- [sing-box TUN inbound](https://sing-box.sagernet.org/configuration/inbound/tun/)
- [Tailscale CLI](https://tailscale.com/docs/reference/tailscale-cli)
- [Tailscale netfilter modes](https://tailscale.com/docs/reference/netfilter-modes)
- [Tailscale exit-node DNS 行为](https://tailscale.com/docs/reference/dns-in-tailscale)
- [Tailscale IP forwarding 检查](https://tailscale.com/docs/reference/troubleshooting/network-configuration/ip-forwarding-errors-advertise)
