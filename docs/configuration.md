# Plug2Proxy 推荐配置教程

本文先介绍显式 SOCKS5 入口的节点拓扑，并列出节点间必须放行的端口。
Linux 整机或 Tailscale 流量可直接换成 Plug2Proxy 原生 TPROXY；相关
权限、自动规则和 systemd 生命周期见[原生 TPROXY 部署](native-tproxy.md)。

```text
                 ┌── peer data ─────────────→ US OUT ─→ 默认非 CN 流量
SOCKS5 → IN ─────┼── relay data ─→ HUB ─────→ HK OUT ─→ okx.com
          │      └── control ────→ HUB（路由与 peer endpoint）
          └──────── DIRECT ──────→ IN 本机网络（CN）
```

这里有意同时保留两种路径：

- US OUT 公布 peer listener，IN 连通后优先直连；peer 尚未建立或在选择
  前失效时，新请求仍可通过 HUB relay 使用同一个出口。已经开始传输的
  请求不会为了切换路径而自动重放。
- HK OUT 不公布 peer listener，只通过 HUB relay，适合不方便开放入站端口
  的 OUT。

HUB 集中保存非 fallback 路由并下发给 IN。IN 只配置入口和 HUB 地址，
不重复维护相同规则。

## 约定

开始前准备：

- 一台 HUB、一台 IN、一台 US OUT 和一台 HK OUT；
- 四台机器使用同一份代码和 lockfile 构建的 `plug2proxy`；
- 每台机器的工作目录均为 `/etc/plug2proxy`；
- HUB 的 TCP 和 UDP `1122` 可被 IN 和两个 OUT 访问；
- US OUT 的 TCP 和 UDP `2233` 可被 IN 直接访问；
- 将示例保留地址 `203.0.113.10` 替换为 HUB 的实际 IP。当前
  `hub.address` 只接受 socket address，不接受域名；IPv6 必须写成
  `[address]:port`。
- 将验证命令中的示例 IN 地址 `192.0.2.10` 替换为 IN 的实际地址。

Plug2Proxy 从当前工作目录读取 `config.json` 和 `node.pem`。配置文件名虽然
是 `.json`，但支持 `//`、`/* ... */` 注释和尾逗号。

推荐长期运行时使用：

```bash
RUST_LOG=info,plug2proxy=debug plug2proxy
```

这会保留 Plug2Proxy 的连接与路由诊断，同时避免依赖库的 debug 日志刷屏。
SOCKS5 暂无认证，监听到局域网地址时必须用防火墙限制访问范围。

### 端口与防火墙

QomT 在一个 listener 上同时使用 TCP 主路径和 UDP QUIC 旁路。所有
`listen` 都必须显式包含非零端口；配置成 `:0` 会在读取配置时被拒绝。
允许省略 listener 的角色（例如只使用 HUB relay 的 OUT）不受影响。

本教程需要的入站规则如下：

| 节点 | 示例 listener | 需要放行的入站流量 |
| --- | --- | --- |
| HUB | `0.0.0.0:1122` | 来自 IN 和 OUT 的 TCP、UDP `1122` |
| 提供 peer 直连的 US OUT | `0.0.0.0:2233` | 来自 IN 的 TCP、UDP `2233` |
| 只使用 relay 的 HK OUT | 无 | 不需要 QomT 入站端口 |
| IN 的 SOCKS5 | `0.0.0.0:1080` | 仅来自受信客户端的 TCP、UDP `1080` |
| IN 的原生 TPROXY | `127.0.0.1:12345` | 仅供本机 nft TPROXY，不应在云防火墙开放 |
| 可选 DNS listener | 配置值 | 仅来自实际 DNS 客户端的 TCP、UDP |

HK OUT 没有 listener 只表示它不接受 peer 入站；它仍会主动连接 HUB 的
TCP、UDP `1122`。HUB relay 的 IN→HUB 与 HUB→OUT 是两个独立的 QomT
hop，UDP 旁路也分别建立和选择。

云平台防火墙或安全组与机器自身的 nftables/iptables/firewalld 都要检查。
发起 QomT 连接的一侧使用临时本地 UDP 端口；普通有状态防火墙不需要为该
临时端口另加入站规则，但出站策略必须允许访问对端 listener 的 UDP 端口。

经过 NAT 或端口映射时，外部 endpoint 的同一个端口必须同时转发 TCP 和
UDP，并最终到达同一个本地 `listen`。`advertise` 应填写 IN 实际能够访问
的外部 endpoint。listener 会用已经建立 mTCP 的 TCP peer IP 校验 UDP
来源，因此两种协议还必须从相同公网 IP 到达；不要让 TCP 代理和 UDP NAT
使用不同出口。UDP 重连时客户端源端口可以改变，防火墙规则不应依赖固定的
客户端源端口。若只放行或映射 TCP，QomT 主路径仍可建立，UDP 旁路则会
不可用并回退到主路径。

## 1. 配置并启动 HUB

在 HUB 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "hub",
  // 此 endpoint 同时监听 TCP 和 UDP。
  "listen": "0.0.0.0:1122",

  // HUB 也可以同时作为入口。只需协调时可删除 inbounds。
  "inbounds": {
    "socks5": {
      "listen": "127.0.0.1:1080",
      "sniff": true
    }
  },

  // HUB 会把这些非 fallback 规则下发给 IN。
  "route": {
    "rules": [
      {
        "type": "domain",
        "match": "okx.com",
        "priority": 10,
        "exit": "hk"
      },
      {
        "type": "protocol",
        "match": "ssh",
        "priority": 900,
        "exit": "DIRECT"
      },
      {
        "type": "domain",
        "match": "geosite:cn",
        "priority": 1000,
        "exit": "DIRECT"
      },
      {
        "type": "geoip",
        "match": "CN",
        "negate": true,
        "priority": 1010,
        "exit": "us"
      }
    ]
  }
}
```

这组规则表达：

- `okx.com` 及其子域优先使用 `hk`；
- 未命中上述明确域名规则、但嗅探为 SSH 的 TCP 连接，优先使用入口节点的
  `DIRECT`；
- Geosite 的 CN 域名使用入口节点的 `DIRECT`；
- GeoIP 不属于 CN 的目标使用 `us`；
- 其他目标使用路由器隐式补充的 `DIRECT`。

`DIRECT` 始终表示“当前处理 inbound 的节点从本机默认网络直出”。因此，
同一条规则在 IN 收到的请求上表示 IN 直出，在 HUB 自己的 SOCKS5 inbound
上表示 HUB 直出。它不是 IN–OUT peer 路径的名称。

规则按较小的 `priority` 优先，但不是传统的命中一条就停止。多个规则命中
时，其 exit 会按优先级依次累计。例如 OKX 的 IP 也匹配非 CN GeoIP 时，
候选顺序是 `hk`、`us`：`hk` 可用时优先，否则可以继续尝试 `us`。同一条
规则的 `match` 数组是 any-of。

需要多个条件同时成立时，使用 `and` 规则：`match` 里是一组只含匹配条件
的规则（不需要 `exit`/`priority`，但可以各自 `negate`），所有条件同时
命中时才命中，`priority` 与 `exit` 由组级配置提供：

```jsonc
// okx.com 且目标端口为 443 时使用 hk。
{
  "type": "and",
  "match": [
    { "type": "domain", "match": "okx.com" },
    { "type": "address", "match_port": 443 }
  ],
  "priority": 10,
  "exit": "hk"
}
```

`and` 规则与普通规则一样参与优先级排序和 exit 累计，也会随 HUB 的
规则下发同步给 IN。

`protocol` 规则匹配嗅探得到的应用层协议，而不是端口号。当前可配置值为
`"http"`、`"tls"`、`"quic"` 和 `"ssh"`；值必须小写。SSH 根据客户端
`SSH-2.0-...`（以及兼容的 `SSH-1.99-...`）identification banner 识别，
因此即使使用非 22 端口也能命中。入口必须启用 `"sniff": true`。

不要在 HUB 集中路由中用 `fallback` 表示默认 US。HUB 下发规则时会有意
排除 fallback；应像上例一样使用 `geoip` 的 `negate` 表达非 CN 默认出口。

启动 HUB：

```bash
cd /etc/plug2proxy
RUST_LOG=info,plug2proxy=debug plug2proxy
```

首次启动会生成：

```text
ca.pem
node.pem
```

`ca.pem` 包含 CA 私钥，只能留在 HUB，不得复制到其他节点或提交 Git。

使用 `geosite:...` 和 GeoIP 时，HUB 与 IN 会分别在自己的工作目录维护：

```text
dlc.dat
geolite2.mmdb
```

首次启动要允许它们下载数据库，并确认日志出现更新成功。运行用户必须对
工作目录有写权限。

## 2. 为三个节点签发证书

在 HUB 上，以能够读取 `ca.pem` 的用户执行：

```bash
cd /etc/plug2proxy
plug2proxy --node-cert in
plug2proxy --node-cert out-us
plug2proxy --node-cert out-hk
```

分别复制：

```text
in/node.pem      → IN:     /etc/plug2proxy/node.pem
out-us/node.pem  → US OUT: /etc/plug2proxy/node.pem
out-hk/node.pem  → HK OUT: /etc/plug2proxy/node.pem
```

每个节点只使用自己的 `node.pem`。文件包含节点私钥，应归实际运行
Plug2Proxy 的用户所有，并仅允许该用户读取。以 `plug2proxy` 用户运行为例：

```bash
chown plug2proxy:plug2proxy /etc/plug2proxy/node.pem
chmod 0600 /etc/plug2proxy/node.pem
```

## 3. 配置提供 peer 直连的 US OUT

在 US OUT 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "out",
  "hub": {
    "address": "203.0.113.10:1122",
    "connections": 4
  },

  // OUT 声明可接受 IN 的 peer 连接。
  // 此 endpoint 同时监听 TCP 和 UDP。
  "listen": "0.0.0.0:2233",

  "exits": [
    {
      "type": "local",
      "tags": ["us"]
    }
  ]
}
```

省略 `advertise` 时，OUT 会发送 `0.0.0.0:2233`，HUB 使用 OUT 连接
HUB 时看到的 peer IP 补全地址。这适用于 OUT 公网地址与监听端口都可被
IN 直接访问的情况。

端口经过映射时，可以只覆盖端口并仍让 HUB 补全 IP：

```jsonc
"advertise": "0.0.0.0:443"
```

如果 HUB 观察到的地址也不是 IN 应连接的地址，则显式填写完整 endpoint：

```jsonc
"advertise": "198.51.100.20:443"
```

`advertise` 只有存在 `listen` 时才允许配置，且端口不能是 `0`。
上述映射必须把外部 TCP、UDP `443` 都转发到本机 TCP、UDP `2233`。

启动 US OUT：

```bash
cd /etc/plug2proxy
RUST_LOG=info,plug2proxy=debug plug2proxy
```

peer 连接成功后，IN 对 `us` 的请求会优先选择
`qomt(priority=PeerProvider, ...)`。无需再配置一个数值 priority。

这里 OUT 的 `hub.connections: 4` 表示到 HUB 的一个 QomT 主路径由 mTCP
承载，mTCP 内部使用四条并行的底层 TCP connection。它与 IN 使用相同
语义，不会建立四个独立 QomT。

## 4. 配置只使用 HUB relay 的 HK OUT

在 HK OUT 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "out",
  "hub": {
    "address": "203.0.113.10:1122",
    "connections": 4
  },
  "exits": [
    {
      "type": "local",
      "tags": ["hk"]
    }
  ]
}
```

该配置没有 `listen`，因此 HUB 不会向 IN 下发 HK peer endpoint。
`hk` 流量通过现有 OUT→HUB QomT connection relay。

启动 HK OUT：

```bash
cd /etc/plug2proxy
RUST_LOG=info,plug2proxy=debug plug2proxy
```

## 5. 配置 IN

在 IN 创建 `/etc/plug2proxy/config.json`：

```jsonc
{
  "type": "in",
  "hub": {
    "address": "203.0.113.10:1122",
    "connections": 4,
    "peer_connections": 1,
    "peer_tcp_max_pacing_rate_bps": 2000000
  },
  "inbounds": {
    "socks5": {
      // 仅本机使用时改为 127.0.0.1:1080。
      "listen": "0.0.0.0:1080",
      "sniff": true
    }
  }
}
```

这里没有 `route`：IN 连接 HUB 后会收到 HUB 的出口、peer endpoint 和
非 fallback 路由快照。IN 自身始终保留一个私有 `DIRECT`，HUB 不需要把
自己的 local exit 下发给 IN。

IN 的 `hub.connections: 4` 表示到 HUB 的 QomT 主路径使用四条并行的
底层 TCP connection。`hub.peer_connections` 可以单独设置 IN 到 peer OUT
的底层 TCP 数量；省略时沿用 `hub.connections`。当 peer 路径经过共享的低速
或突发限速链路时，可以设为 `1`，避免多条独立 TCP 拥塞控制同时冲击同一个
瓶颈，而不降低 IN 到 HUB 的并行度。

`hub.peer_tcp_max_pacing_rate_bps` 分别限制 IN 发往 peer OUT 的每条底层
TCP socket，不影响 IN 到 HUB，也不限制 peer OUT 返回 IN 的方向。遇到已确认
的聚合上行 policer 时，可把它设在无丢包的安全速率；`2000000` 表示
2 Mbit/s。省略时不设应用级 pacing 上限。该选项要求 Linux；配置为 `0`
会被拒绝。

`sniff` 默认为 `true`，推荐显式保留：

- SOCKS5 请求带域名时，Plug2Proxy 直接用域名路由；
- 请求只带 IP 时，会尝试从 TLS、HTTP 或 QUIC 中嗅探域名；
- 本机 `DIRECT` 仍连接原始 IP，避免嗅探改变透明代理的目标；
- 请求选择远端 OUT 时，可以把嗅探到的域名交给 OUT 解析，降低 IN
  本地 DNS 污染的影响。

如果只供本机程序使用，应监听 `127.0.0.1:1080`。只有受信局域网客户端
确实需要访问时才监听 `0.0.0.0`，并限制 TCP、UDP `1080` 的来源。

需要透明接管本机或 Tailscale 转发的 IPv4 流量时，可以删除 `socks5` 并
改为：

```jsonc
"inbounds": {
  "tproxy": {
    "listen": "127.0.0.1:12345",
    "sniff": true,
    "hijack_dns": false,
    "network": {
      "bypass_user": "plug2proxy",
      "mark": "0x00000070",
      "mark_mask": "0x000000ff"
    }
  }
}
```

`listen` 必须是带非零端口的 IPv4 loopback 地址。该端口只由自动生成的
nftables 规则使用，不需要也不应在安全组中开放。不要手工复制规则；安装
仓库提供的 systemd unit 后，启动时调用 `network apply`，reload 时调用
`network reconcile`，正常或异常停止时调用 `network remove`；restart 会先
remove 再 apply。完整步骤见
[原生 TPROXY 部署](native-tproxy.md)。

`network.mark` 和 `network.mark_mask` 都可以省略，默认分别为
`"0x00000070"` 和 `"0x000000ff"`。前者是本机 OUTPUT 值；mask 中最低的
有效 bit 作为角色位，程序据此得到默认 PREROUTING 值 `0x00000071`。写入
时只修改 mask 内的 bit。若需要避开同机其他 policy-routing 组件，可以调整
这两个字段；mask 至少包含两个 bit，mark 必须非零、位于 mask 内并清除角色
bit。活动布局不能通过 `network reconcile` 热切换，应 restart，或先
`network remove` 再 `network apply`。完整约束和冲突检查见
[原生 TPROXY 部署](native-tproxy.md#配置-tproxy-inbound)。

`hijack_dns` 默认 `false`，此时终端显式指定的 DNS 服务器保持为实际目标，
并像其他 TCP/UDP 流量一样经过透明入口。设为 `true` 才会把所有原目标端口
为 53 的请求强制交给顶层 Plug2Proxy DNS。

作为 Tailscale exit node 时，还应按原生 TPROXY 文档配置 tailnet 和云平台
内部网段的 `exclude_ipv4`；否则发往其他 tailnet 节点的目标也会被透明接管。
当前 TPROXY 只接管 IPv4；如果该节点没有可用的 IPv6 转发路径，推荐安装
原生 TPROXY 文档中的 exit-node DNS drop-in，让 Tailscale 默认 DNS 使用
本机 Plug2Proxy DNS，并在顶层 `dns` 同时设置
`"strategy": "ipv4_only"` 和 `"system_default": true`。网络控制器会创建
一条自有的临时 DNS route；它不会写入 `tailscale0`，因此 Tailscale 的
netmap 重配置不会把它清掉。这不会覆盖终端自行指定的 resolver。完整示例与
限制见原生 TPROXY 文档。

下面的手工启动方式只用于本节前面的 SOCKS5 示例。启用 TPROXY 时不要继续
使用 `/etc/plug2proxy` 下的手工命令，应按原生 TPROXY 文档使用专用用户、
`/var/lib/plug2proxy` 工作目录和仓库提供的 systemd unit。

启动 SOCKS5 IN：

```bash
cd /etc/plug2proxy
RUST_LOG=info,plug2proxy=debug plug2proxy
```

推荐启动顺序是 HUB、两个 OUT、最后 IN。某个 OUT 重启后，给 peer 和
relay connection 留出数秒重新注册时间。

## 6. 验证

从能访问 IN SOCKS5 的机器执行：

```bash
# 默认非 CN 流量应显示 US OUT 的公网 IP。
curl --max-time 30 --proxy socks5h://192.0.2.10:1080 \
  https://api.ipify.org

# OKX 应显示 HK OUT 的公网 IP。
curl --max-time 30 --proxy socks5h://192.0.2.10:1080 \
  https://www.okx.com/cdn-cgi/trace

# CN 域名应成功，并在 IN 日志中显示 DIRECT。
curl --max-time 30 --proxy socks5h://192.0.2.10:1080 \
  -o /dev/null -w '%{http_code}\n' https://www.taobao.com/
```

同时观察：

```bash
journalctl -f -u plug2proxy
```

在 HUB 和提供 peer 直连的 OUT 上，还应分别确认 TCP、UDP socket 都监听在
配置的同一个端口：

```bash
sudo ss -lntp
sudo ss -lnup
```

还要检查日志中没有 `error binding UDP listener` 或
`disabling QomT UDP listener`。UDP 旁路建立后，连接发起侧会记录
`QomT UDP generation ... established`，接收侧会记录对应的 accepted
generation；这证明旁路已经就绪，但不能证明某次业务数据使用了它。需要
严格确认实际数据路径时，应在驱动测试流量的同时，对照时间和包量抓取
listener 对应端口的 UDP 包，例如：

```bash
sudo timeout 15s tcpdump -ni any 'udp port 1122 or udp port 2233'
```

应用层 UDP 或 HTTP/3 请求成功只能证明 SOCKS5 UDP 转发可用，不能单独
证明 QomT UDP 旁路承载了该次数据。generation 日志用于确认旁路就绪；要
判断该次数据是否使用旁路，应关联测试时段的抓包。

成功时，IN 日志应分别出现：

```text
api.ipify.org:443 -> us via qomt(priority=PeerProvider, ...)
www.okx.com:443 -> hk via qomt(priority=Provider, ...)
www.taobao.com:443 -> DIRECT via local(default)
```

前两条中的 `PeerProvider` 与 `Provider` 分别表示 peer 直连和 HUB relay。
它们不是配置文件里的 tag。

如果出现 `no out dispatcher matched`：

1. 检查 OUT 的 tag 与 HUB 路由中的 exit 是否完全一致；
2. 检查 OUT 是否已向 HUB 注册；
3. OUT 或 HUB 刚重启时，先等待 QomT connection 和完整快照恢复；
4. 确认四机使用相同版本。

## 7. Exit 与路由速查

- 自定义 tag 推荐使用小写。区域 tag 可用 `us`、`hk`，功能 tag 可用
  `youtube`、`netflix`。
- `DIRECT`、`PROXY`、`ANY` 是保留 selector，保持全大写。
- `DIRECT`：当前 inbound 所在节点的默认本地出口。
- `PROXY`：任意已发布的 provider exit。
- `ANY`：优先当前节点 `DIRECT`，没有时再匹配 provider。
- route 的 `exit` 可以是数组，数组顺序优先于同一 selector 内的路径选择。
- 同一 selector 同时存在 peer 和 relay 时，已连接的 peer 优先。

一个 OUT 可以提供多个本地出口。例如在 HK OUT 上经 WireGuard interface
再提供 `jp`：

```jsonc
{
  "type": "out",
  "hub": {
    "address": "203.0.113.10:1122",
    "connections": 4
  },
  "exits": [
    {
      "type": "local",
      "tags": ["hk"]
    },
    {
      "type": "local",
      "tags": ["jp"],
      "bind": {
        "interface": "wgjp"
      }
    }
  ]
}
```

没有 `bind` 的 local exit 是该节点唯一的默认 local exit，同时提供本机
`DIRECT`。绑定 interface 的 exit 只作为 provider，不会成为 `DIRECT`。
同一 OUT 最多配置一个没有 bind 限制的 local exit。

Linux 上 Plug2Proxy 会为 QomT 主路径中 mTCP 的底层 TCP socket 尝试启用 BBR；
UDP 旁路使用 quiche 自身的 pacing 与拥塞控制。BBR 是推荐优化，不是启动
前置条件。部署前可确认：

```bash
sysctl net.ipv4.tcp_available_congestion_control
```

输出应包含 `bbr`。内核提供模块但尚未加载时，应按发行版方式加载
`tcp_bbr` 并设置开机自动加载。
