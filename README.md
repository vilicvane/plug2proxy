# Plug2Proxy

Plug2Proxy 是一个实验性的多节点代理。它把入口、协调和出口拆成独立节点，
再用配置决定流量从哪里进入、经过哪条链路、最终从哪个网络接口离开。

它目前更像一套可以自己拼装的数据平面，而不是已经封装完成的代理产品。
如果你喜欢搭服务器、调路由、看日志、测跨洲链路，并且不介意配置格式在
快速迭代中发生变化，欢迎来玩。

## 它怎么工作

```text
                               ┌──────── HUB relay ────────┐
SOCKS5 / native TPROXY → IN                           OUT → target
                               └──── peer connection ──────┘
```

- **IN** 接收请求，执行路由规则，并提供当前机器的 `DIRECT` 出口。
- **HUB** 协调节点、汇总 OUT 能力和路由信息，也可以同时提供 inbound
  或 local exit。
- **OUT** 提供一个或多个出口，并用 tag 声明自己能处理的流量。

OUT 可以只连接 HUB，由 HUB 中继数据；也可以公布 peer listener，由 HUB
协调 IN 与 OUT 建立直连。可用的 peer 路径优先，失效时仍可使用 HUB
relay。

## QomT 是什么

QomT 是 Plug2Proxy 的节点间逐跳传输层。它保留一条可靠的 QUIC over mTCP
主路径，并在同一个逻辑连接上维护一条可选的 QUIC over UDP 旁路：

```text
QomtConnection
├── main QUIC over parallel TCP ── stream、可靠包与 fallback
└── optional QUIC over UDP ─────── connection-level DATAGRAM 旁路
```

这里的 mTCP 是一组并行 TCP 连接；QUIC 的连接、流和拥塞状态机运行在这组
连接之上。`QomtStream` 始终是主路径上的可靠字节流。packet stream 从使用
者角度是一条可靠 stream 加一条共享的 UDP DATAGRAM 路径；UDP QUIC
连接由 `QomtConnection` 统一维护，并不是每条 packet stream 各自持有第二
条完整连接。

可靠包始终走主路径。best-effort 包会根据包大小和两条路径观测到的 RTT
选择 UDP 旁路；旁路尚未建立、已经断开或容纳不下当前包时，会回退到可靠
主路径。UDP DATAGRAM 的应用载荷上限由当前 QUIC 开销动态决定，通常略低于
1.4 KiB，当前不在旁路内分片，也不会自适应更小的路径 MTU。

DATAGRAM 本身不保证交付，也不会因网络丢包自动在主路径重放。旁路发送
队列或 reliable fallback 队列已满时，发送端也会按 best-effort 语义主动
丢弃。

UDP 旁路是增强路径，不决定整个 QomT 连接是否可用。它独立握手、发送
keepalive，并等待 quiche 判定当前 QUIC 连接关闭后，以新的连接代次和退避
重新建立；这期间 stream 和 fallback 仍使用 mTCP 主路径。

部署时，HUB 以及提供 peer 直连的 OUT 必须在同一个监听端口同时放行 TCP
和 UDP。发起连接的一侧通常只需要允许出站 UDP 及其有状态回包。只放行
TCP 时主路径仍能工作，但不会获得 UDP 旁路。具体端口和 NAT 要求见
[推荐配置教程](docs/configuration.md#端口与防火墙)。

## 原生透明入口

Linux 上的 IN/HUB 可以直接启用 IPv4 TPROXY inbound，不再需要先用
sing-box 把 TUN 流量转换成 SOCKS5。TCP、UDP 和 TCP/UDP DNS 53 都在
Plug2Proxy 内取得原目标、执行同一套路由，并沿原目标地址回包。

特权被拆成两个很短的阶段：长期运行的数据面使用专用 `plug2proxy` 用户，
只保留 `CAP_NET_RAW` 与 `CAP_NET_BIND_SERVICE`；启动和停止时由同一个
二进制的 `network apply/remove` 子命令以 root 按受控顺序安装或撤销
nftables 与 policy route。其中 nft table 原子替换，route/rule 使用所有权
journal 和失败回滚。规则由配置生成，用户不需要维护 nft 文件或网络变化脚本。
本机和转发方向已有的 conntrack flow 在启用时保持原路径，新 flow 才写入
Plug2Proxy 的 conntrack mark；正常停止时先撤规则再结束进程，异常路径则由
stop-post 尽快清理，整体采用 fail-open。

当前原生透明入口仅实现 Linux IPv4 TPROXY，TUN 和 IPv6 尚未实现。作为
IPv4-only exit-node 时，可让 systemd-resolved 的默认查询使用本机
Plug2Proxy DNS，并设置 `strategy: "ipv4_only"` 让 AAAA 返回 NODATA；终端
显式指定的 DNS 默认仍保留原目标。完整配置、exit-node DNS drop-in、systemd
unit、权限模型和卸载步骤见
[原生 TPROXY 部署](docs/native-tproxy.md)。

## 有什么特点

- **一套进程，三种角色**：`in`、`hub`、`out` 使用同一个二进制和
  JSONC 配置。

- **可组合的出口**：OUT 可以声明多个 tag，也可以把 local exit 绑定到指定 Linux
  interface，用于串接 WireGuard 或其他网络出口。

- **按目标选择出口**：路由支持域名及子域、`geosite:...` 社区域名列表、
  正则表达式、IP/CIDR、端口、GeoIP、取反和 fallback。`DIRECT`、
  `PROXY`、`ANY` 与自定义 tag 可以组合使用。使用 Geosite 规则时会在
  工作目录维护 `dlc.dat`。

- **HUB relay 与 IN–OUT peer 直连**：OUT 决定是否提供直连入口，HUB
  负责协调和下发 endpoint，IN 维护实际可用的 peer 路径。

- **SOCKS5 与原生 TPROXY**：IN/HUB 可以接收 SOCKS5 TCP/UDP；Linux
  IPv4 还可直接管理 TPROXY TCP/UDP，并可选择是否强制劫持 DNS。

- **QomT 传输**：可靠的 QUIC over mTCP 主路径与可选的 QUIC over UDP
  DATAGRAM 旁路并行工作。Linux 上还会尝试为主路径的底层 TCP socket
  启用 BBR，主要用于探索高延迟、受限网络下的实际表现。

- **节点间双向认证**：HUB 持有私有 CA，为每个 IN 和 OUT 签发独立节点
  证书；HUB relay 和 peer 直连使用同一套信任关系。

## 当前状态

Plug2Proxy 仍处于早期实验阶段：

- 主要定位是个人、小规模、节点彼此可信的部署；
- 配置与节点协议不承诺跨版本兼容；
- SOCKS5 暂无认证，不应直接暴露到公网；
- Linux 是目前主要验证环境；
- 自动部署、升级、证书轮换和完善的可观测性仍需自己处理；
- 遇到违反协议不变量的状态时，程序可能直接终止。

它已经能够承担真实的 TCP、UDP、HUB relay、peer 直连和规则路由流量，
但还需要愿意观察日志、理解数据路径并亲手排错的用户。

## 开始尝试

准备 Rust 工具链后，日常调试和测试直接使用 Cargo：

```bash
cargo build --locked
cargo test --locked
```

用于部署的 release 则使用
[Cross](https://github.com/cross-rs/cross)。这在“本机编译、远程部署”时
尤其重要：项目的 `Cross.toml` 固定了目标构建环境，避免本机较新的 glibc
或不同 CPU 架构让二进制无法在服务器上运行。运行 Cross 前需要准备好
Docker。

根据目标服务器架构选择命令：

```bash
# x86_64
cross build --locked --release --target x86_64-unknown-linux-gnu

# ARM64 / aarch64
cross build --locked --release --target aarch64-unknown-linux-gnu
```

对应的二进制是：

```text
target/x86_64-unknown-linux-gnu/release/plug2proxy
target/aarch64-unknown-linux-gnu/release/plug2proxy
```

部署时只取与服务器架构对应的文件。教程中的示例将它安装为更易识别的
`plug2proxy`，例如：

```bash
sudo install -m 0755 \
  target/x86_64-unknown-linux-gnu/release/plug2proxy \
  /usr/sbin/plug2proxy
```

第一次 Cross 构建会编译 BoringSSL，耗时通常明显长于后续增量构建。
IN、HUB 和 OUT 应使用同一份代码和 lockfile 构建的版本。

当前推荐配置使用一个 HUB、一个 IN 和两个 OUT：默认 US OUT 公布 peer
listener，让 IN 优先直连；特殊 HK OUT 只通过 HUB relay；CN 流量从 IN
本机 `DIRECT`。路由集中写在 HUB 并下发给 IN。这样可以在同一套配置中
同时验证直连、relay、按域名分流和本机直出。

长期观察时推荐设置
`RUST_LOG=info,plug2proxy=debug`：Plug2Proxy 保留结构化 debug 诊断，
依赖库仍保持 info。

## 文档

- [Plug2Proxy 推荐配置教程](docs/configuration.md)
- [Linux 原生 TPROXY 部署](docs/native-tproxy.md)

## 一起折腾

欢迎尝试不同地区的 HUB/OUT、不同 RTT 和丢包环境、多个 interface 出口，
以及 TCP/UDP 混合负载。

报告问题时，最好附上：

- IN、HUB、OUT 的拓扑和版本；
- 去除证书与隐私信息后的配置；
- 相关节点同一时间段的日志；
- 目标是 TCP 还是 UDP、HUB relay 还是 peer 直连；
- 可复现问题的最小步骤。

别提交 `ca.pem`、`node.pem`、SSH 私钥或云凭据。
