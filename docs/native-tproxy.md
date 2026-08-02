# Linux 原生 TPROXY 部署

本文说明如何在 Linux 上使用 Plug2Proxy 自带的 TPROXY inbound，直接接管
本机或经本机转发的 TCP/UDP 流量。它不依赖 sing-box，也不要求用户维护
nftables 脚本或 policy routing 脚本。

当前实现仅支持 **Linux IPv4 TPROXY**，不是 TUN：没有创建 TUN 网卡，也
没有内置用户态 TCP/IP 栈。IPv6 流量不会被这套规则接管；如果系统需要
IPv6 透明代理，应先保持原有 IPv6 路径，不能把本文配置当作 IPv6 方案。

## 工作方式

启用后，数据路径为：

```text
本机/转发的 IPv4 TCP、UDP
  -> nftables 标记
  -> IPv4 policy rule 与本地路由表
  -> 127.0.0.1 上的 TPROXY inbound
  -> Plug2Proxy 路由与 QomT
```

Plug2Proxy 的网络控制器会管理以下专用对象：

| 对象 | 固定值 |
| --- | --- |
| nftables table | `inet plug2proxy_tproxy` |
| 本机 OUTPUT 路由 mark / mask | `0x51000000/0xff000000` |
| bypass mark / mask | `0x52000000/0xff000000` |
| 外部 PREROUTING 路由 mark / mask | `0x53000000/0xff000000` |
| IPv4 policy rule priorities | `98`（源校验 guard）、`99`（PREROUTING）、`100`（OUTPUT） |
| IPv4 route table | `20230` |

写入 mark 时只修改高 8 位，保留低 24 位。OUTPUT 链会绕过 Plug2Proxy
运行用户产生的连接、reply 方向流量、bypass mark、已存在的非零外部 mark，
并显式保护 Tailscale 的已知 mark。因此 Plug2Proxy 自己的 mTCP、UDP QUIC
连接不会再次进入 TPROXY，tailscaled 的外层连接也不会被套娃代理。

本机 OUTPUT 和转发 PREROUTING 流量都按 flow 分类。只有规则启用后到达的
第一个 TCP SYN 或 UDP 数据包会建立 Plug2Proxy 的 conntrack 路由标记；
同一 flow 的后续包从 conntrack 恢复标记。规则启用前已经由 conntrack 确认、
且没有 Plug2Proxy 标记的 flow 保持原路径，不会在字节流中途被切入 TPROXY。
`network reconcile` 原子替换 Plug2Proxy 自己的 nft table，但不清空 conntrack，
因此已有 flow 会继续使用原来的分类。它不等于跨 Plug2Proxy 进程重启保留
TCP 会话：数据平面进程退出后，进程内连接仍然会结束。

OUTPUT 与 PREROUTING 必须使用不同 mark。[Tailscale 1.98.1 更新说明](https://tailscale.com/changelog)
明确记录其 Linux 客户端会启用
`net.ipv4.conf.all.src_valid_mark=1`；若两条路径共用一个指向 local table 的
mark，内核对外部入站包做源地址反查时也会命中该 local table，并把正常源地址
误判为 local source 后丢弃。priority `98` 的 guard 只在这次反查使用的
`iif lo` 上跳过 PREROUTING 规则；真实外部入站走 priority `99`，本机 OUTPUT
走 priority `100`。控制器不会修改 `src_valid_mark`、`accept_local` 或
`route_localnet`，也不需要用户按 ingress interface 配置 sysctl。

## 前置条件

目标机器需要：

- Linux 内核的 nftables、policy routing 和 TPROXY 支持；
- `/usr/sbin/nft`（通常由 `nftables` 包提供）；
- `/usr/sbin/ip`（通常由 `iproute2` 包提供）；
- systemd；
- 与 HUB/OUT 使用同一提交和 lockfile 构建的 `plug2proxy`。

同一主机上不要同时启用两个“接管全部流量”的 TUN/TPROXY 管理器。切换自
其他透明代理方案时，应先准备好 Plug2Proxy 配置并完成 `network check`，
再停用旧方案的自动路由/重定向，最后启动本文 unit。普通防火墙规则可以
保留，但必须允许 Plug2Proxy 访问 HUB/OUT 的实际 TCP、UDP 端口。

推荐为数据平面创建专用系统用户。不要用 `root` 长期运行：

```bash
sudo useradd --system \
  --home-dir /var/lib/plug2proxy \
  --shell /usr/sbin/nologin \
  plug2proxy
```

如果用户已经存在，只需确认其 UID 稳定：

```bash
id -u plug2proxy
```

TPROXY 数据平面需要两个 capability：

- `CAP_NET_RAW`：启用 `IP_TRANSPARENT` 并使用非本地源地址发送响应；
- `CAP_NET_BIND_SERVICE`：以原始目标的低端口（尤其是 DNS `53`）作为响应
  源端口。

随仓库提供的 systemd unit 只把这两个 capability 交给长驻进程。修改
nftables 和 policy routing 的 `network` 子命令由 systemd 以 root 短暂执行，
长驻进程不持有 `CAP_NET_ADMIN`，也不需要给二进制设置永久 file capability。

## 配置 TPROXY inbound

下面是在 IN 节点上的完整骨架；将 HUB 地址替换为实际值：

```jsonc
{
  "type": "in",
  "hub": {
    "address": "203.0.113.10:1122",
    "connections": 4
  },
  "inbounds": {
    "tproxy": {
      "listen": "127.0.0.1:12345",
      "sniff": true,
      "hijack_dns": false,
      "network": {
        "bypass_user": "plug2proxy",
        "exclude_ipv4": [
          "192.168.0.0/16"
        ]
      }
    }
  },
  "dns": {
    "listen": "127.0.0.1:53",
    "strategy": "ipv4_only"
  }
}
```

`inbounds.tproxy` 的字段含义：

- `listen`：同一个 TCP/UDP TPROXY listener。必须显式填写非零端口，并且
  必须是 IPv4 loopback 地址，例如 `127.0.0.1:12345`。`:0`、IPv6、
  `0.0.0.0` 和非 loopback 地址都会被拒绝。不要与顶层 `dns.listen`
  使用同一监听地址和端口。
- `sniff`：是否从 TCP、QUIC 首包恢复路由域名/协议，默认 `true`。嗅探只
  补充路由元数据；实际直连仍使用原始目标 IP。
- `hijack_dns`：是否把所有透明入口中原目标端口为 `53` 的 TCP/UDP 请求
  强制交给顶层 Plug2Proxy DNS，默认 `false`。保持默认值时，客户端显式
  指定的 DNS 服务器仍是实际目标；仅在明确需要强制 DNS 策略时启用。
- `network.bypass_user`：运行 Plug2Proxy 数据平面的专用用户，默认
  `plug2proxy`。启动时会校验进程有效 UID 必须与该用户的 UID 相同；网络
  规则也按这个 UID 绕过代理。
- `network.exclude_ipv4`：额外不接管的 IPv4 CIDR 列表。适合保留管理网、
  局域网或其他必须直达的网段；只接受 IPv4。程序已经内置排除 `0/8`、
  loopback、link-local、multicast 和保留地址，但不会默认排除 RFC 1918
  私网或 CGNAT 网段，需要时应显式列出。

例如，若 IN 同时作为 Tailscale exit node，而本机访问 tailnet 地址仍应留在
Tailscale 内，可显式排除 `100.64.0.0/10`。在本次阿里云测试机上还观察到
`100.100.0.0/16` 的平台内部流量；部署到同类环境时建议将该网段加入排除
列表；若已排除更大的 `100.64.0.0/10`，则无需重复填写。生成器也会自动
消除被更大 CIDR 完全覆盖的条目，避免 nft interval 冲突。它们不是内置
默认值，因为其他网络也可能把这些地址作为需要代理的普通目标。

顶层 `dns` 提供按 Plug2Proxy 路由解析的显式 DNS listener，TCP 和 UDP 都
支持。作为 Tailscale exit-node 时，推荐监听标准的 `127.0.0.1:53`，并按
下节让 exit-node 的系统默认 resolver 使用它。这样终端接受 Tailscale DNS
时走 Plug2Proxy；终端自行指定的 resolver 则保持原目标，经透明入口作为
普通 TCP/UDP 流量转发。只有设置 `hijack_dns: true` 时，后者才会被强制
改写为 Plug2Proxy DNS。

`dns.strategy` 缺省或设为 `"default"` 时保留所有受支持的记录类型；设为
`"ipv4_only"` 时，AAAA 查询直接返回 `NOERROR/NODATA`，不会发往上游，A
及其他记录类型仍按原路由解析。当前仅支持 IPv4 TPROXY 的 exit-node 如果
没有独立可用的 IPv6 路径，应使用 `ipv4_only`，避免 DNS 给客户端一条本机
无法接管或转发的 IPv6 路径。这不是 IPv6 literal 的代理方案。

## 安装文件

将为目标架构构建好的 release 二进制安装到 unit 约定的位置。项目规定
release 必须使用 Cross 构建；不要用本机 `cargo build --release` 代替。

```bash
sudo install -o root -g root -m 0755 plug2proxy /usr/sbin/plug2proxy
sudo install -d -o root -g root -m 0755 /etc/plug2proxy
sudo install -d -o plug2proxy -g plug2proxy -m 0750 /var/lib/plug2proxy
```

把配置写到 `/etc/plug2proxy/config.json`。`network apply` 和
`network reconcile` 会以 root 读取它，因此文件必须是 root 拥有的普通
文件、不能是符号链接、不能允许 group/other 写入；其所有上级目录也必须
是 root 拥有、不可由 group/other 写入且不能是符号链接。下面的权限同时
允许数据平面的 `plug2proxy` 用户读取：

```bash
sudo chown root:plug2proxy /etc/plug2proxy/config.json
sudo chmod 0640 /etc/plug2proxy/config.json
```

配置与可写状态必须分开：

- `/etc/plug2proxy/config.json`：root 管理的只读配置；
- `/var/lib/plug2proxy`：`plug2proxy` 用户可写的工作目录，放置该节点的
  `node.pem`、GeoIP/Geosite 数据等；
- `/run/plug2proxy-netctl`：网络控制器自动维护的 root-only、同一 boot 内
  有效的所有权日志和操作锁，用户无需创建或编辑。

例如安装节点证书：

```bash
sudo install -o plug2proxy -g plug2proxy -m 0600 \
  node.pem /var/lib/plug2proxy/node.pem
```

不要把 HUB 的 `ca.pem` 私钥复制到 IN 节点。

最后安装仓库中的 unit：

```bash
sudo install -o root -g root -m 0644 \
  res/systemd/plug2proxy-tproxy.service \
  /etc/systemd/system/plug2proxy-tproxy.service
sudo systemctl daemon-reload
```

该 unit 使用 `/var/lib/plug2proxy` 作为 `WorkingDirectory`，并通过
`StateDirectory=plug2proxy` 保证目录存在。不要把工作目录改回
`/etc/plug2proxy`，否则服务生成或更新状态时会破坏配置与可写数据的隔离。

### Tailscale exit-node 的默认 DNS

Tailscale 客户端接受 Tailscale DNS 并使用 exit-node 时，客户端显示的
`100.100.100.100` 或 `fd7a:115c:a1e0::53` 是正常的本机 MagicDNS 前端；
公网查询最终使用 exit-node 的系统 resolver。若希望默认查询进入本机
Plug2Proxy DNS，同时保留终端自行指定 resolver 的能力，可安装随仓库提供的
systemd drop-in：

```bash
sudo install -d -o root -g root -m 0755 \
  /etc/systemd/system/plug2proxy-tproxy.service.d
sudo install -o root -g root -m 0644 \
  res/systemd/plug2proxy-tailscale-exit-dns.conf \
  /etc/systemd/system/plug2proxy-tproxy.service.d/tailscale-exit-dns.conf
sudo systemctl daemon-reload
```

exit-node 本机必须保持 `tailscale set --accept-dns=false`，避免 tailscaled 与
该 drop-in 同时管理 `tailscale0` 的 resolver 状态。这不影响其他终端接受
Tailscale DNS，也不改变 exit-node 为这些终端提供 DNS 的行为。

该 drop-in 只在服务运行期间为 `tailscale0` 设置 systemd-resolved 的
route-only 根域 `~.`，DNS server 指向本机 `127.0.0.1:53`。服务停止、启动
失败或 systemd-resolved 重启时，runtime 配置会自动撤销或随服务重新应用，
不修改 `/etc/resolv.conf`。它要求顶层 `dns.listen` 使用 `127.0.0.1:53`，
并保持 `inbounds.tproxy.hijack_dns: false`。

## 网络控制命令

建议在第一次启动前先渲染并检查计划：

```bash
sudo -u plug2proxy /usr/sbin/plug2proxy \
  --config /etc/plug2proxy/config.json network render

sudo /usr/sbin/plug2proxy \
  --config /etc/plug2proxy/config.json network check
```

六个子命令的职责如下：

| 命令 | 行为 |
| --- | --- |
| `network render` | 输出将生成的 nftables transaction，不修改系统 |
| `network check` | 检查对象所有权、固定编号冲突与 nft 语法，不修改系统 |
| `network apply` | 等待 TCP/UDP 数据平面就绪，幂等安装 policy route 和 nft table |
| `network reconcile` | 数据平面就绪时重新应用期望状态，用于外部 ruleset reload 后恢复 |
| `network status` | 查看 nft、route、rule 与所有权日志的状态 |
| `network remove` | 仅移除经所有权标记确认属于 Plug2Proxy 的对象 |

`apply` 与 `reconcile` 必须使用绝对配置路径，并由 root 执行；`status` 和
`remove` 不需要读取配置：

```bash
sudo /usr/sbin/plug2proxy network status
sudo /usr/sbin/plug2proxy network remove
```

控制器不会覆盖同名的外部 nft table，也不会静默删除占用 rule priority
`98`–`100`、route table `20230` 或保留 mark 的外部规则。`check` 报告冲突时，
先确认对象的实际所有者，再调整冲突组件；不要直接删除未知规则。

从只使用 priority `100` 和 mark `0x51000000` 的旧版升级时，新控制器会保留
这条规则作为 OUTPUT 规则，先补 priority `98` 的源校验 guard，再添加
priority `99` 的 PREROUTING local route，最后原子升级 nft
table；旧的外部 conntrack mark 会在后续原方向包到达时转换为 PREROUTING
mark。若要降级到不认识三规则/schema 2 nft table 的旧二进制，必须先用新版
停止服务并执行 `network remove`；只有 `network status` 已确认
`nft=Absent, route=Absent, rules=Absent` 后，才能替换二进制并重新启动，不能
直接覆盖后降级。若清理未完成，应保留新版二进制用于继续恢复，不能让旧版
接管它无法识别的 schema 2 状态。

## 启动与重载

启动服务：

```bash
sudo systemctl enable --now plug2proxy-tproxy.service
```

systemd 先以 `plug2proxy` 用户启动数据平面；只有当配置地址上的 TCP listener、
UDP socket 和已配置的 DNS TCP/UDP listener 都已建立，`ExecStartPost` 才安装
网络接管；exit-node DNS drop-in 随后应用 resolver 路由。正常启动后检查：

```bash
sudo systemctl is-active plug2proxy-tproxy.service
sudo systemctl show plug2proxy-tproxy.service \
  -p User -p MainPID -p NRestarts -p ExecMainStatus
sudo journalctl -u plug2proxy-tproxy.service --since '5 minutes ago' --no-pager
sudo /usr/sbin/plug2proxy network status
```

`systemctl reload plug2proxy-tproxy.service` 会执行 `network reconcile`，适合
nftables 被外部工具重载后恢复规则；它不会让长驻进程热加载完整配置。修改
TPROXY listener、HUB 或其他数据平面配置后，应使用：

```bash
sudo systemctl restart plug2proxy-tproxy.service
```

## 验证真实流量

先确认两个 listener 和内核对象都存在：

```bash
sudo ss -lntup | grep -E '127\.0\.0\.1:12345|127\.0\.0\.1:53'
sudo nft list table inet plug2proxy_tproxy
sudo ip -4 rule show priority 98
sudo ip -4 rule show priority 99
sudo ip -4 rule show priority 100
sudo ip -4 route show table 20230
```

再从被接管的主机直接发流量，不要加 SOCKS5 参数：

```bash
curl --connect-timeout 10 --max-time 30 https://api.ipify.org
dig +time=5 +tries=1 example.com A
dig +tcp +time=5 +tries=1 example.com AAAA
dig +time=5 +tries=1 @8.8.8.8 example.com A
dig +time=5 +tries=1 @8.8.8.8 example.com AAAA
```

安装 exit-node DNS drop-in 且配置 `ipv4_only` 时，默认 AAAA 查询必须为
`NOERROR/NODATA`。显式查询 `@8.8.8.8` 必须仍真正访问该 resolver；其 AAAA
应答不得被 Plug2Proxy 的 `ipv4_only` 策略清空。不能只看 `+short` 的空输出，
还应检查完整状态。与此同时观察日志和 nft counter，确认请求命中了预期入口，
而不是仅凭 service 的 `active` 状态判断：

```bash
sudo journalctl -f -u plug2proxy-tproxy.service
sudo nft list table inet plug2proxy_tproxy
```

如果配置了 `exclude_ipv4`，还应访问至少一个被排除网段的目标，确认该流量
没有增加 TPROXY 规则 counter。通过路由器/exit-node 转发到这台机器的流量
需要另行验证客户端路径；本机 curl 只能覆盖 OUTPUT 链。

## 故障与 fail-open 行为

网络控制按“先验证、最后接管”的顺序工作：先检查保留对象和 nft transaction，
再按 OUTPUT rule、源校验 guard、PREROUTING rule 的依赖顺序准备本地
route/rule，最后原子安装 nft table。route/rule 在 nft 标记流量
之前不会主动截获普通连接；中途失败时会回滚本次新增对象。nft 激活后还会
再次确认 TCP/UDP 数据平面仍在，若已消失则立即撤销已拥有的网络状态。

清理顺序反向执行：先删除 PREROUTING rule，确认它已经不存在后才删除源校验
guard；OUTPUT rule 使用独立 mark，会始终单独尝试删除。即使 nft table 删除
本身失败，也不会留下“PREROUTING local route 仍生效但 guard 已消失”的危险
中间状态，后续清理仍朝 fail-open 收敛。

systemd unit 在正常停止数据平面之前先执行 `network remove`，并在
stop-post 阶段再尝试一次。受控的 `network apply` 失败会自行回滚；若启动
超时、启动失败或进程意外退出，数据平面可能已经结束，此时 systemd 通过
`ExecStopPost` 尽快撤销接管后再重启。这是 best-effort fail-open 设计：
代理不可用时尽量不把流量留在一个无人接收的本地 TPROXY 路径，但不承诺
所有异常中都能先于进程退出完成清理。

如果机器被强制断电、内核或 root 网络控制命令本身故障，不能保证任何用户态
清理动作已经运行。恢复后先执行：

```bash
sudo /usr/sbin/plug2proxy network status
sudo /usr/sbin/plug2proxy network remove
```

控制器用 nft table comment 和 `/run/plug2proxy-netctl` 中的同 boot 日志确认
所有权；无法证明对象属于 Plug2Proxy 时会拒绝破坏性删除并明确报错。

## 当前限制

- 只处理 Linux IPv4 TCP/UDP；没有实现 TUN、IPv6 透明代理或 ICMP 代理。
- 网络控制器只管理自己的 nftables table、IPv4 policy rule 和 route table；
  不会替用户开启 `net.ipv4.ip_forward`，也不会配置客户端默认路由、云安全组
  或上游防火墙。仅代理本机 OUTPUT 时不需要开启 IP forwarding；作为路由器
  接管 PREROUTING 流量时，转发与客户端路由仍需由系统环境提供。
- `exclude_ipv4` 目前按目标 IPv4 CIDR 排除，不提供按端口或进程的自定义
  规则语言。Plug2Proxy 进程自身通过专用 UID 自动绕过。
- 顶层未配置 `dns` 时，TCP/UDP 53 不使用本地 DNS hijack；需要路由感知 DNS
  时必须同时配置一个不与 TPROXY listener 冲突的 `dns.listen`。
- `dns.strategy = "ipv4_only"` 只抑制 AAAA 答案，不能代理 IPv6 literal、
  客户端自行使用的加密 DNS，或其他绕过该 DNS listener 获得的 IPv6 目标。
- `reconcile` 能平滑保留内核中已有 flow 的分类，但数据平面进程重启仍会
  中断其持有的 TCP 会话和其他进程内状态。

## 文件描述符上限

透明代理会同时持有监听 socket、活跃 TCP 连接、QomT 主路径中 mTCP 的多条
底层 TCP connection，以及有界缓存中的 UDP response socket。仓库 unit 设置：

```ini
LimitNOFILE=65536
```

这是部署基线，不是容量承诺。高并发节点应观察主进程的实际 FD 数、连接数和
丢包日志后再提高上限；在 systemd 服务外执行 `ulimit` 不会修改该 unit 的
限制。可用下面的命令查看：

```bash
main_pid=$(systemctl show -p MainPID --value plug2proxy-tproxy.service)
sudo ls "/proc/${main_pid}/fd" | wc -l
systemctl show plug2proxy-tproxy.service -p LimitNOFILE
```

## 停用与卸载

停止并禁用服务：

```bash
sudo systemctl disable --now plug2proxy-tproxy.service
sudo /usr/sbin/plug2proxy network remove
sudo /usr/sbin/plug2proxy network status
```

确认状态为 absent 后，移除 unit：

```bash
sudo rm -f /etc/systemd/system/plug2proxy-tproxy.service
sudo systemctl daemon-reload
```

如果机器不再运行任何 Plug2Proxy 角色，可以再移除 `/usr/sbin/plug2proxy`。
`/var/lib/plug2proxy` 中可能含有 `node.pem` 私钥和下载的数据，
`/etc/plug2proxy/config.json` 也可能包含部署信息；请在确认不需要备份后单独
清理，不要把它们作为卸载 unit 的副作用自动删除。
