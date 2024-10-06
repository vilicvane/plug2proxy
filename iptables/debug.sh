# Add a rule to lookup routing table 100 for packets marked with fwmark 1
ip rule add fwmark 1 lookup 100
# Add a route to route all traffic to the local loopback interface in table 100
ip route add local 0.0.0.0/0 dev lo table 100

iptables --table mangle --new-chain DIVERT
iptables --table mangle --append DIVERT --jump MARK --set-mark 1
iptables --table mangle --append DIVERT --jump ACCEPT
iptables --table mangle --append PREROUTING --protocol tcp --match socket --jump DIVERT

iptables --table mangle --append OUTPUT --protocol tcp --destination 198.18.0.0/15 --jump MARK --set-mark 1
iptables --table mangle --append PREROUTING --protocol tcp --destination 198.18.0.0/15 --jump TPROXY --on-port 12345 --tproxy-mark 1

iptables --table nat --append OUTPUT --protocol tcp --destination 198.18.0.0/15 --jump REDIRECT --to-ports 12345

iptables -t mangle -N REDSOCKS
iptables -t mangle -A REDSOCKS -d 127.0.0.1/32 -j RETURN
iptables -t mangle -A REDSOCKS -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A REDSOCKS -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A REDSOCKS -d 192.168.0.0/16 -p tcp -j RETURN                                 # 直连局域网，避免 V2Ray 无法启动时无法连网关的 SSH，如果你配置的是其他网段（如 10.x.x.x 等），则修改成自己的
iptables -t mangle -A REDSOCKS -d 192.168.0.0/16 -p udp -j RETURN                                 # 直连局域网，53 端口除外（因为要使用 V2Ray 的 DNS)
iptables -t mangle -A REDSOCKS -j RETURN -m mark --mark 0xff                                      # 直连 SO_MARK 为 0xff 的流量(0xff 是 16 进制数，数值上等同与上面V2Ray 配置的 255)，此规则目的是解决v2ray占用大量CPU（https://github.com/v2ray/v2ray-core/issues/2621）
iptables -t mangle -A REDSOCKS -p udp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 1 # 给 UDP 打标记 1，转发至 12345 端口
iptables -t mangle -A REDSOCKS -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 12345 --tproxy-mark 1 # 给 TCP 打标记 1，转发至 12345 端口
iptables -t mangle -A PREROUTING -j REDSOCKS                                                      # 应用规则

nft add table plug2proxy

nft add chain plug2proxy prerouting { type filter hook prerouting priority 0 \; }
nft add rule plug2proxy prerouting ip daddr {127.0.0.1/32, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32} return
nft add rule plug2proxy prerouting mark 0xff return # 直连 0xff 流量

nft add rule plug2proxy prerouting ip daddr 198.18.0.0/15 meta l4proto tcp tproxy to 127.0.0.1:12345 mark set 1 accept

nft add table plug2proxy
nft add chain plug2proxy output { type route hook output priority 0 \; }
nft add rule plug2proxy output ip daddr {127.0.0.1/32, 192.168.0.0/16, 224.0.0.0/4, 255.255.255.255/32} return
nft add rule plug2proxy output mark 0xff return                   # 直连 0xff 流量
nft add rule plug2proxy output meta l4proto tcp mark set 1 accept # 重路由至 prerouting

nft add chain plug2proxy divert { type filter hook prerouting priority -150 \; }
nft add rule plug2proxy divert meta l4proto tcp socket transparent 1 meta mark set 1 accept
