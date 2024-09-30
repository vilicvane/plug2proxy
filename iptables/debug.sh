# Add a rule to lookup routing table 100 for packets marked with fwmark 1
ip rule add fwmark 1 lookup 100
# Add a route to route all traffic to the local loopback interface in table 100
ip route add local 0.0.0.0/0 dev lo table 100

iptables --table mangle --new-chain DIVERT
iptables --table mangle --append DIVERT --jump MARK --set-mark 1
iptables --table mangle --append DIVERT --jump ACCEPT
iptables --table mangle --append PREROUTING --protocol tcp --match socket --jump DIVERT

iptables --table mangle --append OUTPUT --protocol tcp --destination 192.168.99.99 --jump MARK --set-mark 1
iptables --table mangle --append PREROUTING  --protocol tcp --destination 192.168.99.99 --jump TPROXY --on-port 12233 --tproxy-mark 1

iptables --table nat --append OUTPUT --protocol tcp --destination 192.168.99.99 --jump REDIRECT --to-ports 12233
