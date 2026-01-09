#!/bin/bash
#
# TPROXY setup script for Multipass VM
#
# Usage:
#   sudo ./tproxy_vm_setup.sh setup    # Configure TPROXY
#   sudo ./tproxy_vm_setup.sh teardown # Remove configuration
#   sudo ./tproxy_vm_setup.sh status   # Show current config
#

set -e

TPROXY_PORT="12345"
PROXY_MARK="0x01"      # Mark for packets that need TPROXY routing
PROXIED_MARK="0xff"    # Mark for packets FROM the proxy (to avoid loops)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (sudo)"
        exit 1
    fi
}

setup_routing() {
    log_info "Setting up policy routing..."

    # Create routing table entry if not exists
    if ! grep -q "^100[[:space:]]tproxy$" /etc/iproute2/rt_tables 2>/dev/null; then
        echo "100 tproxy" >> /etc/iproute2/rt_tables
    fi

    # IPv4 policy routing
    ip route add local default dev lo table tproxy 2>/dev/null || true
    ip rule add fwmark $PROXY_MARK table tproxy 2>/dev/null || true

    # IPv6 policy routing
    ip -6 route add local default dev lo table tproxy 2>/dev/null || true
    ip -6 rule add fwmark $PROXY_MARK table tproxy 2>/dev/null || true

    log_info "Policy routing configured"
}

setup_nftables() {
    log_info "Setting up nftables rules..."

    # Install nftables if not present
    if ! command -v nft &> /dev/null; then
        apt-get update && apt-get install -y nftables
    fi

    nft -f - << EOF
# Ensure tables exist
table ip tproxy_test {}
table ip6 tproxy_test {}

# Flush existing rules
flush table ip tproxy_test
flush table ip6 tproxy_test

# IPv4 rules
table ip tproxy_test {
    chain output {
        type route hook output priority mangle; policy accept;

        # Don't intercept traffic from the proxy itself
        meta mark $PROXIED_MARK accept

        # Don't intercept local traffic
        ip daddr 127.0.0.0/8 accept
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # Mark TCP for TPROXY routing
        meta l4proto tcp meta mark set $PROXY_MARK accept
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        # Don't intercept traffic from the proxy itself
        meta mark $PROXIED_MARK accept

        # Don't intercept local traffic
        ip daddr 127.0.0.0/8 accept
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # TPROXY TCP
        meta l4proto tcp tproxy to 127.0.0.1:$TPROXY_PORT meta mark set $PROXY_MARK accept
    }

    chain divert {
        type filter hook prerouting priority mangle - 1; policy accept;
        meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK accept
    }
}

# IPv6 rules
table ip6 tproxy_test {
    chain output {
        type route hook output priority mangle; policy accept;

        meta mark $PROXIED_MARK accept
        ip6 daddr ::1/128 accept
        ip6 daddr fe80::/10 accept
        ip6 daddr fc00::/7 accept

        meta l4proto tcp meta mark set $PROXY_MARK accept
    }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;

        meta mark $PROXIED_MARK accept
        ip6 daddr ::1/128 accept
        ip6 daddr fe80::/10 accept
        ip6 daddr fc00::/7 accept

        meta l4proto tcp tproxy to [::1]:$TPROXY_PORT meta mark set $PROXY_MARK accept
    }

    chain divert {
        type filter hook prerouting priority mangle - 1; policy accept;
        meta l4proto tcp socket transparent 1 meta mark set $PROXY_MARK accept
    }
}
EOF

    log_info "nftables rules configured"
}

teardown_routing() {
    log_info "Removing policy routing..."

    ip rule del fwmark $PROXY_MARK table tproxy 2>/dev/null || true
    ip route del local default dev lo table tproxy 2>/dev/null || true

    ip -6 rule del fwmark $PROXY_MARK table tproxy 2>/dev/null || true
    ip -6 route del local default dev lo table tproxy 2>/dev/null || true

    log_info "Policy routing removed"
}

teardown_nftables() {
    log_info "Removing nftables rules..."

    nft delete table ip tproxy_test 2>/dev/null || true
    nft delete table ip6 tproxy_test 2>/dev/null || true

    log_info "nftables rules removed"
}

show_status() {
    echo ""
    echo "=== Policy Routing ==="
    echo "IPv4 rules:"
    ip rule list | grep -E "fwmark|tproxy" || echo "  (none)"
    echo ""
    echo "IPv4 table 'tproxy':"
    ip route list table tproxy 2>/dev/null || echo "  (empty or not exists)"
    echo ""
    echo "IPv6 rules:"
    ip -6 rule list | grep -E "fwmark|tproxy" || echo "  (none)"
    echo ""

    echo "=== nftables ==="
    if nft list table ip tproxy_test &>/dev/null; then
        nft list table ip tproxy_test
    else
        echo "  Table 'ip tproxy_test' not found"
    fi
    echo ""

    echo "=== Listening on TPROXY port ==="
    ss -tlnp | grep ":$TPROXY_PORT " || echo "  Nothing listening on port $TPROXY_PORT"
    echo ""
}

case "${1:-}" in
    setup)
        check_root
        setup_routing
        setup_nftables
        log_info "TPROXY setup complete!"
        echo ""
        echo "Now run the TPROXY test binary:"
        echo "  sudo ./tproxy_test"
        echo ""
        echo "In another terminal, test with:"
        echo "  curl -v http://example.com/"
        echo ""
        ;;
    teardown)
        check_root
        teardown_nftables
        teardown_routing
        log_info "TPROXY teardown complete!"
        ;;
    status)
        show_status
        ;;
    *)
        echo "Usage: $0 {setup|teardown|status}"
        exit 1
        ;;
esac
