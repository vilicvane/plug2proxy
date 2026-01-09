#!/bin/bash
#
# plug2proxy TPROXY routing setup
#
# This script sets up the policy routing required for TPROXY to work.
# Run this script once after boot, or add it to your network configuration.
#
# Usage: ./setup-routing.sh [--remove]
#

set -e

TABLE=100
MARK=1

remove_routes() {
    echo "Removing plug2proxy routing rules..."

    # IPv4
    ip rule del fwmark $MARK table $TABLE 2>/dev/null || true
    ip route del local default dev lo table $TABLE 2>/dev/null || true

    # IPv6
    ip -6 rule del fwmark $MARK table $TABLE 2>/dev/null || true
    ip -6 route del local default dev lo table $TABLE 2>/dev/null || true

    echo "Done."
}

add_routes() {
    echo "Setting up plug2proxy routing rules..."

    # IPv4 policy routing
    if [ -z "$(ip route list table $TABLE 2>/dev/null)" ]; then
        ip route add local default dev lo table $TABLE
        echo "  Added IPv4 route: local default dev lo table $TABLE"
    else
        echo "  IPv4 route already exists"
    fi

    if [ -z "$(ip rule list table $TABLE 2>/dev/null | grep fwmark)" ]; then
        ip rule add fwmark $MARK table $TABLE
        echo "  Added IPv4 rule: fwmark $MARK table $TABLE"
    else
        echo "  IPv4 rule already exists"
    fi

    # IPv6 policy routing
    if [ -z "$(ip -6 route list table $TABLE 2>/dev/null)" ]; then
        ip -6 route add local default dev lo table $TABLE
        echo "  Added IPv6 route: local default dev lo table $TABLE"
    else
        echo "  IPv6 route already exists"
    fi

    if [ -z "$(ip -6 rule list table $TABLE 2>/dev/null | grep fwmark)" ]; then
        ip -6 rule add fwmark $MARK table $TABLE
        echo "  Added IPv6 rule: fwmark $MARK table $TABLE"
    else
        echo "  IPv6 rule already exists"
    fi

    echo "Done."
    echo ""
    echo "To apply nftables rules, run:"
    echo "  nft -f /path/to/nftables.conf"
}

case "${1:-}" in
    --remove|-r)
        remove_routes
        ;;
    *)
        add_routes
        ;;
esac
