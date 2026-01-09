#!/bin/bash
#
# TPROXY isolated test using network namespaces.
#
# This script creates a COMPLETELY isolated network environment.
# It does NOT modify ANY host network configuration:
#   - No host iptables/nftables rules
#   - No host routing changes
#   - No host sysctl changes
#   - No host interfaces
#
# Everything runs inside an isolated network namespace using only loopback.
#
# Usage:
#   sudo ./res/in/tproxy_test.sh
#

set -e

NAMESPACE="tproxy_test_$$"  # Use PID to avoid conflicts
TPROXY_PORT="12345"
MARK="0xff"
BINARY="./target/debug/tproxy_test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up namespace: $NAMESPACE"

    # Kill any processes in the namespace
    ip netns pids "$NAMESPACE" 2>/dev/null | xargs -r kill 2>/dev/null || true

    # Delete the namespace
    ip netns del "$NAMESPACE" 2>/dev/null || true

    log_info "Cleanup complete - host network unchanged"
}

# Always cleanup on exit
trap cleanup EXIT

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (sudo)"
    exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    log_error "Binary not found: $BINARY"
    log_info "Build with: cargo build --bin tproxy_test"
    exit 1
fi

log_info "Creating isolated network namespace: $NAMESPACE"
log_info "NOTE: This does NOT modify your host network in any way!"

# Clean up any existing namespace with same name (shouldn't exist due to PID)
ip netns del "$NAMESPACE" 2>/dev/null || true

# Create namespace
ip netns add "$NAMESPACE"

# Enable loopback inside namespace
ip netns exec "$NAMESPACE" ip link set lo up

# Add a dummy interface with a routable IP (for testing destination resolution)
ip netns exec "$NAMESPACE" ip link add dummy0 type dummy
ip netns exec "$NAMESPACE" ip link set dummy0 up
ip netns exec "$NAMESPACE" ip addr add 192.0.2.1/24 dev dummy0  # TEST-NET-1

log_info "Setting up TPROXY rules inside namespace (host unaffected)..."

# Set up policy routing INSIDE the namespace only
ip netns exec "$NAMESPACE" ip route add local default dev lo table 100
ip netns exec "$NAMESPACE" ip rule add fwmark 1 table 100

# Set up nftables INSIDE the namespace only
ip netns exec "$NAMESPACE" nft -f - << 'EOF'
table ip tproxy_test {}
flush table ip tproxy_test

table ip tproxy_test {
    chain output {
        type route hook output priority filter; policy accept;

        # Skip traffic from the proxy itself (marked 0xff)
        meta mark 0xff accept

        # Skip loopback destination (we need local connections to work)
        ip daddr 127.0.0.0/8 accept

        # Mark other TCP for TPROXY routing
        meta l4proto tcp meta mark set 0x01 accept
    }

    chain prerouting {
        type filter hook prerouting priority filter; policy accept;

        # Skip traffic from the proxy itself
        meta mark 0xff accept

        # Skip loopback
        ip daddr 127.0.0.0/8 accept

        # TPROXY TCP to our test listener
        meta l4proto tcp tproxy to 127.0.0.1:12345 meta mark set 0x01 accept
    }

    chain divert {
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto tcp socket transparent 1 meta mark set 0x01 accept
    }
}
EOF

log_info "Namespace setup complete!"
echo ""
echo "==========================================="
echo "  TPROXY Test Environment Ready"
echo "==========================================="
echo "  Namespace:     $NAMESPACE"
echo "  TPROXY port:   $TPROXY_PORT"
echo "  Mark:          $MARK"
echo ""
echo "  Host network:  UNCHANGED"
echo "==========================================="
echo ""

# Start the TPROXY test binary inside the namespace
log_info "Starting TPROXY test binary inside namespace..."

ip netns exec "$NAMESPACE" "$BINARY" "$@" &
BINARY_PID=$!

sleep 1

# Check if binary started
if ! kill -0 $BINARY_PID 2>/dev/null; then
    log_error "Failed to start test binary"
    exit 1
fi

echo ""
log_info "Test binary running (PID: $BINARY_PID)"
echo ""
echo "==========================================="
echo "  How to Test (in another terminal)"
echo "==========================================="
echo ""
echo "# Run a test connection inside the namespace:"
echo "sudo ip netns exec $NAMESPACE curl -v --connect-timeout 5 http://192.0.2.1:80/"
echo ""
echo "# Or start a shell inside the namespace:"
echo "sudo ip netns exec $NAMESPACE bash"
echo ""
echo "# Then from that shell, try connecting to any IP:"
echo "curl -v --connect-timeout 5 http://192.0.2.100:80/"
echo ""
echo "# The TPROXY listener should intercept and show the original destination."
echo "==========================================="
echo ""
log_info "Press Ctrl+C to stop and cleanup"
echo ""

# Wait for the binary
wait $BINARY_PID
