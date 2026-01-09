#!/bin/bash
#
# Install plug2proxy to a remote server
#
# Usage:
#   ./install-to-server.sh -m <mode> -d <destination> [-t <target>] [-r <resources>]
#
# Arguments:
#   -m <mode>        Node mode: hub, in, or out
#   -d <destination> SSH destination (user@host)
#   -t <target>      Cross-compilation target (optional, uses cross if specified)
#   -r <resources>   Comma-separated list of resource directories to install
#                    Default: common,ubuntu
#
# Examples:
#   # Install HUB node
#   ./install-to-server.sh -m hub -d root@hub.example.com
#
#   # Install IN node with cross-compilation
#   ./install-to-server.sh -m in -d root@router.local -t aarch64-unknown-linux-gnu
#
#   # Install OUT node
#   ./install-to-server.sh -m out -d root@exit.example.com
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default values
command="cargo"
target=""
resources="common,ubuntu"
mode=""
destination=""

usage() {
    echo "Usage: $0 -m <mode> -d <destination> [-t <target>] [-r <resources>]"
    echo ""
    echo "Arguments:"
    echo "  -m <mode>        Node mode: hub, in, or out"
    echo "  -d <destination> SSH destination (user@host)"
    echo "  -t <target>      Cross-compilation target (optional)"
    echo "  -r <resources>   Resource directories (default: common,ubuntu)"
    exit 1
}

while getopts "m:d:t:r:h" flag; do
    case $flag in
        m) mode=$OPTARG ;;
        d) destination=$OPTARG ;;
        t)
            target=$OPTARG
            command="cross"
            ;;
        r) resources=$OPTARG ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required arguments
if [ -z "$mode" ]; then
    echo "Error: Mode (-m) is required"
    usage
fi

if [ -z "$destination" ]; then
    echo "Error: Destination (-d) is required"
    usage
fi

if [[ ! "$mode" =~ ^(hub|in|out)$ ]]; then
    echo "Error: Mode must be one of: hub, in, out"
    exit 1
fi

echo "========================================"
echo "plug2proxy Installation"
echo "========================================"
echo "Mode:        $mode"
echo "Destination: $destination"
echo "Target:      ${target:-native}"
echo "Resources:   $resources"
echo "========================================"
echo ""

# Build
echo "Building plug2proxy..."
cd "$PROJECT_DIR"

if [ -n "$target" ]; then
    $command build --target "$target" --release
    target_path="target/$target/release"
else
    $command build --release
    target_path="target/release"
fi

echo ""

# Install binary
echo "Installing binary..."
rsync --mkpath --times --verbose "$target_path/plug2proxy" "$destination:/usr/sbin/"

# Install resources
echo ""
echo "Installing resources..."

IFS=',' read -ra resource_list <<< "$resources"

for resource in "${resource_list[@]}"; do
    resource_path="$PROJECT_DIR/res/$mode/$resource"
    if [ -d "$resource_path" ]; then
        echo "  Installing $mode/$resource..."
        rsync --recursive --relative --mkpath --times --verbose \
            "$resource_path/./" "$destination:/"
    else
        echo "  Warning: Resource directory not found: $resource_path"
    fi
done

echo ""
echo "========================================"
echo "Installation complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo ""

if [ "$mode" = "hub" ]; then
    echo "1. Edit /etc/plug2proxy/config.yaml"
    echo "2. Run: systemctl daemon-reload"
    echo "3. Run: systemctl enable --now plug2proxy"
    echo ""
    echo "Generate node certificates with:"
    echo "  cd /etc/plug2proxy && plug2proxy --node-cert <node-name>"
elif [ "$mode" = "in" ]; then
    echo "1. Copy ca.pem and node.pem from HUB to /etc/plug2proxy/"
    echo "2. Edit /etc/plug2proxy/config.yaml"
    echo "3. Run: systemctl daemon-reload"
    echo "4. Run: systemctl enable --now plug2proxy"
    echo ""
    echo "For TPROXY support:"
    echo "  - The routing rules are set up automatically via networkd-dispatcher"
    echo "  - Or manually run: /etc/networkd-dispatcher/routable.d/plug2proxy"
elif [ "$mode" = "out" ]; then
    echo "1. Copy ca.pem and node.pem from HUB to /etc/plug2proxy/"
    echo "2. Edit /etc/plug2proxy/config.yaml"
    echo "3. Run: systemctl daemon-reload"
    echo "4. Run: systemctl enable --now plug2proxy"
fi
