#!/bin/bash
# Quick test script to run all nodes for testing

set -e

echo "=== Building release binary ==="
cargo build --release

echo ""
echo "=== Starting HUB node ==="
echo "Config: configs/hub.yaml"
./target/release/plug2proxy --config configs/hub.yaml &
HUB_PID=$!
echo "HUB PID: $HUB_PID"

sleep 2

echo ""
echo "=== Starting OUT nodes ==="
echo "Config: configs/out-us.yaml"
./target/release/plug2proxy --config configs/out-us.yaml &
OUT_US_PID=$!
echo "OUT-US PID: $OUT_US_PID"

sleep 1

echo "Config: configs/out-cn.yaml"
./target/release/plug2proxy --config configs/out-cn.yaml &
OUT_CN_PID=$!
echo "OUT-CN PID: $OUT_CN_PID"

sleep 1

echo "Config: configs/out-jp.yaml"
./target/release/plug2proxy --config configs/out-jp.yaml &
OUT_JP_PID=$!
echo "OUT-JP PID: $OUT_JP_PID"

sleep 2

echo ""
echo "=== Starting IN node with SOCKS5 server ==="
echo "Config: configs/in-socks5.yaml"
./target/release/plug2proxy --config configs/in-socks5.yaml &
IN_PID=$!
echo "IN PID: $IN_PID"

sleep 2

echo ""
echo "=========================================="
echo "✅ All nodes started successfully!"
echo "=========================================="
echo ""
echo "HUB:    127.0.0.1:8765"
echo "SOCKS5: 127.0.0.1:1080"
echo ""
echo "Process IDs:"
echo "  HUB:    $HUB_PID"
echo "  OUT-US: $OUT_US_PID"
echo "  OUT-CN: $OUT_CN_PID"
echo "  OUT-JP: $OUT_JP_PID"
echo "  IN:     $IN_PID"
echo ""
echo "To test with curl:"
echo "  curl --socks5 127.0.0.1:1080 http://example.com"
echo ""
echo "To stop all nodes:"
echo "  kill $HUB_PID $OUT_US_PID $OUT_CN_PID $OUT_JP_PID $IN_PID"
echo ""
echo "Or press Ctrl+C and run:"
echo "  pkill -f plug2proxy"
echo ""

# Wait for user interrupt
trap "echo ''; echo 'Stopping all nodes...'; kill $HUB_PID $OUT_US_PID $OUT_CN_PID $OUT_JP_PID $IN_PID 2>/dev/null; exit 0" INT TERM

echo "Press Ctrl+C to stop all nodes..."
wait
