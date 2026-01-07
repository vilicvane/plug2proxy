#!/bin/bash
# Test the proxy with IP-based routing (for fake-ip DNS environments)

echo "Testing SOCKS5 proxy with IP-based routing..."
echo ""
echo "Make sure run-test.sh is running in another terminal!"
echo ""
echo "Note: Your network uses fake-ip DNS (198.18.x.x range)"
echo "      Routing is configured to match these IPs"
echo ""

echo "=================================================="
echo "Test 1: google.com (resolves to 198.18.0.1)"
echo "=================================================="
echo "Command: curl --socks5 127.0.0.1:1080 http://google.com"
echo ""
curl -v --socks5 127.0.0.1:1080 --max-time 10 http://google.com 2>&1 | head -30
echo ""

echo "=================================================="
echo "Test 2: Any site in 198.18.x.x range (e.g., 198.18.5.78)"
echo "=================================================="
echo "Command: curl --socks5 127.0.0.1:1080 http://198.18.5.78"
echo ""
curl -v --socks5 127.0.0.1:1080 --max-time 10 http://198.18.5.78 2>&1 | head -30
echo ""

echo "=================================================="
echo "Test 3: Real IP (should route to HUB DIRECT)"
echo "=================================================="
echo "Command: curl --socks5 127.0.0.1:1080 http://1.1.1.1"
echo ""
curl -v --socks5 127.0.0.1:1080 --max-time 10 http://1.1.1.1 2>&1 | head -30
echo ""

echo "=================================================="
echo "Check the logs from run-test.sh to see:"
echo "  🔵 SOCKS5: New connection request to 198.18.0.1:80 (IP)"
echo "  🔀 ROUTING: 198.18.0.1:80 → OUT [out-us] (tag: 'us')"
echo "  ✅ OUT EXIT: Connected from OUT node"
echo "=================================================="
echo ""
echo "IP-BASED ROUTING:"
echo "  198.18.x.x → OUT-US (fake-ip range)"
echo "  198.19.x.x → OUT-CN (fake-ip range)"
echo "  Other IPs  → HUB DIRECT"
echo ""
