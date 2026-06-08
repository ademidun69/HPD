#!/bin/bash
# test-cli.sh — Quick demo of the HPD CLI in action
echo "================================================"
echo "  Honeypot Detector (HPD) — CLI Quick Demo"
echo "================================================"
echo ""
echo "1) Check version:"
hpd version
echo ""
echo "2) Show help (first 10 lines):"
hpd help 2>&1 | head -10
echo ""
echo "3) Try analyzing a known-bad address (no RPC, expect clean error):"
hpd quick 0x000000000000000000000000000000000000dEaD --no-sim --no-color 2>&1 | head -3
echo ""
echo "4) Try with invalid address (should validate):"
hpd analyze notanaddress 2>&1
echo ""
echo "5) Bare-address shorthand: 'hpd 0xABC...XYZ' is treated as analyze:"
hpd 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 2>&1 | head -3
echo ""
echo "================================================"
echo "  To use a real RPC, set PHAROS_MAINNET_RPC env var"
echo "  or run: hpd init"
echo "================================================"
