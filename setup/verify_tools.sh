#!/bin/bash
# Run after install to confirm every tool is accessible and produces expected output.

PASS=0
FAIL=0

check() {
  local name="$1"
  local cmd="$2"
  if eval "$cmd" &>/dev/null; then
    echo "  [PASS] $name"
    PASS=$((PASS+1))
  else
    echo "  [FAIL] $name — command: $cmd"
    FAIL=$((FAIL+1))
  fi
}

echo "=== Tool Verification ==="

echo ""
echo "-- Core tools --"
check "tshark"     "tshark --version"
check "zeek"       "zeek --version"
check "suricata"   "suricata --version"
check "docker"     "docker info"
check "python3"    "python3 --version"

echo ""
echo "-- Python packages --"
check "pyshark"  "python3 -c 'import pyshark'"
check "scapy"    "python3 -c 'import scapy'"
check "pandas"   "python3 -c 'import pandas'"
check "numpy"    "python3 -c 'import numpy'"
check "scipy"    "python3 -c 'import scipy'"
check "pyyaml"   "python3 -c 'import yaml'"
check "requests" "python3 -c 'import requests'"
check "aiohttp"  "python3 -c 'import aiohttp'"
check "rich"     "python3 -c 'import rich'"
check "dotenv"   "python3 -c 'from dotenv import load_dotenv'"

echo ""
echo "-- API keys (.env) --"
if [ -f ../.env ]; then
  source ../.env 2>/dev/null
elif [ -f .env ]; then
  source .env 2>/dev/null
fi
[ -n "$VirusTotal_API_KEY" ] && echo "  [PASS] VirusTotal_API_KEY set" || echo "  [WARN] VirusTotal_API_KEY not set"
[ -n "$AbuseCh_API_KEY" ]    && echo "  [PASS] AbuseCh_API_KEY set"    || echo "  [WARN] AbuseCh_API_KEY not set"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ] && echo "All checks passed. Ready to proceed." || echo "Fix failures before continuing."
