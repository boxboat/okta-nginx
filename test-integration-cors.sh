#!/bin/bash

TOKEN="$1"

if [ -z "$TOKEN" ]; then
  echo "Usage: $0 <bearer-token>"
  exit 1
fi

echo ""
echo "========================================="
echo "TEST 1: OPTIONS preflight"
echo "========================================="
curl -i -X OPTIONS \
  -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  https://search-operators-integration.reelmetrics.com/cabinets/_msearch

echo ""
echo "========================================="
echo "TEST 2: POST with Bearer + Origin (CRITICAL)"
echo "========================================="
curl -i -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Origin: http://localhost:3000" \
  -H "Content-Type: application/x-ndjson" \
  -d '{"query":{"match_all":{}}}' \
  https://search-operators-integration.reelmetrics.com/cabinets/_msearch

echo ""
echo "========================================="
echo "TEST 3: POST without Origin (baseline)"
echo "========================================="
curl -i -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  -d '{"query":{"match_all":{}}}' \
  https://search-operators-integration.reelmetrics.com/cabinets/_msearch | head -20
