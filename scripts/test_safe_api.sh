#!/bin/bash

# Test Safe API - shows both methods

SAFE="0x3839a2e86a0F19FffC0d171fEe281b594108A783"

echo "Method 1: Using -L flag (follows redirects)"
echo "-------------------------------------------"
curl -sL "https://safe-transaction-polygon.safe.global/api/v1/safes/${SAFE}/" | jq '{nonce, threshold, owners}'

echo ""
echo "Method 2: Using new API URL directly"
echo "-------------------------------------------"
curl -s "https://api.safe.global/tx-service/pol/api/v1/safes/${SAFE}/" | jq '{nonce, threshold, owners}'
