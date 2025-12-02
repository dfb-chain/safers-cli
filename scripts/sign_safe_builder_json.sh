#!/bin/bash

# Script to sign a transaction JSON from Safe Transaction Builder
# Usage: ./sign_safe_builder_json.sh <safe_address> <chain> <json_file> <private_key>

set -e

SAFE_ADDRESS="${1}"
CHAIN="${2:-polygon}"
JSON_FILE="${3}"
PRIVATE_KEY="${4}"

if [ -z "$SAFE_ADDRESS" ] || [ -z "$JSON_FILE" ] || [ -z "$PRIVATE_KEY" ]; then
    echo "Usage: $0 <safe_address> <chain> <json_file> <private_key>"
    echo "Example: $0 0x3839a2e86a0F19FffC0d171fEe281b594108A783 polygon rejection.json <key>"
    exit 1
fi

# Default RPC URLs
case "$CHAIN" in
    polygon|matic)
        RPC_URL="https://polygon-rpc.com"
        ;;
    mainnet|ethereum)
        RPC_URL="https://eth.llamarpc.com"
        ;;
    sepolia)
        RPC_URL="https://sepolia.drpc.org"
        ;;
    base)
        RPC_URL="https://mainnet.base.org"
        ;;
    *)
        echo "Unsupported chain: $CHAIN"
        exit 1
        ;;
esac

echo "🔐 Signing transaction from Safe Builder JSON..."
echo "   Safe: $SAFE_ADDRESS"
echo "   Chain: $CHAIN"
echo "   JSON: $JSON_FILE"
echo ""

# Use safers-cli to sign and submit
safers-cli tx-propose \
    "$SAFE_ADDRESS" \
    "$CHAIN" \
    "$RPC_URL" \
    "$JSON_FILE" \
    "$PRIVATE_KEY"

echo ""
echo "✅ Done! Check the Safe UI for the proposed transaction."

