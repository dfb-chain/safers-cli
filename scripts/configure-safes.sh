#!/bin/bash

# Script to configure Safe wallets with guards and modules
# Usage: ./configure-safes.sh <safe_address> <chain> <node_url> <private_key>
#
# Example:
#   ./configure-safes.sh 0x81d76CFF9D0A4faA3A2150ea7F73Bc3BaC13442b base https://base.llamarpc.com YOUR_PRIVATE_KEY

set -e

if [ $# -lt 4 ]; then
    echo "Usage: $0 <safe_address> <chain> <node_url> <private_key>"
    echo ""
    echo "Example:"
    echo "  $0 0x81d76CFF9D0A4faA3A2150ea7F73Bc3BaC13442b base https://base.llamarpc.com YOUR_PRIVATE_KEY"
    echo ""
    echo "Supported chains: base, polygon, avalanche"
    exit 1
fi

SAFE_ADDRESS="$1"
CHAIN="$2"
NODE_URL="$3"
PRIVATE_KEY="$4"

# Guard addresses per chain
case "$CHAIN" in
    base)
        GUARD_ADDRESS="0x9ECfaA12c2b8C82834B761cDCc42A4671f7Fc11e"
        MODULE_ADDRESS="0x349B8dE9c7853E34b377bDEA7C93754285B3d2f4"
        ;;
    polygon)
        GUARD_ADDRESS="0x60009D1F124214Ff4FA156888458451044Ef2c44"
        MODULE_ADDRESS="0xd2708e692F7f4b5686ceE73767D556FfE516C2b7"
        ;;
    avalanche)
        GUARD_ADDRESS="0xE90d4a6e3541bd5eEfDc0931BFE6F3EA1fA811Ea"
        MODULE_ADDRESS="0x549C3e0DA3Ab65F6ce45055077262C17B3Bd6EF3"
        ;;
    *)
        echo "❌ Unsupported chain: $CHAIN"
        echo "Supported chains: base, polygon, avalanche"
        exit 1
        ;;
esac

# Check if safers-cli is in PATH or use relative path
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v safers-cli &> /dev/null; then
    CLI_CMD="safers-cli"
else
    CLI_CMD="$SCRIPT_DIR/../target/release/safers-cli"
    if [ ! -f "$CLI_CMD" ]; then
        CLI_CMD="$SCRIPT_DIR/../target/debug/safers-cli"
    fi
fi

if [ ! -f "$CLI_CMD" ] && ! command -v safers-cli &> /dev/null; then
    echo "❌ Error: safers-cli not found. Please build it first with: cargo build --release"
    exit 1
fi

# Get Safe Transaction Service URL
case "$CHAIN" in
    base)
        SERVICE_URL="https://safe-transaction-base.safe.global"
        ;;
    polygon)
        SERVICE_URL="https://safe-transaction-polygon.safe.global"
        ;;
    avalanche)
        SERVICE_URL="https://safe-transaction-avalanche.safe.global"
        ;;
    *)
        echo "❌ Unsupported chain: $CHAIN"
        exit 1
        ;;
esac

echo "🔧 Configuring Safe: $SAFE_ADDRESS on $CHAIN"
echo "   Guard: $GUARD_ADDRESS"
echo "   Module: $MODULE_ADDRESS"
echo ""

# Fetch current Safe nonce once
echo "📋 Fetching current Safe nonce..."
SAFE_INFO=$(curl -s "${SERVICE_URL}/api/v1/safes/${SAFE_ADDRESS}/")
if [ $? -ne 0 ] || [ -z "$SAFE_INFO" ]; then
    echo "❌ Failed to get Safe info from API"
    exit 1
fi

# Extract nonce from JSON (works with or without jq)
if command -v jq &> /dev/null; then
    NONCE=$(echo "$SAFE_INFO" | jq -r '.nonce // empty')
else
    # Fallback: extract nonce using grep/sed (less robust but works for simple JSON)
    NONCE=$(echo "$SAFE_INFO" | grep -o '"nonce"[[:space:]]*:[[:space:]]*"[0-9]*"' | grep -o '[0-9]*' | head -1)
fi

if [ -z "$NONCE" ] || ! [[ "$NONCE" =~ ^[0-9]+$ ]]; then
    echo "❌ Failed to parse nonce from Safe API response"
    echo "   Response: $SAFE_INFO"
    exit 1
fi
echo "   Current nonce: $NONCE"
echo "   Will propose transactions with nonces: $NONCE, $((NONCE + 1)), $((NONCE + 2))"
echo ""

# 1. Set Transaction Guard (nonce)
echo "[1/3] Proposing setGuard transaction (nonce: $NONCE)..."
"$CLI_CMD" safe-configure \
    "$SAFE_ADDRESS" \
    "$CHAIN" \
    "$NODE_URL" \
    "setGuard" \
    "$GUARD_ADDRESS" \
    "$PRIVATE_KEY" \
    --nonce "$NONCE" || {
    echo "❌ Failed to propose setGuard transaction"
    exit 1
}
echo "✓ setGuard transaction proposed (nonce: $NONCE)"
echo ""

# Small delay to avoid rate limiting
sleep 1

# 2. Set Module Guard (nonce + 1)
NONCE_PLUS_1=$((NONCE + 1))
echo "[2/3] Proposing setModuleGuard transaction (nonce: $NONCE_PLUS_1)..."
"$CLI_CMD" safe-configure \
    "$SAFE_ADDRESS" \
    "$CHAIN" \
    "$NODE_URL" \
    "setModuleGuard" \
    "$GUARD_ADDRESS" \
    "$PRIVATE_KEY" \
    --nonce "$NONCE_PLUS_1" || {
    echo "❌ Failed to propose setModuleGuard transaction"
    exit 1
}
echo "✓ setModuleGuard transaction proposed (nonce: $NONCE_PLUS_1)"
echo ""

# Small delay to avoid rate limiting
sleep 1

# 3. Enable BotExecutionModule (nonce + 2)
NONCE_PLUS_2=$((NONCE + 2))
echo "[3/3] Proposing enableModule transaction (nonce: $NONCE_PLUS_2)..."
"$CLI_CMD" safe-configure \
    "$SAFE_ADDRESS" \
    "$CHAIN" \
    "$NODE_URL" \
    "enableModule" \
    "$MODULE_ADDRESS" \
    "$PRIVATE_KEY" \
    --nonce "$NONCE_PLUS_2" || {
    echo "❌ Failed to propose enableModule transaction"
    exit 1
}
echo "✓ enableModule transaction proposed (nonce: $NONCE_PLUS_2)"
echo ""

echo "✅ All 3 configuration transactions have been proposed successfully!"
echo ""
echo "📋 Summary:"
echo "   - setGuard: $GUARD_ADDRESS"
echo "   - setModuleGuard: $GUARD_ADDRESS"
echo "   - enableModule: $MODULE_ADDRESS"
echo ""
echo "Next steps:"
echo "   1. Review the proposals in Safe UI: https://app.safe.global/"
echo "   2. Have all owners sign the transactions (3-of-4 required)"
echo "   3. Execute the transactions once all signatures are collected"
