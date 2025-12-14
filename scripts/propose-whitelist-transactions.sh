#!/bin/bash

# Script to propose all whitelist transactions to Safe Guard
# Usage: ./scripts/propose-whitelist-transactions.sh <SAFE_ADDRESS> <GUARD_ADDRESS> <CHAIN> <NODE_URL> <PRIVATE_KEY>

set -e

if [ $# -ne 5 ]; then
    echo "Usage: $0 <SAFE_ADDRESS> <GUARD_ADDRESS> <CHAIN> <NODE_URL> <PRIVATE_KEY>"
    echo ""
    echo "Example:"
    echo "  $0 0x1234... 0x5678... base https://mainnet.base.org YOUR_PRIVATE_KEY"
    exit 1
fi

SAFE_ADDRESS=$1
GUARD_ADDRESS=$2
CHAIN=$3
NODE_URL=$4
PRIVATE_KEY=$5

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$(cd "$SCRIPT_DIR/../examples" && pwd)"

# List of transaction files in order
declare -a TX_FILES=(
    "whitelist-usdc.json"
    "whitelist-tgbp.json"
    "whitelist-aero.json"
    "whitelist-weth.json"
    "whitelist-aerodrome-router.json"
    "whitelist-aerodrome-router-v2.json"
    "whitelist-aerodrome-voter.json"
    "whitelist-aerodrome-factory.json"
    "whitelist-tgbp-usdc-pool.json"
    "authorize-tgbp-usdc-pool.json"
    "whitelist-tgbp-usdc-gauge.json"
    "whitelist-withdrawal-address.json"
)

# Create temporary directory for modified files
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "🔧 Replacing GUARD_ADDRESS placeholder with: $GUARD_ADDRESS"
echo ""

# Replace GUARD_ADDRESS in all files and copy to temp directory
for file in "${TX_FILES[@]}"; do
    src_file="$EXAMPLES_DIR/$file"
    if [ ! -f "$src_file" ]; then
        echo "❌ Error: File not found: $src_file"
        exit 1
    fi
    
    # Replace GUARD_ADDRESS with actual address
    sed "s/GUARD_ADDRESS/$GUARD_ADDRESS/g" "$src_file" > "$TEMP_DIR/$file"
    echo "✓ Prepared: $file"
done

echo ""
echo "📤 Proposing transactions to Safe: $SAFE_ADDRESS"
echo "   Chain: $CHAIN"
echo "   Guard: $GUARD_ADDRESS"
echo ""

# Propose each transaction
for i in "${!TX_FILES[@]}"; do
    file="${TX_FILES[$i]}"
    tx_num=$((i + 1))
    
    echo "[$tx_num/12] Proposing: $file"
    
    # Check if safers-cli is in PATH or use relative path
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
    
    "$CLI_CMD" tx-propose \
        "$SAFE_ADDRESS" \
        "$CHAIN" \
        "$NODE_URL" \
        "$TEMP_DIR/$file" \
        "$PRIVATE_KEY" || {
        echo "❌ Failed to propose transaction $tx_num"
        exit 1
    }
    
    echo "✓ Transaction $tx_num proposed successfully"
    echo ""
    
    # Small delay to avoid rate limiting
    sleep 1
done

echo "✅ All 12 transactions have been proposed successfully!"
echo ""
echo "📋 Summary:"
echo "   - 11 whitelist transactions (allowTarget)"
echo "   - 1 authorization transaction (setPoolAuthorization)"
echo ""
echo "Next steps:"
echo "   1. Review the proposals in Safe UI: https://app.safe.global/"
echo "   2. Have all owners sign the transactions"
echo "   3. Execute the transactions once all signatures are collected"
