#!/bin/bash

# Script to replace GUARD_ADDRESS placeholder in all whitelist transaction files
# Usage: ./scripts/replace-guard-address.sh <GUARD_ADDRESS>

set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <GUARD_ADDRESS>"
    echo ""
    echo "Example:"
    echo "  $0 0x1234567890123456789012345678901234567890"
    exit 1
fi

GUARD_ADDRESS=$1

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLES_DIR="$(cd "$SCRIPT_DIR/../examples" && pwd)"

# List of transaction files
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

echo "🔧 Replacing GUARD_ADDRESS with: $GUARD_ADDRESS"
echo ""

# Replace GUARD_ADDRESS in all files
for file in "${TX_FILES[@]}"; do
    file_path="$EXAMPLES_DIR/$file"
    if [ ! -f "$file_path" ]; then
        echo "⚠️  Warning: File not found: $file_path"
        continue
    fi
    
    # Replace GUARD_ADDRESS with actual address
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        sed -i '' "s/GUARD_ADDRESS/$GUARD_ADDRESS/g" "$file_path"
    else
        # Linux
        sed -i "s/GUARD_ADDRESS/$GUARD_ADDRESS/g" "$file_path"
    fi
    
    echo "✓ Updated: $file"
done

echo ""
echo "✅ All files have been updated!"
echo ""
echo "You can now propose transactions individually using:"
echo "  safers-cli tx-propose <SAFE_ADDRESS> <CHAIN> <NODE_URL> examples/<file>.json <PRIVATE_KEY>"
