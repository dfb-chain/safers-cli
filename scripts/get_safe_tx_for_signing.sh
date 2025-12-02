#!/bin/bash

# Script to get Safe transaction details for manual signing
# Usage: ./get_safe_tx_for_signing.sh <safe_address> <chain> [nonce]

set -e

SAFE_ADDRESS="${1}"
CHAIN="${2:-polygon}"
NONCE="${3}"

if [ -z "$SAFE_ADDRESS" ]; then
    echo "Usage: $0 <safe_address> <chain> [nonce]"
    echo "Example: $0 0x3839a2e86a0F19FffC0d171fEe281b594108A783 polygon"
    exit 1
fi

# Map chain to Safe Transaction Service URL
# Note: Using new unified API, old URLs redirect automatically
case "$CHAIN" in
    polygon|matic)
        SERVICE_URL="https://api.safe.global/tx-service/pol"
        CHAIN_ID=137
        ;;
    mainnet|ethereum)
        SERVICE_URL="https://api.safe.global/tx-service/eth"
        CHAIN_ID=1
        ;;
    sepolia)
        SERVICE_URL="https://api.safe.global/tx-service/sep"
        CHAIN_ID=11155111
        ;;
    base)
        SERVICE_URL="https://api.safe.global/tx-service/base"
        CHAIN_ID=8453
        ;;
    *)
        echo "Unsupported chain: $CHAIN"
        exit 1
        ;;
esac

echo "🔍 Fetching Safe info for $SAFE_ADDRESS on $CHAIN..."
echo ""

# Get Safe nonce
if [ -z "$NONCE" ]; then
    echo "📋 Getting current Safe nonce..."
    NONCE=$(curl -s "${SERVICE_URL}/api/v1/safes/${SAFE_ADDRESS}/" | jq -r '.nonce // empty')
    if [ -z "$NONCE" ]; then
        echo "❌ Failed to get nonce from Safe API"
        exit 1
    fi
    echo "   Current nonce: $NONCE"
else
    echo "   Using provided nonce: $NONCE"
fi

echo ""
echo "📝 Transaction details for rejection (to unstuck):"
echo ""

# For rejection: send 0 ETH to Safe itself with empty data
TO_ADDRESS="$SAFE_ADDRESS"
VALUE="0"
DATA="0x"
OPERATION=0

# Create JSON for signing
cat <<EOF
{
  "safe": "${SAFE_ADDRESS}",
  "chainId": ${CHAIN_ID},
  "to": "${TO_ADDRESS}",
  "value": "${VALUE}",
  "data": "${DATA}",
  "operation": ${OPERATION},
  "safeTxGas": "0",
  "baseGas": "0",
  "gasPrice": "0",
  "gasToken": "0x0000000000000000000000000000000000000000",
  "refundReceiver": "0x0000000000000000000000000000000000000000",
  "nonce": ${NONCE},
  "description": "Rejection transaction to cancel stuck transaction with nonce ${NONCE}"
}
EOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📌 Next steps:"
echo ""
echo "1. Save the JSON above to a file (e.g., tx.json)"
echo ""
echo "2. Sign the transaction hash using EIP-712:"
echo "   - The transaction hash is computed from the above parameters"
echo "   - Use a tool like 'safers-cli' or a wallet that supports EIP-712 signing"
echo ""
echo "3. Submit the signed transaction to Safe Transaction Service:"
echo "   curl -X POST \\"
echo "     ${SERVICE_URL}/api/v1/safes/${SAFE_ADDRESS}/multisig-transactions/ \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"to\":\"${TO_ADDRESS}\",\"value\":\"${VALUE}\",\"data\":\"${DATA}\",\"operation\":${OPERATION},\"safeTxGas\":\"0\",\"baseGas\":\"0\",\"gasPrice\":\"0\",\"gasToken\":\"0x0000000000000000000000000000000000000000\",\"refundReceiver\":\"0x0000000000000000000000000000000000000000\",\"nonce\":\"${NONCE}\",\"contractTransactionHash\":\"<YOUR_SIGNED_HASH>\",\"sender\":\"<YOUR_ADDRESS>\",\"signature\":\"<YOUR_SIGNATURE>\"}'"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "💡 Tip: Use safers-cli to sign and submit:"
echo "   safers-cli tx-reject ${SAFE_ADDRESS} ${CHAIN} <rpc_url> --nonce ${NONCE} <private_key>"
echo ""

