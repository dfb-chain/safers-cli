# Test Commands Using Cast (Foundry)

These commands use `cast` to directly execute transactions and test the guard.

## Setup

```bash
# Set your variables
export SAFE="0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4"
export USDC="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
export RPC="https://mainnet.base.org"
export PRIVATE_KEY="YOUR_PRIVATE_KEY_HERE"
export WHITELISTED_ADDR="0x7C880868c487Faa796d81727B1BD016Fa540385d"
export NOT_WHITELISTED_ADDR="0xd7C578354b575611325De1986e13bAef8cE74429"
```

## ⚠️ Important: Safe Signature Requirement

Safe transactions require proper EIP-712 signatures from owners. You cannot use `cast send` directly with empty signatures (`"0x"`). You'll get `GS020: Invalid signatures` error.

**Options:**
1. Use `safers-cli send-erc20` (handles signatures automatically) - **RECOMMENDED**
2. Generate Safe signatures manually (complex, see below)
3. Use Safe Transaction Service API

---

## Test 1: Withdraw 1 USDC to Whitelisted Address (Should SUCCEED)

### Option A: Using safers-cli (Easiest)

```bash
./target/release/safers-cli send-erc20 \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  0x7C880868c487Faa796d81727B1BD016Fa540385d \
  1000000 \
  YOUR_PRIVATE_KEY
```

### Option B: Using cast to encode, then safers-cli tx-builder

```bash
# Encode the transfer call
TRANSFER_DATA=$(cast calldata "transfer(address,uint256)" $WHITELISTED_ADDR 1000000)

# Create JSON file with the encoded data
cat > test-transfer-whitelisted.json <<EOF
{
  "to": "$USDC",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": 0
}
EOF

# Execute using safers-cli
./target/release/safers-cli tx-builder \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  test-transfer-whitelisted.json \
  YOUR_PRIVATE_KEY
```

**Expected:** ✅ Transaction should succeed - guard allows transfers to whitelisted withdrawal address

---

## Test 2: Withdraw 1 USDC to Non-Whitelisted Address (Should FAIL)

### Option A: Using safers-cli (Easiest)

```bash
./target/release/safers-cli send-erc20 \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  0xd7C578354b575611325De1986e13bAef8cE74429 \
  1000000 \
  YOUR_PRIVATE_KEY
```

### Option B: Using cast to encode, then safers-cli tx-builder

```bash
# Encode the transfer call
TRANSFER_DATA=$(cast calldata "transfer(address,uint256)" $NOT_WHITELISTED_ADDR 1000000)

# Create JSON file with the encoded data
cat > test-transfer-not-whitelisted.json <<EOF
{
  "to": "$USDC",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": 0
}
EOF

# Execute using safers-cli
./target/release/safers-cli tx-builder \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  test-transfer-not-whitelisted.json \
  YOUR_PRIVATE_KEY
```

**Expected:** ❌ Transaction should FAIL - guard should reject transfers to non-whitelisted address

---

## Alternative: Using Cast to Encode Only

If you just want to encode the transfer data and use it elsewhere:

```bash
# Encode transfer to whitelisted address
cast calldata "transfer(address,uint256)" 0x7C880868c487Faa796d81727B1BD016Fa540385d 1000000

# Encode transfer to non-whitelisted address  
cast calldata "transfer(address,uint256)" 0xd7C578354b575611325De1986e13bAef8cE74429 1000000
```

---

## ⚠️ CRITICAL: Guard Checks TARGET Contract, Not Recipient!

**The guard checks if the TARGET contract (USDC) is whitelisted, NOT the recipient address in the transfer call.**

**Before testing, verify both are whitelisted:**
```bash
export GUARD="0xB94986B4dcF396782C442850c054792ce9c0EAF8"

# Check if USDC contract is whitelisted (REQUIRED for transfers)
cast call $GUARD "isTargetAllowed(address)(bool)" 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --rpc-url https://mainnet.base.org

# Check if withdrawal address is whitelisted
cast call $GUARD "isTargetAllowed(address)(bool)" 0x7C880868c487Faa796d81727B1BD016Fa540385d --rpc-url https://mainnet.base.org
```

**If USDC returns `false`, you need to whitelist USDC first!** The guard will reject any transaction to a non-whitelisted target contract, regardless of the recipient address.

**⚠️ IMPORTANT: Proposing ≠ Executing!**

In Safe, a transaction must be **EXECUTED** on-chain, not just proposed and signed. If you see `false` for an address you thought was whitelisted:
1. Check the Safe UI to see if the transaction is still pending (signed but not executed)
2. Execute the transaction in the Safe UI
3. Verify again with `cast call` after execution

**Quick check all whitelist statuses:**
```bash
export GUARD="0xB94986B4dcF396782C442850c054792ce9c0EAF8"

echo "USDC:" && cast call $GUARD "isTargetAllowed(address)(bool)" 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 --rpc-url https://mainnet.base.org
echo "Withdrawal Address:" && cast call $GUARD "isTargetAllowed(address)(bool)" 0x7C880868c487Faa796d81727B1BD016Fa540385d --rpc-url https://mainnet.base.org
echo "TGBP:" && cast call $GUARD "isTargetAllowed(address)(bool)" 0x27f6c8289550fCE67f6B50BeD1F519966aFE5287 --rpc-url https://mainnet.base.org
echo "AERO:" && cast call $GUARD "isTargetAllowed(address)(bool)" 0x940181a94A35A4569E4529A3CDfB74e38FD98631 --rpc-url https://mainnet.base.org
echo "WETH:" && cast call $GUARD "isTargetAllowed(address)(bool)" 0x4200000000000000000000000000000000000006 --rpc-url https://mainnet.base.org
```

---

## Notes

- Amount: `1000000` = 1 USDC (USDC has 6 decimals)
- **The guard checks the TARGET contract address** (the `to` field in Safe transaction), not the recipient in the calldata
- **Important:** The "nonce too low" error refers to the **BOT WALLET's nonce** (0x3A6C37a691279f545984a058F88535bd4B520d25), not the Safe's nonce
- If you get a nonce error:
  ```bash
  # Check current bot wallet nonce
  cast nonce 0x3A6C37a691279f545984a058F88535bd4B520d25 --rpc-url https://mainnet.base.org
  
  # Wait for any pending transactions to confirm, then try again
  ```
- The Safe has its own internal nonce (separate from the bot wallet's nonce)
- For Safe transactions, you need proper signatures. The `safers-cli tx-builder` handles this automatically

---

## Advanced: Using Cast with Manual Signature Generation

If you want to use `cast send` directly, you need to generate proper Safe signatures first. This is complex and requires:

1. **Generate Safe transaction hash** (EIP-712):
```bash
# Get Safe nonce
NONCE=$(cast call $SAFE "nonce()(uint256)" --rpc-url $RPC)

# Generate transaction hash (simplified - actual requires EIP-712 encoding)
# This is complex and better done with a script or safers-cli
```

2. **Sign the hash** with owner private keys:
```bash
# Sign with each owner
SIG1=$(cast wallet sign --private-key $PRIVATE_KEY1 $TX_HASH)
SIG2=$(cast wallet sign --private-key $PRIVATE_KEY2 $TX_HASH)
# ... etc
```

3. **Concatenate signatures** (sorted by signer address)

4. **Execute with cast**:
```bash
cast send $SAFE \
  "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)" \
  $USDC \
  0 \
  $(cast calldata "transfer(address,uint256)" $WHITELISTED_ADDR 1000000) \
  0 \
  0 \
  0 \
  0 \
  0x0000000000000000000000000000000000000000 \
  0x0000000000000000000000000000000000000000 \
  "$CONCATENATED_SIGNATURES" \
  --rpc-url $RPC \
  --private-key $PRIVATE_KEY
```

**Recommendation:** Use `safers-cli` which handles all this complexity automatically.


# Set variables
export SAFE="0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4"
export USDC="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
export WHITELISTED_ADDR="0x7C880868c487Faa796d81727B1BD016Fa540385d"
export NOT_WHITELISTED_ADDR="0xd7C578354b575611325De1986e13bAef8cE74429"

# Test 1: Encode and create JSON for whitelisted address
TRANSFER_DATA=$(cast calldata "transfer(address,uint256)" $WHITELISTED_ADDR 1000000)
cat > test-whitelisted.json <<EOF
{
  "to": "$USDC",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": 0
}
EOF

# IMPORTANT: Check bot wallet nonce first to avoid "nonce too low" errors
# The nonce error refers to the BOT WALLET (0x3A6C37a691279f545984a058F88535bd4B520d25), not the Safe
BOT_ADDR="0x3A6C37a691279f545984a058F88535bd4B520d25"
BOT_NONCE=$(cast nonce $BOT_ADDR --rpc-url https://mainnet.base.org)
echo "Bot wallet ($BOT_ADDR) current nonce: $BOT_NONCE"

# If nonce is 3, make sure there are no pending transactions before proceeding
# Wait for any pending transactions to confirm, then try again

# Execute with safers-cli (handles signatures automatically)
./target/release/safers-cli tx-builder \
  $SAFE \
  https://mainnet.base.org \
  test-whitelisted.json \
  $PRIVATE_KEY

# Test 2: Encode and create JSON for non-whitelisted address
TRANSFER_DATA=$(cast calldata "transfer(address,uint256)" $NOT_WHITELISTED_ADDR 1000000)
cat > test-not-whitelisted.json <<EOF
{
  "to": "$USDC",
  "value": "0",
  "data": "$TRANSFER_DATA",
  "operation": 0
}
EOF

# Check bot wallet nonce first
BOT_ADDR="0x3A6C37a691279f545984a058F88535bd4B520d25"
BOT_NONCE=$(cast nonce $BOT_ADDR --rpc-url https://mainnet.base.org)
echo "Bot wallet ($BOT_ADDR) current nonce: $BOT_NONCE"

# Execute with safers-cli
# Note: The nonce error is from the BOT WALLET, not the Safe
./target/release/safers-cli tx-builder \
  $SAFE \
  https://mainnet.base.org \
  test-not-whitelisted.json \
  $PRIVATE_KEY