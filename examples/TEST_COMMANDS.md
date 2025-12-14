# Test Commands for Guard Validation

These commands directly execute transactions (not proposals) to test if the guard allows/rejects them.

**Note:** For `cast` commands, see `TEST_COMMANDS_CAST.md`

## Bot Address
- Bot: `0x3A6C37a691279f545984a058F88535bd4B520d25`
- Safe: `0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4`
- USDC: `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`

## Test 1: Withdraw 1 USDC to Whitelisted Address (Should SUCCEED)

```bash
./target/release/safers-cli send-erc20 \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  0x7C880868c487Faa796d81727B1BD016Fa540385d \
  1000000 \
  YOUR_PRIVATE_KEY
```

**Expected:** ✅ Transaction should succeed - guard allows transfers to whitelisted withdrawal address

---

## Test 2: Withdraw 1 USDC to Non-Whitelisted Address (Should FAIL)

```bash
./target/release/safers-cli send-erc20 \
  0xb261Db3e2A4a5DC542F7D40dc3b465C7bB104AF4 \
  https://mainnet.base.org \
  0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  0xd7C578354b575611325De1986e13bAef8cE74429 \
  1000000 \
  YOUR_PRIVATE_KEY
```

**Expected:** ❌ Transaction should FAIL - guard should reject transfers to non-whitelisted address

---

## Notes

- Amount: `1000000` = 1 USDC (USDC has 6 decimals)
- These commands execute directly from the Safe (no proposal needed)
- The guard will check the recipient address before allowing the transaction
- Make sure you have enough signatures/approvals to execute directly
