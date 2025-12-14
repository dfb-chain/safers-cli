# safers-cli

A Rust alternative to safe-cli for Gnosis Safe interactions, built with Alloy.

## Features

- **Direct Execution**: Execute transactions immediately with a private key
- **Transaction Proposals**: Propose transactions to Safe Transaction Service for multi-sig approval
- **Hardware Wallet Support**: Sign with Trezor Model One or Ledger devices
- **Multi-chain Support**: Works with any EVM chain (Ethereum, Polygon, Arbitrum, Base, Avalanche, etc.)
- **Encrypted Keystores**: Create and use JSON encrypted keystore files (Web3 Secret Storage format)
- **Safe Configuration**: Easily configure Safe wallets with guards and modules

### Commands

#### Direct Execution (Single Owner)

1. **safe-creator** - Create a new Gnosis Safe
2. **send-ether** - Send ETH from a Safe
3. **send-erc20** - Send ERC20 tokens from a Safe
4. **send-erc721** - Send NFT from a Safe
5. **send-custom** - Execute custom transactions
6. **tx-builder** - Execute from JSON transaction files

#### Transaction Proposals (Multi-sig)

7. **tx-propose** - Propose a transaction using a private key
8. **tx-propose-hw** - Propose a transaction using a hardware wallet (Trezor/Ledger)
9. **tx-reject** - Propose an on-chain rejection transaction to cancel pending transactions
10. **tx-reject-hw** - Propose a rejection transaction using a hardware wallet
11. **tx-confirm-hw** - Confirm a pending Safe transaction using a hardware wallet
12. **tx-simulate** - Simulate and validate a Safe transaction before proposing
13. **safe-configure** - Configure Safe with guards and modules (setGuard, setModuleGuard, enableModule)

#### Keystore Management

14. **keystore-create** - Create an encrypted JSON keystore file from a private key
15. **keystore-address** - Get the Ethereum address from a keystore file

#### Signature Database

16. **sig-sync** - Sync function signatures from 4byte.directory
17. **sig-lookup** - Look up a function signature by selector
18. **sig-decode** - Decode calldata using known signatures
19. **sig-stats** - Show signature database statistics

### Version

Run `safers-cli --version` to see the current version.

## Usage Examples

### Propose Transaction with Hardware Wallet

Using Trezor:

```bash
safers-cli tx-propose-hw \
  0xYourSafeAddress \
  polygon \
  https://polygon-rpc.com \
  transaction.json \
  -w trezor
```

Using Ledger:

```bash
safers-cli tx-propose-hw \
  0xYourSafeAddress \
  ethereum \
  https://eth.drpc.org \
  transaction.json \
  -w ledger
```

### Propose Transaction with Private Key

```bash
safers-cli tx-propose \
  0xYourSafeAddress \
  polygon \
  https://polygon-rpc.com \
  transaction.json \
  your_private_key_hex
```

### Transaction JSON Format

Create a `transaction.json` file:

```json
{
  "to": "0x1234567890123456789012345678901234567890",
  "value": "0",
  "data": "0x1234abcd...",
  "operation": 0
}
```

- `operation`: 0 = Call, 1 = DelegateCall

### Create a Safe

```bash
safers-cli safe-creator \
  https://sepolia.drpc.org \
  your_private_key_hex \
  --threshold 1 \
  --owners 0x1234...,0x5678...
```

### Send ETH

```bash
safers-cli send-ether \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  0xRecipientAddress \
  1000000000000000000 \
  your_private_key_hex
```

### Send ERC20

```bash
safers-cli send-erc20 \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  0xTokenAddress \
  0xRecipientAddress \
  1000000000000000000 \
  your_private_key_hex
```

### Send Custom Transaction

```bash
safers-cli send-custom \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  0xTargetContract \
  --value 0 \
  0x1234abcd \
  your_private_key_hex
```

### Execute from JSON (Direct)

```bash
safers-cli tx-builder \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  transaction.json \
  your_private_key_hex
```

### Configure Safe (Guards and Modules)

Configure a Safe with transaction guard, module guard, and enable modules:

```bash
# Set Transaction Guard
safers-cli safe-configure \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  setGuard \
  0x9ECfaA12c2b8C82834B761cDCc42A4671f7Fc11e \
  your_private_key_hex

# Set Module Guard
safers-cli safe-configure \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  setModuleGuard \
  0x9ECfaA12c2b8C82834B761cDCc42A4671f7Fc11e \
  your_private_key_hex

# Enable Module
safers-cli safe-configure \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  enableModule \
  0x349B8dE9c7853E34b377bDEA7C93754285B3d2f4 \
  your_private_key_hex
```

**Batch Configuration Script:**

Use the helper script to propose all three configuration transactions with consecutive nonces:

```bash
./scripts/configure-safes.sh \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  your_private_key_hex
```

### Keystore Management

Create an encrypted keystore file:

```bash
safers-cli keystore-create \
  your_private_key_hex \
  --output ./my-keystore.json
```

Get address from a keystore:

```bash
safers-cli keystore-address ./my-keystore.json
```

Use keystore in commands (automatically detected if file path is provided):

```bash
# Instead of hex private key, use keystore file path
safers-cli tx-propose \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  transaction.json \
  ./my-keystore.json  # File path instead of hex key
```

### Reject Pending Transactions

Propose an on-chain rejection to cancel pending transactions:

```bash
# With private key
safers-cli tx-reject \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  your_private_key_hex

# With hardware wallet
safers-cli tx-reject-hw \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  --wallet-type trezor
```

### Simulate Transaction

Validate a transaction before proposing:

```bash
safers-cli tx-simulate \
  0xYourSafeAddress \
  base \
  https://base.llamarpc.com \
  transaction.json
```

## Hardware Wallet Setup

### Trezor

1. Connect your Trezor and unlock it with PIN
2. If using a passphrase (hidden wallet), you'll be prompted to enter it
3. Confirm the transaction on the device screen

### Ledger

1. Connect your Ledger and unlock it
2. Open the Ethereum app
3. Enable "Blind signing" in the Ethereum app settings
4. Confirm the transaction on the device screen

## Building

```bash
cargo build --release
```

For hardware wallet support (enabled by default):

```bash
# With Trezor support only
cargo build --release --features trezor

# With Ledger support only  
cargo build --release --features ledger

# With both (default)
cargo build --release --features "trezor,ledger"
```

## Supported Chains

The following chains are supported for transaction proposals:

- `ethereum` / `mainnet`
- `polygon` / `matic`
- `base`
- `avalanche` / `avax`
- `sepolia`

Note: Additional chains can be added by updating the chain configuration in the codebase.

## Technical Details

- Built with [Alloy](https://alloy.rs/) - modern Ethereum library for Rust
- Uses `alloy-sol-types` for type-safe ABI encoding
- Hardware wallet support via `trezor-client` and `ledger-transport-hid`
- Signatures use eth_sign (EIP-191) format for Safe compatibility
- Keystore encryption using Web3 Secret Storage format (via `web3-keystore`)
- Automatic nonce management for consecutive transaction proposals

## License

This project is provided as-is for educational and development purposes.
