# safers-cli

A Rust alternative to safe-cli for Gnosis Safe interactions, built with Alloy.

## Features

- **Direct Execution**: Execute transactions immediately with a private key
- **Transaction Proposals**: Propose transactions to Safe Transaction Service for multi-sig approval
- **Hardware Wallet Support**: Sign with Trezor Model One or Ledger devices
- **Multi-chain Support**: Works with any EVM chain (Ethereum, Polygon, Arbitrum, etc.)

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

#### Signature Database

9. **sig-sync** - Sync function signatures from 4byte.directory
10. **sig-lookup** - Look up a function signature by selector
11. **sig-decode** - Decode calldata using known signatures
12. **sig-stats** - Show signature database statistics

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
- `arbitrum`
- `optimism`
- `base`
- `gnosis`
- `sepolia`
- `goerli`

## Technical Details

- Built with [Alloy](https://alloy.rs/) - modern Ethereum library for Rust
- Uses `alloy-sol-types` for type-safe ABI encoding
- Hardware wallet support via `trezor-client` and `ledger-transport-hid`
- Signatures use eth_sign (EIP-191) format for Safe compatibility

## License

This project is provided as-is for educational and development purposes.
