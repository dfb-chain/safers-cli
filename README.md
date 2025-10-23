# safers-cli

A Rust alternative to safe-cli for Gnosis Safe interactions, built with Alloy.

## Features

### Commands

1. **safe-creator** - Create a new Gnosis Safe
   - Deploy a new Safe with custom owners and threshold
   - Extract the Safe address from deployment transaction

2. **send-ether** - Send ETH from a Safe
   - Execute ETH transfers through a Safe's `execTransaction`

3. **send-erc20** - Send ERC20 tokens from a Safe
   - Transfer ERC20 tokens via Safe's `execTransaction`

4. **send-erc721** - Send NFT from a Safe
   - Transfer ERC721 tokens via Safe's `safeTransferFrom`

5. **send-custom** - Execute custom transactions
   - Send arbitrary calldata to any contract through the Safe

6. **tx-builder** - Execute from JSON transaction files
   - Load transaction parameters from JSON and execute

### Version

Run `safers-cli --version` to see the current version.

## Usage Examples

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

### Send ERC721

```bash
safers-cli send-erc721 \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  0xNFTContractAddress \
  0xRecipientAddress \
  123 \
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

### Execute from JSON

Create a `transaction.json` file:

```json
{
  "to": "0x1234567890123456789012345678901234567890",
  "value": "1000000000000000000",
  "data": "0x1234",
  "operation": 0
}
```

Then run:

```bash
safers-cli tx-builder \
  0xYourSafeAddress \
  https://sepolia.drpc.org \
  transaction.json \
  your_private_key_hex
```

## Building

```bash
cargo build --release
```

## Testing

```bash
cargo test
```

All 20 unit tests cover:
- Address parsing
- U256 number handling
- Hex encoding/decoding
- Private key parsing
- ERC20/ERC721 ABI encoding
- Gnosis Safe call encoding
- JSON transaction parsing
- And more!

## Technical Details

- Built with [Alloy](https://alloy.rs/) - modern Ethereum library for Rust
- Uses `alloy-sol-types` for type-safe ABI encoding
- Supports threshold=1 Safes (multi-sig support can be extended)
- Hardcoded for Sepolia (can be extended with chain-specific addresses)

## Future Enhancements

- Multi-signature support with proper signature collection
- Chain-specific configuration
- Gas estimation
- Transaction simulation
- More interactive modes

## License

This project is provided as-is for educational and development purposes.

