use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "safers-cli")]
#[command(about = "A Rust alternative to safe-cli for Gnosis Safe interactions")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    #[command(name = "safe-creator")]
    SafeCreator {
        /// Ethereum RPC node URL (e.g., https://sepolia.drpc.org)
        node_url: String,
        /// Chain name (sepolia, mainnet)
        chain: String,
        /// Deployer private key (hex, without 0x)
        private_key: String,
        /// Threshold (default: 1)
        #[arg(short, long, default_value = "1")]
        threshold: u32,
        /// Comma-separated owner addresses (default: deployer only)
        #[arg(short, long)]
        owners: Option<String>,
    },
    #[command(name = "send-ether")]
    SendEther {
        /// Safe address
        safe_address: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Recipient address
        to: String,
        /// Amount in wei
        amount: u128,
        /// Private keys for signing (one or more, comma-separated)
        private_keys: String,
    },
    #[command(name = "send-erc20")]
    SendErc20 {
        /// Safe address
        safe_address: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// ERC20 token contract address
        token_address: String,
        /// Recipient address
        to: String,
        /// Amount in token's smallest unit
        amount: String,
        /// Private keys for signing (comma-separated)
        private_keys: String,
    },
    #[command(name = "send-erc721")]
    SendErc721 {
        /// Safe address
        safe_address: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// ERC721 token contract address
        token_address: String,
        /// Recipient address
        to: String,
        /// Token ID
        token_id: String,
        /// Private keys for signing (comma-separated)
        private_keys: String,
    },
    #[command(name = "send-custom")]
    SendCustom {
        /// Safe address
        safe_address: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Target contract address
        to: String,
        /// Amount in wei to send
        #[arg(short, long, default_value = "0")]
        value: u128,
        /// Calldata (hex, with or without 0x prefix)
        data: String,
        /// Private keys for signing (comma-separated)
        private_keys: String,
    },
    #[command(name = "tx-builder")]
    TxBuilder {
        /// Safe address
        safe_address: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Path to JSON transaction file
        json_file: String,
        /// Private keys for signing (comma-separated)
        private_keys: String,
    },
    #[command(name = "sig-sync")]
    SigSync {
        /// Maximum number of signatures to sync (default: 10000)
        #[arg(short, long, default_value = "10000")]
        limit: usize,
    },
    #[command(name = "sig-lookup")]
    SigLookup {
        /// 4-byte hex signature (e.g., 0x567f6500)
        signature: String,
    },
    #[command(name = "sig-decode")]
    SigDecode {
        /// Full calldata hex string
        calldata: String,
    },
    #[command(name = "sig-stats")]
    SigStats,
    #[command(name = "tx-propose")]
    TxPropose {
        /// Safe address
        safe_address: String,
        /// Chain name (sepolia, mainnet, base)
        chain: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Path to JSON transaction file
        json_file: String,
        /// Private key for signing the proposal (single signer)
        private_key: String,
    },
    #[command(name = "tx-reject")]
    TxReject {
        /// Safe address
        safe_address: String,
        /// Chain name (sepolia, mainnet, base)
        chain: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Specific nonce to reject (optional, defaults to current nonce)
        #[arg(short, long)]
        nonce: Option<u64>,
        /// Private key for signing the rejection (single signer)
        private_key: String,
    },
    #[command(name = "tx-propose-hw")]
    TxProposeHw {
        /// Safe address
        safe_address: String,
        /// Chain name (sepolia, mainnet, base, polygon)
        chain: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Path to JSON transaction file
        json_file: String,
        /// Hardware wallet type (trezor, ledger, ledger-flex)
        #[arg(short, long, default_value = "trezor")]
        wallet_type: String,
        /// Derivation path (default: m/44'/60'/0'/0/0)
        #[arg(short, long, default_value = "m/44'/60'/0'/0/0")]
        derivation_path: String,
    },
    #[command(name = "tx-reject-hw")]
    TxRejectHw {
        /// Safe address
        safe_address: String,
        /// Chain name (sepolia, mainnet, base, polygon)
        chain: String,
        /// Ethereum RPC node URL
        node_url: String,
        /// Specific nonce to reject (optional, defaults to current nonce)
        #[arg(short, long)]
        nonce: Option<u64>,
        /// Hardware wallet type (trezor, ledger, ledger-flex)
        #[arg(short, long, default_value = "trezor")]
        wallet_type: String,
        /// Derivation path (default: m/44'/60'/0'/0/0)
        #[arg(short = 'p', long, default_value = "m/44'/60'/0'/0/0")]
        derivation_path: String,
    },
}

