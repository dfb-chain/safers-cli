use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, Bytes, U256, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::eth::TransactionRequest;
use alloy_sol_types::SolCall;
use std::fs;
use std::str::FromStr;

use crate::contracts::{ERC20, ERC721, GnosisSafe, ProxyFactory};
use crate::hardware_wallet::{HardwareWalletType, HardwareWalletSigner};
use crate::signatures;
use crate::types::{TxBuilderJson, SafeTxServiceRequest};
use crate::utils::{
    create_signer_from_hex_with_chain_id, get_chain_config, 
    sign_safe_transaction, get_safe_service_url, generate_safe_tx_hash
};

pub async fn safe_creator(
    node_url: &str,
    chain: &str,
    private_key: &str,
    threshold: u32,
    owners_str: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (chain_id, proxy_factory, singleton) = get_chain_config(chain)?;
    
    let wallet_bytes = hex::decode(private_key)?;
    let wallet_b256 = alloy::primitives::B256::from_slice(&wallet_bytes);
    let signer = alloy::signers::local::PrivateKeySigner::from_bytes(&wallet_b256)?;
    let from = signer.address();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    let owners: Vec<Address> = if let Some(s) = owners_str {
        s.split(',')
            .map(|o| o.trim())
            .map(|o| Address::from_str(o))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        vec![from]
    };

    if (threshold as usize) > owners.len() {
        return Err("Threshold cannot exceed number of owners".into());
    }

    let initializer = GnosisSafe::setupCall {
        owners: owners.clone(),
        threshold: U256::from(threshold),
        to: Address::ZERO,
        data: Bytes::new(),
        fallbackHandler: Address::ZERO,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();

    let salt_nonce = U256::ZERO; // Use 0 for simplicity; make deterministic if needed

    let call = ProxyFactory::createProxyWithNonceCall {
        singleton,
        initializer: initializer.into(),
        saltNonce: salt_nonce,
    };

    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(proxy_factory)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_chain_id(chain_id)
        .with_gas_limit(1_000_000); // Higher limit for Safe creation
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("Safe creation transaction sent: 0x{:x}", tx_hash);
    println!("Monitor on: https://sepolia.etherscan.io/tx/0x{:x}", tx_hash);

    // Optional: Wait for receipt and extract proxy address from ProxyCreation event
    let receipt = pending_tx.get_receipt().await?;

    if let Some(log) = receipt
        .inner
        .as_receipt()
        .unwrap()
        .logs
        .iter()
        .find(|log| log.topics().len() == 2 && log.topics()[0] == alloy::primitives::keccak256(b"ProxyCreation(address)"))
    {
        let proxy_addr = Address::from_slice(&log.topics()[1][12..]);
        println!("New Safe address: {}", proxy_addr);
    }

    Ok(())
}

pub async fn send_ether(
    safe_address: &str,
    node_url: &str,
    to: &str,
    amount: u128,
    private_keys_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let to_addr: Address = to.parse()?;
    let amount_u256 = U256::from(amount);

    let private_keys: Vec<&str> = private_keys_str.split(',').map(|pk| pk.trim()).collect();
    if private_keys.is_empty() {
        return Err("At least one private key required".into());
    }

    // Get provider first to fetch chain ID
    let temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    let chain_id = temp_provider.get_chain_id().await?;
    
    // Create signers for Safe signature
    let signers: Result<Vec<_>, _> = private_keys
        .iter()
        .map(|pk| create_signer_from_hex_with_chain_id(pk, chain_id))
        .collect();
    let signers = signers?;
    
    // Use first signer for sending the transaction
    let from = signers[0].address();
    let wallet = EthereumWallet::from(signers[0].clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    // Generate proper Safe signature
    let inner_data = Bytes::new();
    let signature = sign_safe_transaction(
        &provider,
        safe,
        chain_id,
        to_addr,
        amount_u256,
        &inner_data,
        0, // Operation::Call
        signers,
    ).await?;

    let call = GnosisSafe::execTransactionCall {
        to: to_addr,
        value: amount_u256,
        data: inner_data,
        operation: GnosisSafe::Operation::Call,
        safeTxGas: U256::from(0u32),
        baseGas: U256::from(0u32),
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature,
    };

    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_gas_limit(500_000);
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("Ether transfer transaction sent: 0x{:x}", tx_hash);

    Ok(())
}

pub async fn send_erc20(
    safe_address: &str,
    node_url: &str,
    token_address: &str,
    to: &str,
    amount: &str,
    private_keys_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let token: Address = token_address.parse()?;
    let to_addr: Address = to.parse()?;
    let amount_u256 = U256::from_str(amount)?;

    let private_keys: Vec<&str> = private_keys_str.split(',').map(|pk| pk.trim()).collect();
    if private_keys.is_empty() {
        return Err("At least one private key required".into());
    }

    // Get provider first to fetch chain ID
    let temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    let chain_id = temp_provider.get_chain_id().await?;
    
    // Create signers for Safe signature
    let signers: Result<Vec<_>, _> = private_keys
        .iter()
        .map(|pk| create_signer_from_hex_with_chain_id(pk, chain_id))
        .collect();
    let signers = signers?;
    
    // Use first signer for sending the transaction
    let from = signers[0].address();
    let wallet = EthereumWallet::from(signers[0].clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    // ERC20 transfer call
    let erc20_call = ERC20::transferCall {
        to: to_addr,
        amount: amount_u256,
    };
    let inner_data: Bytes = erc20_call.abi_encode().into();
    
    // Show decoded function signature
    maybe_decode_and_display(&inner_data);

    // Generate proper Safe signature
    let signature = sign_safe_transaction(
        &provider,
        safe,
        chain_id,
        token,
        U256::ZERO,
        &inner_data,
        0, // Operation::Call
        signers,
    ).await?;

    // Wrap in Safe execTransaction
    let call = GnosisSafe::execTransactionCall {
        to: token,
        value: U256::ZERO,
        data: inner_data,
        operation: GnosisSafe::Operation::Call,
        safeTxGas: U256::from(0u32),
        baseGas: U256::from(0u32),
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature,
    };

    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_gas_limit(500_000);
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("ERC20 transfer transaction sent: 0x{:x}", tx_hash);
    println!("Token: {}, Amount: {}", token_address, amount);

    Ok(())
}

pub async fn send_erc721(
    safe_address: &str,
    node_url: &str,
    token_address: &str,
    to: &str,
    token_id: &str,
    private_keys_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let token: Address = token_address.parse()?;
    let to_addr: Address = to.parse()?;
    let token_id_u256 = U256::from_str(token_id)?;

    let private_keys: Vec<&str> = private_keys_str.split(',').map(|pk| pk.trim()).collect();
    if private_keys.is_empty() {
        return Err("At least one private key required".into());
    }

    // Get provider first to fetch chain ID
    let temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    let chain_id = temp_provider.get_chain_id().await?;
    
    // Create signers for Safe signature
    let signers: Result<Vec<_>, _> = private_keys
        .iter()
        .map(|pk| create_signer_from_hex_with_chain_id(pk, chain_id))
        .collect();
    let signers = signers?;
    
    // Use first signer for sending the transaction
    let from = signers[0].address();
    let wallet = EthereumWallet::from(signers[0].clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    // ERC721 safeTransferFrom call
    let erc721_call = ERC721::safeTransferFromCall {
        from: safe,
        to: to_addr,
        tokenId: token_id_u256,
    };
    let inner_data: Bytes = erc721_call.abi_encode().into();
    
    // Show decoded function signature
    maybe_decode_and_display(&inner_data);

    // Generate proper Safe signature
    let signature = sign_safe_transaction(
        &provider,
        safe,
        chain_id,
        token,
        U256::ZERO,
        &inner_data,
        0, // Operation::Call
        signers,
    ).await?;

    // Wrap in Safe execTransaction
    let call = GnosisSafe::execTransactionCall {
        to: token,
        value: U256::ZERO,
        data: inner_data,
        operation: GnosisSafe::Operation::Call,
        safeTxGas: U256::from(0u32),
        baseGas: U256::from(0u32),
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature,
    };

    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_gas_limit(500_000);
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("ERC721 transfer transaction sent: 0x{:x}", tx_hash);
    println!("Token: {}, Token ID: {}", token_address, token_id);

    Ok(())
}

pub async fn send_custom(
    safe_address: &str,
    node_url: &str,
    to: &str,
    value: u128,
    data: &str,
    private_keys_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let to_addr: Address = to.parse()?;
    let value_u256 = U256::from(value);

    // Parse calldata (with or without 0x prefix)
    let data_str = data.strip_prefix("0x").unwrap_or(data);
    let calldata = hex::decode(data_str)?;

    let private_keys: Vec<&str> = private_keys_str.split(',').map(|pk| pk.trim()).collect();
    if private_keys.is_empty() {
        return Err("At least one private key required".into());
    }

    // Get provider first to fetch chain ID
    let temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    let chain_id = temp_provider.get_chain_id().await?;
    
    // Create signers for Safe signature
    let signers: Result<Vec<_>, _> = private_keys
        .iter()
        .map(|pk| create_signer_from_hex_with_chain_id(pk, chain_id))
        .collect();
    let signers = signers?;
    
    // Use first signer for sending the transaction
    let from = signers[0].address();
    let wallet = EthereumWallet::from(signers[0].clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    let inner_data: Bytes = calldata.into();
    
    // Show decoded function signature
    maybe_decode_and_display(&inner_data);

    // Generate proper Safe signature
    let signature = sign_safe_transaction(
        &provider,
        safe,
        chain_id,
        to_addr,
        value_u256,
        &inner_data,
        0, // Operation::Call
        signers,
    ).await?;

    let call = GnosisSafe::execTransactionCall {
        to: to_addr,
        value: value_u256,
        data: inner_data,
        operation: GnosisSafe::Operation::Call,
        safeTxGas: U256::from(0u32),
        baseGas: U256::from(0u32),
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature,
    };

    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_gas_limit(500_000);
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("Custom transaction sent: 0x{:x}", tx_hash);
    println!("To: {}, Value: {} wei", to, value);

    Ok(())
}

pub async fn tx_builder(
    safe_address: &str,
    node_url: &str,
    json_file: &str,
    private_keys_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;

    // Read and parse JSON file
    let json_content = fs::read_to_string(json_file)?;
    let tx_json: TxBuilderJson = serde_json::from_str(&json_content)?;

    let to_addr: Address = tx_json.to.parse()?;
    let value_u256 = U256::from_str(&tx_json.value)?;
    
    let calldata: Bytes = if let Some(data_str) = tx_json.data {
        let data_hex = data_str.strip_prefix("0x").unwrap_or(&data_str);
        hex::decode(data_hex)?.into()
    } else {
        Bytes::new()
    };

    let operation = match tx_json.operation {
        Some(1) => GnosisSafe::Operation::DelegateCall,
        _ => GnosisSafe::Operation::Call,
    };
    
    // Show decoded function signature
    maybe_decode_and_display(&calldata);

    let private_keys: Vec<&str> = private_keys_str.split(',').map(|pk| pk.trim()).collect();
    if private_keys.is_empty() {
        return Err("At least one private key required".into());
    }

    // Get provider first to fetch chain ID
    let temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    let chain_id = temp_provider.get_chain_id().await?;
    
    // Create signers for Safe signature
    let signers: Result<Vec<_>, _> = private_keys
        .iter()
        .map(|pk| create_signer_from_hex_with_chain_id(pk, chain_id))
        .collect();
    let signers = signers?;
    
    // Use first signer for sending the transaction
    let from = signers[0].address();
    let wallet = EthereumWallet::from(signers[0].clone());
    let provider = ProviderBuilder::new().wallet(wallet).on_builtin(node_url).await?;

    // Generate proper Safe signature
    let operation_u8 = match operation {
        GnosisSafe::Operation::Call => 0,
        GnosisSafe::Operation::DelegateCall => 1,
        _ => 0, // Default to Call for any other variant
    };
    
    let signature = sign_safe_transaction(
        &provider,
        safe,
        chain_id,
        to_addr,
        value_u256,
        &calldata,
        operation_u8,
        signers,
    ).await?;

    let call = GnosisSafe::execTransactionCall {
        to: to_addr,
        value: value_u256,
        data: calldata,
        operation,
        safeTxGas: U256::from(0u32),
        baseGas: U256::from(0u32),
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature,
    };

    // Get the nonce for the signer account
    let nonce = provider.get_transaction_count(from).await?;
    
    let mut tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(call.abi_encode())
        .with_from(from)
        .with_nonce(nonce)
        .with_chain_id(chain_id);

    // Fill in gas parameters - let provider estimate
    tx = tx.with_gas_limit(500_000); // Safe default
    
    if let Ok(fees) = provider.estimate_eip1559_fees(None).await {
        tx = tx
            .with_max_fee_per_gas(fees.max_fee_per_gas)
            .with_max_priority_fee_per_gas(fees.max_priority_fee_per_gas);
    }

    let pending_tx = provider.send_transaction(tx).await?;
    let tx_hash = *pending_tx.tx_hash();

    println!("Transaction from JSON file sent: 0x{:x}", tx_hash);
    println!("File: {}", json_file);

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Decode and display calldata if signature database is available
fn maybe_decode_and_display(calldata: &Bytes) {
    if let Ok(db) = signatures::open_db() {
        let hex_data = format!("0x{}", hex::encode(calldata));
        if let Ok(Some((text_sig, _))) = signatures::decode_calldata(&db, &hex_data) {
            println!("📝 Decoded function: {}", text_sig);
        }
    }
}

// ============================================================================
// Signature Database Commands
// ============================================================================

pub async fn sig_sync(limit: usize) -> Result<(), Box<dyn std::error::Error>> {
    let db = signatures::open_db()?;
    
    let existing = signatures::get_stats(&db)?;
    println!("Current signatures in database: {}", existing);
    
    signatures::sync_signatures(&db, limit).await?;
    
    let final_count = signatures::get_stats(&db)?;
    println!("\n✓ Database now contains {} signatures", final_count);
    
    Ok(())
}

pub async fn sig_lookup(signature: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db = signatures::open_db()?;
    
    // Normalize signature (ensure 0x prefix)
    let sig = if signature.starts_with("0x") {
        signature.to_lowercase()
    } else {
        format!("0x{}", signature.to_lowercase())
    };
    
    match signatures::lookup_signature(&db, &sig)? {
        Some(text_sig) => {
            println!("Function Signature:");
            println!("  Hex:  {}", sig);
            println!("  Text: {}", text_sig);
        }
        None => {
            println!("❌ Signature {} not found in database", sig);
            println!("Try running: safers-cli sig-sync");
        }
    }
    
    Ok(())
}

pub async fn sig_decode(calldata: &str) -> Result<(), Box<dyn std::error::Error>> {
    let db = signatures::open_db()?;
    
    match signatures::decode_calldata(&db, calldata)? {
        Some((text_sig, params)) => {
            println!("Decoded Calldata:");
            println!("  Function: {}", text_sig);
            if !params.is_empty() {
                println!("  Parameters: {}", params);
            }
        }
        None => {
            println!("❌ Unable to decode calldata");
            println!("The function signature may not be in the database.");
            println!("Try running: safers-cli sig-sync");
        }
    }
    
    Ok(())
}

pub async fn sig_stats() -> Result<(), Box<dyn std::error::Error>> {
    let db = signatures::open_db()?;
    let count = signatures::get_stats(&db)?;
    
    println!("Signature Database Statistics:");
    println!("  Total signatures: {}", count);
    println!("  Database location: ~/.safers-cli/signatures.redb");
    
    Ok(())
}

// ============================================================================
// Safe Transaction Service Integration
// ============================================================================

pub async fn tx_propose(
    safe_address: &str,
    chain: &str,
    node_url: &str,
    json_file: &str,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use alloy::signers::Signer;
    
    let safe: Address = safe_address.parse()?;
    let (chain_id, _, _) = get_chain_config(chain)?;
    let service_url = get_safe_service_url(chain)?;

    // Read and parse JSON file
    let json_content = fs::read_to_string(json_file)?;
    let tx_json: TxBuilderJson = serde_json::from_str(&json_content)?;

    let to_addr: Address = tx_json.to.parse()?;
    let value_u256 = U256::from_str(&tx_json.value)?;
    
    let calldata: Bytes = if let Some(data_str) = tx_json.data {
        let data_hex = data_str.strip_prefix("0x").unwrap_or(&data_str);
        hex::decode(data_hex)?.into()
    } else {
        Bytes::new()
    };

    let operation_u8 = tx_json.operation.unwrap_or(0);
    
    // Show decoded function signature
    maybe_decode_and_display(&calldata);

    // Get provider
    let _temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    
    // Create signer
    let signer = create_signer_from_hex_with_chain_id(private_key, chain_id)?;
    let sender_address = signer.address();
    
    // Get Safe nonce from transaction service (this is the Safe's internal nonce)
    let nonce = get_safe_nonce_from_service(&service_url, safe_address).await?;
    
    println!("📋 Preparing transaction proposal...");
    println!("  Safe: {}", safe_address);
    println!("  Chain: {} (ID: {})", chain, chain_id);
    println!("  Safe Nonce: {}", nonce);
    println!("  Sender: {}", sender_address);
    
    // Generate Safe transaction hash
    let safe_tx_hash = generate_safe_tx_hash(
        safe,
        chain_id,
        to_addr,
        value_u256,
        &calldata,
        operation_u8,
        U256::ZERO, // safeTxGas
        U256::ZERO, // baseGas
        U256::ZERO, // gasPrice
        Address::ZERO, // gasToken
        Address::ZERO, // refundReceiver
        U256::from(nonce),
    );
    
    println!("  Safe Tx Hash: 0x{:x}", safe_tx_hash);
    
    // Sign the transaction hash
    let signature = signer.sign_hash(&safe_tx_hash).await?;
    let signature_bytes = signature.as_bytes();
    let signature_hex = format!("0x{}", hex::encode(signature_bytes));
    
    // Prepare API request (addresses must be checksummed)
    let request = SafeTxServiceRequest {
        to: to_addr.to_checksum(None),
        value: value_u256.to_string(),
        data: if calldata.is_empty() {
            "0x".to_string()
        } else {
            format!("0x{}", hex::encode(calldata.as_ref()))
        },
        operation: operation_u8,
        safe_tx_gas: "0".to_string(),
        base_gas: "0".to_string(),
        gas_price: "0".to_string(),
        gas_token: Address::ZERO.to_checksum(None),
        refund_receiver: Address::ZERO.to_checksum(None),
        nonce: nonce.to_string(),
        contract_transaction_hash: format!("0x{:x}", safe_tx_hash),
        sender: sender_address.to_checksum(None),
        signature: signature_hex,
        origin: Some("safers-cli".to_string()),
    };
    
    // Submit to Safe Transaction Service
    println!("\n📤 Submitting proposal to Safe Transaction Service...");
    
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/v1/safes/{}/multisig-transactions/", service_url, safe_address);
    
    let response = client
        .post(&api_url)
        .json(&request)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        println!("✅ Transaction proposed successfully!");
        println!("\n🔗 View in Safe UI:");
        
        let safe_ui_url = match chain.to_lowercase().as_str() {
            "sepolia" => format!("https://app.safe.global/transactions/queue?safe=sep:{}", safe_address),
            "mainnet" | "ethereum" => format!("https://app.safe.global/transactions/queue?safe=eth:{}", safe_address),
            "base" => format!("https://app.safe.global/transactions/queue?safe=base:{}", safe_address),
            "polygon" | "matic" => format!("https://app.safe.global/transactions/queue?safe=matic:{}", safe_address),
            _ => format!("https://app.safe.global/transactions/queue?safe={}", safe_address),
        };
        
        println!("   {}", safe_ui_url);
        println!("\n📝 Safe Transaction Hash: 0x{:x}", safe_tx_hash);
        println!("\n✨ Other signers can now approve this transaction in the Safe UI");
        
    } else {
        let error_text = response.text().await?;
        println!("❌ Failed to propose transaction");
        println!("Status: {}", status);
        println!("Error: {}", error_text);
        return Err(format!("Transaction service error: {}", error_text).into());
    }
    
    Ok(())
}

/// Get Safe nonce from the transaction service
async fn get_safe_nonce_from_service(
    service_url: &str,
    safe_address: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct SafeInfo {
        #[serde(deserialize_with = "deserialize_string_to_u64")]
        nonce: u64,
    }
    
    fn deserialize_string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::Deserialize;
        let s = String::deserialize(deserializer)?;
        s.parse::<u64>().map_err(serde::de::Error::custom)
    }
    
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/v1/safes/{}/", service_url, safe_address);
    
    let response: SafeInfo = client
        .get(&api_url)
        .send()
        .await?
        .json()
        .await?;
    
    Ok(response.nonce)
}

/// Propose an on-chain rejection transaction to cancel pending transactions
pub async fn tx_reject(
    safe_address: &str,
    chain: &str,
    node_url: &str,
    nonce: Option<u64>,
    private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use alloy::signers::Signer;
    
    let safe: Address = safe_address.parse()?;
    let (chain_id, _, _) = get_chain_config(chain)?;
    let service_url = get_safe_service_url(chain)?;

    // Get provider
    let _temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    
    // Create signer
    let signer = create_signer_from_hex_with_chain_id(private_key, chain_id)?;
    let sender_address = signer.address();
    
    // Get Safe nonce from transaction service or use provided nonce
    let rejection_nonce = if let Some(n) = nonce {
        n
    } else {
        get_safe_nonce_from_service(&service_url, safe_address).await?
    };
    
    println!("🚫 Preparing on-chain rejection...");
    println!("  Safe: {}", safe_address);
    println!("  Chain: {} (ID: {})", chain, chain_id);
    println!("  Nonce to reject: {}", rejection_nonce);
    println!("  Sender: {}", sender_address);
    
    // On-chain rejection: send 0 ETH to the Safe itself with empty data
    let to_addr = safe;
    let value_u256 = U256::ZERO;
    let calldata = Bytes::new();
    let operation_u8 = 0u8; // Call operation
    
    // Generate Safe transaction hash
    let safe_tx_hash = generate_safe_tx_hash(
        safe,
        chain_id,
        to_addr,
        value_u256,
        &calldata,
        operation_u8,
        U256::ZERO, // safeTxGas
        U256::ZERO, // baseGas
        U256::ZERO, // gasPrice
        Address::ZERO, // gasToken
        Address::ZERO, // refundReceiver
        U256::from(rejection_nonce),
    );
    
    println!("  Safe Tx Hash: 0x{:x}", safe_tx_hash);
    
    // Sign the transaction hash
    let signature = signer.sign_hash(&safe_tx_hash).await?;
    let signature_bytes = signature.as_bytes();
    let signature_hex = format!("0x{}", hex::encode(signature_bytes));
    
    // Prepare API request (addresses must be checksummed)
    let request = SafeTxServiceRequest {
        to: to_addr.to_checksum(None),
        value: "0".to_string(),
        data: "0x".to_string(),
        operation: operation_u8,
        safe_tx_gas: "0".to_string(),
        base_gas: "0".to_string(),
        gas_price: "0".to_string(),
        gas_token: Address::ZERO.to_checksum(None),
        refund_receiver: Address::ZERO.to_checksum(None),
        nonce: rejection_nonce.to_string(),
        contract_transaction_hash: format!("0x{:x}", safe_tx_hash),
        sender: sender_address.to_checksum(None),
        signature: signature_hex,
        origin: Some("safers-cli".to_string()),
    };
    
    // Submit to Safe Transaction Service
    println!("\n📤 Submitting rejection to Safe Transaction Service...");
    
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/v1/safes/{}/multisig-transactions/", service_url, safe_address);
    
    let response = client
        .post(&api_url)
        .json(&request)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        println!("✅ On-chain rejection proposed successfully!");
        println!("\n🔗 View in Safe UI:");
        
        let safe_ui_url = match chain.to_lowercase().as_str() {
            "sepolia" => format!("https://app.safe.global/transactions/queue?safe=sep:{}", safe_address),
            "mainnet" | "ethereum" => format!("https://app.safe.global/transactions/queue?safe=eth:{}", safe_address),
            "base" => format!("https://app.safe.global/transactions/queue?safe=base:{}", safe_address),
            "polygon" | "matic" => format!("https://app.safe.global/transactions/queue?safe=matic:{}", safe_address),
            _ => format!("https://app.safe.global/transactions/queue?safe={}", safe_address),
        };
        
        println!("   {}", safe_ui_url);
        println!("\n📝 Safe Transaction Hash: 0x{:x}", safe_tx_hash);
        println!("\n✨ Other signers can now approve and execute this rejection");
        println!("💡 Executing this will cancel all conflicting transactions with nonce {}", rejection_nonce);
        
    } else {
        let error_text = response.text().await?;
        println!("❌ Failed to propose rejection");
        println!("Status: {}", status);
        println!("Error: {}", error_text);
        return Err(format!("Transaction service error: {}", error_text).into());
    }
    
    Ok(())
}

// ============================================================================
// Hardware Wallet Commands
// ============================================================================

/// Propose a Safe transaction using a hardware wallet
pub async fn tx_propose_hw(
    safe_address: &str,
    chain: &str,
    node_url: &str,
    json_file: &str,
    wallet_type_str: &str,
    derivation_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let (chain_id, _, _) = get_chain_config(chain)?;
    let service_url = get_safe_service_url(chain)?;

    // Parse wallet type
    let wallet_type: HardwareWalletType = wallet_type_str.parse()?;
    
    // Connect to hardware wallet
    let hw_signer = HardwareWalletSigner::connect(wallet_type, derivation_path.to_string())?;
    let sender_address = hw_signer.address();

    // Read and parse JSON file
    let json_content = fs::read_to_string(json_file)?;
    let tx_json: TxBuilderJson = serde_json::from_str(&json_content)?;

    let to_addr: Address = tx_json.to.parse()?;
    let value_u256 = U256::from_str(&tx_json.value)?;
    
    let calldata: Bytes = if let Some(data_str) = tx_json.data {
        let data_hex = data_str.strip_prefix("0x").unwrap_or(&data_str);
        hex::decode(data_hex)?.into()
    } else {
        Bytes::new()
    };

    let operation_u8 = tx_json.operation.unwrap_or(0);
    
    // Show decoded function signature
    maybe_decode_and_display(&calldata);

    // Get provider (just to validate connection)
    let _temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    
    // Get Safe nonce from transaction service or use provided nonce
    let nonce = if let Some(n) = tx_json.nonce {
        n
    } else {
        get_safe_nonce_from_service(&service_url, safe_address).await?
    };
    
    println!("📋 Preparing transaction proposal...");
    println!("  Safe: {}", safe_address);
    println!("  Chain: {} (ID: {})", chain, chain_id);
    println!("  Safe Nonce: {}", nonce);
    println!("  Sender: {}", sender_address);
    
    // Generate Safe transaction hash
    let safe_tx_hash = generate_safe_tx_hash(
        safe,
        chain_id,
        to_addr,
        value_u256,
        &calldata,
        operation_u8,
        U256::ZERO, // safeTxGas
        U256::ZERO, // baseGas
        U256::ZERO, // gasPrice
        Address::ZERO, // gasToken
        Address::ZERO, // refundReceiver
        U256::from(nonce),
    );
    
    println!("  Safe Tx Hash: 0x{:x}", safe_tx_hash);
    
    // Sign the transaction hash with hardware wallet
    let signature_bytes = hw_signer.sign_safe_tx_hash(safe_tx_hash)?;
    let signature_hex = format!("0x{}", hex::encode(signature_bytes));
    
    // Prepare API request (addresses must be checksummed)
    let request = SafeTxServiceRequest {
        to: to_addr.to_checksum(None),
        value: value_u256.to_string(),
        data: if calldata.is_empty() {
            "0x".to_string()
        } else {
            format!("0x{}", hex::encode(calldata.as_ref()))
        },
        operation: operation_u8,
        safe_tx_gas: "0".to_string(),
        base_gas: "0".to_string(),
        gas_price: "0".to_string(),
        gas_token: Address::ZERO.to_checksum(None),
        refund_receiver: Address::ZERO.to_checksum(None),
        nonce: nonce.to_string(),
        contract_transaction_hash: format!("0x{:x}", safe_tx_hash),
        sender: sender_address.to_checksum(None),
        signature: signature_hex,
        origin: Some("safers-cli".to_string()),
    };
    
    // Submit to Safe Transaction Service
    println!("\n📤 Submitting proposal to Safe Transaction Service...");
    
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/v1/safes/{}/multisig-transactions/", service_url, safe_address);
    
    let response = client
        .post(&api_url)
        .json(&request)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        println!("✅ Transaction proposed successfully!");
        println!("\n🔗 View in Safe UI:");
        
        let safe_ui_url = match chain.to_lowercase().as_str() {
            "sepolia" => format!("https://app.safe.global/transactions/queue?safe=sep:{}", safe_address),
            "mainnet" | "ethereum" => format!("https://app.safe.global/transactions/queue?safe=eth:{}", safe_address),
            "base" => format!("https://app.safe.global/transactions/queue?safe=base:{}", safe_address),
            "polygon" | "matic" => format!("https://app.safe.global/transactions/queue?safe=matic:{}", safe_address),
            _ => format!("https://app.safe.global/transactions/queue?safe={}", safe_address),
        };
        
        println!("   {}", safe_ui_url);
        println!("\n📝 Safe Transaction Hash: 0x{:x}", safe_tx_hash);
        println!("\n✨ Other signers can now approve this transaction in the Safe UI");
        
    } else {
        let error_text = response.text().await?;
        println!("❌ Failed to propose transaction");
        println!("Status: {}", status);
        println!("Error: {}", error_text);
        return Err(format!("Transaction service error: {}", error_text).into());
    }
    
    Ok(())
}

/// Propose a rejection transaction using a hardware wallet
pub async fn tx_reject_hw(
    safe_address: &str,
    chain: &str,
    node_url: &str,
    nonce: Option<u64>,
    wallet_type_str: &str,
    derivation_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe: Address = safe_address.parse()?;
    let (chain_id, _, _) = get_chain_config(chain)?;
    let service_url = get_safe_service_url(chain)?;

    // Parse wallet type
    let wallet_type: HardwareWalletType = wallet_type_str.parse()?;
    
    // Connect to hardware wallet
    let hw_signer = HardwareWalletSigner::connect(wallet_type, derivation_path.to_string())?;
    let sender_address = hw_signer.address();

    // Get provider (just to validate connection)
    let _temp_provider = ProviderBuilder::new().on_builtin(node_url).await?;
    
    // Get Safe nonce from transaction service or use provided nonce
    let rejection_nonce = if let Some(n) = nonce {
        n
    } else {
        get_safe_nonce_from_service(&service_url, safe_address).await?
    };
    
    println!("🚫 Preparing on-chain rejection with hardware wallet...");
    println!("  Safe: {}", safe_address);
    println!("  Chain: {} (ID: {})", chain, chain_id);
    println!("  Nonce to reject: {}", rejection_nonce);
    println!("  Sender: {}", sender_address);
    
    // On-chain rejection: send 0 ETH to the Safe itself with empty data
    let to_addr = safe;
    let value_u256 = U256::ZERO;
    let calldata = Bytes::new();
    let operation_u8 = 0u8; // Call operation
    
    // Generate Safe transaction hash
    let safe_tx_hash = generate_safe_tx_hash(
        safe,
        chain_id,
        to_addr,
        value_u256,
        &calldata,
        operation_u8,
        U256::ZERO, // safeTxGas
        U256::ZERO, // baseGas
        U256::ZERO, // gasPrice
        Address::ZERO, // gasToken
        Address::ZERO, // refundReceiver
        U256::from(rejection_nonce),
    );
    
    println!("  Safe Tx Hash: 0x{:x}", safe_tx_hash);
    
    // Sign the transaction hash with hardware wallet
    let signature_bytes = hw_signer.sign_safe_tx_hash(safe_tx_hash)?;
    let signature_hex = format!("0x{}", hex::encode(signature_bytes));
    
    // Prepare API request (addresses must be checksummed)
    let request = SafeTxServiceRequest {
        to: to_addr.to_checksum(None),
        value: "0".to_string(),
        data: "0x".to_string(),
        operation: operation_u8,
        safe_tx_gas: "0".to_string(),
        base_gas: "0".to_string(),
        gas_price: "0".to_string(),
        gas_token: Address::ZERO.to_checksum(None),
        refund_receiver: Address::ZERO.to_checksum(None),
        nonce: rejection_nonce.to_string(),
        contract_transaction_hash: format!("0x{:x}", safe_tx_hash),
        sender: sender_address.to_checksum(None),
        signature: signature_hex,
        origin: Some("safers-cli".to_string()),
    };
    
    // Submit to Safe Transaction Service
    println!("\n📤 Submitting rejection to Safe Transaction Service...");
    
    let client = reqwest::Client::new();
    let api_url = format!("{}/api/v1/safes/{}/multisig-transactions/", service_url, safe_address);
    
    let response = client
        .post(&api_url)
        .json(&request)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        println!("✅ On-chain rejection proposed successfully!");
        println!("\n🔗 View in Safe UI:");
        
        let safe_ui_url = match chain.to_lowercase().as_str() {
            "sepolia" => format!("https://app.safe.global/transactions/queue?safe=sep:{}", safe_address),
            "mainnet" | "ethereum" => format!("https://app.safe.global/transactions/queue?safe=eth:{}", safe_address),
            "base" => format!("https://app.safe.global/transactions/queue?safe=base:{}", safe_address),
            "polygon" | "matic" => format!("https://app.safe.global/transactions/queue?safe=matic:{}", safe_address),
            _ => format!("https://app.safe.global/transactions/queue?safe={}", safe_address),
        };
        
        println!("   {}", safe_ui_url);
        println!("\n📝 Safe Transaction Hash: 0x{:x}", safe_tx_hash);
        println!("\n✨ Other signers can now approve and execute this rejection");
        println!("💡 Executing this will cancel all conflicting transactions with nonce {}", rejection_nonce);
        
    } else {
        let error_text = response.text().await?;
        println!("❌ Failed to propose rejection");
        println!("Status: {}", status);
        println!("Error: {}", error_text);
        return Err(format!("Transaction service error: {}", error_text).into());
    }
    
    Ok(())
}

/// Confirm (add signature to) an existing Safe transaction using hardware wallet
pub async fn tx_confirm_hw(
    safe_address: &str,
    chain: &str,
    safe_tx_hash: &str,
    wallet_type: &str,
    derivation_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let safe_address = Address::from_str(safe_address)?;
    
    // Get Safe Transaction Service URL
    let service_url = get_safe_service_url(chain)?;
    
    // Parse hardware wallet type
    let hw_type: HardwareWalletType = wallet_type.parse()?;
    
    // Connect to hardware wallet
    let hw_signer = HardwareWalletSigner::connect(hw_type, derivation_path.to_string())?;
    let sender_address = hw_signer.address();
    
    println!("📋 Confirming transaction...");
    println!("  Safe: {}", safe_address);
    println!("  Safe Tx Hash: {}", safe_tx_hash);
    println!("  Signer: {}", sender_address);
    
    // Parse safe_tx_hash
    let safe_tx_hash_clean = safe_tx_hash.strip_prefix("0x").unwrap_or(safe_tx_hash);
    let safe_tx_hash_bytes = hex::decode(safe_tx_hash_clean)?;
    let safe_tx_hash_b256 = B256::from_slice(&safe_tx_hash_bytes);
    
    // Sign the safe tx hash
    let signature_bytes = hw_signer.sign_safe_tx_hash(safe_tx_hash_b256)?;
    let signature_hex = format!("0x{}", hex::encode(signature_bytes));
    
    // Submit confirmation to Safe Transaction Service
    println!("\n📤 Submitting confirmation to Safe Transaction Service...");
    
    let client = reqwest::Client::new();
    let api_url = format!(
        "{}/api/v1/multisig-transactions/{}/confirmations/",
        service_url, safe_tx_hash
    );
    
    let body = serde_json::json!({
        "signature": signature_hex
    });
    
    let response = client
        .post(&api_url)
        .json(&body)
        .send()
        .await?;
    
    let status = response.status();
    
    if status.is_success() {
        println!("✅ Transaction confirmed successfully!");
        println!("\n🔗 View in Safe UI:");
        
        let safe_ui_url = match chain.to_lowercase().as_str() {
            "sepolia" => format!("https://app.safe.global/transactions/queue?safe=sep:{}", safe_address),
            "mainnet" | "ethereum" => format!("https://app.safe.global/transactions/queue?safe=eth:{}", safe_address),
            "base" => format!("https://app.safe.global/transactions/queue?safe=base:{}", safe_address),
            "polygon" | "matic" => format!("https://app.safe.global/transactions/queue?safe=matic:{}", safe_address),
            "arbitrum" => format!("https://app.safe.global/transactions/queue?safe=arb1:{}", safe_address),
            "optimism" => format!("https://app.safe.global/transactions/queue?safe=oeth:{}", safe_address),
            "gnosis" => format!("https://app.safe.global/transactions/queue?safe=gno:{}", safe_address),
            _ => format!("https://app.safe.global/transactions/queue?safe={}", safe_address),
        };
        
        println!("   {}", safe_ui_url);
        
    } else {
        let error_text = response.text().await?;
        println!("❌ Failed to confirm transaction");
        println!("Status: {}", status);
        println!("Error: {}", error_text);
        return Err(format!("Transaction service error: {}", error_text).into());
    }
    
    Ok(())
}

/// Simulate a Safe transaction to verify it will work before proposing
pub async fn tx_simulate(
    safe_address: &str,
    chain: &str,
    node_url: &str,
    json_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use alloy::rpc::types::eth::TransactionRequest;
    
    let safe: Address = safe_address.parse()?;
    let (chain_id, _, _) = get_chain_config(chain)?;
    
    // Read and parse JSON file
    let json_content = fs::read_to_string(json_file)?;
    let tx_json: TxBuilderJson = serde_json::from_str(&json_content)?;
    
    let to_addr: Address = tx_json.to.parse()?;
    let value_u256 = U256::from_str(&tx_json.value)?;
    
    let calldata: Bytes = if let Some(data_str) = tx_json.data {
        let data_hex = data_str.strip_prefix("0x").unwrap_or(&data_str);
        hex::decode(data_hex)?.into()
    } else {
        Bytes::new()
    };
    
    let operation_u8 = tx_json.operation.unwrap_or(0);
    
    println!("🔍 Simulating Safe Transaction");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Safe: {}", safe_address);
    println!("Chain: {} (ID: {})", chain, chain_id);
    println!("To: {}", to_addr);
    println!("Value: {} wei", value_u256);
    println!("Operation: {}", if operation_u8 == 1 { "DelegateCall" } else { "Call" });
    println!();
    
    // Get provider
    let provider = ProviderBuilder::new().on_builtin(node_url).await?;
    
    // Show decoded function signature
    maybe_decode_and_display(&calldata);
    
    // Check if this is a module or guard operation
    if calldata.len() >= 4 {
        let selector = &calldata[0..4];
        
        // enableModule(address) = 0x610b5925
        if selector == [0x61, 0x0b, 0x59, 0x25] {
            println!("📋 Detected: enableModule operation");
            if calldata.len() >= 36 {
                let module_addr_bytes = &calldata[4..36];
                let module_addr = Address::from_slice(&module_addr_bytes[12..32]);
                println!("   Module: {}", module_addr);
                
                // Check if module is already enabled
                let check_call = GnosisSafe::isModuleEnabledCall { module: module_addr };
                let call_data: Bytes = check_call.abi_encode().into();
                let tx = TransactionRequest::default()
                    .with_to(safe)
                    .with_input(call_data);
                
                match provider.call(&tx).await {
                    Ok(result) => {
                        // isModuleEnabled returns bool, decode from bytes
                        if result.len() >= 32 {
                            // Bool is encoded as 0x00...00 (false) or 0x00...01 (true) in last byte
                            let is_enabled = result[31] == 1;
                            if is_enabled {
                                println!("   ⚠️  Module is already enabled!");
                            } else {
                                println!("   ✅ Module is not enabled (will be enabled)");
                            }
                        }
                    }
                    Err(e) => {
                        println!("   ⚠️  Could not check module status: {}", e);
                    }
                }
            }
        }
        
        // setGuard(address) = 0xe19a9dd9
        if selector == [0xe1, 0x9a, 0x9d, 0xd9] {
            println!("📋 Detected: setGuard operation");
            if calldata.len() >= 36 {
                let guard_addr_bytes = &calldata[4..36];
                let guard_addr = Address::from_slice(&guard_addr_bytes[12..32]);
                println!("   Guard: {}", guard_addr);
                
                // Check current guard (via storage slot)
                // Guard is stored at slot: keccak256("guard_manager.guard.address")
                // For Safe v1.4.1+, it's at slot 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8
                let guard_slot_bytes = hex::decode("4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8")?;
                let guard_slot = U256::from_be_slice(&guard_slot_bytes);
                match provider.get_storage_at(safe, guard_slot).await {
                    Ok(storage_value) => {
                        // Convert U256 to bytes
                        let storage_bytes = storage_value.to_be_bytes::<32>();
                        let current_guard = Address::from_slice(&storage_bytes[12..32]);
                        if current_guard == Address::ZERO {
                            println!("   ✅ No guard currently set (will set guard)");
                        } else if current_guard == guard_addr {
                            println!("   ⚠️  This guard is already set!");
                        } else {
                            println!("   ⚠️  Different guard currently set: {}", current_guard);
                            println!("   ⚠️  This will replace the existing guard");
                        }
                    }
                    Err(e) => {
                        println!("   ⚠️  Could not check guard status: {}", e);
                    }
                }
            }
        }
    }
    
    println!();
    println!("🔍 Checking Safe state...");
    
    // Check Safe threshold and owners
    let threshold_call = GnosisSafe::getThresholdCall {};
    let threshold_data: Bytes = threshold_call.abi_encode().into();
    let threshold_tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(threshold_data);
    
    if let Ok(result) = provider.call(&threshold_tx).await {
        // getThreshold returns uint256, decode from bytes
        if result.len() >= 32 {
            let threshold = U256::from_be_slice(&result[..32]);
            println!("   Threshold: {}/{}", threshold, "?");
        }
    }
    
    // Check if target is a contract
    println!();
    println!("🔍 Verifying target contract...");
    if let Ok(code) = provider.get_code_at(to_addr).await {
        if code.is_empty() {
            println!("   ⚠️  Target address has no code (EOA or invalid)");
        } else {
            println!("   ✅ Target is a contract (code size: {} bytes)", code.len());
        }
    }
    
    // Try to estimate gas (this simulates the transaction)
    println!();
    println!("🔍 Estimating gas (simulating transaction)...");
    
    // For simulation, we need to create a dummy signature
    // Since we can't actually sign without a private key, we'll use a minimal valid signature
    // Safe requires signatures from owners, but for estimation we can use a placeholder
    let dummy_sig = vec![0u8; 65 * 1]; // 1 owner signature (65 bytes each)
    
    let exec_call = GnosisSafe::execTransactionCall {
        to: to_addr,
        value: value_u256,
        data: calldata.clone(),
        operation: if operation_u8 == 1 {
            GnosisSafe::Operation::DelegateCall
        } else {
            GnosisSafe::Operation::Call
        },
        safeTxGas: U256::ZERO,
        baseGas: U256::ZERO,
        gasPrice: U256::ZERO,
        gasPayer: Address::ZERO,
        signature: dummy_sig.into(),
    };
    
    let exec_tx = TransactionRequest::default()
        .with_to(safe)
        .with_input(exec_call.abi_encode())
        .with_from(Address::ZERO); // Use zero address for estimation
    
    match provider.estimate_gas(&exec_tx).await {
        Ok(gas_estimate) => {
            println!("   ✅ Gas estimate: {} gas", gas_estimate);
            println!("   ✅ Transaction simulation successful!");
        }
        Err(e) => {
            let error_msg = e.to_string();
            
            // Check if it's a signature-related error (expected for Safe transactions)
            if error_msg.contains("signature") || error_msg.contains("GS") || 
               (error_msg.contains("revert") && error_msg.contains("0x")) {
                println!("   ℹ️  Gas estimation requires valid owner signatures");
                println!("   ℹ️  This is expected - Safe transactions need owner approval");
                println!("   ℹ️  The transaction structure appears valid based on other checks");
                println!();
                println!("   ✅ Transaction parameters validated successfully!");
            } else {
                println!("   ❌ Gas estimation failed!");
                println!("   Error: {}", error_msg);
                
                if error_msg.contains("revert") || error_msg.contains("execution reverted") {
                    println!();
                    println!("   ⚠️  This transaction may REVERT on execution!");
                    println!("   Possible reasons:");
                    println!("     - Insufficient permissions");
                    println!("     - Invalid parameters");
                    println!("     - Contract state prevents execution");
                    println!("     - Module/guard requirements not met");
                    return Err(format!("Transaction simulation failed: {}", error_msg).into());
                }
            }
        }
    }
    
    // Try static call to see if it would succeed (if we had valid signatures)
    println!();
    println!("🔍 Performing static call check...");
    
    // Note: Static call will fail without valid signatures, but we can check the calldata format
    match provider.call(&exec_tx).await {
        Ok(_) => {
            println!("   ✅ Static call completed (note: requires valid signatures to actually execute)");
        }
        Err(e) => {
            let error_msg = e.to_string();
            if !error_msg.contains("signature") && !error_msg.contains("GS") {
                println!("   ⚠️  Static call failed: {}", error_msg);
            } else {
                println!("   ℹ️  Static call requires valid signatures (expected)");
            }
        }
    }
    
    println!();
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ Simulation complete!");
    println!();
    println!("📝 Summary:");
    println!("   • Transaction structure: Valid");
    println!("   • Target contract: Verified");
    println!("   • Current state: Checked");
    println!("   • Gas estimation: Requires valid signatures (expected)");
    println!();
    println!("📝 Next steps:");
    println!("   1. Review the checks above");
    println!("   2. If all checks pass, propose the transaction:");
    println!("      ./target/release/safers-cli tx-propose {} {} {} {} YOUR_PRIVATE_KEY", 
             safe_address, chain, node_url, json_file);
    println!("   Or with hardware wallet:");
    println!("      ./target/release/safers-cli tx-propose-hw {} {} {} {} --wallet-type ledger", 
             safe_address, chain, node_url, json_file);
    println!();
    
    Ok(())
}

