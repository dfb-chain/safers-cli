use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use alloy::providers::Provider;

/// Helper function to create signer from hex-encoded private key with chain ID
pub fn create_signer_from_hex_with_chain_id(private_key_hex: &str, chain_id: u64) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let bytes = hex::decode(private_key_hex)?;
    let b256 = B256::from_slice(&bytes);
    let signer = PrivateKeySigner::from_bytes(&b256)?;
    Ok(signer.with_chain_id(Some(chain_id)))
}

/// Map chain name to chain ID and Safe contract addresses
pub fn get_chain_config(chain: &str) -> Result<(u64, Address, Address), Box<dyn std::error::Error>> {
    match chain.to_lowercase().as_str() {
        "sepolia" => Ok((
            11155111,
            "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2".parse()?, // ProxyFactory
            "0xc650B598b095613cCddF0f49570FfA475175A5D5".parse()?, // Singleton
        )),
        "mainnet" | "ethereum" => Ok((
            1,
            "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2".parse()?,
            "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552".parse()?,
        )),
        "base" => Ok((
            8453,
            "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2".parse()?, // ProxyFactory
            "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552".parse()?, // Singleton
        )),
        "polygon" | "matic" => Ok((
            137,
            "0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2".parse()?, // ProxyFactory
            "0xd9Db270c1B5E3Bd161E8c8503c55cEABeE709552".parse()?, // Singleton
        )),
        _ => Err(format!("Unsupported chain: {}", chain).into()),
    }
}

/// Get Safe Transaction Service URL for a chain
pub fn get_safe_service_url(chain: &str) -> Result<String, Box<dyn std::error::Error>> {
    match chain.to_lowercase().as_str() {
        "sepolia" => Ok("https://safe-transaction-sepolia.safe.global".to_string()),
        "mainnet" | "ethereum" => Ok("https://safe-transaction-mainnet.safe.global".to_string()),
        "base" => Ok("https://safe-transaction-base.safe.global".to_string()),
        "polygon" | "matic" => Ok("https://safe-transaction-polygon.safe.global".to_string()),
        _ => Err(format!("No Safe Transaction Service for chain: {}", chain).into()),
    }
}

/// Generate EIP-712 Safe transaction hash
pub fn generate_safe_tx_hash(
    safe_address: Address,
    chain_id: u64,
    to: Address,
    value: U256,
    data: &Bytes,
    operation: u8,
    safe_tx_gas: U256,
    base_gas: U256,
    gas_price: U256,
    gas_token: Address,
    refund_receiver: Address,
    safe_nonce: U256,
) -> B256 {
    // EIP-712 domain separator
    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    let domain_separator_type_hash = keccak256(b"EIP712Domain(uint256 chainId,address verifyingContract)");
    
    let domain_separator = keccak256(
        [
            domain_separator_type_hash.as_slice(),
            &encode_uint256(U256::from(chain_id)),
            &encode_address(safe_address),
        ].concat()
    );
    
    // Safe transaction type hash
    // keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")
    let safe_tx_type_hash = keccak256(b"SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)");
    
    let data_hash = keccak256(data.as_ref());
    
    let safe_tx_hash = keccak256(
        [
            safe_tx_type_hash.as_slice(),
            &encode_address(to),
            &encode_uint256(value),
            data_hash.as_slice(),
            &encode_uint8(operation),
            &encode_uint256(safe_tx_gas),
            &encode_uint256(base_gas),
            &encode_uint256(gas_price),
            &encode_address(gas_token),
            &encode_address(refund_receiver),
            &encode_uint256(safe_nonce),
        ].concat()
    );
    
    // Final EIP-712 hash: keccak256("\x19\x01" + domainSeparator + safeTxHash)
    keccak256(
        [
            &[0x19, 0x01],
            domain_separator.as_slice(),
            safe_tx_hash.as_slice(),
        ].concat()
    )
}

/// Sign Safe transaction with multiple signers
pub async fn sign_safe_transaction<P: Provider>(
    provider: &P,
    safe_address: Address,
    chain_id: u64,
    to: Address,
    value: U256,
    data: &Bytes,
    operation: u8,
    signers: Vec<PrivateKeySigner>,
) -> Result<Bytes, Box<dyn std::error::Error>> {
    // Get Safe nonce
    let safe_nonce = get_safe_nonce(provider, safe_address).await?;
    
    let tx_hash = generate_safe_tx_hash(
        safe_address,
        chain_id,
        to,
        value,
        data,
        operation,
        U256::ZERO, // safeTxGas
        U256::ZERO, // baseGas
        U256::ZERO, // gasPrice
        Address::ZERO, // gasToken
        Address::ZERO, // refundReceiver
        safe_nonce,
    );
    
    // Sign with all signers and sort by signer address (Safe requires sorted signatures)
    let mut signatures: Vec<(Address, Vec<u8>)> = Vec::new();
    
    for signer in signers {
        let sig = signer.sign_hash(&tx_hash).await?;
        // Convert signature to bytes (r, s, v format)
        let sig_bytes = sig.as_bytes();
        signatures.push((signer.address(), sig_bytes.to_vec()));
    }
    
    // Sort by address (Safe requires this)
    signatures.sort_by_key(|(addr, _)| *addr);
    
    // Concatenate signatures
    let mut all_sig_bytes = Vec::new();
    for (_, sig) in signatures {
        all_sig_bytes.extend_from_slice(&sig);
    }
    
    Ok(Bytes::from(all_sig_bytes))
}

/// Get Safe nonce from the contract
async fn get_safe_nonce<P: Provider>(
    provider: &P,
    safe_address: Address,
) -> Result<U256, Box<dyn std::error::Error>> {
    use alloy::sol;
    use alloy_sol_types::SolCall;
    
    // nonce() function selector
    sol! {
        function nonce() external view returns (uint256);
    }
    
    let call = nonceCall {};
    let call_data = call.abi_encode();
    
    let tx = alloy::rpc::types::eth::TransactionRequest::default()
        .to(safe_address)
        .input(call_data.into());
    
    let result = provider.call(&tx).await?;
    
    // Decode the result
    if result.len() >= 32 {
        Ok(U256::from_be_slice(&result[..32]))
    } else {
        Ok(U256::ZERO)
    }
}

// Helper functions for EIP-712 encoding
fn encode_uint256(value: U256) -> [u8; 32] {
    value.to_be_bytes()
}

fn encode_address(addr: Address) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[12..32].copy_from_slice(addr.as_slice());
    bytes
}

fn encode_uint8(value: u8) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    bytes
}

