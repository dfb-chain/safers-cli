mod cli;
mod commands;
mod contracts;
mod hardware_wallet;
mod signatures;
mod types;
mod utils;

use clap::Parser;
use cli::{Cli, Commands};
use tokio::runtime::Runtime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let rt = Runtime::new()?;
    rt.block_on(async {
        match cli.command {
            Commands::SafeCreator {
                node_url,
                chain,
                private_key,
                threshold,
                owners,
            } => commands::safe_creator(&node_url, &chain, &private_key, threshold, owners).await,
            Commands::SendEther {
                safe_address,
                node_url,
                to,
                amount,
                private_keys,
            } => commands::send_ether(&safe_address, &node_url, &to, amount, &private_keys).await,
            Commands::SendErc20 {
                safe_address,
                node_url,
                token_address,
                to,
                amount,
                private_keys,
            } => commands::send_erc20(&safe_address, &node_url, &token_address, &to, &amount, &private_keys).await,
            Commands::SendErc721 {
                safe_address,
                node_url,
                token_address,
                to,
                token_id,
                private_keys,
            } => commands::send_erc721(&safe_address, &node_url, &token_address, &to, &token_id, &private_keys).await,
            Commands::SendCustom {
                safe_address,
                node_url,
                to,
                value,
                data,
                private_keys,
            } => commands::send_custom(&safe_address, &node_url, &to, value, &data, &private_keys).await,
            Commands::TxBuilder {
                safe_address,
                node_url,
                json_file,
                private_keys,
            } => commands::tx_builder(&safe_address, &node_url, &json_file, &private_keys).await,
            Commands::SigSync { limit } => commands::sig_sync(limit).await,
            Commands::SigLookup { signature } => commands::sig_lookup(&signature).await,
            Commands::SigDecode { calldata } => commands::sig_decode(&calldata).await,
            Commands::SigStats => commands::sig_stats().await,
            Commands::TxPropose {
                safe_address,
                chain,
                node_url,
                json_file,
                private_key,
            } => commands::tx_propose(&safe_address, &chain, &node_url, &json_file, &private_key).await,
            Commands::TxReject {
                safe_address,
                chain,
                node_url,
                nonce,
                private_key,
            } => commands::tx_reject(&safe_address, &chain, &node_url, nonce, &private_key).await,
            Commands::TxProposeHw {
                safe_address,
                chain,
                node_url,
                json_file,
                wallet_type,
                derivation_path,
            } => commands::tx_propose_hw(&safe_address, &chain, &node_url, &json_file, &wallet_type, &derivation_path).await,
            Commands::TxRejectHw {
                safe_address,
                chain,
                node_url,
                nonce,
                wallet_type,
                derivation_path,
            } => commands::tx_reject_hw(&safe_address, &chain, &node_url, nonce, &wallet_type, &derivation_path).await,
            Commands::TxConfirmHw {
                safe_address,
                chain,
                safe_tx_hash,
                wallet_type,
                derivation_path,
            } => commands::tx_confirm_hw(&safe_address, &chain, &safe_tx_hash, &wallet_type, &derivation_path).await,
            Commands::TxSimulate {
                safe_address,
                chain,
                node_url,
                json_file,
            } => commands::tx_simulate(&safe_address, &chain, &node_url, &json_file).await,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256};
    use contracts::{ERC20, ERC721, GnosisSafe, ProxyFactory};
    use std::str::FromStr;
    use alloy_sol_types::SolCall;
    use types::TxBuilderJson;

    #[test]
    fn test_address_parsing() {
        let valid_address = "0x1234567890123456789012345678901234567890";
        let result = Address::from_str(valid_address);
        assert!(result.is_ok());
    }

    #[test]
    fn test_invalid_address_parsing() {
        let invalid_address = "0xinvalid";
        let result = Address::from_str(invalid_address);
        assert!(result.is_err());
    }

    #[test]
    fn test_u256_parsing() {
        let amount = "1000000000000000000"; // 1 ETH in wei
        let result = U256::from_str(amount);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), U256::from(1000000000000000000u128));
    }

    #[test]
    fn test_u256_large_number() {
        let large_amount = "1000000000000000000000000"; // 1 million tokens with 18 decimals
        let result = U256::from_str(large_amount);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hex_decode_with_prefix() {
        let hex_with_prefix = "0x1234abcd";
        let stripped = hex_with_prefix.strip_prefix("0x").unwrap_or(hex_with_prefix);
        let result = hex::decode(stripped);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_hex_decode_without_prefix() {
        let hex_without_prefix = "1234abcd";
        let result = hex::decode(hex_without_prefix);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_private_key_parsing() {
        let valid_pk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let result = hex::decode(valid_pk);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn test_private_key_comma_split() {
        let keys_str = "pk1,pk2,pk3";
        let keys: Vec<&str> = keys_str.split(',').map(|s| s.trim()).collect();
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0], "pk1");
        assert_eq!(keys[1], "pk2");
        assert_eq!(keys[2], "pk3");
    }

    #[test]
    fn test_tx_builder_json_parsing() {
        let json = r#"{
            "to": "0x1234567890123456789012345678901234567890",
            "value": "1000000000000000000",
            "data": "0x1234",
            "operation": 0
        }"#;
        let result: Result<TxBuilderJson, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.to, "0x1234567890123456789012345678901234567890");
        assert_eq!(tx.value, "1000000000000000000");
        assert_eq!(tx.data, Some("0x1234".to_string()));
        assert_eq!(tx.operation, Some(0));
    }

    #[test]
    fn test_tx_builder_json_optional_fields() {
        let json = r#"{
            "to": "0x1234567890123456789012345678901234567890",
            "value": "0"
        }"#;
        let result: Result<TxBuilderJson, _> = serde_json::from_str(json);
        assert!(result.is_ok());
        let tx = result.unwrap();
        assert_eq!(tx.data, None);
        assert_eq!(tx.operation, None);
    }

    #[test]
    fn test_erc20_transfer_call_encoding() {
        let to = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let amount = U256::from(1000000000000000000u128);
        
        let call = ERC20::transferCall {
            to,
            amount,
        };
        
        let encoded = call.abi_encode();
        assert!(!encoded.is_empty());
        // First 4 bytes should be the function selector for transfer(address,uint256)
        assert_eq!(encoded.len(), 68); // 4 bytes selector + 32 bytes address + 32 bytes amount
    }

    #[test]
    fn test_erc721_transfer_call_encoding() {
        let from = Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let to = Address::from_str("0x2222222222222222222222222222222222222222").unwrap();
        let token_id = U256::from(123u128);
        
        let call = ERC721::safeTransferFromCall {
            from,
            to,
            tokenId: token_id,
        };
        
        let encoded = call.abi_encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_gnosis_safe_operation_enum() {
        // Test that both operation types can be constructed
        let _call_op = GnosisSafe::Operation::Call;
        let _delegatecall_op = GnosisSafe::Operation::DelegateCall;
        // Operations exist and can be used
    }

    #[test]
    fn test_owners_parsing_from_comma_separated() {
        let owners_str = "0x1111111111111111111111111111111111111111,0x2222222222222222222222222222222222222222";
        let owners: Result<Vec<Address>, _> = owners_str
            .split(',')
            .map(|o| Address::from_str(o.trim()))
            .collect();
        
        assert!(owners.is_ok());
        assert_eq!(owners.unwrap().len(), 2);
    }

    #[test]
    fn test_threshold_validation() {
        let threshold = 2u32;
        let owners_count = 3usize;
        assert!(threshold as usize <= owners_count);
        
        let invalid_threshold = 5u32;
        assert!(invalid_threshold as usize > owners_count);
    }

    #[test]
    fn test_bytes_from_hex() {
        let hex_str = "1234abcd";
        let bytes = hex::decode(hex_str).unwrap();
        let alloy_bytes: Bytes = bytes.into();
        assert_eq!(alloy_bytes.len(), 4);
    }

    #[test]
    fn test_empty_bytes() {
        let empty = Bytes::new();
        assert_eq!(empty.len(), 0);
    }

    #[test]
    fn test_proxy_factory_call_encoding() {
        let singleton = Address::from_str("0xc650B598b095613cCddF0f49570FfA475175A5D5").unwrap();
        let initializer: Bytes = vec![0u8; 32].into();
        let salt_nonce = U256::ZERO;
        
        let call = ProxyFactory::createProxyWithNonceCall {
            singleton,
            initializer,
            saltNonce: salt_nonce,
        };
        
        let encoded = call.abi_encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_gnosis_safe_setup_call() {
        let owners = vec![
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap()
        ];
        let threshold = U256::from(1u32);
        
        let call = GnosisSafe::setupCall {
            owners,
            threshold,
            to: Address::ZERO,
            data: Bytes::new(),
            fallbackHandler: Address::ZERO,
            paymentToken: Address::ZERO,
            payment: U256::ZERO,
            paymentReceiver: Address::ZERO,
        };
        
        let encoded = call.abi_encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_gnosis_safe_exec_transaction_call() {
        let to = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let value = U256::from(1000000000000000000u128);
        
        let call = GnosisSafe::execTransactionCall {
            to,
            value,
            data: Bytes::new(),
            operation: GnosisSafe::Operation::Call,
            safeTxGas: U256::ZERO,
            baseGas: U256::ZERO,
            gasPrice: U256::ZERO,
            gasPayer: Address::ZERO,
            signature: Bytes::new(),
        };
        
        let encoded = call.abi_encode();
        assert!(!encoded.is_empty());
    }
}
