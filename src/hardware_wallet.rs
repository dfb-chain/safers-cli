// Hardware wallet support for Trezor Model One, Ledger Nano X, and Ledger Flex
use alloy::primitives::{Address, B256, keccak256};

#[derive(Debug, Clone)]
pub enum HardwareWalletType {
    TrezorOne,
    LedgerNanoX,
    LedgerFlex,
}

impl std::str::FromStr for HardwareWalletType {
    type Err = String;
    
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "trezor" | "trezor-one" | "trezor_one" | "trezor1" => Ok(HardwareWalletType::TrezorOne),
            "ledger" | "ledger-nano-x" | "ledger_nano_x" | "nano-x" => Ok(HardwareWalletType::LedgerNanoX),
            "ledger-flex" | "ledger_flex" | "nano-flex" | "nano_flex" | "flex" => Ok(HardwareWalletType::LedgerFlex),
            _ => Err(format!("Unknown hardware wallet type: {}. Use 'trezor', 'ledger', 'ledger-flex', or 'nano-flex'", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HardwareWalletInfo {
    pub wallet_type: HardwareWalletType,
    pub address: Address,
    pub derivation_path: String,
    pub device_id: Option<String>,
}

pub struct HardwareWalletSigner {
    pub wallet_type: HardwareWalletType,
    pub address: Address,
    pub derivation_path: String,
}

impl HardwareWalletSigner {
    /// Connect to a hardware wallet and get the address at a specific derivation path
    pub fn connect(
        wallet_type: HardwareWalletType,
        derivation_path: String,
    ) -> Result<Self, String> {
        let info = match wallet_type {
            HardwareWalletType::LedgerNanoX | HardwareWalletType::LedgerFlex => {
                #[cfg(feature = "ledger")]
                {
                    ledger_impl::connect_ledger(wallet_type, derivation_path)?
                }
                #[cfg(not(feature = "ledger"))]
                {
                    return Err("Ledger support not compiled. Enable 'ledger' feature.".to_string());
                }
            }
            HardwareWalletType::TrezorOne => {
                #[cfg(feature = "trezor")]
                {
                    trezor_impl::connect_trezor(derivation_path)?
                }
                #[cfg(not(feature = "trezor"))]
                {
                    return Err("Trezor support not compiled. Enable 'trezor' feature.".to_string());
                }
            }
        };
        
        Ok(Self {
            wallet_type: info.wallet_type,
            address: info.address,
            derivation_path: info.derivation_path,
        })
    }

    /// Sign a Safe transaction hash with the hardware wallet (EIP-191 personal sign)
    /// Returns raw signature bytes [r (32) + s (32) + v (1)] with v = 31 or 32 for eth_sign
    pub fn sign_safe_tx_hash(&self, safe_tx_hash: B256) -> Result<[u8; 65], String> {
        match self.wallet_type {
            HardwareWalletType::LedgerNanoX | HardwareWalletType::LedgerFlex => {
                #[cfg(feature = "ledger")]
                {
                    // For Safe tx hash, we sign the raw hash with personal_sign
                    // The hash is already calculated, we need to apply EIP-191 prefix
                    let prefixed_message = format!(
                        "\x19Ethereum Signed Message:\n{}",
                        safe_tx_hash.len()
                    );
                    let mut message = prefixed_message.as_bytes().to_vec();
                    message.extend_from_slice(safe_tx_hash.as_slice());
                    let final_hash = keccak256(&message);
                    
                    ledger_impl::sign_with_ledger(&self.derivation_path, final_hash.as_slice())
                }
                #[cfg(not(feature = "ledger"))]
                {
                    Err("Ledger support not compiled".to_string())
                }
            }
            HardwareWalletType::TrezorOne => {
                #[cfg(feature = "trezor")]
                {
                    // Trezor's ethereum_sign_message applies EIP-191 internally
                    // We pass the raw Safe tx hash bytes
                    // Use combined connect-and-sign to maintain passphrase session
                    trezor_impl::connect_and_sign_trezor(&self.derivation_path, safe_tx_hash.as_slice(), &self.address)
                }
                #[cfg(not(feature = "trezor"))]
                {
                    Err("Trezor support not compiled".to_string())
                }
            }
        }
    }
    
    /// Get the address of the connected wallet
    pub fn address(&self) -> Address {
        self.address
    }
}

// ============================================================================
// Trezor Implementation
// ============================================================================

#[cfg(feature = "trezor")]
mod trezor_impl {
    use super::*;
    use trezor_client::{find_devices, Trezor, TrezorResponse};
    use std::io::{self, Write};
    
    fn prompt_passphrase() -> String {
        println!("\n🔐 Passphrase (Hidden Wallet)");
        println!("If you use a passphrase with your Trezor, enter it now.");
        println!("If you don't use a passphrase, just press ENTER.");
        print!("\nPassphrase: ");
        io::stdout().flush().unwrap();
        
        let mut passphrase = String::new();
        io::stdin().read_line(&mut passphrase).unwrap();
        passphrase.trim().to_string()
    }
    
    // Store passphrase for the session
    static PASSPHRASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    
    fn get_or_prompt_passphrase() -> String {
        PASSPHRASE.get_or_init(|| prompt_passphrase()).clone()
    }
    
    fn prompt_unlock() {
        println!("\n🔐 Your Trezor is locked!");
        println!("\nPlease unlock it first:");
        println!("  1. Open Trezor Suite (or go to suite.trezor.io)");
        println!("  2. Enter your PIN on the Trezor device");
        println!("  3. Once unlocked, press ENTER here to continue...");
        print!("\nPress ENTER when ready: ");
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
    }
    
    /// Custom interaction handler that supports passphrase entry from host
    fn handle_interaction_with_passphrase<T, R: trezor_client::TrezorMessage>(
        resp: TrezorResponse<'_, T, R>,
        passphrase: &str,
    ) -> Result<T, String> {
        match resp {
            TrezorResponse::Ok(res) => Ok(res),
            TrezorResponse::Failure(f) => {
                Err(format!("Trezor failure: {:?}", f.message()))
            }
            TrezorResponse::ButtonRequest(req) => {
                println!("📱 Please confirm on your Trezor...");
                handle_interaction_with_passphrase(
                    req.ack().map_err(|e| format!("Button ack failed: {}", e))?,
                    passphrase,
                )
            }
            TrezorResponse::PinMatrixRequest(_) => {
                Err("PIN entry required. Please unlock your Trezor first using Trezor Suite.".to_string())
            }
            TrezorResponse::PassphraseRequest(req) => {
                // ALWAYS send passphrase from host for Trezor Model One
                // Model One doesn't have a keyboard, so on-device entry isn't possible
                // Even if the device settings say "on_device", we must send from host
                println!("🔐 Sending passphrase to device...");
                handle_interaction_with_passphrase(
                    req.ack_passphrase(passphrase.to_string())
                        .map_err(|e| format!("Passphrase ack failed: {}", e))?,
                    passphrase,
                )
            }
        }
    }
    
    /// Get Ethereum address with passphrase support
    fn get_ethereum_address_with_passphrase(
        trezor: &mut Trezor,
        path: Vec<u32>,
        passphrase: &str,
    ) -> Result<String, String> {
        use trezor_client::protos;
        
        let mut req = protos::EthereumGetAddress::new();
        req.address_n = path;
        
        let resp = trezor.call(req, Box::new(|_, m: protos::EthereumAddress| Ok(m.address().to_string())))
            .map_err(|e| format!("Failed to call Trezor: {}", e))?;
        
        handle_interaction_with_passphrase(resp, passphrase)
    }
    
    /// Sign Ethereum message with passphrase support
    fn sign_ethereum_message_with_passphrase(
        trezor: &mut Trezor,
        message: Vec<u8>,
        path: Vec<u32>,
        passphrase: &str,
    ) -> Result<trezor_client::client::Signature, String> {
        use trezor_client::protos;
        use trezor_client::client::Signature;
        use trezor_client::Error;
        
        let mut req = protos::EthereumSignMessage::new();
        req.address_n = path;
        req.set_message(message);
        
        let resp = trezor.call(
            req,
            Box::new(|_, m: protos::EthereumMessageSignature| {
                let signature = m.signature();
                if signature.len() != 65 {
                    return Err(Error::MalformedSignature);
                }
                let r = signature[0..32].try_into().unwrap();
                let s = signature[32..64].try_into().unwrap();
                let v = signature[64] as u64;
                Ok(Signature { r, s, v })
            }),
        ).map_err(|e| format!("Failed to call Trezor: {}", e))?;
        
        handle_interaction_with_passphrase(resp, passphrase)
    }
    
    fn parse_derivation_path(path: &str) -> Result<Vec<u32>, String> {
        if !path.starts_with("m/") {
            return Err("Derivation path must start with 'm/'".to_string());
        }
        
        let parts: Vec<&str> = path[2..].split('/').collect();
        let mut indices = Vec::new();
        
        for part in parts {
            let hardened = part.ends_with('\'');
            let num_str = if hardened { &part[..part.len() - 1] } else { part };
            let num = num_str.parse::<u32>()
                .map_err(|_| format!("Invalid derivation path segment: {}", part))?;
            
            // Apply hardened bit (0x80000000)
            let index = if hardened {
                num | 0x80000000
            } else {
                num
            };
            indices.push(index);
        }
        
        Ok(indices)
    }
    
    pub fn connect_trezor(derivation_path: String) -> Result<HardwareWalletInfo, String> {
        println!("🔌 Connecting to Trezor...");
        
        // Prompt for passphrase first (for Trezor Model One, entered on computer)
        let passphrase = get_or_prompt_passphrase();
        
        // Find available Trezor devices
        let available_devices = find_devices(false);
        
        if available_devices.is_empty() {
            return Err("No Trezor device found. Make sure it's connected and unlocked.".to_string());
        }
        
        // Connect to the first available device
        let device = available_devices.into_iter().next().unwrap();
        let device_id = Some("Trezor Device #1".to_string());
        
        let mut trezor = match device.connect() {
            Ok(t) => t,
            Err(e) => {
                let error_str = e.to_string().to_lowercase();
                if error_str.contains("pin") || error_str.contains("locked") {
                    return Err("Trezor is locked. Please unlock it on the device.".to_string());
                }
                return Err(format!("Failed to connect to Trezor device: {}", e));
            }
        };
        
        // Initialize device (without passphrase - passphrase is handled during operations)
        if let Err(e) = trezor.init_device(None) {
            let error_str = e.to_string().to_lowercase();
            if !error_str.contains("already initialized") {
                return Err(format!("Failed to initialize Trezor: {}", e));
            }
        }
        
        // Parse derivation path
        let path_indices = parse_derivation_path(&derivation_path)?;
        
        println!("🔑 Getting address for path: {}", derivation_path);
        if !passphrase.is_empty() {
            println!("🔐 Using passphrase for hidden wallet...");
        }
        
        // Get Ethereum address with passphrase support
        let address_hex = get_ethereum_address_with_passphrase(&mut trezor, path_indices, &passphrase)?;
        
        // Convert address from hex string to Address
        // Trezor may return with or without 0x prefix
        let address_hex_clean = address_hex.strip_prefix("0x")
            .or_else(|| address_hex.strip_prefix("0X"))
            .unwrap_or(&address_hex);
        
        let address_bytes = hex::decode(address_hex_clean)
            .map_err(|e| format!("Invalid hex address from Trezor: {}", e))?;
        
        if address_bytes.len() != 20 {
            return Err(format!("Invalid address length from Trezor: {}", address_bytes.len()));
        }
        
        let address = Address::from_slice(&address_bytes);
        
        println!("✅ Connected! Address: {}", address);
        
        Ok(HardwareWalletInfo {
            wallet_type: HardwareWalletType::TrezorOne,
            address,
            derivation_path,
            device_id,
        })
    }

    pub fn sign_with_trezor(
        derivation_path: &str,
        message: &[u8],
    ) -> Result<[u8; 65], String> {
        println!("✍️  Please confirm signing on your Trezor device...");
        println!("📱 If you use a PASSPHRASE, enter it on your Trezor when prompted!");
        
        // Find available Trezor devices
        let available_devices = find_devices(false);
        
        if available_devices.is_empty() {
            return Err("No Trezor device found. Make sure it's connected and unlocked.".to_string());
        }
        
        // Connect to the first available device
        let device = available_devices.into_iter().next().unwrap();
        let mut trezor = device.connect()
            .map_err(|e| format!("Failed to connect to Trezor device: {}", e))?;
        
        // Parse derivation path
        let path_indices = parse_derivation_path(derivation_path)?;
        
        // Sign the message - retry loop for PIN unlock
        // Trezor's ethereum_sign_message expects the raw message and applies EIP-191 prefixing internally
        let signature = loop {
            match trezor.ethereum_sign_message(message.to_vec(), path_indices.clone()) {
                Ok(sig) => break sig,
                Err(e) => {
                    let error_msg = e.to_string().to_lowercase();
                    
                    if error_msg.contains("pin") || error_msg.contains("locked") || 
                       error_msg.contains("network") || error_msg.contains("not supported") {
                        prompt_unlock();
                        
                        // Reconnect after user unlocks
                        let available_devices = find_devices(false);
                        if available_devices.is_empty() {
                            return Err("Trezor disconnected. Please reconnect and try again.".to_string());
                        }
                        let device = available_devices.into_iter().next().unwrap();
                        trezor = device.connect()
                            .map_err(|e| format!("Failed to reconnect: {}", e))?;
                        
                        continue;
                    } else {
                        return Err(format!("Failed to sign with Trezor: {}", e));
                    }
                }
            }
        };
        
        // Extract signature components
        let r = B256::from_slice(&signature.r);
        let s = B256::from_slice(&signature.s);
        let v = signature.v;
        
        // For Safe eth_sign signatures, v must be 31 or 32
        // Trezor's ethereum_sign_message applies EIP-191 prefix internally
        // Safe uses v >= 31 to indicate eth_sign (EIP-191 prefixed) signatures
        let v_for_safe = if v >= 27 { 
            (v + 4) as u8  // 27->31, 28->32
        } else { 
            (v + 31) as u8  // 0->31, 1->32
        };
        
        // Create signature bytes: r (32) + s (32) + v (1) = 65 bytes
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(r.as_slice());
        sig_bytes.extend_from_slice(s.as_slice());
        sig_bytes.push(v_for_safe);
        
        sig_bytes.try_into()
            .map_err(|_| "Invalid signature length".to_string())
    }
    
    /// Connect to Trezor with passphrase support and sign in one session
    /// This ensures the passphrase session is maintained for signing
    /// Returns raw signature bytes with v = 31 or 32 for eth_sign
    pub fn connect_and_sign_trezor(
        derivation_path: &str,
        message: &[u8],
        expected_address: &Address,
    ) -> Result<[u8; 65], String> {
        println!("✍️  Reconnecting to Trezor for signing...");
        
        // Get the stored passphrase (already prompted during connect)
        let passphrase = get_or_prompt_passphrase();
        
        // Find available Trezor devices
        let available_devices = find_devices(false);
        
        if available_devices.is_empty() {
            return Err("No Trezor device found. Make sure it's connected.".to_string());
        }
        
        // Connect to the first available device
        let device = available_devices.into_iter().next().unwrap();
        let mut trezor = device.connect()
            .map_err(|e| format!("Failed to connect to Trezor device: {}", e))?;
        
        // Initialize device
        if let Err(e) = trezor.init_device(None) {
            let error_str = e.to_string().to_lowercase();
            if !error_str.contains("already initialized") {
                return Err(format!("Failed to initialize Trezor: {}", e));
            }
        }
        
        // Parse derivation path
        let path_indices = parse_derivation_path(derivation_path)?;
        
        // First, get the address to verify passphrase is correct
        println!("🔐 Verifying wallet address...");
        let address_hex = get_ethereum_address_with_passphrase(&mut trezor, path_indices.clone(), &passphrase)?;
        
        // Verify address matches
        let address_hex_clean = address_hex.strip_prefix("0x")
            .or_else(|| address_hex.strip_prefix("0X"))
            .unwrap_or(&address_hex);
        let address_bytes = hex::decode(address_hex_clean)
            .map_err(|e| format!("Invalid address from Trezor: {}", e))?;
        let signing_address = Address::from_slice(&address_bytes);
        
        if signing_address != *expected_address {
            return Err(format!(
                "Address mismatch! Expected {} but Trezor returned {}.\n\
                 Did you enter the correct passphrase?",
                expected_address, signing_address
            ));
        }
        
        println!("✅ Address verified: {}", signing_address);
        println!("📝 Please confirm the signing request on your Trezor...");
        
        // Now sign with passphrase support
        let signature = sign_ethereum_message_with_passphrase(
            &mut trezor,
            message.to_vec(),
            path_indices,
            &passphrase,
        )?;
        
        // Extract signature components
        let r = B256::from_slice(&signature.r);
        let s = B256::from_slice(&signature.s);
        let v = signature.v;
        
        // For Safe eth_sign signatures, v must be 31 or 32
        // Trezor's ethereum_sign_message applies EIP-191 prefix internally
        // Safe uses v >= 31 to indicate eth_sign (EIP-191 prefixed) signatures
        let v_for_safe = if v >= 27 { 
            (v + 4) as u8  // 27->31, 28->32
        } else { 
            (v + 31) as u8  // 0->31, 1->32
        };
        
        // Create signature bytes: r (32) + s (32) + v (1) = 65 bytes
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(r.as_slice());
        sig_bytes.extend_from_slice(s.as_slice());
        sig_bytes.push(v_for_safe);
        
        sig_bytes.try_into()
            .map_err(|_| "Invalid signature length".to_string())
    }
}

// ============================================================================
// Ledger Implementation
// ============================================================================

#[cfg(feature = "ledger")]
mod ledger_impl {
    use super::*;
    use ledger_transport_hid::hidapi::HidApi;
    use ledger_transport::APDUCommand;
    use std::sync::Arc;
    
    // Ethereum app constants
    const CLA: u8 = 0xE0;
    const INS_GET_PUBLIC_KEY: u8 = 0x02;
    const INS_SIGN: u8 = 0x04;
    const P1_CONFIRM: u8 = 0x01;
    const P1_NON_CONFIRM: u8 = 0x00;
    
    fn parse_derivation_path(path: &str) -> Result<Vec<u32>, String> {
        if !path.starts_with("m/") {
            return Err("Derivation path must start with 'm/'".to_string());
        }
        
        let parts: Vec<&str> = path[2..].split('/').collect();
        let mut indices = Vec::new();
        
        for part in parts {
            let hardened = part.ends_with('\'');
            let num_str = if hardened { &part[..part.len() - 1] } else { part };
            let num = num_str.parse::<u32>()
                .map_err(|_| format!("Invalid derivation path segment: {}", part))?;
            
            let index = if hardened {
                num | 0x80000000
            } else {
                num
            };
            indices.push(index);
        }
        
        Ok(indices)
    }
    
    fn derivation_path_to_bytes(path: &str) -> Result<Vec<u8>, String> {
        let indices = parse_derivation_path(path)?;
        let mut bytes = Vec::new();
        bytes.push(indices.len() as u8);
        for index in indices {
            bytes.extend_from_slice(&index.to_be_bytes());
        }
        Ok(bytes)
    }
    
    pub fn connect_ledger(
        wallet_type: HardwareWalletType,
        derivation_path: String,
    ) -> Result<HardwareWalletInfo, String> {
        println!("🔌 Connecting to Ledger...");
        
        let api = HidApi::new()
            .map_err(|e| format!("Failed to initialize HID API: {}", e))?;
        
        // Check if any Ledger device is available (vendor ID 0x2c97)
        let has_device = api.device_list()
            .any(|d| d.vendor_id() == 0x2c97);
        
        if !has_device {
            return Err("No Ledger device found. Make sure it's connected and the Ethereum app is open.".to_string());
        }
        
        let transport = Arc::new(
            ledger_transport_hid::TransportNativeHID::new(&api)
                .map_err(|e| format!("Failed to connect to Ledger device: {}", e))?
        );
        
        println!("🔑 Getting address for path: {}", derivation_path);
        
        // Get public key from derivation path
        let path_bytes = derivation_path_to_bytes(&derivation_path)?;
        
        let mut command_data = Vec::new();
        command_data.extend_from_slice(&path_bytes);
        
        let command = APDUCommand {
            cla: CLA,
            ins: INS_GET_PUBLIC_KEY,
            p1: P1_NON_CONFIRM,
            p2: 0x00,
            data: command_data,
        };
        
        let response = transport.exchange(&command)
            .map_err(|e| format!("Failed to communicate with Ledger: {}", e))?;
        
        if response.retcode() != 0x9000 {
            return Err(format!("Ledger error: 0x{:04x}. Make sure the Ethereum app is open.", response.retcode()));
        }
        
        let response_data = response.data();
        if response_data.len() < 65 {
            return Err("Invalid response from Ledger".to_string());
        }
        
        // Response format: [1 byte: length] [64 bytes: public key]
        let public_key_bytes = &response_data[1..65];
        
        // Convert public key to address: keccak256(pubkey)[12:32]
        let pubkey_hash = keccak256(public_key_bytes);
        let address = Address::from_slice(&pubkey_hash[12..32]);
        
        println!("✅ Connected! Address: {}", address);
        
        Ok(HardwareWalletInfo {
            wallet_type,
            address,
            derivation_path,
            device_id: None,
        })
    }

    pub fn sign_with_ledger(
        derivation_path: &str,
        message_hash: &[u8],
    ) -> Result<[u8; 65], String> {
        println!("✍️  Please confirm signing on your Ledger device...");
        
        let api = HidApi::new()
            .map_err(|e| format!("Failed to initialize HID API: {}", e))?;
        
        let has_device = api.device_list()
            .any(|d| d.vendor_id() == 0x2c97);
        
        if !has_device {
            return Err("No Ledger device found. Make sure it's connected and the Ethereum app is open.".to_string());
        }
        
        let transport = Arc::new(
            ledger_transport_hid::TransportNativeHID::new(&api)
                .map_err(|e| format!("Failed to connect to Ledger device: {}", e))?
        );
        
        // Prepare signing command
        let path_bytes = derivation_path_to_bytes(derivation_path)?;
        
        let mut command_data = Vec::new();
        command_data.extend_from_slice(&path_bytes);
        command_data.extend_from_slice(message_hash);
        
        let command = APDUCommand {
            cla: CLA,
            ins: INS_SIGN,
            p1: P1_CONFIRM,
            p2: 0x00,
            data: command_data,
        };
        
        let response = transport.exchange(&command)
            .map_err(|e| format!("Failed to sign with Ledger: {}", e))?;
        
        if response.retcode() != 0x9000 {
            return Err(format!("Ledger signing error: 0x{:04x}", response.retcode()));
        }
        
        let response_data = response.data();
        if response_data.len() < 65 {
            return Err("Invalid signature response from Ledger".to_string());
        }
        
        // Response format: [1 byte: v] [32 bytes: r] [32 bytes: s]
        let v = response_data[0];
        let r = B256::from_slice(&response_data[1..33]);
        let s = B256::from_slice(&response_data[33..65]);
        
        // For Safe eth_sign signatures, v must be 31 or 32
        // Trezor's ethereum_sign_message applies EIP-191 prefix internally
        // Safe uses v >= 31 to indicate eth_sign (EIP-191 prefixed) signatures
        let v_for_safe = if v >= 27 { 
            (v + 4) as u8  // 27->31, 28->32
        } else { 
            (v + 31) as u8  // 0->31, 1->32
        };
        
        // Create signature bytes: r (32) + s (32) + v (1) = 65 bytes
        let mut sig_bytes = Vec::with_capacity(65);
        sig_bytes.extend_from_slice(r.as_slice());
        sig_bytes.extend_from_slice(s.as_slice());
        sig_bytes.push(v_for_safe);
        
        sig_bytes.try_into()
            .map_err(|_| "Invalid signature length".to_string())
    }
}

