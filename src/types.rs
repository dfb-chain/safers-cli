use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct TxBuilderJson {
    pub to: String,
    pub value: String,
    pub data: Option<String>,
    pub operation: Option<u8>,
}

/// Safe Transaction Service API request body
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeTxServiceRequest {
    pub to: String,
    pub value: String,
    pub data: String,
    pub operation: u8,
    pub safe_tx_gas: String,
    pub base_gas: String,
    pub gas_price: String,
    pub gas_token: String,
    pub refund_receiver: String,
    pub nonce: String,
    pub contract_transaction_hash: String,
    pub sender: String,
    pub signature: String,
    pub origin: Option<String>,
}

