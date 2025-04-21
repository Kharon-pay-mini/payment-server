use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bank {
    id: i64,
    pub name: String,
    pub code: String,
    pub active: bool,
    #[serde(rename = "country")]
    pub country_code: String,
    #[serde(rename = "type")]
    pub bank_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoTransaction {
    pub tx_hash: String,
    pub amount: f64,
    pub token_symbol: String,
}

//  RESPONSES   //
#[derive(Debug, Serialize, Deserialize)]
pub struct BankApiResponse<T> {
    pub status: bool,
    pub message: String,
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyResponse<T> {
    pub status: bool,
    pub message: String,
    pub code: String,
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyAuthResponse {
    pub access_token: String,
    pub expires_in: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountVerificationResponse {
    pub account_name: String,
    pub account_number: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitDisbursementResponse {
    pub success: bool,
    pub message: String,
    pub reference: String,
    pub data: Option<DisbursementDetails>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisbursementDetails {
    pub account_name: String,
    pub account_number: String,
    pub bank_name: String,
    pub bank_code: String,
    pub amount: f64,
    pub currency: String,
    pub crypto_tx_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PendingDisbursement {
    pub user_id: Uuid,
    pub amount: f64,
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    pub currency: String,
    pub crypto_amount: f64,
    pub crypto_symbol: String,
    pub order_type: String,
    pub payment_method: String,
    pub crypto_tx_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisbursementResponse {
    pub transaction_reference: String,
    pub payment_reference: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentResult {
    pub success: bool,
    pub message: String,
    pub reference: String,
    pub transaction_ref: Option<String>,
    pub status: Option<String>,
    pub error: Option<String>,
}

//  SCHEMAS //
#[derive(Debug, Deserialize)]
pub struct BankVerificationSchema {
    pub account_number: String,
    pub bank_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DisbursementSchema {
    pub reference: String,
    pub amount: f64,
    pub currency: String,
    pub destination_bank_code: String,
    pub destination_account_number: String,
    pub source_account_number: String,
    pub wallet_id: String,
    pub from_available_balance: bool,
    pub narration: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OfframpRequest {
    pub crypto_transaction: CryptoTransaction,
    pub amount: f64,
    pub bank_name: String,
    pub account_number: String,
    pub destination_account_number: String,
    pub currency: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitDisbursementRequest {
    pub crypto_transaction: CryptoTransaction,
    pub amount: f64,
    pub bank_name: String,
    pub account_number: String,
    pub currency: String,
    pub order_type: String,
    pub payment_method: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmDisbursementRequest {
    pub reference: String,
}
