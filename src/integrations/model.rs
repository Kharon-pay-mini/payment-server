use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct Bank {
    id: i64,
    pub name: String,
    pub code: String,
    #[serde(rename = "type")]
    pub bank_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptoTransaction {
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
pub struct FlutterwaveBankApiResponse<T> {
    pub status: String,
    pub message: String,
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyResponse {
    #[serde(rename = "requestSuccessful")]
    pub request_successful: bool,
    #[serde(rename = "responseMessage")]
    pub response_message: String,
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseBody")]
    pub response_body: MonnifyDisbursementResponseBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyAuthResponse {
    #[serde(rename = "requestSuccessful")]
    pub request_successful: bool,
    #[serde(rename = "responseMessage")]
    pub response_message: String,
    #[serde(rename = "responseCode")]
    pub response_code: String,
    #[serde(rename = "responseBody")]
    pub response_body: MonnifyAuthResponseBody,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyAuthResponseBody {
    #[serde(rename = "accessToken")]
    pub access_token: String,
    #[serde(rename = "expiresIn")]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PendingDisbursement {
    pub user_id: Uuid,
    pub bank_code: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    pub currency: String,
    pub crypto_amount: f64,
    pub crypto_symbol: String,
    pub order_type: String,
    pub payment_method: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyDisbursementResponseBody {
    pub amount: f64,
    pub reference: String,
    pub status: String,
    #[serde(rename = "dateCreated")]
    pub date_created: DateTime<Utc>,
    #[serde(rename = "totalFee")]
    pub total_fee: f64,
    #[serde(rename = "destinationAccountName", default)]
    pub destination_account_name: Option<String>,

    #[serde(rename = "destinationBankName", default)]
    pub destination_bank_name: Option<String>,

    #[serde(rename = "destinationAccountNumber", default)]
    pub destination_account_number: Option<String>,

    #[serde(rename = "destinationBankCode", default)]
    pub destination_bank_code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyEventData {
    #[serde(rename = "transactionReference")]
    pub transaction_reference: String,
    pub reference: String,
    pub status: String,
    pub amount: f64,
    #[serde(rename = "destinationAccountNumber", default)]
    pub destination_account_number: Option<String>,
    #[serde(rename = "destinationBankCode", default)]
    pub destination_bank_code: Option<String>,
    #[serde(rename = "destinationAccountName", default)]
    pub destination_account_name: Option<String>,
    #[serde(rename = "paymentReference", default)]
    pub payment_reference: Option<String>,
    #[serde(rename = "statusMessage", default)]
    pub status_message: Option<String>,
    #[serde(rename = "completedOn", default)]
    pub completed_on: Option<String>,
    #[serde(rename = "paymentMethod", default)]
    pub payment_method: Option<String>,
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
    pub amount: i64,
    pub reference: String,
    pub narration: Option<String>,
    #[serde(rename = "destinationBankCode")]
    pub destination_bank_code: String,
    #[serde(rename = "destinationAccountNumber")]
    pub destination_account_number: String,
    pub currency: String,
    #[serde(rename = "sourceAccountNumber")]
    pub source_account_number: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InitDisbursementRequest {
    pub crypto_transaction: CryptoTransaction,
    pub bank_name: String,
    pub account_number: String,
    pub currency: String,
    pub order_type: String,
    pub payment_method: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfirmDisbursementRequest {
    pub user_id: String,
    pub sender: String,
    pub reference: String,
    pub transaction_hash: String,
    pub amount: String,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MonnifyWebhookPayload {
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "eventData")]
    pub event_data: MonnifyEventData,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FlutterwaveTransferRequest {
    pub account_bank: String,
    pub account_number: String,
    pub amount: i64,
    pub debit_currency: String,
    pub reference: String,
    pub narration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub beneficiary_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FlutterwaveTransferData {
    pub id: u64,
    pub account_number: String,
    pub bank_code: String,
    pub full_name: String,
    pub created_at: String,
    pub currency: String,
    pub debit_currency: String,
    pub amount: i64,
    pub fee: i64,
    pub status: String,
    pub reference: String,
    pub narration: String,
    pub complete_message: String,
    pub requires_approval: u8,
    pub is_approved: u8,
    pub bank_name: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FlutterwaveTransferResponse {
    pub status: String,
    pub message: String,
    pub data: FlutterwaveTransferData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlutterwaveWebhookPayload {
    pub event: String,
    pub data: FlutterwaveWebhookData,
    #[serde(rename = "event.type")]
    pub event_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlutterwaveWebhookData {
    pub id: u64,
    pub account_number: String,
    pub bank_code: String,
    pub full_name: Option<String>,
    pub created_at: String,
    pub currency: String,
    pub debit_currency: Option<String>,
    pub amount: i64,
    pub fee: Option<i64>,
    pub status: String,
    pub reference: String,
    pub narration: Option<String>,
    pub complete_message: Option<String>,
    pub requires_approval: Option<u8>,
    pub is_approved: Option<u8>,
    pub bank_name: Option<String>,
    #[serde(rename = "tx_ref")]
    pub tx_ref: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionDetails {
    pub reference: String,
    pub transaction_ref: Option<String>,
    pub crypto_amount: String,
    pub crypto_symbol: String,
    pub fiat_amount: String,
    pub bank_name: String,
    pub account_number: String,
    pub account_name: String,
    pub transaction_hash: String,
    pub transaction_date: String,
}