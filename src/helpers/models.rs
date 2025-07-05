use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub struct AuthHeaders {
    pub api_key: String,
    pub timestamp: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryableTransfer {
    pub user_id: String,
    pub reference: String,
    pub amount: i64,
    pub narration: Option<String>,
    pub bank_code: String,
    pub account_number: String,
    pub currency: String,
    pub beneficiary_name: String,
    pub retry_count: u32,
    pub max_retries: u32,
    pub last_attempt: DateTime<Utc>,
    pub next_retry: DateTime<Utc>,
    pub original_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDetails {
    pub user_id: String,
    pub reference: String,
    pub amount: i64,
    pub narration: Option<String>,
    pub bank_code: String,
    pub account_number: String,
    pub currency: String,
    pub beneficiary_name: String,
}
