use chrono::prelude::*;
use rust_decimal::Decimal;
use serde::Serialize;

#[allow(non_snake_case)]
#[derive(Debug, Serialize)]
pub struct FilteredUser {
    pub id: String,
    pub email: String,
    pub phone: Option<String>,
    pub last_logged_in: DateTime<Utc>,
    pub verified: bool,
    pub role: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    pub user: FilteredUser,
}

#[derive(Debug, Serialize)]
pub struct FilteredWallet {
    pub user_id: String,
    pub wallet_address: String,
    pub network_used_last: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WalletData {
    pub wallet: FilteredWallet,
}

/*
#[derive(Debug, Serialize)]
pub struct WalletResponse {
    status: String,
    pub data: WalletData
} */

#[derive(Debug, Serialize)]
pub struct FilteredTransaction {
    pub tx_id: String,
    pub user_id: String,
    pub order_type: String,
    pub crypto_amount: Decimal,
    pub crypto_type: String,
    pub fiat_amount: Decimal,
    pub fiat_currency: String,
    pub payment_method: String,
    pub payment_status: String,
    pub tx_hash: String,
    pub reference: String,
    pub settlement_status: Option<String>,
    pub transaction_reference: Option<String>,
    pub settlement_date: Option<DateTime<Utc>>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct TransactionData {
    pub tx: FilteredTransaction,
}

#[derive(Debug, Serialize)]
pub struct FilteredUserSecurityLogs {
    pub log_id: String,
    pub user_id: String,
    pub ip_address: String,
    pub city: String,
    pub country: String,
    pub failed_login_attempts: i64,
    pub flagged_for_review: bool,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct UserSecurityLogsData {
    pub user_security_log: FilteredUserSecurityLogs,
}

#[derive(Debug, Serialize)]
pub struct FilteredOtp {
    pub otp_id: String,
    pub user_id: String,
    pub otp: i32,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct OtpData {
    pub otp: FilteredOtp,
}

/*
#[derive(Debug, Serialize)]
pub struct OtpResponse {
    status: String,
    pub data: OtpData
} */

#[derive(Debug, Serialize)]
pub struct ApiResponse<T> {
    status: String,
    pub data: T,
}
