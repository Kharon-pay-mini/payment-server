use chrono::prelude::*;
use serde::{ Deserialize, Serialize };

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub email: String,
    pub password: String,
    pub phone: String,
    pub verified: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserWallet {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid, //foreign key ref
    pub wallet_address: String,
    // network: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Transactions {
    pub tx_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub order_type: OrderType,
    pub crypto_amount: u128,
    pub crypto_type: CryptoType,
    pub fiat_amount: u128,
    pub fiat_currency: String,
    pub payment_method: PaymentMethod,
    pub payment_status: PaymentStatus,
    pub tx_hash: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UserSecurityLogs {
    pub log_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub ip_address: String,
    pub city: String,
    pub country: String,
    pub failed_login_attempts: u64,
    pub flagged_for_review: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "lastLoggedIn")]
    pub last_logged_in: Option<DateTime<Utc>>
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Otp {
    pub otp_id: uuid::Uuid,
    pub otp: u32,
    pub user_id: uuid::Uuid,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "expiresAt")]
    pub expires_at: Option<DateTime<Utc>>
}


#[derive(Debug, Deserialize, Serialize)]
pub enum OrderType {
    Buy,
    Sell,
    Swap
}

#[derive(Debug, Deserialize, Serialize)]
pub enum CryptoType {
    USDC,
    USDT
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PaymentMethod {
    BankTransfer,
    Crypto,
    Card
}

#[derive(Debug, Deserialize, Serialize)]
pub enum PaymentStatus {
    Pending,
    Completed,
    Failed
}

