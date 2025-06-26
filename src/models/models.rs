use chrono::prelude::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use diesel::{AsChangeset, Insertable, Queryable};

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::users)]
pub struct User {
    pub id: String,
    pub email: String,
    pub phone: Option<String>,
    pub last_logged_in: Option<DateTime<Utc>>,
    pub verified: bool,
    pub role: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
}

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::users)]
pub struct NewUser {
    pub email: String,
    pub phone: Option<String>,
    pub verified: bool,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_wallet)]
pub struct UserWallet {
    pub id: uuid::Uuid,
    pub user_id: String, //foreign key ref
    pub wallet_address: Option<String>,
    pub network_used_last: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_wallet)]
pub struct NewUserWallet {
    pub user_id: String,
    pub wallet_address: Option<String>,
    pub network_used_last: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::transactions)]
pub struct Transaction {
    pub tx_id: uuid::Uuid,
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
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::transactions)]
pub struct NewTransaction {
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
}

#[derive(Debug, Deserialize, Serialize, Queryable, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_bank_account)]
pub struct UserBankAccount {
    pub id: uuid::Uuid,
    pub user_id: String, // foreign key ref
    pub bank_name: String,
    pub account_number: String,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(rename = "updatedAt")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_bank_account)]
pub struct NewUserBankAccount {
    pub user_id: String,
    pub bank_name: String,
    pub account_number: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_security_logs)]
pub struct UserSecurityLog {
    pub log_id: uuid::Uuid,
    pub user_id: String,
    pub ip_address: String,
    pub city: String,
    pub country: String,
    pub failed_login_attempts: i32,
    pub flagged_for_review: bool,
    #[serde(rename = "createdAt")]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_security_logs)]
pub struct NewUserSecurityLog {
    pub user_id: String,
    pub ip_address: String,
    pub city: String,
    pub country: String,
    pub failed_login_attempts: i32,
    pub flagged_for_review: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::otp)]
pub struct Otp {
    pub otp_id: uuid::Uuid,
    pub otp_code: i32,
    pub user_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "expiresAt")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::otp)]
pub struct NewOtp {
    pub otp_code: i32,
    pub user_id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Copy)]
pub enum Role {
    Admin,
    User,
}

/*      JSONWEBTOKEN TOKEN DECODE PARAMS     */
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

#[derive(Debug, Deserialize)]
pub struct TransactionSchema {
    pub order_type: String,
    pub crypto_amount: Decimal,
    pub crypto_type: String,
    pub fiat_amount: Decimal,
    pub fiat_currency: String,
    pub payment_method: String,
    pub payment_status: String,
    pub tx_hash: String,
    pub reference: String,
}

// /*  DISPLAY IMPLEMENTATION FOR ENUMS */
macro_rules! impl_display {
    ($($t:ty), *) => {
        $(
            impl std::fmt::Display for $t {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    write!(f, "{:?}", self)
                }
            }
        )*
    };
}
impl_display!(Role);
