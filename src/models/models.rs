use std::io::Write;

use account_sdk::account::session::policy::Policy;
use chrono::prelude::*;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use diesel::{
    deserialize::{FromSql, Result as DeserializeResult},
    pg::{Pg, PgValue},
    serialize::{IsNull, Output, ToSql},
    sql_types::{Jsonb, Text},
    AsChangeset, Insertable, Queryable,
};

use crate::wallets::models::SessionPolicies;

#[allow(non_snake_case)]
#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::users)]
pub struct User {
    pub id: String,
    pub phone: String,
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
    pub phone: String,
    pub verified: bool,
    pub role: String,
}

#[derive(Debug, Deserialize, Serialize, Clone, Queryable, AsChangeset, Insertable)]
#[diesel(table_name=crate::models::schema::user_wallet)]
pub struct UserWallet {
    pub id: String,
    pub user_id: String, //foreign key ref
    pub wallet_address: Option<String>,
    pub network_used_last: Option<String>,
    pub controller_info: Option<String>,
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
    pub controller_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, diesel::expression::AsExpression)]
#[diesel(sql_type = Jsonb)]
pub struct PolicyList(pub Vec<Policy>);

#[derive(Debug, Deserialize, Serialize, Clone, AsChangeset, Insertable, Queryable)]
#[diesel(table_name=crate::models::schema::session_controller_info)]
pub struct ControllerSessionInfo {
    pub user_id: String,
    pub username: String,
    pub controller_address: String,
    pub session_policies: PolicyList,
    pub session_expires_at: i64,
    pub user_permissions: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub is_deployed: bool,
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

// Diesel impl for SessionPolicies
impl ToSql<Text, diesel::pg::Pg> for SessionPolicies {
    fn to_sql<'b>(
        &'b self,
        out: &mut diesel::serialize::Output<'b, '_, diesel::pg::Pg>,
    ) -> diesel::serialize::Result {
        let json_string = serde_json::to_string(self)?;
        out.write_all(json_string.as_bytes())?;
        Ok(diesel::serialize::IsNull::No)
    }
}

impl FromSql<Text, diesel::pg::Pg> for SessionPolicies {
    fn from_sql(
        bytes: <diesel::pg::Pg as diesel::backend::Backend>::RawValue<'_>,
    ) -> diesel::deserialize::Result<Self> {
        let json_str = std::str::from_utf8(bytes.as_bytes())?;
        Ok(serde_json::from_str(json_str)?)
    }
}

impl ToSql<Jsonb, Pg> for PolicyList {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> diesel::serialize::Result {
        let json_string = serde_json::to_string(&self.0)?;
        // Write the JSON string as bytes, prefixed with version byte (1) for JSONB
        out.write_all(&[1u8])?; // JSONB version byte
        out.write_all(json_string.as_bytes())?;
        Ok(IsNull::No)
    }
}

impl FromSql<Jsonb, Pg> for PolicyList {
    fn from_sql(bytes: PgValue) -> DeserializeResult<Self> {
        let json_bytes = &bytes.as_bytes()[1..];
        let json_str = std::str::from_utf8(json_bytes)?;
        let policies: Vec<Policy> = serde_json::from_str(json_str)?;
        Ok(PolicyList(policies))
    }
}
