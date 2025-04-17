use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Bank {
    id: i64,
    pub name: String,
    pub code: String,
    pub active: bool,
    #[serde(rename = "country")]
    pub country_code: String,
    #[serde(rename = "type")]
    pub bank_type: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BankApiResponse<T> {
    pub status: bool,
    pub message: String,
    pub data: T
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountVerificationResponse {
    pub account_name: String,
    pub account_number: String
}

#[derive(Debug, Deserialize)]
pub struct BankVerificationSchema {
    pub account_number: String,
    pub bank_name: String,
}
