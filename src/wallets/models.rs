use std::collections::HashMap;

use diesel::{deserialize::FromSqlRow, expression::AsExpression, sql_types::Jsonb};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionOptions {
    pub policies: SessionPolicies,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, AsExpression, FromSqlRow)]
#[diesel(sql_type = Jsonb)]
pub struct SessionPolicies {
    pub contract: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub messages: Option<Vec<SignMessagePolicy>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContractPolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub methods: Vec<ContractMethod>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ContractMethod {
    pub name: String,
    pub entrypoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignMessagePolicy {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub types: HashMap<String, Vec<StarknetType>>,
    pub primary_type: String,
    pub domain: StarknetDomain,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StarknetType {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StarknetDomain {
    pub name: String,
    pub version: String,
    pub chain_id: String,
    pub revision: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateSessionRequest {
    pub user_email: String,
    #[serde(default)]
    pub user_permissions: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CreateSessionResponse {
    pub controller_address: String,
    pub username: String,
    pub session_id: String,
    pub session_options: SessionOptions,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ReceivePaymentRequest {
    pub token: String,
    pub amount: String,
    pub reference: String,
    pub user_email: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ReceivePaymentResponse {
    pub success: bool,
    pub message: String,
    pub data: Option<TransactionResponse>,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct WithdrawRequest {
    pub controller_address: String,
    pub token: String,
    pub receiver: String,
    pub amount: String,
}

// #[derive(Deserialize)]
// pub struct SystemManagementRequest {
//     pub controller_address: String,
//     pub user_email: String,
// }

#[derive(Serialize, Deserialize, Clone)]
pub struct TransactionResponse {
    pub transaction_hash: String,
    pub status: String,
    pub function_called: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ControllerInfo {
    pub controller_address: String,
    pub username: String,
    pub session_options: SessionOptions,
}

#[derive(Deserialize)]
pub struct GetControllerRequest {
    pub user_email: String,
}

#[derive(Deserialize)]
pub struct CheckTokenBalanceRequest {
    pub token: String,
    pub user_address: String,
}
