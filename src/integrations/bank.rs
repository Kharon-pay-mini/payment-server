use super::model::{
    AccountVerificationResponse, Bank, BankApiResponse, DisbursementSchema, MonnifyAuthResponse,
    MonnifyDisbursementResponseBody, MonnifyEventData, MonnifyResponse, MonnifyWebhookPayload,
    PendingDisbursement,
};
use crate::{database::transaction_db::TransactionImpl, models::models::NewTransaction, AppState};
use actix_web::{web, HttpRequest, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use num_traits::FromPrimitive;
use redis::AsyncCommands;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use rust_decimal::Decimal;
use sha2::Sha512;
use uuid::Uuid;

type HmacSha512 = Hmac<Sha512>;

pub async fn fetch_banks_via_paystack(
    app_state: &web::Data<AppState>,
) -> Result<Vec<Bank>, String> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.paystack.co/bank")
        .header(
            "Authorization",
            format!("Bearer {}", app_state.env.paystack_secret_key),
        )
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let banks_response: BankApiResponse<Vec<Bank>> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            match banks_response.status {
                true => Ok(banks_response.data),
                false => Err(format!("API returned error: {}", banks_response.message)),
            }
        }
        false => {
            let status = response.status();
            let error_message = response.text().await.unwrap_or_default();
            Err(format!("API error: {} - {}", status, error_message))
        }
    }
}

pub async fn verify_account_via_paystack(
    app_state: &web::Data<AppState>,
    account_number: &str,
    bank_code: &str,
) -> Result<AccountVerificationResponse, String> {
    let client = reqwest::Client::new();

    let url = format!(
        "https://api.paystack.co/bank/resolve?account_number={}&bank_code={}",
        account_number, bank_code
    );

    let response = client
        .get(&url)
        .header(
            "Authorization",
            format!("Bearer {}", app_state.env.paystack_secret_key),
        )
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let verification_response: BankApiResponse<AccountVerificationResponse> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse response: {}", e))?;

            match verification_response.status {
                true => Ok(verification_response.data),
                false => Err(format!(
                    "Verification failed: {}",
                    verification_response.message
                )),
            }
        }
        false => {
            let status = response.status();
            let error_message = response.text().await.unwrap_or_default();
            Err(format!("API error: {} - {}", status, error_message))
        }
    }
}

pub async fn store_pending_disbursement(
    app_state: &web::Data<AppState>,
    reference: &str,
    user_id: &str,
    disbursement: &PendingDisbursement,
) -> Result<(), String> {
    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let key = format!("pending disbursement:{}:{}", reference, user_id);

    let data = serde_json::to_string(disbursement)
        .map_err(|e| format!("Failed to serialize disbursement: {}", e))?;

    match redis_conn.set_ex(&key, data, 86400).await {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Failed to store pending disbursement: {}", e)),
    }
}

pub async fn retrieve_pending_disbursement(
    app_state: &web::Data<AppState>,
    reference: &str,
    user_id: &str,
) -> Result<PendingDisbursement, String> {
    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let key = format!("pending disbursement:{}:{}", reference, user_id);

    let data: Option<String> = redis_conn
        .get(&key)
        .await
        .map_err(|e| format!("Failed to retrieve disbursement data from Redis: {}", e))?;

    match data {
        Some(json_data) => serde_json::from_str(&json_data)
            .map_err(|e| format!("Failed to deserialize disbursement data: {}", e)),
        None => Err(format!(
            "No pending disbursement found for reference: {}",
            reference
        )),
    }
}

pub async fn _delete_pending_disbursement(
    app_state: &web::Data<AppState>,
    reference: &str,
    user_id: Uuid,
) -> Result<(), String> {
    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let key = format!("pending disbursement:{}:{}", reference, user_id);

    redis_conn
        .del::<&str, ()>(&key)
        .await
        .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;

    Ok(())
}
