use super::model::{
    AccountVerificationResponse, Bank, BankApiResponse, DisbursementResponse, DisbursementSchema,
    MonnifyAuthResponse, MonnifyResponse, PendingDisbursement,
};
use crate::AppState;
use actix_web::{web, Result};
use base64::Engine;
use redis::AsyncCommands;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use uuid::Uuid;

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

pub async fn get_monnify_auth_token(app_state: &web::Data<AppState>) -> Result<String, String> {
    let client = reqwest::Client::new();

    let auth_credentials = format!(
        "{}:{}",
        app_state.env.monnify_api_key, app_state.env.monnify_secret_key
    );

    let encoded_auth = base64::engine::general_purpose::STANDARD.encode(&auth_credentials);

    let response = client
        .post("https://sandbox.monnify.com/api/v1/auth/login")
        .header(AUTHORIZATION, format!("Basic {}", encoded_auth))
        .send()
        .await
        .map_err(|e| format!("Monnify auth request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let auth_response: MonnifyResponse<MonnifyAuthResponse> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse auth response: {}", e))?;

            match auth_response.status {
                true => Ok(auth_response.data.access_token),
                false => Err(format!("Monnify auth error: {}", auth_response.message)),
            }
        }
        false => {
            let status = response.status();
            let error_message = response.text().await.unwrap_or_default();
            Err(format!(
                "Monnify auth API error: {} - {}",
                status, error_message
            ))
        }
    }
}

pub async fn disburse_payment(
    app_state: &web::Data<AppState>,
    reference: &str,
    amount: f64,
    narration: Option<&str>,
    bank_code: &str,
    account_number: &str,
    currency: &str,
) -> Result<DisbursementResponse, String> {
    let auth_token = get_monnify_auth_token(app_state).await?;

    let disbursement_request = DisbursementSchema {
        reference: reference.to_string(),
        amount,
        currency: currency.to_string(),
        destination_bank_code: bank_code.to_string(),
        destination_account_number: account_number.to_string(),
        source_account_number: app_state.env.monnify_wallet_account_number.clone(),
        wallet_id: app_state.env.monnify_contract_code.clone(),
        from_available_balance: true,
        narration: narration.map(|n| n.to_string()),
    };

    let client = reqwest::Client::new();
    let response = client
        .post("https://sandbox.monnify.com/api/v2/disbursements/single")
        .header(AUTHORIZATION, format!("Bearer {}", auth_token))
        .header(CONTENT_TYPE, "application/json")
        .json(&disbursement_request)
        .send()
        .await
        .map_err(|e| format!("Disbursement request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let disbursement_response: MonnifyResponse<DisbursementResponse> = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse disbursement response: {}", e))?;

            match disbursement_response.status {
                true => Ok(disbursement_response.data),
                false => Err(format!(
                    "Disbursement error: {}",
                    disbursement_response.message
                )),
            }
        }
        false => {
            let status = response.status();
            let error_message = response.text().await.unwrap_or_default();
            Err(format!(
                "Disbursement API error: {} - {}",
                status, error_message
            ))
        }
    }
}

pub async fn store_pending_disbursement(
    app_state: &web::Data<AppState>,
    reference: &str,
    user_id: Uuid,
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

    match redis_conn.set_ex(&key, data, 1800).await {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Failed to store pending disbursement: {}", e)),
    }
}

pub async fn retrieve_pending_disbursement(
    app_state: &web::Data<AppState>,
    reference: &str,
    user_id: Uuid,
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

pub async fn delete_pending_disbursement(
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

    redis_conn.del::<&str, ()>(&key)
        .await
        .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;

    Ok(())
}
