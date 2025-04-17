use actix_web::{web, Result};
use crate::AppState;
use super::bank_model::{
    AccountVerificationResponse, Bank, BankApiResponse, BankVerificationSchema,
};

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
            Err(format!("API error status: {} - {}", status, error_message))
        }
    }
}

pub async fn verify_account_via_paystack(
    app_state: &web::Data<AppState>,
    account_number: &str,
    bank_code: &str
) -> Result<AccountVerificationResponse, String> {
    let client = reqwest::Client::new();

    let url = format!("https://api.paystack.co/bank/resolve?account_number={}&bank_code={}", account_number, bank_code);

    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", app_state.env.paystack_secret_key))
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
                false => Err(format!("Verification failed: {}", verification_response.message))
            }
        },
        false => {
            let status = response.status();
            let error_message = response
                .text()
                .await
                .unwrap_or_default();
            Err(format!("API returned error: {} - {}", status, error_message))
        }
    }
}
