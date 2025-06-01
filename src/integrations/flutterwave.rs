use actix_web::web;
use num_traits::FromPrimitive;
use redis::AsyncCommands;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use rust_decimal::Decimal;
use sha2::{Digest, Sha512};
use uuid::Uuid;

use crate::{
    database::transaction_db::TransactionImpl,
    integrations::model::{FlutterwaveTransferResponse, PendingDisbursement},
    models::models::NewTransaction,
    AppState,
};

use super::model::{
    AccountVerificationResponse, Bank, FlutterwaveBankApiResponse, FlutterwaveTransferData,
    FlutterwaveTransferRequest, FlutterwaveWebhookData, FlutterwaveWebhookPayload,
};

pub async fn disburse_payment_using_flutterwave(
    app_state: &web::Data<AppState>,
    reference: &str,
    amount: i64,
    narration: Option<&str>,
    bank_code: &str,
    account_number: &str,
    currency: &str,
    beneficiary_name: Option<&str>,
) -> Result<FlutterwaveTransferData, String> {
    let transfer_request = FlutterwaveTransferRequest {
        account_bank: bank_code.to_string(),
        account_number: account_number.to_string(),
        amount,
        debit_currency: currency.to_string(),
        reference: reference.to_string(),
        narration: narration.map(|n| n.to_string()),
        beneficiary_name: beneficiary_name.map(|b| b.to_string()),
        callback_url: Some(app_state.env.flutterwave_callback_url.clone()),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&app_state.env.flutterwave_payment_url)
        .header(
            AUTHORIZATION,
            format!("Bearer {}", app_state.env.flutterwave_secret_key),
        )
        .header(CONTENT_TYPE, "application/json")
        .header("accept", "application/json")
        .json(&transfer_request)
        .send()
        .await
        .map_err(|e| format!("Transfer request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let raw_body = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            log::info!("Flutterwave transfer response: {}", raw_body);

            match serde_json::from_str::<FlutterwaveTransferResponse>(&raw_body) {
                Ok(transfer_response) => {
                    if transfer_response.status == "success" {
                        Ok(transfer_response.data)
                    } else {
                        Err(format!("Transfer error: {}", transfer_response.message))
                    }
                }
                Err(e) => Err(format!("Failed to parse transfer response: {}", e)),
            }
        }
        false => {
            let status = response.status();
            let error_message = response.text().await.unwrap_or_default();
            Err(format!(
                "Transfer API error: {} - {}",
                status, error_message
            ))
        }
    }
}

pub async fn fetch_banks_via_flutterwave(
    app_state: &web::Data<AppState>,
) -> Result<Vec<Bank>, String> {
    let client = reqwest::Client::new();
    let response = client
        .get("https://api.flutterwave.com/v3/banks/NG")
        .header(
            "Authorization",
            format!("Bearer {}", app_state.env.flutterwave_secret_key),
        )
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    let raw_response = &response
        .text()
        .await
        .map_err(|e| format!("Failed to get response text: {}", e))?;

    let banks_response: FlutterwaveBankApiResponse<Vec<Bank>> = serde_json::from_str(&raw_response)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    match banks_response.status.as_str() {
        "success" => Ok(banks_response.data),
        _ => Err(format!("API returned error: {}", banks_response.message)),
    }
}

pub async fn verify_account_via_flutterwave(
    app_state: &web::Data<AppState>,
    account_number: &str,
    bank_code: &str,
) -> Result<AccountVerificationResponse, String> {
    let client = reqwest::Client::new();

    let url = format!("https://api.flutterwave.com/v3/accounts/resolve");

    let payload = serde_json::json!({
        "account_number": account_number,
        "account_bank": bank_code
    });

    let response = client
        .post(&url)
        .header(
            "Authorization",
            format!("Bearer {}", app_state.env.flutterwave_secret_key),
        )
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("API request failed: {}", e))?;

    match response.status().is_success() {
        true => {
            let verification_response: FlutterwaveBankApiResponse<AccountVerificationResponse> =
                response
                    .json()
                    .await
                    .map_err(|e| format!("Failed to parse response: {}", e))?;

            match verification_response.status.as_str() {
                "success" => Ok(verification_response.data),
                _ => Err(format!(
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

pub async fn process_flutterwave_webhook(
    app_state: &web::Data<AppState>,
    payload: FlutterwaveWebhookPayload,
) -> Result<(), String> {
    log::info!(
        "Received Flutterwave webhook: event={}, status={}",
        payload.event,
        payload.data.status
    );

    match payload.event.as_str() {
        "transfer.completed" => handle_successful_transfer(app_state, &payload.data).await,
        "transfer.failed" => handle_failed_transfer(app_state, &payload.data).await,
        "transfer.pending" | "transfer.processing" => {
            handle_pending_transfer(app_state, &payload.data).await
        }
        "transfer.reversed" => handle_reversed_transfer(app_state, &payload.data).await,
        _ => {
            log::info!("Unhandled Flutterwave event type: {}", payload.event);
            Ok(())
        }
    }
}

async fn handle_successful_transfer(
    app_state: &web::Data<AppState>,
    data: &FlutterwaveWebhookData,
) -> Result<(), String> {
    log::info!(
        "Processing successful transfer: reference={}, id={}",
        data.reference,
        data.id
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
    }

    if !keys.is_empty() {
        for key in keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 3 {
                continue;
            }

            let user_id = match Uuid::parse_str(parts[2]) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to get pending disbursement data from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let rows_affected = app_state.db.update_transaction(
                    user_id,
                    "COMPLETED".to_string(),
                    data.id.to_string(),
                );

                if rows_affected.unwrap() == 0 {
                    let new_tx = NewTransaction {
                        user_id: user_id.clone(),
                        order_type: disbursement.order_type.clone(),
                        crypto_amount: Decimal::from_f64(disbursement.crypto_amount)
                            .expect("Invalid float -> Decimal conversion"),
                        crypto_type: disbursement.crypto_symbol.clone(),
                        fiat_amount: Decimal::from_f64(00.00)
                            .expect("Invalid float -> Decimal conversion"),
                        fiat_currency: disbursement.currency.clone(),
                        payment_method: disbursement.payment_method.clone(),
                        payment_status: "COMPLETED".into(),
                        reference: data.reference.clone(),
                        transaction_reference: Some(data.id.to_string()),
                        settlement_status: None,
                        settlement_date: None,
                        tx_hash: "0x00".to_string(),
                    };
                    app_state.db.create_transaction(new_tx);
                }

                redis_conn
                    .del::<String, ()>(key)
                    .await
                    .map_err(|e| format!("Failed to delete Redis key: {}", e))?;

                log::info!("Successfully completed transfer for user: {}", user_id);
            }
        }
    } else {
        let new_rows_affected = app_state.db.update_transaction_by_tx_ref(
            data.id.to_string(),
            "COMPLETED".to_string(),
            data.reference.clone(),
        );

        if new_rows_affected.unwrap() == 0 {
            log::warn!("No transaction found for reference: {}", data.id);
        }
    }

    Ok(())
}


async fn handle_reversed_transfer(
    app_state: &web::Data<AppState>,
    data: &FlutterwaveWebhookData,
) -> Result<(), String> {
    log::warn!(
        "Processing reversed transfer: reference={}, id={}",
        data.reference,
        data.id
    );

    println!(
        "Processing reversed transfer: reference={}, id={}",
        data.reference, data.id
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
    }

    if !keys.is_empty() {
        for key in keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 3 {
                continue;
            }

            let user_id = match Uuid::parse_str(parts[2]) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to retrieve pending disbursement from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let rows_affected = app_state.db.update_transaction(
                    user_id,
                    "REVERSED".to_string(),
                    data.id.to_string(),
                );

                // ALERT ADMIN
                // RETRY DISBURSEMENT
                log::info!(
                    "Successfully marked disbursement as reversed for user: {}",
                    user_id
                );
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        app_state
            .db
            .update_transaction_status_by_tx_ref(data.id.to_string(), "REVERSED".to_string());
    }

    Ok(())
}



async fn handle_failed_transfer(
    app_state: &web::Data<AppState>,
    data: &FlutterwaveWebhookData,
) -> Result<(), String> {
    log::warn!(
        "Processing failed transfer: reference={}, id={}",
        data.reference,
        data.id
    );

    println!(
        "Processing failed transfer: reference={}, id={}",
        data.reference, data.id
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
    }

    if !keys.is_empty() {
        for key in keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 3 {
                continue;
            }

            let user_id = match Uuid::parse_str(parts[2]) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to retrieve pending disbursement from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let rows_affected = app_state.db.update_transaction(
                    user_id,
                    "FAILED".to_string(),
                    data.id.to_string(),
                );

                // ALERT ADMIN
                //RETRY DISBURSEMENT
                log::info!(
                    "Successfully marked disbursement as failed for user: {}",
                    user_id
                );

                 println!(
                    "Successfully marked disbursement as failed for user: {}",
                    user_id
                );
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        app_state
            .db
            .update_transaction_status_by_tx_ref(data.id.to_string(), "REVERSED".to_string());
    }

    Ok(())
}


async fn handle_pending_transfer(
    app_state: &web::Data<AppState>,
    data: &FlutterwaveWebhookData,
) -> Result<(), String> {
    log::info!(
        "Processing pending transfer: reference={}, id={}",
        data.reference,
        data.id
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }
    }

    if !keys.is_empty() {
        for key in keys {
            let parts: Vec<&str> = key.split(":").collect();
            if parts.len() != 3 {
                continue;
            }

            let user_id = match Uuid::parse_str(parts[2]) {
                Ok(id) => id,
                Err(_) => continue,
            };

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!(
                    "Failed to retrieve pending disbursement data from Redis: {}",
                    e
                )
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                app_state.db.update_transaction(
                    user_id,
                    "PENDING".to_string(),
                    data.id.to_string(),
                );
                log::info!("Updated transaction to PENDING for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        app_state
            .db
            .update_transaction_status_by_tx_ref(data.id.to_string(), "PENDING".to_string());
    }

    Ok(())
}
