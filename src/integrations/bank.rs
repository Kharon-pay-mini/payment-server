use super::model::{
    AccountVerificationResponse, Bank, BankApiResponse, DisbursementSchema, MonnifyAuthResponse,
    MonnifyDisbursementResponseBody, MonnifyEventData, MonnifyResponse, MonnifyWebhookPayload,
    PendingDisbursement,
};
use crate::AppState;
use actix_web::{web, HttpRequest, Result};
use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use redis::AsyncCommands;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
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
            let auth_response: MonnifyAuthResponse = response
                .json()
                .await
                .map_err(|e| format!("Failed to parse auth response: {}", e))?;

            Ok(auth_response.response_body.access_token)
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
) -> Result<MonnifyDisbursementResponseBody, String> {
    let auth_token = get_monnify_auth_token(app_state).await?;

    let monnify_reference = if reference.len() > 64 {
        reference[0..64].to_string()
    } else {
        reference.to_string()
    };

    let disbursement_request = DisbursementSchema {
        amount,
        reference: monnify_reference,
        narration: narration.map(|n| n.to_string()),
        destination_bank_code: bank_code.to_string(),
        destination_account_number: account_number.to_string(),
        currency: currency.to_string(),
        source_account_number: app_state.env.monnify_wallet_account_number.clone(),
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
            let raw_body = response
                .text()
                .await
                .map_err(|e| format!("Failed to read response body: {}", e))?;

            log::info!("Raw disbursement response: {}", raw_body);

            match serde_json::from_str::<MonnifyResponse>(&raw_body) {
                Ok(disbursement_response) => {
                    if disbursement_response.request_successful {
                        Ok(disbursement_response.response_body)
                    } else {
                        Err(format!(
                            "Disbursement error: {} (code: {})",
                            disbursement_response.response_message,
                            disbursement_response.response_code
                        ))
                    }
                }
                Err(e) => Err(format!("Failed to parse disbursement response: {}", e)),
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

    match redis_conn.set_ex(&key, data, 86400).await {
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

    redis_conn
        .del::<&str, ()>(&key)
        .await
        .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;

    Ok(())
}

pub fn verify_monnify_webhook_signature(
    req: &HttpRequest,
    raw_body: &[u8],
    secret_key: &str,
) -> bool {
    let signature = match req.headers().get("monnify-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(_) => return false,
        },
        None => return false,
    };

    let mut mac = match HmacSha512::new_from_slice(secret_key.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };

    mac.update(raw_body);
    let result = mac.finalize().into_bytes();
    let calculated_signature = hex::encode(result);

    calculated_signature == signature
}

pub async fn process_monnify_webhook(
    app_state: &web::Data<AppState>,
    payload: MonnifyWebhookPayload,
) -> Result<(), String> {
    match payload.event_type.as_str() {
        "SUCCESSFUL_DISBURSEMENT" => {
            handle_successful_disbursement(app_state, &payload.event_data).await
        }
        "FAILED_DISBURSEMENT" => handle_failed_disbursement(app_state, &payload.event_data).await,
        "PENDING_DISBURSEMENT" => handle_pending_disbursement(app_state, &payload.event_data).await,
        "DISBURSEMENT_PROCESSING" => {
            handle_processing_disbursement(app_state, &payload.event_data).await
        }
        "SETTLEMENT_COMPLETED" => handle_settlement_completed(app_state, &payload.event_data).await,
        _ => {
            log::info!("Unhandled webhook event type: {}", payload.event_type);
            Ok(())
        }
    }
}

pub async fn handle_successful_disbursement(
    app_state: &web::Data<AppState>,
    event_data: &MonnifyEventData,
) -> Result<(), String> {
    log::info!(
        "Processing successful disbursement: reference={}, transaction_ref={}",
        event_data.reference,
        event_data.transaction_reference
    );
    println!(
        "Processing successful disbursement: reference={}, transaction_ref={}",
        event_data.reference, event_data.transaction_reference
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    loop {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", event_data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }

        break; // Exit the loop since `scan_match` does not use cursors in this context
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

            if let Some(data) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let result = sqlx::query(
                    r#"
                    UPDATE transactions
                    SET payment_status = $1,
                        updated_at = $2,
                        transaction_reference = $3,
                    WHERE user_id = $4 AND tx_hash = $5
                    "#,
                )
                .bind("COMPLETED")
                .bind(Utc::now())
                .bind(&event_data.transaction_reference)
                .bind(&user_id)
                .bind(&disbursement.crypto_tx_hash)
                .execute(&app_state.db)
                .await
                .map_err(|e| format!("Failed to update transaction: {}", e))?;

                if result.rows_affected() == 0 {
                    sqlx::query(
                        r#"
                        INSERT INTO transactions (
                            user_id, order_type, crypto_amount, crypto_type,
                            fiat_amount, fiat_currency, payment_method, payment_status,
                            tx_hash, reference, transaction_reference
                    )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                        "#,
                    )
                    .bind(&user_id)
                    .bind(&disbursement.order_type)
                    .bind(&disbursement.crypto_amount)
                    .bind(&disbursement.crypto_symbol)
                    .bind(&disbursement.amount)
                    .bind(&disbursement.currency)
                    .bind(&disbursement.payment_method)
                    .bind("COMPLETED")
                    .bind(&disbursement.crypto_tx_hash)
                    .bind(&event_data.reference)
                    .bind(&event_data.transaction_reference)
                    .execute(&app_state.db)
                    .await
                    .map_err(|e| format!("Failed to create transaction: {}", e))?;
                }

                redis_conn
                    .del::<String, ()>(key)
                    .await
                    .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;

                log::info!("Successfully completed disbursement for user: {}", user_id);
            }
        }
    } else {
        let result = sqlx::query(
            r#"
            UPDATE transactions
            SET payment_status = $1,
                updated_at = $2,
                reference = $3
            WHERE transaction_reference = $4
            "#,
        )
        .bind("COMPLETED")
        .bind(Utc::now())
        .bind(&event_data.reference)
        .bind(&event_data.transaction_reference)
        .execute(&app_state.db)
        .await
        .map_err(|e| format!("Failed to update transaction: {}", e))?;

        if result.rows_affected() == 0 {
            log::warn!(
                "No transaction found for reference: {}",
                event_data.transaction_reference
            );
        }
    }

    Ok(())
}

pub async fn handle_failed_disbursement(
    app_state: &web::Data<AppState>,
    event_data: &MonnifyEventData,
) -> Result<(), String> {
    log::warn!(
        "Processing failed disbursement: reference={}, transaction_ref={}",
        event_data.reference,
        event_data.transaction_reference
    );

    println!(
        "Processing failed disbursement: reference={}, transaction_ref={}",
        event_data.reference, event_data.transaction_reference
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    loop {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", event_data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }

        break;
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

            if let Some(data) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                sqlx::query(
                    r#"
                    UPDATE transactions
                    SET payment_status = $1,
                        updated_at = $2,
                        transaction_reference = $3
                    WHERE user_id = $4 AND tx_hash = $5
                    "#,
                )
                .bind("FAILED")
                .bind(Utc::now())
                .bind(&event_data.transaction_reference)
                .bind(&user_id)
                .bind(&disbursement.crypto_tx_hash)
                .execute(&app_state.db)
                .await
                .map_err(|e| format!("Failed to update transaction: {}", e))?;

                redis_conn
                    .del::<String, ()>(key)
                    .await
                    .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;

                log::info!(
                    "Successfully marked disbursement as failed for user: {}",
                    user_id
                );
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            event_data.reference
        );
        sqlx::query(
            r#"
            UPDATE transactions
            SET payment_status = $1,
                updated_at = $2
            WHERE transaction_reference = $3
            "#,
        )
        .bind("FAILED")
        .bind(Utc::now())
        .bind(&event_data.transaction_reference)
        .execute(&app_state.db)
        .await
        .map_err(|e| format!("Failed to update transaction: {}", e))?;
    }

    Ok(())
}

pub async fn handle_pending_disbursement(
    app_state: &web::Data<AppState>,
    event_data: &MonnifyEventData,
) -> Result<(), String> {
    log::info!(
        "Processing pending disbursement: reference={}, transaction_ref={}",
        event_data.reference,
        event_data.transaction_reference
    );
    println!(
        "Processing pending disbursement: reference={}, transaction_ref={}",
        event_data.reference, event_data.transaction_reference
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    loop {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", event_data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }

        break;
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

            if let Some(data) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                sqlx::query(
                    r#"
                    UPDATE transactions
                    SET payment_status = $1,
                        updated_at = $2,
                        transaction_reference = $3
                    WHERE user_id = $4 AND tx_hash = $5
                    "#,
                )
                .bind("PENDING")
                .bind(Utc::now())
                .bind(&event_data.transaction_reference)
                .bind(&user_id)
                .bind(&disbursement.crypto_tx_hash)
                .execute(&app_state.db)
                .await
                .map_err(|e| format!("Failed to update transaction: {}", e))?;

                log::info!("Updated disbursement as pending for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            event_data.reference
        );
        sqlx::query(
            r#"
            UPDATE transactions
            SET payment_status = $1,
                updated_at = $2
            WHERE transaction_reference = $3 OR tx_hash = $4
            "#,
        )
        .bind("PENDING")
        .bind(Utc::now())
        .bind(&event_data.transaction_reference)
        .execute(&app_state.db)
        .await
        .map_err(|e| format!("Failed to update transaction: {}", e))?;
    }

    Ok(())
}

pub async fn handle_processing_disbursement(
    app_state: &web::Data<AppState>,
    event_data: &MonnifyEventData,
) -> Result<(), String> {
    log::info!(
        "Processing disbursement: reference={}, transaction_ref={}",
        event_data.reference,
        event_data.transaction_reference
    );
    println!(
        "Processing disbursement: reference={}, transaction_ref={}",
        event_data.reference, event_data.transaction_reference
    );

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let mut keys = Vec::new();

    loop {
        let mut iter = redis_conn
            .scan_match::<_, String>(format!("pending disbursement: {}:*", event_data.reference))
            .await
            .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

        while let Some(key) = iter.next_item().await {
            keys.push(key);
        }

        break;
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

            if let Some(data) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                sqlx::query(
                    r#"
                    UPDATE transactions
                    SET payment_status = $1,
                        updated_at = $2,
                        transaction_reference = $3
                    WHERE user_id = $4 AND tx_hash = $5
                    "#,
                )
                .bind("PROCESSING")
                .bind(Utc::now())
                .bind(&event_data.transaction_reference)
                .bind(&user_id)
                .bind(&disbursement.crypto_tx_hash)
                .execute(&app_state.db)
                .await
                .map_err(|e| format!("Failed to update transaction: {}", e))?;

                log::info!("Updated disbursement as processing for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            event_data.reference
        );
        sqlx::query(
            r#"
            UPDATE transactions
            SET payment_status = $1,
                updated_at = $2
            WHERE transaction_reference = $3 OR tx_hash = $4
            "#,
        )
        .bind("PROCESSING")
        .bind(Utc::now())
        .bind(&event_data.transaction_reference)
        .execute(&app_state.db)
        .await
        .map_err(|e| format!("Failed to update transaction: {}", e))?;
    }

    Ok(())
}

pub async fn handle_settlement_completed(
    app_state: &web::Data<AppState>,
    event_data: &MonnifyEventData,
) -> Result<(), String> {
    log::info!(
        "Settlement completed for reference={}, transaction_ref={}",
        event_data.reference,
        event_data.transaction_reference
    );
    println!(
        "Settlement completed for reference={}, transaction_ref={}",
        event_data.reference, event_data.transaction_reference
    );

    let result = sqlx::query(
        r#"
        UPDATE transactions
        SET settlement_status = 'SETTLED', 
            settlement_date = $1,
            transaction_reference = $2
        WHERE reference = $3 
        "#,
    )
    .bind(Utc::now())
    .bind(&event_data.transaction_reference)
    .bind(&event_data.reference)
    .execute(&app_state.db)
    .await
    .map_err(|e| format!("Failed to update transaction: {}", e))?;

    if result.rows_affected() == 0 {
        log::warn!(
            "No transactions found for settlement with transaction_ref: {}",
            event_data.transaction_reference
        );
    } else {
        log::info!(
            "Updated {} transactions for settlement with transaction_ref: {}",
            result.rows_affected(),
            event_data.transaction_reference
        );
    }

    Ok(())
}
