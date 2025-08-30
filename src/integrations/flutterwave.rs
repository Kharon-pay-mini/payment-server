use actix_web::web;

use num_traits::FromPrimitive;
use redis::AsyncCommands;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use rust_decimal::Decimal;

use crate::{
    database::{db::AppError, transaction_db::TransactionImpl, user_db::UserImpl},
    helpers::payment_helpers::{
        calculate_fiat_amount, create_transaction_details, notify_admin_of_failed_transfer,
    },
    integrations::model::{FlutterwaveTransferResponse, PendingDisbursement},
    models::models::NewTransaction,
    pricefeed::pricefeed,
    service::email_service::send_confirmation_email,
    AppState,
};

use super::model::{
    AccountVerificationResponse, Bank, FlutterwaveBankApiResponse, FlutterwaveTransferData,
    FlutterwaveTransferRequest, FlutterwaveWebhookData, FlutterwaveWebhookPayload,
};

pub async fn disburse_payment_using_flutterwave(
    app_state: &web::Data<AppState>,
    reference: &str,
    amount: f64,
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

    match payload.data.status.as_str() {
        "SUCCESSFUL" => {
            log::info!("🟢 Routing to handle_successful_transfer");
            handle_successful_transfer(app_state, &payload.data).await
        }
        "FAILED" => {
            log::info!("🔴 Routing to handle_failed_transfer");
            handle_failed_transfer(app_state, &payload.data).await
        }
        "PENDING" | "PROCESSING" => {
            log::info!("🟡 Routing to handle_pending_transfer");
            handle_pending_transfer(app_state, &payload.data).await
        }
        "REVERSED" => handle_reversed_transfer(app_state, &payload.data).await,
        _ => {
            log::warn!("Unhandled Flutterwave event type: {}", payload.event);
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
            .scan_match::<_, String>(format!("pending disbursement:{}:*", data.reference))
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

            let user_id = parts[2].to_string();

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to get pending disbursement data from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let tx_hash_key = format!("tx_hash:{}:{}", data.reference, user_id);
                let stored_hash: Option<String> = redis_conn.get(&tx_hash_key).await.ok();

                // Try to update existing transaction first
                match app_state
                    .db
                    .update_transaction(&user_id, &data.reference, "COMPLETED".to_string())
                {
                    Ok(rows_affected) => {
                        if rows_affected == 0 {
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
                                tx_hash: stored_hash.clone().unwrap_or("0x00".to_string()),
                            };

                            match app_state.db.create_transaction(new_tx) {
                                Ok(_) => {
                                    log::info!(
                                        "Successfully created new transaction for reference: {}",
                                        data.id
                                    );
                                }
                                Err(e) => {
                                    // Check if it's a unique violation error
                                    if let AppError::DieselError(
                                        diesel::result::Error::DatabaseError(
                                            diesel::result::DatabaseErrorKind::UniqueViolation,
                                            _,
                                        ),
                                    ) = e
                                    {
                                        log::warn!("Transaction with reference {} already exists (race condition), skipping creation", data.id);
                                    } else {
                                        log::error!("Failed to create transaction: {:?}", e);
                                        return Err(format!(
                                            "Failed to create transaction: {:?}",
                                            e
                                        ));
                                    }
                                }
                            }
                        } else {
                            log::info!(
                                "Successfully updated existing transaction for user: {}",
                                user_id
                            );
                        }
                    }
                    Err(e) => {
                        // Handle unique violation in update as well
                        if let AppError::DieselError(diesel::result::Error::DatabaseError(
                            diesel::result::DatabaseErrorKind::UniqueViolation,
                            _,
                        )) = e
                        {
                            log::warn!("Transaction with reference {} already exists during update (race condition), continuing with email", data.id);
                        } else {
                            log::error!("Failed to update transaction: {:?}", e);
                            return Err(format!("Failed to update transaction: {:?}", e));
                        }
                    }
                }

                // Send confirmation email
                match app_state.db.get_user_by_id(user_id.as_str()) {
                    Ok(user) => {
                        let usdt_ngn_rate = match pricefeed::get_current_usdt_ngn_rate(
                            app_state.price_feed.clone(),
                        ) {
                            Ok(rate) => rate,
                            Err(e) => {
                                log::error!("Failed to fetch USDT to NGN rate for email: {}", e);
                                0.0
                            }
                        };

                        let crypto_amount = disbursement.crypto_amount;
                        let fiat_amount = calculate_fiat_amount(crypto_amount, usdt_ngn_rate);

                        let transaction_details = create_transaction_details(
                            data.reference.clone(),
                            data.id.to_string(),
                            crypto_amount,
                            disbursement.crypto_symbol.clone(),
                            fiat_amount,
                            &disbursement,
                            stored_hash.unwrap_or("0x00".to_string()),
                        );

                        if let Err(e) =
                            send_confirmation_email(&user.email, transaction_details).await
                        {
                            log::error!("Failed to send confirmation email: {}", e);
                        } else {
                            log::info!(
                                "Confirmation email sent successfully to user: {}",
                                user.email
                            );
                        }
                    }
                    Err(e) => {
                        log::error!("Failed to get user for email notification: {:?}", e);
                    }
                }

                redis_conn
                    .del::<String, ()>(key)
                    .await
                    .map_err(|e| format!("Failed to delete Redis key: {}", e))?;

                log::info!("Successfully completed transfer for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        match app_state.db.update_transaction_by_tx_ref(
            data.id.to_string(),
            "COMPLETED".to_string(),
            data.reference.clone(),
        ) {
            Ok(rows_affected) => {
                if rows_affected == 0 {
                    log::warn!("No transaction found for reference: {}", data.id);
                } else {
                    log::info!("Successfully updated transaction by reference: {}", data.id);
                }
            }
            Err(e) => {
                log::error!("Failed to update transaction by reference: {:?}", e);
                return Err(format!(
                    "Failed to update transaction by reference: {:?}",
                    e
                ));
            }
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
            .scan_match::<_, String>(format!("pending disbursement:{}:*", data.reference))
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

            let user_id = parts[2].to_string();

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to retrieve pending disbursement from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let _disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let _rows_affected = app_state
                    .db
                    .update_transaction(&user_id, &data.reference,"REVERSED".to_string());

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

        let _ = app_state
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

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    // Find pending disbursement
    let pending_key = format!("pending disbursement:{}:*", data.reference);
    let keys: Vec<String> = redis_conn
        .keys(&pending_key)
        .await
        .map_err(|e| format!("Failed to scan Redis keys: {}", e))?;

    if !keys.is_empty() {
        for key in keys {
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 3 {
                continue;
            }

            let user_id = parts[2].to_string();

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!("Failed to get pending disbursement data from Redis: {}", e)
            })?;

            if let Some(data_str) = pending_data {
                let disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let tx_hash_key = format!("tx_hash:{}:{}", data.reference, user_id);
                let stored_hash: Option<String> = redis_conn.get(&tx_hash_key).await.ok();

                // Get exchange rate for proper fiat amount calculation
                let usdt_ngn_rate: f64 = match pricefeed::get_current_usdt_ngn_rate(
                    app_state.price_feed.clone(),
                ) {
                    Ok(rate) => rate,
                    Err(e) => {
                        log::error!("Failed to fetch USDT to NGN rate: {}", e);
                        return Err("Failed to fetch exchange rate".to_string());
                    }
                };

                let crypto_amount = disbursement.crypto_amount as f64;
                let fiat_amount = calculate_fiat_amount(crypto_amount, usdt_ngn_rate);

                // Try to update existing transaction first
                match app_state
                    .db
                    .update_transaction(&user_id, &data.reference,"FAILED".to_string())
                {
                    Ok(rows_affected) => {
                        if rows_affected == 0 {
                            // No existing transaction found, create new one
                            let new_tx = NewTransaction {
                                user_id: user_id.clone(),
                                order_type: disbursement.order_type.clone(),
                                crypto_amount: Decimal::from_f64(disbursement.crypto_amount)
                                    .expect("Invalid float -> Decimal conversion"),
                                crypto_type: disbursement.crypto_symbol.clone(),
                                fiat_amount: Decimal::from_f64(fiat_amount as f64)
                                    .expect("Invalid float -> Decimal conversion"),
                                fiat_currency: disbursement.currency.clone(),
                                payment_method: disbursement.payment_method.clone(),
                                payment_status: "FAILED".into(),
                                reference: data.reference.clone(),
                                transaction_reference: Some(data.id.to_string()),
                                settlement_status: None,
                                settlement_date: None,
                                tx_hash: stored_hash.clone().unwrap_or("0x00".to_string()),
                            };

                            match app_state.db.create_transaction(new_tx) {
                                Ok(_) => {
                                    log::info!(
                                        "Successfully created new FAILED transaction for reference: {}",
                                        data.id
                                    );
                                }
                                Err(e) => {
                                    // Check if it's a unique violation error
                                    if let AppError::DieselError(
                                        diesel::result::Error::DatabaseError(
                                            diesel::result::DatabaseErrorKind::UniqueViolation,
                                            _,
                                        ),
                                    ) = e
                                    {
                                        log::warn!("Transaction with reference {} already exists (race condition), skipping creation", data.id);
                                    } else {
                                        log::error!("Failed to create FAILED transaction: {:?}", e);
                                        return Err(format!(
                                            "Failed to create FAILED transaction: {:?}",
                                            e
                                        ));
                                    }
                                }
                            }
                        } else {
                            log::info!(
                                "Successfully updated existing transaction to FAILED for user: {}",
                                user_id
                            );
                        }
                    }
                    Err(e) => {
                        // Handle unique violation in update as well
                        if let AppError::DieselError(diesel::result::Error::DatabaseError(
                            diesel::result::DatabaseErrorKind::UniqueViolation,
                            _,
                        )) = e
                        {
                            log::warn!("Transaction with reference {} already exists during update (race condition), continuing", data.id);
                        } else {
                            log::error!("Failed to update transaction to FAILED: {:?}", e);
                            return Err(format!("Failed to update transaction to FAILED: {:?}", e));
                        }
                    }
                }

                let transfer_details = create_transaction_details(
                    data.reference.clone(),
                    data.id.to_string(),
                    crypto_amount,
                    disbursement.crypto_symbol.clone(),
                    fiat_amount,
                    &disbursement,
                    stored_hash.unwrap_or("0x00".to_string()),
                );

                if let Err(e) = notify_admin_of_failed_transfer(&transfer_details).await {
                    log::error!(
                        "Failed to notify admin about failed transfer {}: {}",
                        data.reference,
                        e
                    );
                }

                // Clean up the pending disbursement from Redis
                redis_conn
                    .del::<String, ()>(key)
                    .await
                    .map_err(|e| format!("Failed to delete Redis key: {}", e))?;

                log::info!("Successfully completed failed transfer processing for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        // Update existing transaction to FAILED status even if no pending disbursement
        match app_state.db.update_transaction_by_tx_ref(
            data.id.to_string(),
            "FAILED".to_string(),
            data.reference.clone(),
        ) {
            Ok(rows_affected) => {
                if rows_affected == 0 {
                    log::warn!("No transaction found for reference: {}", data.id);
                } else {
                    log::info!("Successfully updated transaction to FAILED by reference: {}", data.id);
                }
            }
            Err(e) => {
                log::error!("Failed to update transaction to FAILED by reference: {:?}", e);
                return Err(format!(
                    "Failed to update transaction to FAILED by reference: {:?}",
                    e
                ));
            }
        }
    }

    Ok(())
}

async fn handle_pending_transfer(
    app_state: &web::Data<AppState>,
    data: &FlutterwaveWebhookData,
) -> Result<(), String> {
    log::info!(
        "PENDING WEBHOOK RECEIVED: reference={}, id={}",
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
            .scan_match::<_, String>(format!("pending disbursement:{}:*", data.reference))
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

            let user_id = parts[2].to_string();

            let pending_data: Option<String> = redis_conn.get(&key).await.map_err(|e| {
                format!(
                    "Failed to retrieve pending disbursement data from Redis: {}",
                    e
                )
            })?;

            if let Some(data_str) = pending_data {
                let _disbursement: PendingDisbursement = serde_json::from_str(&data_str)
                    .map_err(|e| format!("Failed to parse pending disbursement: {}", e))?;

                let _ = app_state
                    .db
                    .update_transaction(&user_id, &data.reference,  "PENDING".to_string());
                log::info!("Updated transaction to PENDING for user: {}", user_id);
            }
        }
    } else {
        log::warn!(
            "No pending disbursement found for reference: {}",
            data.reference
        );

        let _ = app_state
            .db
            .update_transaction_status_by_tx_ref(data.id.to_string(), "PENDING".to_string());
    }

    Ok(())
}

/*
SIDE NOTES FOR LATER IMPLEMENTATIONS
Additional Recommendations:

Circuit Breaker: Stop retries if Flutterwave is experiencing widespread issues
Monitoring: Track retry success rates and adjust intervals
Dead Letter Queue: Store permanently failed transfers for manual review
Rate Limiting: Don't overwhelm Flutterwave API with retries
*/
