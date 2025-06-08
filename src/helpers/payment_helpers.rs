use std::time::Duration;

use actix_web::web;
use chrono::{FixedOffset, Utc};
use num_traits::FromPrimitive;
use rand::Rng;
use redis::AsyncCommands;
use rust_decimal::Decimal;
use std::time::Duration as stdDuration;
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    database::transaction_db::TransactionImpl,
    helpers::models::{RetryableTransfer, TransferDetails},
    integrations::{
        flutterwave::disburse_payment_using_flutterwave,
        model::{PendingDisbursement, TransactionDetails},
    },
    models::models::NewTransaction,
    service::email_service::send_admin_failed_transfer_alert,
    AppState,
};

pub fn calculate_fiat_amount(crypto_amount: i64, exchange_rate: i64) -> i64 {
    crypto_amount * exchange_rate
}

pub fn create_transaction_record(
    user_id: Uuid,
    pending_disbursement: &PendingDisbursement,
    crypto_amount: i64,
    fiat_amount: i64,
    payment_status: String,
    reference: String,
    transaction_hash: String,
) -> NewTransaction {
    NewTransaction {
        user_id,
        order_type: pending_disbursement.order_type.clone(),
        crypto_amount: Decimal::from_f64(crypto_amount as f64)
            .expect("Invalid crypto amount conversion"),
        crypto_type: pending_disbursement.crypto_symbol.clone(),
        fiat_amount: Decimal::from_i64(fiat_amount).expect("Invalid fiat amount conversion"),
        fiat_currency: pending_disbursement.currency.clone(),
        payment_method: pending_disbursement.payment_method.clone(),
        payment_status,
        tx_hash: transaction_hash,
        reference,
        settlement_status: None,
        transaction_reference: None,
        settlement_date: None,
    }
}

pub fn create_transaction_details(
    reference: String,
    transaction_ref: String,
    crypto_amount: i64,
    crypto_symbol: String,
    fiat_amount: i64,
    pending_disbursement: &PendingDisbursement,
    transaction_hash: String,
) -> TransactionDetails {
    TransactionDetails {
        reference,
        transaction_ref: Some(transaction_ref),
        crypto_amount: crypto_amount.to_string(),
        crypto_symbol,
        fiat_amount: fiat_amount.to_string(),
        bank_name: pending_disbursement.bank_name.clone(),
        account_number: pending_disbursement.account_number.clone(),
        account_name: pending_disbursement.account_name.clone(),
        transaction_hash,
        transaction_date: Utc::now()
            .with_timezone(&FixedOffset::east_opt(1 * 3600).unwrap())
            .format("%B %d, %Y at %I:%M %p WAT")
            .to_string(),
    }
}

pub async fn notify_admin_of_failed_transfer(
    transfer_details: &TransactionDetails,
) -> Result<(), String> {
    log::error!("Transfer failed, alerting admins...");

    let transfer_details = TransactionDetails {
        reference: transfer_details.reference.clone(),
        transaction_ref: transfer_details.transaction_ref.clone(),
        crypto_amount: transfer_details.crypto_amount.clone(),
        crypto_symbol: transfer_details.crypto_symbol.clone(),
        fiat_amount: transfer_details.fiat_amount.clone(),
        bank_name: transfer_details.bank_name.clone(),
        account_number: transfer_details.account_number.clone(),
        account_name: transfer_details.account_name.clone(),
        transaction_hash: transfer_details.transaction_hash.clone(),
        transaction_date: transfer_details.transaction_date.clone(),
    };
    // send email
    if let Err(e) = send_admin_failed_transfer_alert(&transfer_details).await {
        log::error!("Failed to send failed transfer alerts: {}", e);
    };

    Ok(())
}

/*
impl RetryableTransfer {
    pub fn new(
        user_id: Uuid,
        reference: String,
        amount: i64,
        narration: Option<String>,
        bank_code: String,
        account_number: String,
        currency: String,
        beneficiary_name: String,
    ) -> Self {
        Self {
            user_id,
            reference,
            amount,
            narration,
            bank_code,
            account_number,
            currency,
            beneficiary_name,
            retry_count: 0,
            max_retries: 3,
            last_attempt: Utc::now(),
            next_retry: Utc::now() + chrono::Duration::seconds(60),
            original_error: None,
        }
    }

    pub fn calculate_next_retry(&mut self) {
        let base_delays = [60, 180, 600];

        if self.retry_count < base_delays.len() as u32 {
            let base_delay = base_delays[self.retry_count as usize];

            let mut rng = rand::rng();
            let jitter_factor = rng.random_range(0.75..=1.25);
            let delay_with_jitter = (base_delay as f64 * jitter_factor) as f64;

            self.next_retry = Utc::now() + chrono::Duration::seconds(delay_with_jitter as i64);
        }
    }

    pub fn should_retry(&self) -> bool {
        self.retry_count < self.max_retries && Utc::now() >= self.next_retry
    }

    pub fn is_exhausted(&self) -> bool {
        self.retry_count >= self.max_retries
    }
}

pub async fn schedule_transfer_retry(
    retryable_transfer: &RetryableTransfer,
    app_state: &web::Data<AppState>,
) -> Result<(), String> {
    let retry_job = serde_json::to_string(&retryable_transfer)
        .map_err(|e| format!("Failed to serialize retry job: {}", e))?;

    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    let _: () = redis_conn
        .lpush("retry_queue", retry_job)
        .await
        .map_err(|e| format!("Failed to queue retry job: {}", e))?;

    Ok(())
}

pub async fn process_retry_transfer(app_state: &web::Data<AppState>) -> Result<(), String> {
    let mut redis_conn = app_state
        .redis_pool
        .get()
        .await
        .map_err(|e| format!("Failed to get Redis connection: {}", e))?;

    loop {
        let job_data: Option<Vec<String>> = redis_conn
            .brpop("retry_queue", 5.0)
            .await
            .map_err(|e| format!("Failed to pop retry job: {}", e))?;

        if let Some(mut job_vec) = job_data {
            if job_vec.len() < 2 {
                log::warn!("Invalid job data format from retry queue");
                continue;
            }

            let job_str = job_vec.pop().unwrap();
            let mut retryable_transfer: RetryableTransfer = serde_json::from_str(&job_str)
                .map_err(|e| format!("Failed to parse retry job: {}", e))?;

            if retryable_transfer.should_retry() {
                log::info!(
                    "Executing retry #{} for transfer: {}",
                    retryable_transfer.retry_count,
                    retryable_transfer.reference
                );

                match disburse_payment_using_flutterwave(
                    app_state,
                    &retryable_transfer.reference,
                    retryable_transfer.amount,
                    retryable_transfer.narration.as_deref(),
                    &retryable_transfer.bank_code,
                    &retryable_transfer.account_number,
                    &retryable_transfer.currency,
                    Some(&retryable_transfer.beneficiary_name),
                )
                .await
                {
                    Ok(transfer_data) => {
                        log::info!(
                            "Retry successful for transfer: {}, new_id: {}",
                            retryable_transfer.reference,
                            transfer_data.id
                        );

                        let _ = app_state
                            .db
                            .update_transaction(retryable_transfer.user_id, "SUCCESS".to_string());

                        let retry_key = format!("retry_transfer:{}", retryable_transfer.reference);
                        let _: () = redis_conn
                            .del(&retry_key)
                            .await
                            .map_err(|e| format!("Failed to delete retry record: {}", e))?;

                        let pending_key = format!(
                            "pending disbursement:{}:{}",
                            retryable_transfer.reference, retryable_transfer.user_id
                        );

                        let _: () = redis_conn
                            .del(&pending_key)
                            .await
                            .map_err(|e| format!("Failed to delete pending disbursement: {}", e))?;
                    }
                    Err(e) => {
                        log::warn!(
                            "Retry #{} failed for transfer: {}, error: {}",
                            retryable_transfer.retry_count,
                            retryable_transfer.reference,
                            e
                        );

                        retryable_transfer.retry_count += 1;
                        retryable_transfer.last_attempt = Utc::now();
                        retryable_transfer.original_error = Some(e);

                        if retryable_transfer.is_exhausted() {
                            // Permanent failure - cleanup and notify
                            log::error!(
                                "Transfer permanently failed after {} retries: {}",
                                retryable_transfer.max_retries,
                                retryable_transfer.reference
                            );

                            // Mark as failed
                            let _ = app_state.db.update_transaction(
                                retryable_transfer.user_id,
                                "FAILED".to_string(),
                            );

                            // Notify admin
                            notify_admin_of_failed_transfer(&retryable_transfer, app_state).await?;

                            // Clean up
                            let retry_key =
                                format!("retry_transfer:{}", retryable_transfer.reference);
                            let _: () = redis_conn
                                .del(&retry_key)
                                .await
                                .map_err(|e| format!("Failed to delete retry record: {}", e))?;

                            let pending_key = format!(
                                "pending disbursement:{}:{}",
                                retryable_transfer.reference, retryable_transfer.user_id
                            );
                            let _: () = redis_conn.del(&pending_key).await.map_err(|e| {
                                format!("Failed to delete pending disbursement: {}", e)
                            })?;
                        } else {
                            retryable_transfer.calculate_next_retry();

                            log::info!(
                                "Scheduling retry #{} for transfer: {} at {}",
                                retryable_transfer.retry_count,
                                retryable_transfer.reference,
                                retryable_transfer
                                    .next_retry
                                    .format("%Y-%m-%d %H:%M:%S UTC")
                            );

                            // Update retry record
                            let retry_key =
                                format!("retry_transfer:{}", retryable_transfer.reference);
                            let retry_data = serde_json::to_string(&retryable_transfer)
                                .map_err(|e| format!("Failed to serialize retry record: {}", e))?;

                            let expiration_seconds = 1800; // 30 minutes
                            let _: () = redis_conn
                                .set_ex(&retry_key, retry_data, expiration_seconds)
                                .await
                                .map_err(|e| format!("Failed to store retry record: {}", e))?;

                            // Re-queue for next attempt
                            let job_str = serde_json::to_string(&retryable_transfer)
                                .map_err(|e| format!("Failed to serialize retry job: {}", e))?;
                            let _: () = redis_conn
                                .lpush("retry_queue", job_str)
                                .await
                                .map_err(|e| format!("Failed to re-queue retry job: {}", e))?;
                        }
                    }
                }
            } else {
                // Not time yet, put it back in queue
                log::debug!(
                    "Transfer retry not due yet: {}, next retry at: {}",
                    retryable_transfer.reference,
                    retryable_transfer
                        .next_retry
                        .format("%Y-%m-%d %H:%M:%S UTC")
                );

                let job_str = serde_json::to_string(&retryable_transfer)
                    .map_err(|e| format!("Failed to serialize retry job: {}", e))?;
                let _: () = redis_conn
                    .lpush("retry_queue", job_str)
                    .await
                    .map_err(|e| format!("Failed to re-queue retry job: {}", e))?;

                sleep(stdDuration::from_secs(30)).await;
            }
        } else {
            // No jobs in queue, wait a bit
            sleep(stdDuration::from_secs(5)).await;
        }
    }
}

pub async fn start_retry_processor(app_state: web::Data<AppState>) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = process_retry_transfer(&app_state).await {
                log::error!("Retry processor error: {}", e);
                sleep(stdDuration::from_secs(10)).await;
            }
        }
    });
}


*/
