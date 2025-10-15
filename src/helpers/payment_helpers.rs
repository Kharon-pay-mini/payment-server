use crate::helpers::auth_helpers::{extract_auth_headers, verify_api_key, verify_hmac_signature};
use crate::helpers::validation_helpers::{validate_reference, validate_user_id, verify_timestamp};
use crate::integrations::model::{
    ConfirmDisbursementRequest, FlutterwaveTransferData, PaymentResult,
};
use crate::pricefeed;
use crate::{
    database::{db::Database, transaction_db::TransactionImpl, user_bank_account_db::UserBankImpl},
    integrations::{
        bank::store_pending_disbursement,
        flutterwave::{fetch_banks_via_flutterwave, verify_account_via_flutterwave},
        model::{
            AccountVerificationResponse, InitDisbursementResponse, InitOfframpRequest,
            PendingDisbursement, TransactionDetails,
        },
    },
    models::models::{NewTransaction, UserBankAccount},
    service::email_service::send_admin_failed_transfer_alert,
    AppState,
};
use actix_web::{web, HttpRequest, HttpResponse};
use chrono::{FixedOffset, Utc};
use num_traits::FromPrimitive;

use redis::AsyncCommands;
use rust_decimal::Decimal;
use serde_json::json;

use uuid::Uuid;

pub fn calculate_fiat_amount(crypto_amount: f64, exchange_rate: f64) -> f64 {
    crypto_amount * exchange_rate
}

pub fn create_transaction_record(
    user_id: String,
    pending_disbursement: &PendingDisbursement,
    crypto_amount: f64,
    fiat_amount: f64,
    payment_status: String,
    reference: String,
    transaction_hash: String,
) -> NewTransaction {
    NewTransaction {
        user_id: user_id.clone(),
        order_type: pending_disbursement.order_type.clone(),
        crypto_amount: Decimal::from_f64(crypto_amount as f64)
            .expect("Invalid crypto amount conversion"),
        crypto_type: pending_disbursement.crypto_symbol.clone(),
        fiat_amount: Decimal::from_f64(fiat_amount).expect("Invalid fiat amount conversion"),
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
    crypto_amount: f64,
    crypto_symbol: String,
    fiat_amount: f64,
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

pub fn get_and_confirm_bank_details(
    db: &Database,
    user_id: &str,
    bank_account_id: Uuid,
    reference: String,
) -> Result<UserBankAccount, HttpResponse> {
    let bank_details = match db.get_bank_by_id(bank_account_id) {
        Ok(bank) => bank,
        Err(e) => {
            log::error!("Failed to fetch bank account: {:?}", e);
            return Err(
                HttpResponse::InternalServerError().json(InitDisbursementResponse {
                    success: false,
                    message: "Failed to fetch bank account".to_string(),
                    reference,
                    data: None,
                    error: Some(format!("Failed to fetch bank account: {:?}", e)),
                }),
            );
        }
    };
    if bank_details.user_id != user_id {
        log::error!("User ID mismatch: {} != {}", bank_details.user_id, user_id);
        return Err(HttpResponse::Forbidden().json(InitDisbursementResponse {
            success: false,
            reference: "unknown".to_string(),
            data: None,
            message: "Unauthorized access to bank account".to_string(),
            error: Some("Unauthorized access to bank account".to_string()),
        }));
    } else {
        log::info!(
            "Bank account confirmed for user {}: {}",
            user_id,
            bank_details.account_number
        );
        return Ok(bank_details);
    }
}

pub async fn get_bank_code_and_verify_account(
    app_state: &web::Data<AppState>,
    bank_details: &UserBankAccount,
    reference: String,
) -> Result<(AccountVerificationResponse, String), HttpResponse> {
    let banks = match fetch_banks_via_flutterwave(&app_state).await {
        Ok(banks) => banks,
        Err(e) => {
            return Err(
                HttpResponse::InternalServerError().json(InitDisbursementResponse {
                    success: false,
                    message: "Failed to fetch banks".to_string(),
                    reference,
                    data: None,
                    error: Some(e.to_string()),
                }),
            );
        }
    };

    let bank_code = banks
        .iter()
        .find(|bank| bank.name == bank_details.bank_name)
        .map(|bank| bank.code.clone());

    let bank_code = match bank_code {
        Some(code) => code,
        None => {
            return Err(
                HttpResponse::InternalServerError().json(InitDisbursementResponse {
                    success: false,
                    message: "Bank not found".to_string(),
                    reference,
                    data: None,
                    error: Some(format!("Bank '{}' not found", bank_details.bank_name)),
                }),
            );
        }
    };

    match verify_account_via_flutterwave(&app_state, &bank_details.account_number, &bank_code).await
    {
        Ok(account_details) => return Ok((account_details, bank_code)),
        Err(e) => {
            return Err(
                HttpResponse::InternalServerError().json(InitDisbursementResponse {
                    success: false,
                    message: "Bank account verification failed".to_string(),
                    reference,
                    data: None,
                    error: Some(e),
                }),
            );
        }
    }
}

pub async fn create_and_and_store_pending_transactions_to_redis(
    user_id: String,
    bank_code: String,
    bank_details: &UserBankAccount,
    account_name: String,
    offramp_request: &InitOfframpRequest,
    signature: String,
    reference: String,
    app_state: &web::Data<AppState>,
) -> Result<(), HttpResponse> {
    let pending_disbursement = PendingDisbursement {
        user_id: user_id.clone(),
        bank_code: bank_code.clone(),
        bank_name: bank_details.bank_name.clone(),
        account_number: bank_details.account_number.clone(),
        account_name: account_name.clone(),
        currency: offramp_request.currency.clone(),
        crypto_amount: offramp_request.amount,
        crypto_symbol: offramp_request.token_symbol.clone(),
        order_type: offramp_request.order_type.clone(),
        payment_method: offramp_request.payment_method.clone(),
        signature: signature.clone(),
    };

    if let Err(e) =
        store_pending_disbursement(&app_state, &reference, &user_id, &pending_disbursement).await
    {
        return Err(
            HttpResponse::InternalServerError().json(InitDisbursementResponse {
                success: false,
                message: "Failed to store pending disbursement".to_string(),
                reference,
                data: None,
                error: Some(e.to_string()),
            }),
        );
    }

    return Ok(());
}

pub fn get_fiat_amount(
    app_state: &web::Data<AppState>,
    reference: String,
    amount: f64,
) -> Result<f64, HttpResponse> {
    let usdt_ngn_rate: f64 =
        match pricefeed::pricefeed::get_current_usdt_ngn_rate(app_state.price_feed.clone()) {
            Ok(rate) => {
                log::info!("Current USDT to NGN rate: {}", rate);
                rate as f64
            }
            Err(e) => {
                log::error!("Failed to fetch USDT to NGN rate: {}", e);
                return Err(HttpResponse::InternalServerError().json(PaymentResult {
                    success: false,
                    reference: reference.clone(),
                    transaction_ref: None,
                    status: None,
                    message: "Failed to fetch USDT to NGN rate".to_string(),
                    error: Some(e.to_string()),
                }));
            }
        };

    let fiat_amount: f64 = calculate_fiat_amount(amount, usdt_ngn_rate);
    return Ok(fiat_amount);
}

pub fn run_confirm_disburse_validations(
    req: HttpRequest,
    app_state: &web::Data<AppState>,
    body: &web::Bytes,
) -> Result<(ConfirmDisbursementRequest, String), HttpResponse> {
    let auth_headers = match extract_auth_headers(&req) {
        Ok(headers) => headers,
        Err(error) => {
            return Err(HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: "unknown".to_string(),
                transaction_ref: None,
                status: None,
                message: "Missing authentication headers".to_string(),
                error: Some(error),
            }));
        }
    };

    if let Err(error) = verify_api_key(&auth_headers.api_key, &app_state.env.hmac_key) {
        return Err(HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Invalid API key".to_string(),
            error: Some(error),
        }));
    }

    if let Err(error) = verify_timestamp(&auth_headers.timestamp) {
        return Err(HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Request timestamp expired".to_string(),
            error: Some(error),
        }));
    }

    if let Err(error) = verify_hmac_signature(
        &auth_headers.timestamp,
        &body,
        &auth_headers.signature,
        &app_state.env.hmac_secret,
    ) {
        return Err(HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Invalid signature".to_string(),
            error: Some(error),
        }));
    }

    let request: ConfirmDisbursementRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return Err(HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: "unknown".to_string(),
                transaction_ref: None,
                status: None,
                message: "Invalid JSON payload".to_string(),
                error: Some(format!("JSON deserialization failed: {}", e)),
            }));
        }
    };

    let user_id = match validate_user_id(&request.user_id) {
        Ok(id) => id,
        Err(error) => {
            return Err(HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: request.reference.clone(),
                transaction_ref: None,
                status: None,
                message: "Invalid user ID".to_string(),
                error: Some(error),
            }));
        }
    };

    if let Err(error) = validate_reference(&request.reference) {
        return Err(HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: request.reference.clone(),
            transaction_ref: None,
            status: None,
            message: "Invalid reference".to_string(),
            error: Some(error),
        }));
    }
    return Ok((request, user_id));
}

pub async fn structure_and_record_initialized_disbursement(
    disbursement: FlutterwaveTransferData,
    app_state: &web::Data<AppState>,
    request: ConfirmDisbursementRequest,
    user_id: String,
    pending_disbursement: PendingDisbursement,
    crypto_amount: f64,
    fiat_amount: f64,
) -> Result<HttpResponse, HttpResponse> {
    let payment_status = disbursement.status.clone();
    let reference = disbursement.reference.clone();

    let new_tx = create_transaction_record(
        user_id.clone(),
        &pending_disbursement,
        crypto_amount,
        fiat_amount,
        payment_status.clone(),
        reference.clone(),
        request.transaction_hash.clone(),
    );

    let transaction_result = app_state.db.create_transaction(new_tx);

    match &transaction_result {
        Ok(_tx) => log::info!("Transaction saved successfully"),
        Err(e) => {
            log::error!("Failed to save transaction to DB: {:?}", e)
        }
    }

    let mut redis_conn = match app_state.redis_pool.get().await {
        Ok(conn) => conn,
        Err(e) => {
            log::error!("Failed to get Redis connection: {}", e);
            return Err(HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to get Redis connection"
            })));
        }
    };

    let key = format!("pending disbursement:{}:{}", request.reference, user_id);
    let _: Result<(), _> = redis_conn.expire(&key, 86400).await;

    let tx_hash = &request.transaction_hash;
    let tx_hash_key = format!("tx_hash:{}:{}", request.reference, user_id);
    println!("Request reference: {}", &request.reference);
    let _: Result<(), _> = redis_conn.set_ex(&tx_hash_key, tx_hash, 3600).await;

    log::info!("Payment initiated successfully for user: {}", user_id);

    return Ok(HttpResponse::Ok().json(PaymentResult {
        success: true,
        reference: request.reference.clone(),
        transaction_ref: Some(reference),
        status: Some(disbursement.status),
        message: "Payment initiated".to_string(),
        error: None,
    }));
}
