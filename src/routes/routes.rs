use std::collections::HashMap;

use crate::{
    database::{
        db::AppError, transaction_db::TransactionImpl, user_db::UserImpl,
        user_wallet_db::UserWalletImpl,
    },
    helpers::{
        payment_helpers::{
            create_and_and_store_pending_transactions_to_redis, get_and_confirm_bank_details,
            get_bank_code_and_verify_account, get_fiat_amount, run_confirm_disburse_validations,
            structure_and_record_initialized_disbursement,
        },
        validation_helpers::validate_amount_match,
    },
    integrations::{
        flutterwave::{disburse_payment_using_flutterwave, fetch_banks_via_flutterwave, process_flutterwave_webhook},
        model::FlutterwaveWebhookPayload,
    },
    models::models::{NewTransaction, Transaction, TransactionSchema},
    wallets::{
        cartridge::ControllerService,
        helper::{
            check_token_balance, get_controller, get_or_create_controller_from_db,
            parse_felt_from_hex, validate_payment_inputs,
        },
        models::{
            CheckTokenBalanceRequest, ControllerInfo, CreateSessionRequest, CreateSessionResponse,
            GetControllerRequest, ReceivePaymentRequest, ReceivePaymentResponse,
        },
    },
};
use actix_web::{get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder};

use chrono::Utc;
use hmac::{Hmac, Mac};

use serde_json::json;
use sha2::Sha256;
use starknet::accounts::Account;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

use crate::{
    auth::jwt_auth,
    integrations::{
        bank::{
            fetch_banks_via_paystack, process_monnify_webhook, retrieve_pending_disbursement,
            verify_account_via_paystack, verify_monnify_webhook_signature,
        },
        model::{
            BankVerificationSchema, DisbursementDetails, InitDisbursementResponse,
            InitOfframpRequest, MonnifyWebhookPayload, PaymentResult,
        },
    },
    models::response::FilteredTransaction,
    pricefeed, AppState,
};

fn filtered_transaction_record(transaction: &Transaction) -> FilteredTransaction {
    FilteredTransaction {
        tx_id: transaction.tx_id.to_string(),
        user_id: transaction.user_id.to_string(),
        order_type: transaction.order_type.clone(),
        crypto_amount: transaction.crypto_amount,
        crypto_type: transaction.crypto_type.clone(),
        fiat_amount: transaction.fiat_amount,
        fiat_currency: transaction.fiat_currency.to_string(),
        payment_method: transaction.payment_method.clone(),
        payment_status: transaction.payment_status.clone(),
        tx_hash: transaction.tx_hash.to_string(),
        reference: transaction.reference.to_string(),
        settlement_status: transaction.settlement_status.clone(),
        transaction_reference: transaction.transaction_reference.clone(),
        settlement_date: transaction.settlement_date,
        created_at: transaction.created_at,
        updated_at: transaction.updated_at.unwrap_or_else(|| Utc::now()),
    }
}

#[post("/users/me/transactions")]
async fn update_transaction_handler(
    body: web::Json<TransactionSchema>,
    data: web::Data<AppState>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;
    let order_type = body.order_type.to_string();
    let crypto_amount = body.crypto_amount;
    let crypto_type = body.crypto_type.to_string();
    let fiat_amount = body.fiat_amount;
    let fiat_currency = body.fiat_currency.to_string();
    let payment_method = body.payment_method.to_string();
    let payment_status = body.payment_status.to_string();
    let tx_hash = body.tx_hash.to_string();
    let reference = body.reference.to_string();

    match data.db.get_user_by_id(user_id.as_str()) {
        Ok(_) => {
            let new_tx = NewTransaction {
                user_id: user_id.clone(),
                order_type: order_type.clone(),
                crypto_amount: crypto_amount.clone(),
                crypto_type: crypto_type.clone(),
                fiat_amount: fiat_amount.clone(),
                fiat_currency: fiat_currency.clone(),
                payment_method: payment_method.clone(),
                payment_status: payment_status.clone(),
                reference: reference.clone(),
                tx_hash: tx_hash.clone(),
                settlement_status: None,
                transaction_reference: None,
                settlement_date: None,
            };

            match data.db.create_transaction(new_tx) {
                Ok(transaction) => {
                    let filtered_transaction = filtered_transaction_record(&transaction);
                    HttpResponse::Created().json(filtered_transaction)
                }
                Err(e) => {
                    eprintln!("Failed to create transaction: {:?}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": format!("Failed to create transaction: {:?}", e)
                    }));
                }
            }
        }
        Err(e) => {
            match e {
                AppError::DieselError(diesel::result::Error::NotFound) => {
                    return HttpResponse::NotFound().json(json!({
                        "status": "error",
                        "message": "User not found"
                    }));
                }
                _ => {
                    eprintln!("Failed to create transaction: {:?}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": format!("Failed to create transaction: {:?}", e)
                    }));
                }
            };
        }
    }
}

#[get("/users/me/transactions")]
async fn get_transaction_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<String>().unwrap();

    let transactions = match data.db.get_transaction_by_user_id(*&user_id.as_str()) {
        Ok(tx) => tx,
        Err(AppError::DieselError(diesel::result::Error::NotFound)) => {
            return HttpResponse::NotFound().json("User not found")
        }
        Err(e) => {
            eprint!("Error fetching transactions: {:?}", e);
            {
                return HttpResponse::InternalServerError().json("Error fetching transactions");
            }
        }
    };

    let filtered_transactions: Vec<FilteredTransaction> = transactions
        .into_iter()
        .map(|transaction| filtered_transaction_record(&transaction))
        .collect();

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "transactions": filtered_transactions
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[get("/banks")]
pub async fn fetch_banks_handler(data: web::Data<AppState>) -> impl Responder {
    match fetch_banks_via_flutterwave(&data).await {
        Ok(banks) => HttpResponse::Ok().json(json!({
            "status": "success",
            "data": banks
        })),
        Err(e) => {
            eprintln!("Failed to fetch banks: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve bank list"
            }))
        }
    }
}

#[get("/banks/verify")]
pub async fn verify_bank_account_handler(
    data: web::Data<AppState>,
    body: web::Json<BankVerificationSchema>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let account_number = body.account_number.trim();
    let bank_name = body.bank_name.trim();

    if account_number.is_empty() || bank_name.is_empty() {
        return HttpResponse::BadRequest().json(json!({
            "status": "error",
            "message": "Account number and bank code are required"
        }));
    }

    match fetch_banks_via_paystack(&data).await {
        Ok(banks) => {
            let bank = banks
                .iter()
                .find(|b| b.name.to_lowercase() == bank_name.to_lowercase());

            if let Some(bank) = bank {
                match verify_account_via_paystack(&data, account_number, &bank.code).await {
                    Ok(account_details) => HttpResponse::Ok().json(json!({
                        "status": "success",
                        "data": {
                            "account_name": account_details.account_name,
                            "account_number": account_details.account_number
                        }
                    })),
                    Err(e) => HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": format!("Account verification failed: {}", e)
                    })),
                }
            } else {
                HttpResponse::BadRequest().json(json!({
                    "status": "error",
                    "message": "Bank not found"
                }))
            }
        }
        Err(e) => {
            eprintln!("Failed to fetch banks: {}", e);
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve bank list"
            }));
        }
    }
}

#[post("/offramp/init-offramp-transaction")]
pub async fn init_offramp_transaction(
    app_state: web::Data<AppState>,
    request: web::Json<InitOfframpRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;
    let reference = format!(
        "{}{}",
        Uuid::new_v4().simple().to_string(),
        Utc::now().timestamp()
    );
    let hmac_secret = &app_state.env.hmac_secret;
    let mut mac =
        HmacSha256::new_from_slice(hmac_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(reference.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    log::info!(
        "Initializing disbursement for user: {}, reference: {}",
        user_id,
        reference
    );

    if request.amount <= 0.0 {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: reference.clone(),
            transaction_ref: None,
            status: None,
            message: "Invalid crypto amount".to_string(),
            error: Some("Crypto amount must be greater than zero".to_string()),
        });
    }

    let bank_details = match get_and_confirm_bank_details(
        &app_state.db,
        &user_id.as_str(),
        request.bank_account_id,
        reference.clone(),
    ) {
        Ok(details) => details,
        Err(e) => return e,
    };

    log::info!(
        "Initializing disbursement for user: {}, reference: {}",
        user_id,
        reference
    );

    match get_bank_code_and_verify_account(&app_state, &bank_details, reference.clone()).await {
        Ok((account_details, bank_code)) => {
            match create_and_and_store_pending_transactions_to_redis(
                user_id.clone(),
                bank_code.clone(),
                &bank_details,
                account_details.account_name.clone(),
                &request,
                signature.clone(),
                reference.clone(),
                &app_state,
            )
            .await
            {
                Ok(_) => {
                    log::info!(
                        "Pending disbursement for {} with ref: {}, stored successfully",
                        user_id,
                        reference
                    );
                    // TODO: SAVE OFFRAMP REQUEST TO DATABASE
                }
                Err(e) => {
                    return e;
                }
            }

            match get_fiat_amount(&app_state, reference.clone(), request.amount as i64) {
                Ok(fiat_amount) => {
                    // TODO: SEND EMAIL NOTIFICATION TO USER

                    return HttpResponse::Ok().json(InitDisbursementResponse {
                        success: true,
                        message: "Payment initialized, please confirm to proceed".to_string(),
                        reference,
                        data: Some(DisbursementDetails {
                            account_name: account_details.account_name,
                            account_number: bank_details.account_number.clone(),
                            bank_name: bank_details.bank_name.clone(),
                            bank_code: bank_code.clone(),
                            amount: fiat_amount as f64,
                            currency: request.currency.clone(),
                            crypto_tx_hash: "".to_string(),
                        }),
                        error: None,
                    });
                }
                Err(e) => return e,
            };
        }
        Err(e) => return e,
    }
}

#[post("/offramp/confirm-disburse")]
pub async fn confirm_disburse_payment_handler(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> impl Responder {
    let (request, user_id) = match run_confirm_disburse_validations(req, &app_state, &body) {
        Ok(req) => req,
        Err(e) => return e,
    };

    let pending_disbursement = match retrieve_pending_disbursement(
        &app_state,
        &request.reference,
        &user_id.as_str(),
    )
    .await
    {
        Ok(disbursement) => disbursement,
        Err(e) => {
            return HttpResponse::InternalServerError().json(PaymentResult {
                success: false,
                reference: request.reference.clone(),
                transaction_ref: None,
                status: None,
                message: "Failed to retrieve pending disbursement".to_string(),
                error: Some(e),
            });
        }
    };

    let crypto_amount = match validate_amount_match(
        &request.amount,
        pending_disbursement.crypto_amount as i64,
        request.reference.clone(),
    ) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    let fiat_amount = match get_fiat_amount(&app_state, request.reference.clone(), crypto_amount) {
        Ok(amount) => amount,
        Err(e) => return e,
    };

    let narration = Some("Services");

    log::info!(
        "Converting {} USDT to NGN at value: {} NGN",
        crypto_amount,
        fiat_amount
    );

    match disburse_payment_using_flutterwave(
        &app_state,
        &request.reference,
        fiat_amount,
        narration,
        &pending_disbursement.bank_code,
        &pending_disbursement.account_number,
        &pending_disbursement.currency,
        Some(&pending_disbursement.account_name),
    )
    .await
    {
        Ok(disbursement) => {
            match structure_and_record_initialized_disbursement(
                disbursement,
                &app_state,
                request,
                user_id,
                pending_disbursement,
                crypto_amount,
                fiat_amount,
            )
            .await
            {
                Ok(success) => return success,
                Err(e) => return e,
            }
        }
        Err(e) => HttpResponse::InternalServerError().json(PaymentResult {
            success: false,
            reference: request.reference.clone(),
            transaction_ref: None,
            status: None,
            message: "Payment disbursement failed".to_string(),
            error: Some(e),
        }),
    }
}

#[post("/webhooks/monnify")]
pub async fn monnify_webhook_handler(
    app_state: web::Data<AppState>,
    body: web::Bytes,
    req: HttpRequest,
) -> impl Responder {
    log::info!("Received Monnify webhook: {:?}", body);

    if !verify_monnify_webhook_signature(&req, &body, &app_state.env.monnify_secret_key) {
        log::warn!("Invalid Monnify webhook signature received");
        return HttpResponse::Unauthorized().finish();
    }

    let payload: MonnifyWebhookPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(e) => {
            log::error!("Failed to parse Monnify webhook payload: {}", e);
            return HttpResponse::BadRequest().body(format!("Invalid payload: {}", e));
        }
    };

    log::info!(
        "Processing webhook: event_type={}, reference={}",
        payload.event_type,
        payload.event_data.reference
    );

    match process_monnify_webhook(&app_state, payload).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => {
            log::error!("Failed to process Monnify webhook: {}", e);
            HttpResponse::InternalServerError().body(format!("Error processing webhook: {}", e))
        }
    }
}

#[post("/webhooks/flutterwave")]
pub async fn flutterwave_webhook_handler(
    app_state: web::Data<AppState>,
    body: web::Bytes,
    req: HttpRequest,
) -> impl Responder {
    let header_secret_hash = match req.headers().get("verif-hash") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to parse signature header: {}", e);
                return HttpResponse::BadRequest().body(format!("Invalid signature header: {}", e));
            }
        },
        None => {
            log::warn!("Missing signature header in Flutterwave webhook");
            return HttpResponse::Unauthorized().body("Missing signature");
        }
    };

    if !(header_secret_hash == &app_state.env.flutterwave_secret_hash) {
        log::warn!("Invalid Flutterwave webhook signature received");
        println!("Invalid Flutterwave webhook signature received");
        return HttpResponse::Unauthorized().finish();
    }

    let payload: FlutterwaveWebhookPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(e) => {
            log::error!("Failed to parse Flutterwave webhook payload: {}", e);
            return HttpResponse::BadRequest().body(format!("Invalid payload: {}", e));
        }
    };

    log::info!(
        "Processing Flutterwave webhook: event={}, status={}",
        payload.event,
        payload.data.status
    );

    match process_flutterwave_webhook(&app_state, payload).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => {
            log::error!("Failed to process Flutterwave webhook: {}", e);
            HttpResponse::InternalServerError().body(format!("Error processing webhook: {}", e))
        }
    }
}

#[get("/rates/usd-ngn-rate")]
async fn get_usd_ngn_rate_handler(data: web::Data<AppState>) -> impl Responder {
    match pricefeed::pricefeed::get_current_usdt_ngn_rate(data.price_feed.clone()) {
        Ok(rate) => HttpResponse::Ok().json(json!({
            "status": "success",
            "data": {
                "usd_ngn_rate": rate
            }
        })),
        Err(e) => {
            eprintln!("Failed to fetch USD to NGN rate: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve USD to NGN rate"
            }))
        }
    }
}

/*
TODO after MVP is completed
#[get("/stats")]
async fn get_stats_handler(
) -> impl Responder {
}
 */

#[get("/healthz")]
async fn check_health(_data: web::Data<AppState>) -> impl Responder {
    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "health": "Server is active"
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[post("/wallet/controller/create-session")]
pub async fn create_session_handler(
    app_state: web::Data<AppState>,
    body: web::Json<CreateSessionRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    let user = match app_state.db.get_user_by_id(user_id.as_str()) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    if user.email != body.user_email {
        return HttpResponse::BadRequest().json(json!({
            "success": "false",
            "message": "User email does not match",
            "error": "Provided email does not match authenticated user"
        }));
    }

    let controller_service = ControllerService::new(app_state.clone());

    if let Err(e) = app_state.db.clear_controller_session(&user_id) {
        log::warn!("Failed to clear existing session: {:?}", e);
        // Continue anyway - might not have had a session
    }

    match controller_service.create_controller(&body.user_email).await {
        Ok((controller, username, session_options)) => {
            let controller_address = format!("{:#x}", controller.address());
            let session_id = Uuid::new_v4().to_string();

            let response = CreateSessionResponse {
                controller_address,
                username,
                session_id,
                session_options,
            };

            HttpResponse::Created().json(json!({
                "success": "true",
                "message": "Controller session created successfully",
                "data": response
            }))
        }
        Err(e) => {
            eprintln!("Failed to create controller session: {:?}", e);
            HttpResponse::InternalServerError().json(json!({
                "success": "false",
                "message": "Failed to create controller session",
                "error": format!("Error creating controller session: {}", e)
            }))
        }
    }
}

/*
#[get("/wallet/controller/session")]
pub async fn get_session_handler(
    app_state: web::Data<AppState>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    let user = match app_state.db.get_user_by_id(user_id.as_str()) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    let controller_service = ControllerService::new(app_state.clone());

    // Use email from authenticated user
    let (user_data, user_permissions) =
        match controller_service.validate_user_and_get_permissions(&user.email) {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::BadRequest().json(json!({
                    "success": "false",
                    "message": "Failed to validate user",
                    "error": format!("User validation error: {}", e)
                }));
            }
        };

    match get_or_create_controller_from_db(
        &app_state.db,
        &controller_service,
        &user_data.id,
        &user_permissions,
    )
    .await
    {
        Ok((controller, username, session_options)) => {
            let controller_address = format!("{:#x}", controller.address());
            let session_id = Uuid::new_v4().to_string();

            let response = CreateSessionResponse {
                controller_address,
                username,
                session_id,
                session_options,
            };

            HttpResponse::Ok().json(json!({
                "success": "true",
                "message": "Controller session retrieved successfully",
                "data": response
            }))
        }
        Err(e) => HttpResponse::NotFound().json(json!({
            "success": "false",
            "message": "No valid session found",
            "error": format!("No existing session: {}", e)
        })),
    }
}   */

#[post("/wallet/controller/receive-payment")]
pub async fn receive_payment_handler(
    app_state: web::Data<AppState>,
    body: web::Json<ReceivePaymentRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    if !app_state
        .db
        .is_controller_session_valid(&user_id)
        .unwrap_or(false)
    {
        return HttpResponse::Unauthorized().json(json!({
            "success": "false",
            "message": "Controller session expired or invalid",
            "error": "Please create a new controller session"
        }));
    }

    let controller_service = ControllerService::new(app_state.clone());

    let (user, user_permissions) =
        match controller_service.validate_user_and_get_permissions(&body.user_email) {
            Ok(result) => result,
            Err(e) => {
                return HttpResponse::BadRequest().json(ReceivePaymentResponse {
                    success: false,
                    message: "User validation failed".to_string(),
                    data: None,
                    error: Some(format!("Error validating user: {}", e)),
                });
            }
        };

    if user.id != user_id {
        return HttpResponse::Forbidden().json(ReceivePaymentResponse {
            success: false,
            message: "Authentication mismatch".to_string(),
            data: None,
            error: Some("Cannot make payment requests for other users".to_string()),
        });
    }

    let pending_disbursement =
        match retrieve_pending_disbursement(&app_state, &body.reference, &user_id.as_str()).await {
            Ok(disbursement) => disbursement,
            Err(e) => {
                return HttpResponse::InternalServerError().json(PaymentResult {
                    success: false,
                    reference: body.reference.clone(),
                    transaction_ref: None,
                    status: None,
                    message: "Failed to retrieve pending disbursement".to_string(),
                    error: Some(e),
                });
            }
        };

    match validate_amount_match(
        &body.amount,
        pending_disbursement.crypto_amount as i64,
        body.reference.clone(),
    ) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    let (controller, _controller_info) = match get_controller(
        &app_state.db,
        &controller_service,
        &user_id,
        &body.user_email,
    )
    .await
    {
        Ok((controller, detail)) => (controller, detail),
        Err(e) => {
            return HttpResponse::NotFound().json(ReceivePaymentResponse {
                success: false,
                message: "Controller session not found".to_string(),
                data: None,
                error: Some(format!("No active controller session for this user: {}", e)),
            });
        }
    };

    log::info!(
        "Processing receive_payment for user: {} (ID: {})",
        body.user_email,
        user_id
    );

    match controller_service
        .receive_payment(
            &controller,
            &body.token,
            &body.amount,
            &body.reference,
            &user_id.to_string(),
            &user_permissions,
        )
        .await
    {
        Ok(transaction_response) => {
            if transaction_response.status == "success" {
                HttpResponse::Ok().json(ReceivePaymentResponse {
                    success: true,
                    message: "Payment received successfully".to_string(),
                    data: Some(transaction_response),
                    error: None,
                })
            } else {
                let message = transaction_response
                    .message
                    .clone()
                    .unwrap_or_else(|| "payment failed".to_string());
                HttpResponse::BadRequest().json(ReceivePaymentResponse {
                    success: false,
                    message,
                    data: Some(transaction_response),
                    error: None,
                })
            }
        }
        Err(e) => {
            log::error!(
                "Payment processing failed for user {}: {}",
                body.user_email,
                e
            );

            HttpResponse::InternalServerError().json(ReceivePaymentResponse {
                success: false,
                message: "Failed to process payment".to_string(),
                data: None,
                error: Some(format!("Error: {}", e)),
            })
        }
    }
}

#[get("/wallet/controller/get-balance")]
pub async fn get_controller_balance_handler(
    app_state: web::Data<AppState>,
    query: web::Query<CheckTokenBalanceRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    if !app_state
        .db
        .is_controller_session_valid(&user_id)
        .unwrap_or(false)
    {
        return HttpResponse::Unauthorized().json(json!({
            "success": "false",
            "message": "Controller session expired or invalid",
            "error": "Please create a new controller session"
        }));
    }

    let token = match parse_felt_from_hex(&query.token) {
        Ok(token) => token,
        Err(e) => {
            return HttpResponse::BadRequest().json(json!({
                "success": "false",
                "message": "Invalid token address format",
                "error": format!("Error parsing token address: {}", e)
            }));
        }
    };

    let user_address = match parse_felt_from_hex(&query.user_address) {
        Ok(address) => address,
        Err(e) => {
            return HttpResponse::BadRequest().json(json!({
                "success": "false",
                "message": "Invalid user address format",
                "error": format!("Error parsing user address: {}", e)
            }));
        }
    };

    match check_token_balance(token, user_address).await {
        Ok(balance) => HttpResponse::Ok().json(json!({
            "success": "true",
            "message": "Token balance retrieved successfully",
            "data": {
                "balance": format!("{}", balance),
                "token": query.token,
                "user_address": query.user_address
            }
        })),
        Err(e) => {
            log::error!(
                "Failed to check token balance for address {}: {}",
                query.user_address,
                e
            );
            HttpResponse::BadRequest().json(json!({
                "success": "false",
                "message": "Failed to check token balance",
                "error": format!("Error: {}", e)
            }))
        }
    }
}

#[get("/wallet/controller/get-controller")]
pub async fn get_controller_handler(
    app_state: web::Data<AppState>,
    query: web::Query<GetControllerRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    if !app_state
        .db
        .is_controller_session_valid(&user_id)
        .unwrap_or(false)
    {
        return HttpResponse::Unauthorized().json(json!({
            "success": "false",
            "message": "Controller session expired or invalid",
            "error": "Please create a new controller session"
        }));
    }

    let user = match app_state.db.get_user_by_id(&user_id) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    if user.email != query.user_email {
        return HttpResponse::BadRequest().json(json!({
            "success": "false",
            "message": "User email does not match",
            "error": "Provided email does not match authenticated user"
        }));
    }

    let controller_service = ControllerService::new(app_state.clone());

    match get_controller(
        &app_state.db,
        &controller_service,
        &user_id,
        &query.user_email,
    )
    .await
    {
        Ok((_controller, controller_info)) => HttpResponse::Ok().json(json!({
            "success": "true",
            "message": "Controller retrieved successfully",
            "data": {
                "controller_address": controller_info.controller_address,
                "username": controller_info.username,
                "session_policies": controller_info.session_policies,
                "session_expires_at": controller_info.session_expires_at,
                "user_permissions": controller_info.user_permissions,
                "is_deployed": controller_info.is_deployed,
            }
        })),
        Err(e) => {
            log::error!(
                "Failed to get controller for user {}: {}",
                query.user_email,
                e
            );
            HttpResponse::InternalServerError().json(json!({
                "success": "false",
                "message": "Failed to retrieve controller",
                "error": format!("Error: {}", e)
            }))
        }
    }
}

// TODO: HANDLE FAILED AND REVERSED TRANSACTIONS
// TODO: CHECK REFERENCES FOR IDEMPOTENCY
