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
        flutterwave::{disburse_payment, fetch_banks_via_flutterwave, process_flutterwave_webhook},
        model::{FlutterwaveWebhookPayload, TransactionStatus, WebhookStatusResponse},
    },
    models::models::{NewTransaction, Transaction, TransactionSchema},
    wallets::{
        cartridge::ControllerService,
        helper::{check_token_balance, get_controller, pad_starknet_address, parse_felt_from_hex},
        models::{
            CheckTokenBalanceRequest, CreateSessionRequest, CreateSessionResponse,
            GetControllerRequest, ReceivePaymentRequest, ReceivePaymentResponse,
            TransactionStatusQuery,
        },
    },
};
use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use num_traits::ToPrimitive;

use chrono::Utc;
use hmac::{Hmac, Mac};

use serde_json::json;
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

use crate::{
    integrations::{
        bank::{
            fetch_banks_via_paystack, retrieve_pending_disbursement, verify_account_via_paystack,
        },
        model::{
            BankVerificationSchema, DisbursementDetails, InitDisbursementResponse,
            InitOfframpRequest, PaymentResult,
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

#[post("/offramp/init-offramp-transaction")]
pub async fn init_offramp_transaction(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    request: web::Json<InitOfframpRequest>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "Missing API key"
            }));
        }
    }

    let user_phone = request.phone.clone();

    let user = match app_state.db.get_user_by_phone(&user_phone) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    let user_id = user.id;
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

            match get_fiat_amount(&app_state, reference.clone(), request.amount) {
                Ok(fiat_amount) => {
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
        pending_disbursement.crypto_amount,
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

    match disburse_payment(
        &app_state,
        &request.reference,
        fiat_amount.trunc(),
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

#[get("/transactions/{reference}/status")]
pub async fn get_transaction_status_handler(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<TransactionStatusQuery>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "Missing API key"
            }));
        }
    }

    let user_phone = query.phone.clone();

    let user = match app_state.db.get_user_by_phone(&user_phone) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    let reference = path.into_inner();
    let user_id = user.id;

    match app_state
        .db
        .get_transaction_by_user_and_reference(&user_id, &reference)
    {
        Ok(Some(tx)) => {
            let status_data = TransactionStatus {
                transaction_id: tx.tx_id.to_string().clone(),
                reference: tx.reference.clone(),
                status: tx.payment_status.clone(),
                amount: Some(tx.fiat_amount.to_f64().unwrap_or(0.0)),
                currency: Some(tx.fiat_currency.clone()),
                last_updated: tx.updated_at.unwrap_or_else(|| Utc::now()),
                metadata: None,
            };

            HttpResponse::Ok().json(WebhookStatusResponse {
                success: true,
                data: Some(status_data),
                message: "Transaction status retrieved successfully".to_string(),
            })
        }
        Ok(None) => HttpResponse::NotFound().json(WebhookStatusResponse {
            success: false,
            data: None,
            message: "Transaction not found".to_string(),
        }),
        Err(_) => HttpResponse::InternalServerError().json(WebhookStatusResponse {
            success: false,
            data: None,
            message: "Failed to retrieve transaction status".to_string(),
        }),
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

#[post("/wallet/controller/create-session")]
pub async fn create_session_handler(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Json<CreateSessionRequest>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "Missing API key"
            }));
        }
    }

    let user_phone = body.phone.trim();

    let user = match app_state.db.get_user_by_phone(&user_phone.to_string()) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    if user.phone != body.phone {
        return HttpResponse::BadRequest().json(json!({
            "success": "false",
            "message": "User phone does not match",
            "error": "Provided phone number does not match authenticated user"
        }));
    }

    let controller_service = ControllerService::new(app_state.clone());

    if let Err(e) = app_state.db.clear_controller_session(&user.id) {
        log::warn!("Failed to clear existing session: {:?}", e);
        // Continue anyway - might not have had a session
    }

    match controller_service.create_controller(&body.phone).await {
        Ok((controller, username, session_options)) => {
            // let raw_controller_address = format!("{:#x}", controller.address);
            let (_, controller_address) = pad_starknet_address(controller.address).unwrap();
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

#[post("/wallet/controller/receive-payment")]
pub async fn receive_payment_handler(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Json<ReceivePaymentRequest>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "Missing API key"
            }));
        }
    }

    let user_phone = body.phone.clone();

    let user = match app_state.db.get_user_by_phone(&user_phone) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    let user_id = user.id;

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
        match controller_service.validate_user_and_get_permissions(&body.phone) {
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
        pending_disbursement.crypto_amount,
        body.reference.clone(),
    ) {
        Ok(amount) => amount,
        Err(error) => return error,
    };

    let (controller, _controller_info) =
        match get_controller(&app_state.db, &controller_service, &user_id, &body.phone).await {
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
        body.phone,
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
            log::error!("Payment processing failed for user {}: {}", body.phone, e);

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
    req: HttpRequest,
    app_state: web::Data<AppState>,
    query: web::Query<CheckTokenBalanceRequest>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "Missing API key"
            }));
        }
    }

    let user_phone = query.phone.trim();

    let user = match app_state.db.get_user_by_phone(&user_phone.to_string()) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };
    let user_id = user.id;

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

#[get("/healthz")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Service is healthy"
    }))
}

#[get("/")]
pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "success",
        "message": "Welcome to the Offramp Service API"
    }))
}

#[get("/wallet/controller/get-controller")]
pub async fn get_controller_handler(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    query: web::Query<GetControllerRequest>,
) -> impl Responder {
    let expected_api_key = &app_state.env.hmac_key;

    match req.headers().get("x-api-key") {
        Some(provided_key) => {
            if *provided_key != *expected_api_key {
                return HttpResponse::Unauthorized().json(json!({
                    "status": "error",
                    "message": "Invalid API key"
                }));
            }
        }
        None => {
            return HttpResponse::Unauthorized().json(json!({
                "status": "error",
                "message": "API key missing"
            }));
        }
    }

    let user_phone = query.phone.trim().to_string();

    let user = match app_state.db.get_user_by_phone(&user_phone) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "success": "false",
                "message": "User not found",
                "error": "User not found in database"
            }));
        }
    };

    if user.phone != query.phone {
        return HttpResponse::BadRequest().json(json!({
            "success": "false",
            "message": "User phone does not match",
            "error": "Provided phone does not match authenticated user"
        }));
    }

    let controller_service = ControllerService::new(app_state.clone());

    match get_controller(&app_state.db, &controller_service, &user.id, &query.phone).await {
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
            log::error!("Failed to get controller for user {}: {}", query.phone, e);
            HttpResponse::InternalServerError().json(json!({
                "success": "false",
                "message": "Failed to retrieve controller",
                "error": format!("Error: {}", e)
            }))
        }
    }
}
