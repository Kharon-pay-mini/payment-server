use crate::{
    auth::{
        auth::{log_failed_login, log_successful_login, logout, verify_admin_role},
        jwt_auth::JwtMiddleware,
        models::{FlaggedUserQuery, LoginHistoryQuery, UserLoginHistoryItem, UserLoginStats},
    },
    database::{
        db::AppError, otp_db::OtpImpl, transaction_db::TransactionImpl, user_db::UserImpl,
        user_security_log_db::UserSecurityLogsImpl, user_wallet_db::UserWalletImpl,
    },
    integrations::{
        flutterwave::{
            disburse_payment_using_flutterwave, fetch_banks_via_flutterwave,
            process_flutterwave_webhook, verify_account_via_flutterwave,
        },
        model::FlutterwaveWebhookPayload,
    },
    models::models::{
        CreateUserSchema, NewOtp, NewTransaction, NewUser, NewUserSecurityLog, NewUserWallet, Otp,
        OtpSchema, TokenClaims, Transaction, TransactionSchema, User, UserSecurityLog,
        UserSecurityLogsSchema, UserWallet, UserWalletSchema, ValidateOtpSchema,
    },
};
use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use awc::{body, cookie::time::OffsetDateTime};
use chrono::{Duration, Utc};
use diesel::expression::is_aggregate::No;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, EncodingKey, Header};
use num_traits::FromPrimitive;
use rand::{rng, Rng};
use redis::AsyncCommands;
use rust_decimal::Decimal;
use serde_json::json;
use sha2::Sha256;
use std::usize;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

use crate::{
    auth::jwt_auth,
    integrations::{
        bank::{
            disburse_payment, fetch_banks_via_paystack, process_monnify_webhook,
            retrieve_pending_disbursement, store_pending_disbursement, verify_account_via_paystack,
            verify_monnify_webhook_signature,
        },
        model::{
            BankVerificationSchema, ConfirmDisbursementRequest, DisbursementDetails,
            InitDisbursementRequest, InitDisbursementResponse, MonnifyWebhookPayload,
            PaymentResult, PendingDisbursement,
        },
    },
    models::response::{
        FilteredOtp, FilteredTransaction, FilteredUser, FilteredUserSecurityLogs, FilteredWallet,
    },
    pricefeed,
    service::email_service::send_verification_email,
    AppState,
};

fn filtered_user_record(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_string(),
        email: user.email.to_string(),
        phone: user.phone.clone(),
        last_logged_in: user.last_logged_in.unwrap_or_else(|| Utc::now()),
        verified: user.verified,
        role: user.role.clone(),
        created_at: user.created_at.unwrap(),
    }
}

fn filtered_wallet_record(wallet: &UserWallet) -> FilteredWallet {
    FilteredWallet {
        user_id: wallet.user_id.to_string(),
        wallet_address: wallet
            .wallet_address
            .as_ref()
            .map_or("Unknown".to_string(), |s| s.to_string()),
        network_used_last: wallet
            .network_used_last
            .as_ref()
            .map_or("Unknown".to_string(), |s| s.to_string()),
        created_at: wallet.created_at,
        updated_at: wallet.updated_at.unwrap_or_else(|| Utc::now()),
    }
}

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

fn filtered_security_logs(security_log: &UserSecurityLog) -> FilteredUserSecurityLogs {
    FilteredUserSecurityLogs {
        log_id: security_log.log_id.to_string(),
        user_id: security_log.user_id.to_string(),
        ip_address: security_log.ip_address.to_string(),
        city: security_log.city.to_string(),
        country: security_log.country.to_string(),
        failed_login_attempts: security_log.failed_login_attempts,
        flagged_for_review: security_log.flagged_for_review,
        created_at: security_log.created_at.unwrap_or_else(|| Utc::now()),
    }
}

fn filtered_otp(otp: &Otp) -> FilteredOtp {
    FilteredOtp {
        otp_id: otp.otp_id.to_string(),
        user_id: otp.user_id.to_string(),
        otp: otp.otp_code,
        created_at: otp.created_at,
        expires_at: otp.expires_at,
    }
}
#[post("/auth/create")]
async fn create_user_handler(
    body: web::Json<CreateUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let email = body.email.to_string().to_lowercase();
    let phone: Option<String> = body.phone.as_ref().map(|s| s.to_string());

    // Early return pattern - check email first
    match data.db.get_user_by_email(email.clone()) {
        Ok(existing_user) => {
            return HttpResponse::Ok().json(json!({
                "status": "success",
                "data": filtered_user_record(&existing_user)
            }));
        }
        Err(AppError::DbConnectionError(e)) => {
            eprintln!("DB connection error: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": format!("{:?}", e)
            }));
        }
        Err(AppError::DieselError(diesel::result::Error::NotFound)) => {
            // Continue to phone check
            eprintln!("Email {} not found for user, checking phone.", email);
        }
        Err(AppError::DieselError(e)) => {
            eprintln!("Query error: {:?}", e);
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": format!("{:?}", e)
            }));
        }
    }

    // Check phone if provided
    if let Some(phone_number) = phone.clone() {
        match data.db.get_user_by_phone(phone_number) {
            Ok(existing_user) => {
                return HttpResponse::Ok().json(json!({
                    "status": "success",
                    "data": filtered_user_record(&existing_user)
                }));
            }
            Err(AppError::DbConnectionError(e)) => {
                eprintln!("DB connection error: {:?}", e);
                return HttpResponse::InternalServerError().json(json!({
                    "status": "error",
                    "message": format!("{:?}", e)
                }));
            }
            Err(AppError::DieselError(diesel::result::Error::NotFound)) => {
                // Continue to user creation
                eprintln!("Phone not found for user, creating user...");
            }
            Err(AppError::DieselError(e)) => {
                eprintln!("Query error: {:?}", e);
                return HttpResponse::InternalServerError().json(json!({
                    "status": "error",
                    "message": format!("{:?}", e)
                }));
            }
        }
    }

    // Neither email nor phone found - create new user
    let new_user = NewUser {
        email: email.clone(),
        phone: phone.clone(),
        verified: false,
        role: String::from("user"),
    };

    match data.db.create_user(new_user.clone()) {
        Ok(user) => HttpResponse::Ok().json(json!({
            "status": "success",
            "data": filtered_user_record(&user)
        })),
        Err(e) => {
            eprintln!("Failed to create user: {:?}", e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": format!("Failed to create user: {:?}", e)
            }))
        }
    }
}

#[get("/admin/users/login-stats")]
pub async fn get_user_login_stats(
    body: web::Json<CreateUserSchema>,
    data: web::Data<AppState>,
    auth: JwtMiddleware,
) -> impl Responder {
    let admin_user_id = auth.user_id;
    let user_email = body.email.to_string().to_lowercase();

    let target_user_id = match data.db.get_user_by_email(user_email.clone()) {
        Ok(user) => user.id,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "status": "error",
                "message": "User not found"
            }))
        }
    };

    if let Err(response) = verify_admin_role(admin_user_id, &data).await {
        return response;
    }

    let total_attempts = match data.db.get_user_security_logs_count(target_user_id) {
        Ok(count) => count,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve login stats"
            }))
        }
    };

    let failed_attempts = match data.db.get_user_total_failed_logins(target_user_id) {
        Ok(count) => count,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve login stats"
            }))
        }
    };

    let recent_logs = match data
        .db
        .get_user_security_logs_with_limit(target_user_id, Some(10))
    {
        Ok(logs) => logs,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve recent logs"
            }))
        }
    };

    let successful_logins = total_attempts - failed_attempts;
    let last_successful_login = recent_logs
        .iter()
        .find(|log| log.failed_login_attempts == 0)
        .and_then(|log| log.created_at);

    let last_failed_login = recent_logs
        .iter()
        .find(|log| log.failed_login_attempts > 0)
        .and_then(|log| log.created_at);

    let is_flagged_for_review = recent_logs.iter().any(|log| log.flagged_for_review);

    let now = Utc::now();
    let twenty_four_hours_ago = now - Duration::hours(24);

    let recent_failed_attempts = recent_logs
        .iter()
        .filter(|log| log.created_at > Some(twenty_four_hours_ago) && log.failed_login_attempts > 0)
        .map(|log| log.failed_login_attempts)
        .sum();

    let stats = UserLoginStats {
        user_id: target_user_id,
        total_logins: total_attempts,
        successful_logins,
        failed_logins: failed_attempts,
        last_successful_login,
        last_failed_login,
        is_flagged_for_review,
        recent_failed_attempts,
    };

    HttpResponse::Ok().json(json!({
        "status": "success",
        "data": stats
    }))
}

#[get("/admin/users/login-history")]
pub async fn get_user_login_history(
    body: web::Json<LoginHistoryQuery>,
    data: web::Data<AppState>,
    auth: JwtMiddleware,
) -> impl Responder {
    let admin_user_id = auth.user_id;
    println!("admin id: {}", admin_user_id);
    let user_email = body.email.to_string().to_lowercase();

    let target_user_id = match data.db.get_user_by_email(user_email.clone()) {
        Ok(user) => user.id,
        Err(_) => {
            return HttpResponse::NotFound().json(json!({
                "status": "error",
                "message": "User not found"
            }))
        }
    };

    if let Err(response) = verify_admin_role(admin_user_id, &data).await {
        return response;
    }

    let limit = body.limit.unwrap_or(50);
    let offset = body.offset.unwrap_or(0);

    let logs = match data
        .db
        .get_user_security_logs_paginated(target_user_id, limit, offset)
    {
        Ok(logs) => logs,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve login history"
            }))
        }
    };

    let history: Vec<UserLoginHistoryItem> = logs
        .into_iter()
        .map(|log| UserLoginHistoryItem {
            id: log.log_id,
            timestamp: log.created_at.unwrap_or_else(|| chrono::Utc::now()),
            ip_address: log.ip_address,
            city: log.city,
            country: log.country,
            was_successful: log.failed_login_attempts == 0,
            failed_login_attempts: log.failed_login_attempts,
            flagged_for_review: log.flagged_for_review,
        })
        .collect();

    let total_count = data
        .db
        .get_user_security_logs_count(target_user_id)
        .unwrap_or(history.len() as i64);

    HttpResponse::Ok().json(json!({
        "status": "success",
        "data": {
            "history": history,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_count
            }
        }
    }))
}

#[get("/admin/flagged-users")]
pub async fn get_flagged_users(
    body: web::Json<FlaggedUserQuery>,
    data: web::Data<AppState>,
    auth: JwtMiddleware,
) -> impl Responder {
    let admin_user_id = auth.user_id;
    let limit = body.limit.unwrap_or(100);
    let offset = body.offset.unwrap_or(0);

    if let Err(response) = verify_admin_role(admin_user_id, &data).await {
        return response;
    }

    let flagged_users = match data.db.get_flagged_users_security_logs() {
        Ok(users) => users,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve flagged users"
            }))
        }
    };

    let total_count = match data.db.get_flagged_users_count() {
        Ok(count) => count,
        Err(_) => {
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve flagged users count"
            }))
        }
    };

    HttpResponse::Ok().json(json!({
        "status": "success",
        "data": {
            "users": flagged_users,
            "pagination": {
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": (offset + limit) < total_count
            }
        }
    }))
}

#[post("/users/me/wallet")]
async fn update_user_wallet_handler(
    body: web::Json<UserWalletSchema>,
    data: web::Data<AppState>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;
    let wallet_address = body.wallet_address.to_string();
    let network = body.network.to_string();

    match data.db.get_user_by_id(user_id) {
        Ok(_) => {
            let wallet = NewUserWallet {
                user_id: user_id.clone(),
                wallet_address: Some(wallet_address.clone()),
                network_used_last: Some(network.clone()),
            };

            match data.db.create_user_wallet(wallet) {
                Ok(wallet) => {
                    let filtered_wallet = filtered_wallet_record(&wallet);
                    HttpResponse::Created().json(filtered_wallet)
                }
                Err(e) => {
                    eprintln!("Failed to create wallet: {:?}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": format!("Failed to create user: {:?}", e)
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
                    eprintln!("Failed to create wallet: {:?}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": format!("Failed to create wallet: {:?}", e)
                    }));
                }
            };
        }
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

    match data.db.get_user_by_id(user_id) {
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

#[post("/users/request-otp")]
async fn request_otp_handler(
    body: web::Json<OtpSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = body.user_id;
    let email = body.email.clone();

    match data.db.get_user_by_id(user_id) {
        Ok(_) => {
            match data.db.get_otp_by_user_id(user_id) {
                Ok(existing_otp) => {
                    let now = Utc::now();
                    let time_since_creation = now - existing_otp.created_at;

                    if time_since_creation < Duration::minutes(5) {
                        let remaining_seconds =
                            (Duration::minutes(5) - time_since_creation).num_seconds();
                        return HttpResponse::TooManyRequests().json(json!({
                            "status": "error",
                            "message": "OTP already sent. Please wait before requesting another.",
                            "retry_after_seconds": remaining_seconds,
                            "retry_after_minutes": (remaining_seconds as f64 / 60.0).ceil() as i64
                        }));
                    }

                    if let Err(e) = data.db.delete_otp_by_id(existing_otp.otp_id) {
                        eprintln!("Failed to delete old OTP: {:?}", e);
                        return HttpResponse::InternalServerError().json(json!({
                            "status": "error",
                            "message": "Failed to process OTP request"
                        }));
                    }
                }
                Err(AppError::DieselError(diesel::result::Error::NotFound)) => {
                    println!(
                        "No existing OTP found for user {}, creating new one",
                        user_id
                    );
                }
                Err(e) => {
                    eprintln!("Database error checking existing OTP: {:?}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": "Failed to process OTP request"
                    }));
                }
            }

            let otp_code = rng().random_range(100_000..=999_999);

            let new_otp = NewOtp {
                otp_code: otp_code.clone(),
                user_id: user_id.clone(),
            };

            match data.db.create_otp(new_otp) {
                Ok(_) => {
                    if let Err(e) = send_verification_email(&email, otp_code).await {
                        eprint!("Failed to send email: {}", e);
                        return HttpResponse::InternalServerError().json(json!({
                            "status": "error",
                            "message": "Failed to send verification email"
                        }));
                    }

                    HttpResponse::Ok().json(json!({
                        "status": "success",
                        "message": format!("OTP sent to {}", email),
                        "expires_in_minutes": 5
                    }))
                }
                Err(e) => {
                    eprintln!("Failed to create OTP: {:?}", e);
                    HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": "Failed to create OTP"
                    }))
                }
            }
        }
        Err(e) => match e {
            AppError::DieselError(diesel::result::Error::NotFound) => HttpResponse::NotFound()
                .json(json!({
                    "status": "error",
                    "message": "User not found"
                })),
            _ => {
                eprintln!("Failed to verify user: {:?}", e);
                HttpResponse::InternalServerError().json(json!({
                    "status": "error",
                    "message": "Failed to process request"
                }))
            }
        },
    }
}

#[post("/users/validate-otp")]
async fn validate_otp_handler(
    body: web::Json<ValidateOtpSchema>,
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = body.user_id;
    let otp = body.otp;

    let stored_otp = data.db.get_otp_by_user_id(user_id);

    match stored_otp {
        Ok(otp_record) => {
            if otp_record.expires_at < Utc::now() {
                if let Err(e) = data.db.delete_expired_otps() {
                    eprint!("Failed to clean expired OTPs: {:?}", e);
                }
                return HttpResponse::Unauthorized().json("OTP has expired.");
            }

            if otp_record.otp_code != otp {
                log_failed_login(&data, &req, user_id, Some("Invalid otp".to_string())).await;
                return HttpResponse::Unauthorized().json("Invalid otp");
            }

            if let Err(e) = data.db.delete_otp_by_id(otp_record.otp_id) {
                eprint!("Failed to delete used OTP: {:?}", e);
                return HttpResponse::InternalServerError().json("Failed to clean up OTP");
            }

            let now = Utc::now();
            let iat = now.timestamp() as usize;
            let exp = (now + Duration::seconds(24 * 60 * 60)).timestamp() as usize;
            let claims: TokenClaims = TokenClaims {
                sub: user_id.to_string(),
                iat,
                exp,
            };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(data.env.jwt_secret.as_ref()),
            )
            .unwrap();

            let cookie = Cookie::build("token", token.to_owned())
                .path("/")
                .max_age(ActixWebDuration::new(24 * 60 * 60, 0)) //24h
                .http_only(true)
                .finish();

            log_successful_login(&data, &req, user_id).await;

            HttpResponse::Ok()
                .cookie(cookie)
                .json(json!({"status": "success", "message": "Sign in successful"}))
        }
        Err(e) => {
            match e {
                AppError::DieselError(diesel::result::Error::NotFound) => {
                    return HttpResponse::Unauthorized().json("No OTP found");
                }
                _ => {
                    eprint!("Database error: {:?}", e);
                    return HttpResponse::InternalServerError().json("Database error.");
                }
            };
        }
    }
}

#[get("/users/me")]
async fn get_user_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();
    let user = match data.db.get_user_by_id(*user_id) {
        Ok(user) => user,
        Err(AppError::DieselError(diesel::result::Error::NotFound)) => {
            return HttpResponse::NotFound().json("User not found")
        }
        Err(e) => {
            eprint!("Error fetching user: {:?}", e);
            return HttpResponse::InternalServerError().json("Error fetching user");
        }
    };

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "user": filtered_user_record(&user)
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[get("/users/me/transactions")]
async fn get_transaction_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let transactions = match data.db.get_transaction_by_user_id(*user_id) {
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

#[get("/users/me/logs")]
async fn get_user_logs_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let logs = match data.db.get_security_logs_by_user_id(*user_id) {
        Ok(log) => log,
        Err(e) => {
            eprint!("Error fetching user logs: {:?}", e);
            return HttpResponse::InternalServerError().json("Error fetching user logs");
        }
    };

    let filtered_logs: Vec<FilteredUserSecurityLogs> = logs
        .into_iter()
        .map(|log| filtered_security_logs(&log))
        .collect();

    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "user_logs": filtered_logs
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[get("/users/me/wallet")]
async fn get_wallet_handler(
    req: HttpRequest,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let ext = req.extensions();
    let user_id = ext.get::<uuid::Uuid>().unwrap();

    let wallet = match data.db.get_wallet_by_user_id(*user_id) {
        Ok(wallet) => wallet,
        Err(e) => {
            match e {
                AppError::DieselError(diesel::result::Error::NotFound) => {
                    return HttpResponse::NotFound().json("Wallet not found");
                }
                _ => {
                    eprint!("Database error: {:?}", e);
                    return HttpResponse::InternalServerError().json("Error fetching user wallet");
                }
            };
        }
    };
    let json_response = serde_json::json!({
        "status": "success",
        "data": serde_json::json!({
            "wallet": filtered_wallet_record(&wallet)
        })
    });

    HttpResponse::Ok().json(json_response)
}

#[get("/banks")]
pub async fn fetch_banks_handler(data: web::Data<AppState>) -> impl Responder {
    match fetch_banks_via_paystack(&data).await {
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

#[post("/offramp/init-disburse")]
pub async fn init_disburse_payment_handler(
    app_state: web::Data<AppState>,
    request: web::Json<InitDisbursementRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    let reference = format!("{}-{}", Uuid::new_v4().to_string(), Utc::now().timestamp());

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

    let banks = match fetch_banks_via_flutterwave(&app_state).await {
        Ok(banks) => banks,
        Err(e) => {
            return HttpResponse::InternalServerError().json(InitDisbursementResponse {
                success: false,
                message: "Failed to fetch banks".to_string(),
                reference,
                data: None,
                error: Some(e.to_string()),
            });
        }
    };

    let bank_code = banks
        .iter()
        .find(|bank| bank.name.to_lowercase() == request.bank_name.to_lowercase())
        .map(|bank| bank.code.clone());

    let bank_code = match bank_code {
        Some(code) => code,
        None => {
            return HttpResponse::InternalServerError().json(InitDisbursementResponse {
                success: false,
                message: "Bank not found".to_string(),
                reference,
                data: None,
                error: Some(format!("Bank '{}' not found", request.bank_name)),
            });
        }
    };

    match verify_account_via_flutterwave(&app_state, &request.account_number, &bank_code).await {
        Ok(account_details) => {
            let crypto_amount = request.crypto_transaction.amount;
            let crypto_symbol = request.crypto_transaction.token_symbol.clone();

            let pending_disbursement = PendingDisbursement {
                user_id,
                bank_code: bank_code.clone(),
                bank_name: request.bank_name.clone(),
                account_number: request.account_number.clone(),
                account_name: account_details.account_name.clone(),
                currency: request.currency.clone(),
                crypto_amount,
                crypto_symbol,
                order_type: request.order_type.clone(),
                payment_method: request.payment_method.clone(),
                signature: signature.clone(),
            };

            //TODO: PERIST DATA ON REDIS TILL PAYMENT IS CONFIRMED
            if let Err(e) =
                store_pending_disbursement(&app_state, &reference, user_id, &pending_disbursement)
                    .await
            {
                return HttpResponse::InternalServerError().json(InitDisbursementResponse {
                    success: false,
                    message: "Failed to store pending disbursement".to_string(),
                    reference,
                    data: None,
                    error: Some(e.to_string()),
                });
            }

            HttpResponse::Ok().json(InitDisbursementResponse {
                success: true,
                message: "Payment initialized, please confirm to proceed".to_string(),
                reference,
                data: Some(DisbursementDetails {
                    account_name: account_details.account_name,
                    account_number: request.account_number.clone(),
                    bank_name: request.bank_name.clone(),
                    bank_code: bank_code.clone(),
                    amount: 0.0,
                    currency: request.currency.clone(),
                    crypto_tx_hash: "".to_string(),
                }),
                error: None,
            })
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(InitDisbursementResponse {
                success: false,
                message: "Bank account verification failed".to_string(),
                reference,
                data: None,
                error: Some(e),
            });
        }
    }
}

#[post("/offramp/confirm-disburse")]
pub async fn confirm_disburse_payment_handler(
    app_state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Bytes,
) -> impl Responder {
    // Verify HMAC signature from headers
    let api_key = req
        .headers()
        .get("X-Api-Key")
        .and_then(|value| value.to_str().ok());
    let timestamp = req
        .headers()
        .get("X-Timestamp")
        .and_then(|value| value.to_str().ok());
    let signature = req
        .headers()
        .get("X-Signature")
        .and_then(|value| value.to_str().ok());

    if api_key.is_none() || timestamp.is_none() || signature.is_none() {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Missing authentication headers".to_string(),
            error: Some("Missing X-Api-Key, X-Timestamp, or X-Signature header".to_string()),
        });
    }

    let api_key = api_key.unwrap();
    let timestamp = timestamp.unwrap();
    let signature = signature.unwrap();

    // verify api_key
    if api_key != app_state.env.hmac_key {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Invalid API key".to_string(),
            error: Some("Unauthorized".to_string()),
        });
    }

    // verify timestamp
    let current_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let request_timestamp: u64 = match timestamp.parse() {
        Ok(ts) => ts,
        Err(_) => {
            return HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: "unknown".to_string(),
                transaction_ref: None,
                status: None,
                message: "Invalid timestamp".to_string(),
                error: Some("Invalid timestamp format".to_string()),
            });
        }
    };

    if current_timestamp.abs_diff(request_timestamp) > 300 {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Request timestamp expired".to_string(),
            error: Some("Timestamp outside acceptable window".to_string()),
        });
    }

    // verify signature
    let payload = String::from_utf8_lossy(&body);
    let message = format!("{}{}", timestamp, payload);

    let hmac_secret = &app_state.env.hmac_secret;
    let mut mac = HmacSha256::new_from_slice(hmac_secret.as_bytes())
        .expect("msg: HMAC can take key of any size");
    mac.update(message.as_bytes());
    let calculated_signature = hex::encode(mac.finalize().into_bytes());

    if calculated_signature != signature {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: "unknown".to_string(),
            transaction_ref: None,
            status: None,
            message: "Invalid signature".to_string(),
            error: Some("HMAC signature verification failed".to_string()),
        });
    }

    let request: ConfirmDisbursementRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: "unknown".to_string(),
                transaction_ref: None,
                status: None,
                message: "Invalid JSON payload".to_string(),
                error: Some(format!("JSON deserialization failed: {}", e)),
            });
        }
    };

    let user_id = request.user_id.clone();

    // convert user_id to Uuid
    let user_id = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => {
            return HttpResponse::BadRequest().json(PaymentResult {
                success: false,
                reference: request.reference.clone(),
                transaction_ref: None,
                status: None,
                message: "Invalid user ID".to_string(),
                error: Some("Invalid user ID".to_string()),
            });
        }
    };

    log::info!(
        "Confirming disbursement for user {}, reference: {}",
        user_id,
        request.reference
    );

    // ASSERT reference length
    if request.reference.len() > 56 {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: request.reference.clone(),
            transaction_ref: None,
            status: None,
            message: "Invalid reference".to_string(),
            error: Some("Invalid reference".to_string()),
        });
    }

    // ASSERT user_id length
    if user_id.to_string().len() > 40 {
        return HttpResponse::BadRequest().json(PaymentResult {
            success: false,
            reference: request.reference.clone(),
            transaction_ref: None,
            status: None,
            message: "Invalid user ID".to_string(),
            error: Some("Invalid user ID".to_string()),
        });
    }

    let pending_disbursement =
        match retrieve_pending_disbursement(&app_state, &request.reference, user_id).await {
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

    let usdt_ngn_rate: i64 =
        match pricefeed::pricefeed::get_current_usdt_ngn_rate(app_state.price_feed.clone()) {
            Ok(rate) => {
                log::info!("Current USDT to NGN rate: {}", rate);
                rate as i64
            }
            Err(e) => {
                log::error!("Failed to fetch USDT to NGN rate: {}", e);
                return HttpResponse::InternalServerError().json(PaymentResult {
                    success: false,
                    reference: request.reference.clone(),
                    transaction_ref: None,
                    status: None,
                    message: "Failed to fetch USDT to NGN rate".to_string(),
                    error: Some(e.to_string()),
                });
            }
        };

    let narration = Some("Services");
    let amount: i64 = request.amount.parse().expect("failed to parse amount");
    //convert amount to Naira
    let fiat_amount = amount * usdt_ngn_rate;

    log::info!(
        "Converting {} USDT to NGN at rate {}: {} NGN",
        amount,
        usdt_ngn_rate,
        fiat_amount
    );

    println!(
        "Converting {} USDT to NGN at rate {}: {} NGN",
        amount, usdt_ngn_rate, fiat_amount
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
            let payment_status = disbursement.status.clone();
            let monnify_reference = disbursement.reference.clone();
            let crypto_amount = Decimal::from_f64(pending_disbursement.crypto_amount)
                .expect("Invalid float -> Decimal conversion");
            let fiat_amount =
                Decimal::from_i64(fiat_amount).expect("Invalid float -> Decimal conversion");

            let new_tx = NewTransaction {
                user_id: user_id.clone(),
                order_type: pending_disbursement.order_type.clone(),
                crypto_amount: crypto_amount,
                crypto_type: pending_disbursement.crypto_symbol.clone(),
                fiat_amount: fiat_amount,
                fiat_currency: pending_disbursement.currency,
                payment_method: pending_disbursement.payment_method.clone(),
                payment_status: payment_status.clone(),
                tx_hash: request.transaction_hash.clone(),
                reference: monnify_reference.clone(),
                settlement_status: None,
                transaction_reference: None,
                settlement_date: None,
            };

            let transaction_result = app_state.db.create_transaction(new_tx);

            match &transaction_result {
                Ok(tx) => log::info!("Transaction saved successfully: {:?}", tx),
                Err(e) => log::error!("Failed to save transaction to DB: {:?}", e),
            }

            let mut redis_conn = match app_state.redis_pool.get().await {
                Ok(conn) => conn,
                Err(e) => {
                    log::error!("Failed to get Redis connection: {}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "status": "error",
                        "message": "Failed to get Redis connection"
                    }));
                }
            };

            let key = format!("pending disbursement:{}:{}", request.reference, user_id);
            let _: Result<(), _> = redis_conn.expire(&key, 86400).await;
            // let _: Result<(), _> = redis_conn.del(&key).await;

            //      TODO: SEND CONFIRMATION EMAIL TO USER WITH NECESSARY DETAILS

            HttpResponse::Ok().json(PaymentResult {
                success: true,
                reference: request.reference.clone(),
                transaction_ref: Some(monnify_reference),
                status: Some(disbursement.status),
                message: "Payment initiated".to_string(),
                error: None,
            })
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

#[post("/users/logout")]
async fn logout_handler(
    data: web::Data<AppState>,
    req: HttpRequest,
    auth: JwtMiddleware
) -> impl Responder {
    let user_id = auth.user_id;

    logout(&data, &req, user_id).await;

    let cookie = Cookie::build("token", "")
        .path("/")
        .max_age(ActixWebDuration::new(0, 0))
        .http_only(true)
        .expires(OffsetDateTime::now_utc())
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(json!({
            "status": "success",
            "message": "Logged out successfully"
        }))
}