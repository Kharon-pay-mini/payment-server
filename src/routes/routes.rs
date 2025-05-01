use actix_web::{
    cookie::{time::Duration as ActixWebDuration, Cookie},
    get, post, web, HttpMessage, HttpRequest, HttpResponse, Responder,
};
use awc::body;
use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use rand::{rng, Rng};
use redis::AsyncCommands;
use serde_json::json;
use sqlx::Row;
use std::{time::Duration, usize};
use uuid::Uuid;

use crate::{
    auth::jwt_auth,
    integrations::{
        bank::{
            delete_pending_disbursement, disburse_payment, fetch_banks_via_paystack,
            process_monnify_webhook, retrieve_pending_disbursement, store_pending_disbursement,
            verify_account_via_paystack, verify_monnify_webhook_signature,
        },
        model::{
            BankVerificationSchema, ConfirmDisbursementRequest, DisbursementDetails,
            InitDisbursementRequest, InitDisbursementResponse, MonnifyWebhookPayload,
            OfframpRequest, PaymentResult, PendingDisbursement,
        },
    },
    models::{
        models::{
            CreateUserSchema, Otp, OtpSchema, TokenClaims, TransactionSchema, Transactions, User,
            UserSecurityLogs, UserWallet, UserWalletSchema, ValidateOtpSchema,
        },
        response::{
            FilteredOtp, FilteredTransaction, FilteredUser, FilteredUserSecurityLogs,
            FilteredWallet,
        },
    },
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

fn filtered_transaction_record(transaction: &Transactions) -> FilteredTransaction {
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

fn filtered_security_logs(security_log: &UserSecurityLogs) -> FilteredUserSecurityLogs {
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
        otp: otp.otp,
        created_at: otp.created_at.unwrap_or_else(|| Utc::now()),
        expires_at: otp.expires_at.unwrap(),
    }
}

#[post("/auth/create")]
async fn create_user_handler(
    body: web::Json<CreateUserSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let email = body.email.to_string().to_lowercase();
    let phone = body.phone.as_ref().map(|s| s.to_string());
    let role = body.role.to_string();

    let exists: bool = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(&email)
        .fetch_one(&data.db)
        .await
        .unwrap()
        .get(0);

    if exists {
        let query_result = match &phone {
            Some(phone_value) => sqlx::query_as::<_, User>(
                "UPDATE users SET last_logged_in = NOW(), phone = $2 WHERE email = $1 RETURNING *",
            )
            .bind(&email)
            .bind(phone_value)
            .fetch_one(&data.db)
            .await,
            None => {
                sqlx::query_as::<_, User>(
                    "UPDATE users SET last_logged_in = NOW() WHERE email = $1 RETURNING *",
                )
                .bind(&email)
                .fetch_one(&data.db)
                .await
            }
        };

        match query_result {
            Ok(user) => {
                let user_response = serde_json::json!({"status": "success", "data": serde_json::json!({
                    "user": filtered_user_record(&user)
                })});

                return HttpResponse::Ok().json(user_response);
            }
            Err(e) => {
                eprintln!("Database error on update: {:?}", e);
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"status": "error", "message": format!("{:?}", e)}));
            }
        }
    } else {
        let query_result = match &phone {
            Some(phone_value) => {
                sqlx::query_as::<_, User>("INSERT INTO users (email, role, phone, last_logged_in) VALUES ($1, $2, $3, now()) RETURNING *")
                    .bind(&email)
                    .bind(&role)
                    .bind(phone_value)
                    .fetch_one(&data.db)
                    .await
            },
            None => {
                sqlx::query_as::<_, User>("INSERT INTO users (email, role, last_logged_in) VALUES ($1, $2, now()) RETURNING *")
                    .bind(&email)
                    .bind(&role)
                    .fetch_one(&data.db)
                    .await
            }
        };

        match query_result {
            Ok(user) => {
                let user_response = serde_json::json!({"status": "success", "data": serde_json::json!({
                    "user": filtered_user_record(&user)
                })});

                return HttpResponse::Ok().json(user_response);
            }
            Err(e) => {
                eprintln!("Database error on insert: {:?}", e);
                return HttpResponse::InternalServerError()
                    .json(serde_json::json!({"status": "error", "message": format!("{:?}", e)}));
            }
        }
    }
}

#[post("/users/me/wallet")]
async fn update_user_wallet_handler(
    body: web::Json<UserWalletSchema>,
    data: web::Data<AppState>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;
    println!("User ID: {}", user_id);
    let wallet_address = body.wallet_address.to_string();
    let network = body.network.to_string();

    let user_exists: bool =
        match sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&data.db)
            .await
        {
            Ok(exists) => exists,
            Err(e) => {
                eprintln!("User verification error: {}", e);
                return HttpResponse::InternalServerError().json(json!({
                    "status": "error",
                    "message": "User verification failed"
                }));
            }
        };

    if !user_exists {
        return HttpResponse::NotFound().json(json!({
            "status": "error",
            "message": "User not found"
        }));
    }

    // 2. Insert or update wallet with ownership check
    let wallet = match sqlx::query_as::<_, UserWallet>(
        r#"
        WITH new_wallet AS (
            INSERT INTO user_wallet (user_id, wallet_address, network_used_last)
            VALUES ($1, $2, $3)
            ON CONFLICT (wallet_address) 
            DO UPDATE SET 
                network_used_last = EXCLUDED.network_used_last,
                updated_at = NOW()
            WHERE user_wallet.user_id = $1
            RETURNING *
        )
        SELECT * FROM new_wallet
        UNION ALL
        SELECT * FROM user_wallet 
        WHERE wallet_address = $2 AND user_id = $1 AND NOT EXISTS (
            SELECT 1 FROM new_wallet
        )
        "#,
    )
    .bind(user_id)
    .bind(&wallet_address)
    .bind(&network)
    .fetch_one(&data.db)
    .await
    {
        Ok(wallet) => wallet,
        Err(sqlx::Error::RowNotFound) => {
            return HttpResponse::Conflict().json(json!({
                "status": "error",
                "message": "Wallet address already belongs to another user"
            }));
        }
        Err(e) => {
            eprintln!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to update wallet"
            }));
        }
    };

    let filtered_wallet = filtered_wallet_record(&wallet);
    HttpResponse::Created().json(filtered_wallet)
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

    let transaction = sqlx::query_as::<_, Transactions>(
        r#"
        INSERT INTO transactions (
            user_id, order_type, crypto_amount, crypto_type,
            fiat_amount, fiat_currency, payment_method, payment_status,
            tx_hash
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT ON CONSTRAINT unique_transaction_hash
        DO UPDATE
        SET
            user_id = EXCLUDED.user_id,
            order_type = EXCLUDED.order_type,
            crypto_amount = EXCLUDED.crypto_amount,
            crypto_type = EXCLUDED.crypto_type,
            fiat_amount = EXCLUDED.fiat_amount,
            fiat_currency = EXCLUDED.fiat_currency,
            payment_method = EXCLUDED.payment_method,
            payment_status = EXCLUDED.payment_status,
            updated_at = NOW()
        RETURNING *
    "#,
    )
    .bind(user_id)
    .bind(order_type)
    .bind(crypto_amount)
    .bind(crypto_type)
    .bind(fiat_amount)
    .bind(fiat_currency)
    .bind(payment_method)
    .bind(payment_status)
    .bind(tx_hash)
    .fetch_optional(&data.db)
    .await;

    match transaction {
        Ok(Some(transaction)) => {
            let filtered_transaction = filtered_transaction_record(&transaction);
            HttpResponse::Ok().json(filtered_transaction)
        }
        Ok(None) => HttpResponse::Conflict().json("Transaction already exists"),
        Err(e) => {
            eprint!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Database error")
        }
    }
}

/*
DEPRECATED, LOGGING NOW DONE AUTOMATICALLY
#[post("/users/me/logs")]
async fn update_user_logs_handler(
    body: web::Json<UserSecurityLogsSchema>,
    data: web::Data<AppState>,
    _: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = body.user_id;
    let ip_address = body.ip_address.to_string();
    let city = body.city.to_string();
    let country = body.country.to_string();
    let failed_login_attempts = body.failed_login_attempts;
    let flagged_for_review = body.flagged_for_review;
    let security_log = sqlx::query_as::<_, UserSecurityLogs>(
        r#"
        INSERT INTO user_security_logs (
            user_id, ip_address, city, country,
            failed_login_attempts, flagged_for_review
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(user_id)
    .bind(ip_address)
    .bind(city)
    .bind(country)
    .bind(failed_login_attempts)
    .bind(flagged_for_review)
    .fetch_optional(&data.db)
    .await;
    match security_log {
        Ok(Some(security_log)) => {
            /*
            let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
                .bind(security_log.user_id)
                .fetch_one(&data.db)
                .await;
            match user {
                Ok(user) => {
                    let filtered_security_logs = filtered_security_logs(&security_log);
                    HttpResponse::Ok().json(filtered_security_logs)
                }
                Err(e) => {
                    eprint!("Error fetching user: {}", e);
                    HttpResponse::InternalServerError().json("User data retrieval failed!")
                }
            } */
            let filtered_security_logs = filtered_security_logs(&security_log);
            HttpResponse::Ok().json(filtered_security_logs)
        }
        Ok(None) => {
            HttpResponse::Conflict().json("Security log already exists or no changes detected")
        }
        Err(e) => {
            eprint!("Database error: {}", e);
            return HttpResponse::InternalServerError().json("Database error");
        }
    }
}       */

#[post("/users/request-otp")]
async fn request_otp_handler(
    body: web::Json<OtpSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = body.user_id;
    let email = body.email.clone();

    let otp_code = rng().random_range(100_000..=999_999);

    let expiry = Utc::now() + Duration::from_secs(15 * 60);

    let otp = sqlx::query_as::<_, Otp>(
        r#"
        INSERT INTO otp (user_id, otp, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT ON CONSTRAINT unique_user_id DO UPDATE 
        SET otp = $2,
            created_at = NOW(),
            expires_at = $3
        RETURNING otp_id, user_id, otp, created_at, expires_at
        "#,
    )
    .bind(user_id)
    .bind(otp_code)
    .bind(expiry)
    .fetch_one(&data.db)
    .await;

    match otp {
        Ok(otp) => {
            let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
                .bind(otp.user_id)
                .fetch_one(&data.db)
                .await;

            match user {
                Ok(user) => {
                    if let Err(e) = send_verification_email(&email, otp_code).await {
                        eprint!("Failed to send email: {}", e);
                        return HttpResponse::InternalServerError()
                            .json("Failed to send verification email");
                    }
                    let filtered_otp = filtered_otp(&otp);
                    HttpResponse::Ok().json(json!({
                        "otp": filtered_otp,
                        "user": filtered_user_record(&user),
                    }))
                }
                Err(e) => {
                    eprint!("Error fetching user: {}", e);
                    HttpResponse::InternalServerError().json("User data retrieval failed!")
                }
            }
        }
        Err(e) => {
            eprint!("Database error: {}", e);
            return HttpResponse::InternalServerError().json("Database error");
        }
    }
}

#[post("/users/validate-otp")]
async fn validate_otp_handler(
    body: web::Json<ValidateOtpSchema>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = body.user_id;
    let otp = body.otp;

    let stored_otp = sqlx::query_as::<_, Otp>("SELECT * FROM otp WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&data.db)
        .await;

    match stored_otp {
        Ok(Some(otp_record)) => {
            if let Some(expiry) = otp_record.expires_at {
                if expiry < Utc::now() {
                    if let Err(e) = sqlx::query("DELETE FROM otp WHERE expires_at < NOW()")
                        .execute(&data.db)
                        .await
                    {
                        eprint!("Failed to clean expired OTPs: {}", e);
                    }

                    return HttpResponse::Unauthorized().json("OTP has expired.");
                }
            } else {
                HttpResponse::Unauthorized().json("OTP expiry time is missing.");
            }
            if otp_record.otp != otp {
                return HttpResponse::Unauthorized().json("Invalid otp");
            }

            if let Err(e) = sqlx::query("DELETE FROM otp WHERE user_id = $1")
                .bind(user_id)
                .execute(&data.db)
                .await
            {
                eprint!("Failed to delete used OTP: {}", e);
                return HttpResponse::InternalServerError().json("Failed to clean up OTP");
            }

            let now = Utc::now();
            let iat = now.timestamp() as usize;
            let exp = (now + Duration::from_secs(24 * 60 * 60)).timestamp() as usize;
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

            HttpResponse::Ok()
                .cookie(cookie)
                .json(json!({"status": "success", "token": token}))
        }
        Ok(None) => HttpResponse::Unauthorized().json("No OTP found"),
        Err(e) => {
            eprint!("Database error: {}", e);
            HttpResponse::InternalServerError().json("Database error.")
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
    let user = match sqlx::query_as!(User, "SELECT id, email, phone, last_logged_in, verified,role, created_at FROM users WHERE id = $1", user_id)
        .fetch_optional(&data.db)
        .await
        {
            Ok(Some(user)) => user,
            Ok(None) => return HttpResponse::NotFound().json("User not found"),
            Err(e) => {
                eprint!("Error fetching user: {}", e);
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

    let transactions = match sqlx::query_as!(
        Transactions,
        "SELECT 
            tx_id, user_id, order_type, crypto_amount, crypto_type, 
            fiat_amount, fiat_currency, payment_method, payment_status, tx_hash, 
            reference, settlement_status, transaction_reference, 
            settlement_date, created_at, updated_at 
            FROM transactions WHERE user_id = $1",
        user_id
    )
    .fetch_all(&data.db)
    .await
    {
        Ok(tx) => tx,
        Err(e) => {
            eprint!("Error fetching transactions: {}", e);
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

    let logs = match sqlx::query_as!(
        UserSecurityLogs,
        "SELECT log_id, user_id, ip_address,city,
            country, failed_login_attempts, flagged_for_review,
            created_at
            FROM user_security_logs WHERE user_id = $1",
        user_id
    )
    .fetch_all(&data.db)
    .await
    {
        Ok(log) => log,
        Err(e) => {
            eprint!("Error fetching user logs: {}", e);
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

    let wallet = match sqlx::query_as!(
        UserWallet,
        "SELECT id, user_id, wallet_address, network_used_last, created_at, updated_at FROM user_wallet WHERE user_id = $1",
        user_id
    )
    .fetch_optional(&data.db)
    .await 
    {
        Ok(Some(wallet)) => wallet,
        Ok(None) => return HttpResponse::NotFound().json("Wallet not found"),
        Err(e) => {
            eprint!("Error fetching user wallet: {}", e);
            return HttpResponse::InternalServerError().json("Error fetching user wallet");
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

    // let reference = format!("{}-{}", Uuid::new_v4().to_string(), Utc::now().timestamp());

    let reference = match Uuid::parse_str(&request.reference) {
        Ok(uuid) => uuid.to_string(),
        Err(_) => {
            return HttpResponse::BadRequest().json(InitDisbursementResponse {
                success: false,
                message: "Invalid reference format. Must be a valid UUID".to_string(),
                reference: request.reference.clone(),
                data: None,
                error: Some("Invalid reference format".to_string()),
            });
        }
    };

    log::info!(
        "Initializing disbursement for user: {}, reference: {}",
        user_id,
        reference
    );

    let banks = match fetch_banks_via_paystack(&app_state).await {
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

    match verify_account_via_paystack(&app_state, &request.account_number, &bank_code).await {
        Ok(account_details) => {
            let crypto_amount = request.crypto_transaction.amount;
            let crypto_symbol = request.crypto_transaction.token_symbol.clone();

            let pending_disbursement = PendingDisbursement {
                user_id,
                amount: request.amount,
                bank_code: bank_code.clone(),
                bank_name: request.bank_name.clone(),
                account_number: request.account_number.clone(),
                account_name: account_details.account_name.clone(),
                currency: request.currency.clone(),
                crypto_amount,
                crypto_symbol,
                order_type: request.order_type.clone(),
                payment_method: request.payment_method.clone(),
            };

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
                    amount: request.amount,
                    currency: request.currency.clone(),
                    crypto_tx_hash: request.crypto_transaction.tx_hash.clone(),
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
    request: web::Json<ConfirmDisbursementRequest>,
    auth: jwt_auth::JwtMiddleware,
) -> impl Responder {
    let user_id = auth.user_id;

    log::info!(
        "Confirming disbursement for user {}, reference: {}",
        user_id,
        request.reference
    );

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

    let narration = Some("Service charge");
    match disburse_payment(
        &app_state,
        &request.reference,
        pending_disbursement.amount,
        narration,
        &pending_disbursement.bank_code,
        &pending_disbursement.account_number,
        &pending_disbursement.currency,
    )
    .await
    {
        Ok(disbursement) => {
            let payment_status = disbursement.status.clone();
            let monnify_reference = disbursement.reference.clone();
            let transaction_result = sqlx::query_as::<_, Transactions>(
                r#"
                    INSERT INTO transactions (
                        user_id, created_at, order_type, crypto_amount, crypto_type,
                        fiat_amount, fiat_currency, payment_method, payment_status,
                        tx_hash
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    RETURNING *
                    "#,
            )
            .bind(&user_id)
            .bind(Utc::now())
            .bind(&pending_disbursement.order_type.clone())
            .bind(&pending_disbursement.crypto_amount)
            .bind(&pending_disbursement.crypto_symbol.clone())
            .bind(&pending_disbursement.amount)
            .bind(&pending_disbursement.currency.clone())
            .bind(&pending_disbursement.payment_method.clone())
            .bind(&payment_status)
            .bind(&request.crypto_tx_hash.clone())
            .bind(&monnify_reference)
            .fetch_optional(&app_state.db)
            .await;

            match &transaction_result {
                Ok(tx) => log::info!("Transaction saved successfully: {:?}", tx),
                Err(e) => log::error!("Failed to save transaction to DB: {}", e),
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

            //      TODO: SEND CONFIRMATION EMAIL TO USER WITH NECESSARY DETAILS

            HttpResponse::Ok().json(PaymentResult {
                success: true,
                reference: request.reference.clone(),
                transaction_ref: Some(disbursement.reference),
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

/*
TODO after MVP is completed
#[get("/stats")]
async fn get_stats_handler(
) -> impl Responder {
}
 */
