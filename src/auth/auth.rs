use crate::database::user_db::UserImpl;
use crate::models::models::{TokenClaims, User};
use crate::{
    database::db::AppError, database::user_security_log_db::UserSecurityLogsImpl,
    models::models::NewUserSecurityLog, AppState,
};
use actix_web::{web, HttpMessage, HttpRequest, HttpResponse};
use chrono::{Date, DateTime, Utc};
use jsonwebtoken::{DecodingKey, Validation};
use log::info;
use serde_json::json;
use std::result::Result;
use uuid::Uuid;

async fn store_login_attempt(
    app_state: &AppState,
    req: &HttpRequest,
    user_id: Uuid,
    success: bool,
    failure_reason: Option<String>,
) -> Result<(), AppError> {
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let geo = app_state
        .geo_locator
        .lookup(&ip_address)
        .await
        .unwrap_or_default();

    let city = geo.city.unwrap_or_else(|| "unknown".into());
    let country = geo.country.unwrap_or_else(|| "unknown".into());

    let failed_login_attempts = if success { 0 } else { 1 };

    actix_web::rt::spawn({
        let db = app_state.db.clone();
        let ip_address_clone = ip_address.clone();
        let city_clone = city.clone();
        let country_clone = country.clone();

        async move {
            let mut flagged_for_review = false;

            if !success {
                if let Ok(recent_failures) = db.get_user_total_failed_logins(user_id) {
                    if recent_failures + failed_login_attempts >= 3 {
                        flagged_for_review = true;
                    }
                }
            }

            let new_log = NewUserSecurityLog {
                user_id,
                ip_address: ip_address_clone,
                city: city_clone,
                country: country_clone,
                failed_login_attempts: failed_login_attempts as i32,
                flagged_for_review,
                created_at: Utc::now()
            };

            if let Err(e) = db.create_user_security_log(new_log) {
                log::error!("Failed to store login attempt: {:?}", e);
            } else {
                log::info!("Login attempt stored successfully for user: {}", user_id);
            }
        }
    });

    Ok(())
}

pub async fn log_successful_login(app_state: &AppState, req: &HttpRequest, user_id: Uuid) {
    if let Err(e) = store_login_attempt(app_state, req, user_id, true, None).await {
        log::error!("Failed to log successful login: {:?}", e);
    }
}

pub async fn log_failed_login(
    app_state: &AppState,
    req: &HttpRequest,
    user_id: Uuid,
    reason: Option<String>,
) {
    if let Err(e) = store_login_attempt(app_state, req, user_id, false, reason).await {
        log::error!("Failed to log failed login: {:?}", e);
    }
}

pub async fn verify_admin_role(
    admin_id: Uuid,
    data: &web::Data<AppState>,
) -> Result<(), HttpResponse> {
    
    match data.db.get_user_by_id(admin_id) {
        Ok(user) => {
            if user.role != "Admin" {
                return Err(HttpResponse::Forbidden().json(json!({
                 "status": "error",
                 "message": "Admin access required."
                })));
            }
            Ok(())
        }
        Err(_) => Err(HttpResponse::Unauthorized().json(json!({
            "status": "error",
            "message": "User not found or failed to verify user role"
        }))),
    }
}


pub async fn logout(
    data: &web::Data<AppState>,
    req: &HttpRequest,
    user_id: Uuid
) {
    let client_ip = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    info!(
        "User logout - ID: {}, IP: {}, User-Agent: {}, Timestamp: {}",
        user_id,
        client_ip,
        user_agent,
        Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );

    // log user logout?
}