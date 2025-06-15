use crate::database::user_security_log_db::UserSecurityLogsImpl;
use crate::models::models::NewUserSecurityLog;
use crate::{models::models::TokenClaims, AppState};
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    middleware::Next,
    web, Error,
};
use chrono::Utc;

pub async fn security_logger_middleware(
    req: ServiceRequest,
    next: Next<impl actix_web::body::MessageBody>,
) -> Result<ServiceResponse<impl actix_web::body::MessageBody>, Error> {
    let app_data = req.app_data::<actix_web::web::Data<AppState>>().cloned();
    let user_id = extract_user_id_from_jwt(&req, app_data.as_ref());
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let path = req.path().to_string();
    let method = req.method().to_string();

    let response = next.call(req).await?;
    let status = response.status().as_u16();

    if let Some(app_data) = app_data {
        let is_login_failure = (path.contains("/auth") || path.contains("/validate-otp"))
            && (status == 401 || status == 403);

        let failed_login_attempts = if is_login_failure { 1 } else { 0 };

        let geo = app_data
            .geo_locator
            .lookup(&ip_address)
            .await
            .unwrap_or_default();
        let city = geo.city.unwrap_or_else(|| "unknown".into());
        let country = geo.country.unwrap_or_else(|| "unknown".into());

        actix_web::rt::spawn({
            let db = app_data.db.clone();

            async move {
                let mut flagged_for_review = false;

                if is_login_failure {
                    let failures = db.get_user_total_failed_logins(user_id.unwrap());

                    if let Ok(recent_failures) = failures {
                        if recent_failures + failed_login_attempts >= 3 {
                            flagged_for_review = true;
                        }

                        if method == "DELETE" && path.clone().contains("/users") {
                            flagged_for_review = true;
                        }

                        let new_log = NewUserSecurityLog {
                            user_id: user_id.unwrap().clone(),
                            ip_address: ip_address.clone(),
                            city: city.clone(),
                            country: country.clone(),
                            failed_login_attempts: failed_login_attempts as i32,
                            flagged_for_review: flagged_for_review.clone(),
                            created_at: Utc::now(),
                        };

                        let _ = db.create_user_security_log(new_log);
                    }
                }
            }
        });
    }

    Ok(response)
}

fn extract_user_id_from_jwt(
    req: &ServiceRequest,
    app_state: Option<&web::Data<AppState>>,
) -> Option<uuid::Uuid> {
    let token = req
        .cookie("token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            req.headers()
                .get(header::AUTHORIZATION)
                .map(|h| h.to_str().unwrap_or_default().split_at(7).1.to_string())
        });

    if let (Some(token), Some(app_state)) = (token, app_state) {
        match jsonwebtoken::decode::<TokenClaims>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(app_state.env.jwt_secret.as_ref()),
            &jsonwebtoken::Validation::default(),
        ) {
            Ok(data) => {
                if let Ok(user_id) = uuid::Uuid::parse_str(&data.claims.sub) {
                    return Some(user_id);
                }
            }
            Err(_) => return None,
        }
    }

    None
}
