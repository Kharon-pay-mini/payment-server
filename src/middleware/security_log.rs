use crate::AppState;
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    Error, HttpMessage,
};

pub async fn security_logger_middleware(
    req: ServiceRequest,
    next: Next<impl actix_web::body::MessageBody>,
) -> Result<ServiceResponse<impl actix_web::body::MessageBody>, Error> {
    let app_data = req.app_data::<actix_web::web::Data<AppState>>().cloned();
    let user_id = req.extensions().get::<uuid::Uuid>().cloned();
    let ip_address = req
        .connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    let path = req.path().to_string();
    let method = req.method().to_string();

    let response = next.call(req).await?;
    let status = response.status().as_u16();

    if let (Some(user_id), Some(app_data)) = (user_id, app_data) {
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
                    let recent_failures = sqlx::query!(
                        r#"
                                SELECT SUM(failed_login_attempts) as total_failures
                                FROM user_security_logs
                                WHERE user_id = $1
                            "#,
                        user_id
                    )
                    .fetch_one(&db)
                    .await
                    .map(|row| row.total_failures.unwrap_or(0))
                    .unwrap_or(0);

                    if recent_failures + failed_login_attempts >= 3 {
                        flagged_for_review = true;
                    }

                    if method == "DELETE" && path.clone().contains("/users") {
                        flagged_for_review = true;
                    }
                }

                let _ = sqlx::query!(
                    r#"
                        INSERT INTO user_security_logs (
                            user_id, ip_address, city, country,
                            failed_login_attempts, flagged_for_review
                        )
                        VALUES ($1, $2, $3, $4, $5, $6)
                    "#,
                    user_id,
                    ip_address,
                    city,
                    country,
                    failed_login_attempts as i32,
                    flagged_for_review
                )
                .execute(&db)
                .await;
            }
        });
    }

    Ok(response)
}
