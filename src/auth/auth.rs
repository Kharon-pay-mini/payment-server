use crate::database::user_db::UserImpl;
use crate::AppState;
use actix_web::{web, HttpResponse};

use serde_json::json;
use std::result::Result;

pub async fn _verify_admin_role(
    admin_id: &str,
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
