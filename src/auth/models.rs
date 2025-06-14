use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug)]
pub struct UserLoginStats {
    pub user_id: Uuid,
    pub total_logins: i64,
    pub successful_logins: i64,
    pub failed_logins: i64,
    pub last_successful_login: Option<DateTime<Utc>>,
    pub last_failed_login: Option<DateTime<Utc>>,
    pub is_flagged_for_review: bool,
    pub recent_failed_attempts: i32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserLoginHistoryItem {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub ip_address: String,
    pub city: String,
    pub country: String,
    pub was_successful: bool,
    pub failed_login_attempts: i32,
    pub flagged_for_review: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginHistoryQuery {
    pub email: String,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    pub days_back: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlaggedUserQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}
