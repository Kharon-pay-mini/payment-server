use super::db::{AppError, DbAccess};
use crate::models::models::{NewUserSecurityLog, UserSecurityLog};
use crate::models::schema::user_security_logs::dsl::*;
use diesel::dsl::sum;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserSecurityLogsImpl: DbAccess {
    fn create_user_security_log(
        &self,
        security_log: NewUserSecurityLog,
    ) -> Result<UserSecurityLog, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::insert_into(user_security_logs)
            .values(&security_log)
            .get_result(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_security_logs_by_user_id(
        &self,
        find_user: uuid::Uuid,
    ) -> Result<Vec<UserSecurityLog>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(user_id.eq(find_user))
            .get_results::<UserSecurityLog>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_user_total_failed_logins(&self, uid: uuid::Uuid) -> Result<i64, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(user_id.eq(uid))
            .select(sum(failed_login_attempts))
            .first::<Option<i64>>(&mut conn)
            .map(|opt| opt.unwrap_or(0))
            .map_err(AppError::DieselError)
    }

    fn get_user_security_logs_count(&self, uid: uuid::Uuid) -> Result<i64, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(user_id.eq(uid))
            .count()
            .get_result::<i64>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_user_security_logs_with_limit(
        &self,
        uid: uuid::Uuid,
        limit_count: Option<i64>,
    ) -> Result<Vec<UserSecurityLog>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;
        let query_limit = limit_count.unwrap_or(100);

        user_security_logs
            .filter(user_id.eq(uid))
            .order(created_at.desc())
            .limit(query_limit)
            .load::<UserSecurityLog>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_user_security_logs_paginated(
        &self,
        uid: uuid::Uuid,
        limit_count: i64,
        offset_count: i64,
    ) -> Result<Vec<UserSecurityLog>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(user_id.eq(uid))
            .order(created_at.desc())
            .limit(limit_count)
            .offset(offset_count)
            .load::<UserSecurityLog>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_flagged_users_security_logs(&self) -> Result<Vec<UserSecurityLog>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(flagged_for_review.eq(true))
            .order(created_at.desc())
            .limit(100)
            .load::<UserSecurityLog>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_flagged_users_count(&self) -> Result<i64, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_security_logs
            .filter(flagged_for_review.eq(true))
            .count()
            .get_result::<i64>(&mut conn)
            .map_err(AppError::DieselError)
    }
}
