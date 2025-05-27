use super::db::{AppError, DbAccess};
use crate::models::models::{NewOtp, Otp};
use crate::models::schema::otp::dsl::*;
use chrono::Utc;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait OtpImpl: DbAccess {
    fn create_otp(&self, new_otp: NewOtp) -> Result<Otp, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::insert_into(otp)
            .values(&new_otp)
            .get_result(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_otp_by_user_id(&self, find_user: uuid::Uuid) -> Result<Otp, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        otp.filter(user_id.eq(find_user))
            .first::<Otp>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn delete_otp_by_id(&self, find_id: uuid::Uuid) -> Result<Otp, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::delete(otp.filter(otp_id.eq(find_id)))
            .get_result::<Otp>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn delete_expired_otps(&self) -> Result<Vec<Otp>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;
        diesel::delete(otp.filter(expires_at.lt(Utc::now().naive_utc())))
            .get_results(&mut conn)
            .map_err(AppError::DieselError)
    }
}
