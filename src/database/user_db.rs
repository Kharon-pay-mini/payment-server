use super::db::{AppError, DbAccess};
use crate::models::models::User;
use crate::models::schema::users::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserImpl: DbAccess {
    fn get_user_by_email(&self, find_email: String) -> Result<User, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;
        users
            .filter(lower(email).eq(lower(find_email)))
            .first::<User>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_user_by_id(&self, find_id: &str) -> Result<User, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;
        users
            .find(find_id)
            .first::<User>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_user_by_phone(&self, find_phone: String) -> Result<User, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;
        users
            .filter(phone.eq(find_phone))
            .first::<User>(&mut conn)
            .map_err(AppError::DieselError)
    }
}
