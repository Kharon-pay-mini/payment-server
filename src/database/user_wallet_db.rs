use super::db::{AppError, DbAccess};

use crate::models::models::{NewUserWallet, UserWallet};
use crate::models::schema::user_wallet::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserWalletImpl: DbAccess {
    fn create_user_wallet(&self, wallet: NewUserWallet) -> Result<UserWallet, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::insert_into(user_wallet)
            .values(&wallet)
            .get_result(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_wallet_by_user_id(&self, find_user: uuid::Uuid) -> Result<UserWallet, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_wallet
            .filter(user_id.eq(find_user))
            .get_result::<UserWallet>(&mut conn)
            .map_err(AppError::DieselError)
    }
}
