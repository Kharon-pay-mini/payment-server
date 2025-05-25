use super::db::DbAccess;
use crate::models::models::{NewUserWallet, UserWallet};
use crate::models::schema::user_wallet::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserWalletImpl: DbAccess {
    fn create_user_wallet(
        &self,
        wallet: NewUserWallet,
    ) -> Result<UserWallet, diesel::result::Error> {
        diesel::insert_into(user_wallet)
            .values(&wallet)
            .get_result(&mut self.conn())
    }
}
