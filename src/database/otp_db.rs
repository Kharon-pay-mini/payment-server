use super::db::DbAccess;
use crate::models::models::{NewOtp, Otp};
use crate::models::schema::otp::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait OtpImpl: DbAccess {
    fn create_otp(&self, new_otp: NewOtp) -> Result<Otp, diesel::result::Error> {
        let mut conn = self.conn().map_err(|_| diesel::result::Error::NotFound)?;

        diesel::insert_into(otp)
            .values(&new_otp)
            .get_result(&mut conn)
    }
}
