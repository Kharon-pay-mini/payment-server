use super::db::DbAccess;
use crate::models::models::{NewUserSecurityLog, UserSecurityLog};
use crate::models::schema::user_security_logs::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserSecurityLogsImpl: DbAccess {
    fn create_transaction(
        &self,
        security_log: NewUserSecurityLog,
    ) -> Result<UserSecurityLog, diesel::result::Error> {
        diesel::insert_into(user_security_logs)
            .values(&security_log)
            .get_result(&mut self.conn())
    }
}
