use super::db::DbAccess;
use crate::models::models::{NewTransaction, Transaction};
use crate::models::schema::transactions::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait TransactionImpl: DbAccess {
    fn create_transaction(
        &self,
        transaction: NewTransaction,
    ) -> Result<Transaction, diesel::result::Error> {
        let mut conn = self.conn().map_err(|_| diesel::result::Error::NotFound)?;

        diesel::insert_into(transactions)
            .values(&transaction)
            .get_result(&mut conn)
    }
}
