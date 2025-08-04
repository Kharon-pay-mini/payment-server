use super::db::{AppError, DbAccess};

use crate::models::models::{NewTransaction, Transaction};
use crate::models::schema::transactions::dsl::*;
use chrono::Utc;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait TransactionImpl: DbAccess {
    fn create_transaction(&self, transaction: NewTransaction) -> Result<Transaction, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::insert_into(transactions)
            .values(&transaction)
            .get_result(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_transaction_by_user_id(&self, find_user: &str) -> Result<Vec<Transaction>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        transactions
            .filter(user_id.eq(find_user))
            .get_results::<Transaction>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn get_transaction_by_user_and_reference(
        &self,
        find_user: &str,
        ref_value: &str,
    ) -> Result<Option<Transaction>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        transactions
            .filter(user_id.eq(find_user))
            .filter(reference.eq(ref_value))
            .first::<Transaction>(&mut conn)
            .optional()
            .map_err(AppError::DieselError)
    }

    fn update_transaction(&self, user_id_val: &str, status: String) -> Result<usize, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let updated_rows = diesel::update(transactions.filter(user_id.eq(user_id_val)))
            .set((
                payment_status.eq(status),
                updated_at.eq(Utc::now().naive_utc()),
            ))
            .execute(&mut conn)
            .map_err(AppError::DieselError)?;

        Ok(updated_rows)
    }

    fn update_transaction_by_tx_ref(
        &self,
        transaction_ref: String,
        status: String,
        ref_str: String,
    ) -> Result<usize, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let updated_rows =
            diesel::update(transactions.filter(transaction_reference.eq(transaction_ref.clone())))
                .set((
                    payment_status.eq(status),
                    updated_at.eq(Utc::now().naive_utc()),
                    reference.eq(ref_str),
                ))
                .execute(&mut conn)
                .map_err(AppError::DieselError)?;

        Ok(updated_rows)
    }

    fn update_transaction_status_by_tx_ref(
        &self,
        transaction_ref: String,
        status: String,
    ) -> Result<usize, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let updated_rows =
            diesel::update(transactions.filter(transaction_reference.eq(transaction_ref.clone())))
                .set((
                    payment_status.eq(status),
                    updated_at.eq(Utc::now().naive_utc()),
                ))
                .execute(&mut conn)
                .map_err(AppError::DieselError)?;

        Ok(updated_rows)
    }

    fn mark_transaction_settled_by_ref(
        &self,
        tx_ref: String,
        ref_str: String,
        status: String,
    ) -> Result<usize, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let updated_rows = diesel::update(transactions.filter(reference.eq(ref_str.clone())))
            .set((
                settlement_status.eq(status),
                settlement_date.eq(Utc::now().naive_utc()),
                transaction_reference.eq(tx_ref),
            ))
            .execute(&mut conn)
            .map_err(AppError::DieselError)?;

        Ok(updated_rows)
    }
}
