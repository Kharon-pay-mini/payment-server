use super::db::{AppError, DbAccess};

use crate::models::models::{ControllerSessionInfo, NewUserWallet, UserWallet};
use crate::models::schema::user_wallet::dsl::*;
use chrono::Utc;
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

    fn get_wallet_by_user_id(&self, find_user: &str) -> Result<UserWallet, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        user_wallet
            .filter(user_id.eq(find_user))
            .get_result::<UserWallet>(&mut conn)
            .map_err(AppError::DieselError)
    }

    fn update_wallet_controller_info(
        &self,
        find_user: &str,
        controller_detail: &ControllerSessionInfo,
    ) -> Result<UserWallet, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let session_data = serde_json::to_string(&controller_detail)
            .map_err(|e| AppError::SerializationError(e.to_string()))?;

        let update_result = diesel::update(user_wallet.filter(user_id.eq(find_user)))
            .set((
                controller_info.eq(Some(session_data.clone())),
                updated_at.eq(Some(Utc::now())),
            ))
            .get_result(&mut conn);

        match update_result {
            Ok(wallet) => {
                log::debug!("Successfully updated wallet controller info");
                Ok(wallet)
            }
            Err(diesel::result::Error::NotFound) => {
                log::debug!("Wallet not found, creating new one");
                let new_wallet = NewUserWallet {
                    user_id: find_user.to_string(),
                    wallet_address: Some(controller_detail.controller_address.clone()),
                    network_used_last: Some("starknet".to_string()),
                    controller_info: Some(session_data),
                };

                diesel::insert_into(user_wallet)
                    .values(&new_wallet)
                    .get_result(&mut conn)
                    .map_err(AppError::DieselError)
            }
            Err(e) => Err(AppError::DieselError(e)),
        }
    }

    fn get_controller_details(
        &self,
        find_user: &str,
    ) -> Result<Option<ControllerSessionInfo>, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        let wallet = user_wallet
            .filter(user_id.eq(find_user))
            .first::<UserWallet>(&mut conn)
            .optional()
            .map_err(AppError::DieselError)?;

        match wallet {
            Some(wallet) => match &wallet.controller_info {
                Some(session_data) => {
                    let controller_session_details: ControllerSessionInfo =
                        serde_json::from_str(&session_data).map_err(|e| {
                            log::error!("Failed to deserialize session data: {}", e);
                            AppError::SerializationError(e.to_string())
                        })?;
                println!("Controller info for user {}: {:?}", find_user, &wallet.controller_info);

                    Ok(Some(controller_session_details))
                }
                None => {
                    log::debug!("No controller info found for user: {}", find_user);
                    Ok(None)
                }
            },
            None => {
                log::debug!("No wallet found for user: {}", find_user);
                Ok(None)
            }
        }
        
    }

    fn is_controller_session_valid(&self, find_user: &str) -> Result<bool, AppError> {
        let controller_details = self.get_controller_details(find_user)?;

        match controller_details {
            Some(info) => {
                let current_time = Utc::now().timestamp();
                Ok(info.session_expires_at as i64 > current_time)
            }
            None => Ok(false),
        }
    }

    fn clear_controller_session(&self, find_user: &str) -> Result<UserWallet, AppError> {
        let mut conn = self.conn().map_err(AppError::DbConnectionError)?;

        diesel::update(user_wallet.filter(user_id.eq(find_user)))
            .set((
                controller_info.eq(None::<String>),
                updated_at.eq(Some(Utc::now())),
            ))
            .get_result(&mut conn)
            .map_err(AppError::DieselError)
    }
}
