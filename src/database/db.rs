use crate::database::{
    otp_db::OtpImpl, transaction_db::TransactionImpl, user_db::UserImpl,
    user_security_log_db::UserSecurityLogsImpl, user_wallet_db::UserWalletImpl,
};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, PooledConnection};
use dotenv::dotenv;

pub type DBPool = r2d2::Pool<ConnectionManager<PgConnection>>;

#[derive(Clone)]
pub struct Database {
    pub pool: DBPool,
}

impl Database {
    pub fn new() -> Self {
        dotenv().ok();
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

        let manager = ConnectionManager::<PgConnection>::new(database_url);

        let result = r2d2::Pool::builder()
            .build(manager)
            .expect("Failed to create pool.");

        Database { pool: result }
    }
}

pub trait DbAccess {
    fn conn(&self) -> PooledConnection<ConnectionManager<PgConnection>>;
}

impl DbAccess for Database {
    fn conn(&self) -> PooledConnection<ConnectionManager<PgConnection>> {
        self.pool.get().expect("Failed to get DB connection")
    }
}

impl UserWalletImpl for Database {}
impl UserImpl for Database {}
impl OtpImpl for Database {}
impl TransactionImpl for Database {}
impl UserSecurityLogsImpl for Database {}
