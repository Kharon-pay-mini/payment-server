use actix_web::{web, HttpResponse};
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager};
use dotenv::dotenv;

use crate::models::models::{self, NewUser, Otp, Transaction, User, UserSecurityLog, UserWallet};
use crate::models::schema::{
    otp::dsl::*, transactions::dsl::*, user_security_logs::dsl::*, user_wallet::dsl::*,
    users::dsl::*,
};

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

    pub fn get_users(&self) -> Vec<User> {
        users
            .load::<User>(&mut self.pool.get().unwrap())
            .expect("Failed to get users.")
    }

    pub fn create_user(&self, user: NewUser) -> Result<User, diesel::result::Error> {
        diesel::insert_into(users)
            .values(&user)
            .get_result(&mut self.pool.get().unwrap())
    }
}
