use super::db::DbAccess;
use crate::models::models::{NewUser, User};
use crate::models::schema::users::dsl::*;
use diesel::prelude::*;
use diesel::sql_types::Text;

diesel::define_sql_function! {
    fn lower(x: Text) -> Text;
}

pub trait UserImpl: DbAccess {
    fn get_users(&self) -> Option<Vec<User>> {
        users.load::<User>(&mut self.conn()).ok()
    }

    fn get_user_by_email(&self, find_email: String) -> Option<User> {
        users
            .filter(lower(email).eq(lower(find_email)))
            .first::<User>(&mut self.conn())
            .ok()
    }

    fn get_user_by_id(&self, find_id: uuid::Uuid) -> Option<User> {
        users.find(find_id).first::<User>(&mut self.conn()).ok()
    }

    fn get_user_by_phone(&self, find_phone: String) -> Option<User> {
        users
            .filter(phone.eq(find_phone))
            .first::<User>(&mut self.conn())
            .ok()
    }

    fn create_user(&self, user: NewUser) -> Result<User, diesel::result::Error> {
        diesel::insert_into(users)
            .values(&user)
            .get_result(&mut self.conn())
    }
}
