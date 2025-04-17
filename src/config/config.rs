#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_maxage: i32,
    pub ip_info_token: String,
    pub paystack_secret_key: String,
    pub paystack_public_key: String,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRES_IN").expect("JWT_EXPIRES_IN must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");
        let ip_info_token = std::env::var("IP_INFO_TOKEN").expect("IP_INFO_TOKEN must be set");
        let paystack_secret_key = std::env::var("PAYSTACK_SECRET_KEY").expect("PAYSTACK_SECRET_KEY must be set");
        let paystack_public_key = std::env::var("PAYSTACK_PUBLIC_KEY").expect("PAYSTACK_PUBLIC_KEY must be set");

        Config {
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_maxage: jwt_maxage.parse::<i32>().unwrap(),
            ip_info_token,
            paystack_secret_key,
            paystack_public_key
        }
    }
}

unsafe impl Send for Config {}
unsafe impl Sync for Config {}
