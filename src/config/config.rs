#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: String,
    pub jwt_maxage: i32,
    pub ip_info_token: String,
    pub paystack_secret_key: String,
    pub paystack_public_key: String,
    pub monnify_secret_key: String,
    pub monnify_api_key: String,
    pub monnify_wallet_account_number: String,
    pub monnify_contract_code: String,
    pub redis_url: String,
    pub port: String,
    pub hmac_secret: String,
    pub hmac_key: String,
    pub flutterwave_secret_key: String,
    pub flutterwave_payment_url: String,
    pub flutterwave_callback_url: String,
    pub flutterwave_secret_hash: String,
    pub flutterwave_test_key: String,
    pub flutterwave_test_secret_hash: String,
}

impl Config {
    pub fn init() -> Config {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let jwt_secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
        let jwt_expires_in = std::env::var("JWT_EXPIRES_IN").expect("JWT_EXPIRES_IN must be set");
        let jwt_maxage = std::env::var("JWT_MAXAGE").expect("JWT_MAXAGE must be set");
        let ip_info_token = std::env::var("IP_INFO_TOKEN").expect("IP_INFO_TOKEN must be set");
        let paystack_secret_key =
            std::env::var("PAYSTACK_SECRET_KEY").expect("PAYSTACK_SECRET_KEY must be set");
        let paystack_public_key =
            std::env::var("PAYSTACK_PUBLIC_KEY").expect("PAYSTACK_PUBLIC_KEY must be set");
        let monnify_secret_key =
            std::env::var("MONNIFY_SECRET_KEY").expect("MONNIFY_SECRET_KEY must be set");
        let monnify_api_key =
            std::env::var("MONNIFY_API_KEY").expect("MONNIFY_API_KEY must be set");
        let monnify_wallet_account_number = std::env::var("MONNIFY_WALLET_ACCOUNT_NUMBER")
            .expect("MONNIFY_WALLET_ACCOUNT_NUMBER must be set");
        let monnify_contract_code =
            std::env::var("MONNIFY_CONTRACT_CODE").expect("MONNIFY_CONTRACT_CODE must be set");
        let redis_url = std::env::var("REDIS_URL").expect("REDIS_URL must be set");
        let port = std::env::var("PORT").expect("PORT must be set");
        let hmac_secret = std::env::var("HMAC_SECRET").expect("HMAC_SECRET must be set");
        let hmac_key = std::env::var("HMAC_KEY").expect("HMAC_KEY must be set");
        let flutterwave_secret_key =
            std::env::var("FLUTTERWAVE_SECRET_KEY").expect("FLUTTERWAVE_SECRET_KEY must be set");
        let flutterwave_public_key =
            std::env::var("FLUTTERWAVE_PUBLIC_KEY").expect("FLUTTERWAVE_PUBLIC_KEY must be set");
        let flutterwave_payment_url =
            std::env::var("FLUTTERWAVE_PAYMENT_URL").expect("FLUTTERWAVE_PAYMENT_URL must be set");
        let flutterwave_callback_url = std::env::var("FLUTTERWAVE_CALLBACK_URL")
            .expect("FLUTTERWAVE_CALLBACK_URL must be set");
        let flutterwave_secret_hash = std::env::var("FLUTTERWAVE_SECRET_HASH")
            .expect("FLUTTERWAVE_SECRET_HASH must be set");
        let flutterwave_test_key =
            std::env::var("FLUTTERWAVE_TEST_SECRET_KEY").expect("FLUTTERWAVE_TEST_KEY must be set");
        let flutterwave_test_secret_hash =
            std::env::var("FLUTTERWAVE_TEST_SECRET_HASH").expect("FLUTTERWAVE_TEST_SECRET_HASH must be set");

        Config {
            database_url,
            jwt_secret,
            jwt_expires_in,
            jwt_maxage: jwt_maxage.parse::<i32>().unwrap(),
            ip_info_token,
            paystack_secret_key,
            paystack_public_key,
            monnify_secret_key,
            monnify_api_key,
            monnify_wallet_account_number,
            monnify_contract_code,
            redis_url,
            port,
            hmac_secret,
            hmac_key,
            flutterwave_secret_key,
            flutterwave_payment_url,
            flutterwave_callback_url,
            flutterwave_secret_hash,
            flutterwave_test_key,
            flutterwave_test_secret_hash,
        }
    }
}

unsafe impl Send for Config {}
unsafe impl Sync for Config {}
