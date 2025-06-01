use actix_web::web;

use crate::routes::routes::{
    confirm_disburse_payment_handler, create_user_handler, fetch_banks_handler, flutterwave_webhook_handler, get_transaction_handler, get_usd_ngn_rate_handler, get_user_handler, get_user_logs_handler, get_wallet_handler, init_disburse_payment_handler, monnify_webhook_handler, request_otp_handler, update_transaction_handler, update_user_wallet_handler, validate_otp_handler, verify_bank_account_handler
};

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api")
        .service(create_user_handler)
        .service(update_user_wallet_handler)
        .service(update_transaction_handler)
        .service(request_otp_handler)
        .service(validate_otp_handler)
        .service(get_user_handler)
        .service(get_transaction_handler)
        .service(get_user_logs_handler)
        .service(get_wallet_handler)
        .service(fetch_banks_handler)
        .service(verify_bank_account_handler)
        .service(init_disburse_payment_handler)
        .service(confirm_disburse_payment_handler)
        .service(monnify_webhook_handler)
        .service(get_usd_ngn_rate_handler)
        .service(flutterwave_webhook_handler);

    conf.service(scope);
}
