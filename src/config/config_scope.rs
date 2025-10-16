use actix_web::web;

use crate::routes::routes::{
    confirm_disburse_payment_handler, create_session_handler, fetch_banks_handler, flutterwave_webhook_handler, get_controller_balance_handler, get_controller_handler, get_transaction_status_handler, get_usd_ngn_rate_handler, health, health_check, init_offramp_transaction, receive_payment_handler
};

pub fn config(conf: &mut web::ServiceConfig) {
    let scope = web::scope("/api/v1")
        .service(fetch_banks_handler)
        .service(init_offramp_transaction)
        .service(confirm_disburse_payment_handler)
        .service(get_usd_ngn_rate_handler)
        .service(flutterwave_webhook_handler)
        .service(create_session_handler)
        .service(receive_payment_handler)
        .service(get_controller_handler)
        .service(get_controller_balance_handler)
        .service(get_transaction_status_handler)
        .service(health_check)
        .service(health);

    conf.service(scope);
}
