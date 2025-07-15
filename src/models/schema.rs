// @generated automatically by Diesel CLI.

diesel::table! {
    otp (otp_id) {
        otp_id -> Uuid,
        otp_code -> Int4,
        #[max_length = 50]
        user_id -> Varchar,
        created_at -> Timestamptz,
        expires_at -> Timestamptz,
    }
}

diesel::table! {
    session_controller_info (id) {
        id -> Uuid,
        #[max_length = 50]
        user_id -> Varchar,
        #[max_length = 50]
        username -> Varchar,
        #[max_length = 64]
        controller_address -> Varchar,
        session_policies -> Jsonb,
        session_expires_at -> Int8,
        user_permissions -> Array<Nullable<Text>>,
        created_at -> Timestamptz,
        last_used_at -> Timestamptz,
        is_deployed -> Bool,
    }
}

diesel::table! {
    transactions (tx_id) {
        tx_id -> Uuid,
        #[max_length = 50]
        user_id -> Varchar,
        #[max_length = 10]
        order_type -> Varchar,
        crypto_amount -> Numeric,
        #[max_length = 10]
        crypto_type -> Varchar,
        fiat_amount -> Numeric,
        #[max_length = 20]
        fiat_currency -> Varchar,
        #[max_length = 20]
        payment_method -> Varchar,
        #[max_length = 20]
        payment_status -> Varchar,
        #[max_length = 250]
        tx_hash -> Varchar,
        #[max_length = 250]
        reference -> Varchar,
        #[max_length = 20]
        settlement_status -> Nullable<Varchar>,
        #[max_length = 250]
        transaction_reference -> Nullable<Varchar>,
        settlement_date -> Nullable<Timestamptz>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_bank_account (id) {
        id -> Uuid,
        #[max_length = 50]
        user_id -> Varchar,
        #[max_length = 255]
        bank_name -> Varchar,
        #[max_length = 50]
        account_number -> Varchar,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_security_logs (log_id) {
        log_id -> Uuid,
        #[max_length = 50]
        user_id -> Varchar,
        #[max_length = 50]
        ip_address -> Varchar,
        #[max_length = 50]
        city -> Varchar,
        #[max_length = 50]
        country -> Varchar,
        failed_login_attempts -> Int4,
        flagged_for_review -> Bool,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    user_wallet (id) {
        #[max_length = 50]
        id -> Varchar,
        #[max_length = 50]
        user_id -> Varchar,
        #[max_length = 100]
        wallet_address -> Nullable<Varchar>,
        #[max_length = 50]
        network_used_last -> Nullable<Varchar>,
        controller_info -> Nullable<Text>,
        created_at -> Nullable<Timestamptz>,
        updated_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    users (id) {
        #[max_length = 50]
        id -> Varchar,
        #[max_length = 255]
        email -> Varchar,
        #[max_length = 20]
        phone -> Nullable<Varchar>,
        last_logged_in -> Nullable<Timestamptz>,
        verified -> Bool,
        #[max_length = 10]
        role -> Varchar,
        created_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(otp -> users (user_id));
diesel::joinable!(session_controller_info -> users (user_id));
diesel::joinable!(transactions -> users (user_id));
diesel::joinable!(user_bank_account -> users (user_id));
diesel::joinable!(user_security_logs -> users (user_id));
diesel::joinable!(user_wallet -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    otp,
    session_controller_info,
    transactions,
    user_bank_account,
    user_security_logs,
    user_wallet,
    users,
);
