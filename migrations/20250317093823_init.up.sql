-- Add up migration script here
-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE "users" (
    id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(20) UNIQUE,
    password VARCHAR(100) NOT NULL,
    photo VARCHAR(50) NOT NULL DEFAULT 'default.png',
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE "user_wallet" (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wallet_address VARCHAR(100) UNIQUE,
    network VARCHAR(50),
    -- wallet_balance DECIMAL(18,8) NOT NULL DEFAULT 0.0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE "transactions" (
    tx_id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    order_type ENUM('buy', 'sell', 'swap') NOT NULL,
    crypto_amount DECIMAL(18,8) NOT NULL DEFAULT 0.0,
    crypto_type ENUM('USDT', 'USDC'),
    fiat_amount DECIMAL(18,8) NOT NULL DEFAULT 0.0,
    fiat_currency VARCHAR(20),
    payment_method ENUM('bank_transfer', 'crypto', 'card'),
    payment_status ENUM('pending', 'completed', 'failed'),
    tx_hash VARCHAR(250) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE "user_security_logs" (
    log_id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(50),
    city VARCHAR(50),
    country VARCHAR(50),
    failed_login_attempts INT NOT NULL DEFAULT 0,
    flagged_for_review BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_logged_in TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);


CREATE INDEX users_email_idx ON users (email);
CREATE INDEX users_phone_idx ON users (phone);
CREATE INDEX user_wallet_idx ON user_wallet(user_id);
CREATE INDEX user_tx_idx ON transactions(user_id);
CREATE INDEX tx_created_at_idx ON transactions(created_at);
CREATE INDEX user_security_logs_idx ON user_security_logs(user_id);
CREATE INDEX user_security_logs_flagged ON user_security_logs(flagged_for_review);