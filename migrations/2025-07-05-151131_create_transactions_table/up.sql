-- Your SQL goes here
-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS transactions (
    tx_id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    order_type VARCHAR(10) NOT NULL,
    crypto_amount DECIMAL(18, 8) NOT NULL DEFAULT 0.0,
    crypto_type VARCHAR(10) NOT NULL,
    fiat_amount DECIMAL(18, 8) NOT NULL DEFAULT 0.0,
    fiat_currency VARCHAR(20) NOT NULL,
    payment_method VARCHAR(20) NOT NULL,
    payment_status VARCHAR(20) NOT NULL,
    tx_hash VARCHAR(250) UNIQUE NOT NULL,
    reference VARCHAR(250) UNIQUE NOT NULL,
    settlement_status VARCHAR(20) NULL,
    transaction_reference VARCHAR(250) UNIQUE NULL,
    settlement_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);