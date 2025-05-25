-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS user_wallet (
    id UUID NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wallet_address VARCHAR(100) UNIQUE,
    network_used_last VARCHAR(50),
    -- wallet_balance DECIMAL(18,8) NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);