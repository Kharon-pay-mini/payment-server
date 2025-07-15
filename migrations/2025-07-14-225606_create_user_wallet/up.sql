-- Your SQL goes here
-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS user_wallet (
    id VARCHAR(50) NOT NULL PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id VARCHAR(50) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wallet_address VARCHAR(100) UNIQUE,
    network_used_last VARCHAR(50),
    controller_info TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);