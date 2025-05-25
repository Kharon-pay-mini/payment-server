-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS user_security_logs (
    log_id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_address VARCHAR(50) NOT NULL,
    city VARCHAR(50) NOT NULL,
    country VARCHAR(50) NOT NULL,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    flagged_for_review BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);