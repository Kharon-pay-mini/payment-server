-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS otp (
    otp_id UUID PRIMARY KEY DEFAULT (uuid_generate_v4()),
    otp_code INT NOT NULL DEFAULT 0 CHECK (
        otp_code BETWEEN 100000
        AND 999999
    ),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '15 minutes')
);