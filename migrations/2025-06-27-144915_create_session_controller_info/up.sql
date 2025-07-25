-- Your SQL goes here
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS session_controller_info (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id TEXT NOT NULL,
    username VARCHAR(50) NOT NULL,
    controller_address VARCHAR(64) NOT NULL,
    session_policies JSONB NOT NULL,
    session_expires_at BIGINT NOT NULL,
    user_permissions TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_deployed BOOLEAN NOT NULL DEFAULT FALSE
);

ALTER TABLE session_controller_info
ADD CONSTRAINT IF NOT EXISTS session_controller_info_user_id_fkey
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;