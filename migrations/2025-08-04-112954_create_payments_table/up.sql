

-- Your SQL goes here
-- Create payments table for indexer
CREATE TABLE IF NOT EXISTS payments (
    id SERIAL PRIMARY KEY,
    event_id TEXT NOT NULL,
    block_number BIGINT NOT NULL,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    transaction_hash TEXT NOT NULL,
    sender TEXT NOT NULL,
    token TEXT NOT NULL,
    amount TEXT NOT NULL,
    reference TEXT NOT NULL,
    status TEXT NOT NULL
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_payments_block_number ON payments(block_number);
CREATE INDEX IF NOT EXISTS idx_payments_sender ON payments(sender);