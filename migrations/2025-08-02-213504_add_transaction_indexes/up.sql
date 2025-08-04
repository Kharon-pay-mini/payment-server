-- Your SQL goes here
CREATE INDEX idx_transactions_user_reference ON transactions(user_id, reference);