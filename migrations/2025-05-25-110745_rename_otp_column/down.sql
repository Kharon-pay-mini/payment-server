-- This file should undo anything in `up.sql`
ALTER TABLE
    otp RENAME COLUMN otp_code TO otp;