-- Make email required and unique, drop username field
-- This migration updates the user model to use email as the primary identifier

-- Backfill any legacy accounts that registered without an email.
-- Uses the user UUID as a unique placeholder so the NOT NULL + UNIQUE
-- constraints below can always succeed.  Affected users will need to
-- set a real email address on next login.
UPDATE users
    SET email = id::text || '@legacy.placeholder.invalid'
    WHERE email IS NULL;

-- Now safe to add NOT NULL
ALTER TABLE users
    ALTER COLUMN email SET NOT NULL;

-- Add unique constraint on email
ALTER TABLE users
    ADD CONSTRAINT users_email_unique UNIQUE(email);

-- Drop the username column
ALTER TABLE users
    DROP COLUMN username;
