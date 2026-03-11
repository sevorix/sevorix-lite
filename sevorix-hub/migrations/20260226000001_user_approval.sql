-- Add is_approved column to users for account approval workflow
-- New accounts require admin approval before users can push artifacts

ALTER TABLE users
    ADD COLUMN is_approved BOOLEAN NOT NULL DEFAULT true;

-- For existing databases, all current users are approved by default
-- New users will need approval (handled at registration time)

-- Create index for quick approval status lookups
CREATE INDEX users_is_approved_idx ON users(is_approved) WHERE is_approved = false;
