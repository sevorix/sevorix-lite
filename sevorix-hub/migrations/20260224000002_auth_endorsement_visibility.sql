-- Add visibility column to artifacts
ALTER TABLE artifacts
    ADD COLUMN visibility VARCHAR(16) NOT NULL DEFAULT 'public';

-- Create enum-like constraint for visibility
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_visibility_check
    CHECK (visibility IN ('public', 'private', 'draft'));

-- Create endorsements table
CREATE TABLE endorsements (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    level       VARCHAR(32) NOT NULL DEFAULT 'verified',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT endorsements_artifact_user_unique UNIQUE(artifact_id, user_id)
);

-- Create index for endorsements lookups
CREATE INDEX endorsements_artifact_idx ON endorsements(artifact_id);
CREATE INDEX endorsements_user_idx ON endorsements(user_id);

-- Add constraint for endorsement levels
ALTER TABLE endorsements
    ADD CONSTRAINT endorsements_level_check
    CHECK (level IN ('verified', 'trusted_author', 'official'));

-- Add is_endorsed computed field to users (for badge display)
-- This is derived from having any endorsements
ALTER TABLE users
    ADD COLUMN is_endorsed BOOLEAN NOT NULL DEFAULT false;

-- Create function to update user endorsement status
CREATE OR REPLACE FUNCTION update_user_endorsement()
RETURNS TRIGGER AS $$
BEGIN
    -- Check if user has any endorsements
    UPDATE users
    SET is_endorsed = EXISTS (
        SELECT 1 FROM endorsements WHERE user_id = NEW.user_id
    )
    WHERE id = NEW.user_id;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update endorsement status on insert
CREATE TRIGGER endorsement_insert_trigger
    AFTER INSERT ON endorsements
    FOR EACH ROW
    EXECUTE FUNCTION update_user_endorsement();

-- Trigger to update endorsement status on delete
CREATE TRIGGER endorsement_delete_trigger
    AFTER DELETE ON endorsements
    FOR EACH ROW
    EXECUTE FUNCTION update_user_endorsement();
