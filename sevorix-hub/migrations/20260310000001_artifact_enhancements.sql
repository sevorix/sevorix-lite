-- Add artifact quality columns: checksums, signing, type, yanking
-- All nullable or defaulted so existing rows are unaffected.

ALTER TABLE artifacts ADD COLUMN content_hash    VARCHAR(64);
ALTER TABLE artifacts ADD COLUMN content_schema  TEXT;
ALTER TABLE artifacts ADD COLUMN signature       TEXT;
ALTER TABLE artifacts ADD COLUMN key_fingerprint VARCHAR(64);
ALTER TABLE artifacts ADD COLUMN artifact_type   VARCHAR(16) NOT NULL DEFAULT 'artifact';
ALTER TABLE artifacts ADD CONSTRAINT artifacts_type_check CHECK (artifact_type IN ('artifact', 'set'));
ALTER TABLE artifacts ADD COLUMN yanked          BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE artifacts ADD COLUMN yanked_reason   TEXT;
ALTER TABLE artifacts ADD COLUMN denied_pulls    INTEGER NOT NULL DEFAULT 0;
