-- Initial schema for sevorix-hub

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username    VARCHAR(64) UNIQUE NOT NULL,
    email       VARCHAR(255),
    password_hash TEXT NOT NULL,
    is_admin    BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE artifacts (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(128) NOT NULL,
    version     VARCHAR(64) NOT NULL,
    description TEXT,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    file_path   TEXT NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    downloads   INTEGER NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT artifacts_name_version_unique UNIQUE(name, version)
);

CREATE INDEX artifacts_name_idx ON artifacts(name);
CREATE INDEX artifacts_owner_idx ON artifacts(owner_id);
CREATE INDEX artifacts_tags_idx ON artifacts USING GIN(tags);
