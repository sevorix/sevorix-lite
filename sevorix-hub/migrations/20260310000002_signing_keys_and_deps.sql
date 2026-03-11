-- Create user_signing_keys and artifact_dependencies tables

CREATE TABLE user_signing_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    fingerprint VARCHAR(64) NOT NULL UNIQUE,
    label       VARCHAR(128),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at  TIMESTAMPTZ
);
CREATE INDEX signing_keys_user_idx        ON user_signing_keys(user_id);
CREATE INDEX signing_keys_fingerprint_idx ON user_signing_keys(fingerprint);

CREATE TABLE artifact_dependencies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id  UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    dep_name     VARCHAR(128) NOT NULL,
    dep_version  VARCHAR(64) NOT NULL,
    dep_required BOOLEAN NOT NULL DEFAULT true
);
CREATE INDEX artifact_deps_artifact_idx ON artifact_dependencies(artifact_id);
CREATE INDEX artifact_deps_dep_idx      ON artifact_dependencies(dep_name, dep_version);
