BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(32) NOT NULL UNIQUE,
    role            VARCHAR(16) NOT NULL DEFAULT 'user',
    hardware_uuid   VARCHAR(255) DEFAULT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT users_role_check CHECK (role IN ('leader', 'admin', 'user')),
    CONSTRAINT users_username_check CHECK (username ~ '^[A-Za-z][A-Za-z-]{1,31}$')
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_idx ON users (username);
CREATE UNIQUE INDEX IF NOT EXISTS users_hardware_uuid_idx
    ON users (hardware_uuid)
    WHERE hardware_uuid IS NOT NULL;
CREATE INDEX IF NOT EXISTS users_active_idx ON users (is_active);

CREATE TABLE IF NOT EXISTS activation_tokens (
    id              BIGSERIAL PRIMARY KEY,
    jti             UUID NOT NULL UNIQUE,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    issued_by       VARCHAR(128) NOT NULL,
    CONSTRAINT activation_expiry_check CHECK (expires_at > issued_at),
    CONSTRAINT activation_use_check CHECK (used_at IS NULL OR used_at >= issued_at)
);

CREATE INDEX IF NOT EXISTS activation_tokens_user_idx ON activation_tokens (user_id, expires_at);
CREATE INDEX IF NOT EXISTS activation_tokens_expiry_idx ON activation_tokens (expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    username        VARCHAR(32),
    user_id         INTEGER REFERENCES users(id) ON DELETE SET NULL,
    request_id      UUID,
    ip_address      INET,
    metadata        JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_events_user_idx ON audit_events (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_created_idx ON audit_events (created_at DESC);

CREATE OR REPLACE FUNCTION set_users_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_updated_at_trigger ON users;
CREATE TRIGGER users_updated_at_trigger
BEFORE UPDATE ON users
FOR EACH ROW EXECUTE FUNCTION set_users_updated_at();

-- Exactly 31 predefined profiles: 26 base identities plus five security roles.
INSERT INTO users (username, role) VALUES
    ('ALFA', 'leader'),
    ('Bravo', 'user'),
    ('Charlie', 'user'),
    ('Delta', 'user'),
    ('Echo', 'user'),
    ('Foxtrot', 'user'),
    ('Golf', 'user'),
    ('Hotel', 'user'),
    ('India', 'user'),
    ('Juliet', 'user'),
    ('Kilo', 'user'),
    ('Lima', 'user'),
    ('Mike', 'user'),
    ('November', 'user'),
    ('Oscar', 'user'),
    ('Papa', 'user'),
    ('Romeo', 'user'),
    ('Quadec', 'user'),
    ('Sierra', 'user'),
    ('Tango', 'user'),
    ('Uniform', 'user'),
    ('Victor', 'user'),
    ('Whisky', 'user'),
    ('X-ray', 'user'),
    ('Yankee', 'user'),
    ('Zulu', 'user'),
    ('Sentinel', 'user'),
    ('Patrol', 'user'),
    ('Response', 'user'),
    ('Guardian', 'user'),
    ('Control', 'admin')
ON CONFLICT (username) DO UPDATE SET
    role = EXCLUDED.role,
    is_active = TRUE;

COMMIT;
