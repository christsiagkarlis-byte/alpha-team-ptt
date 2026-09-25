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

CREATE TABLE IF NOT EXISTS user_locations (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    latitude      NUMERIC(9, 6) NOT NULL,
    longitude     NUMERIC(9, 6) NOT NULL,
    accuracy_m    NUMERIC(10, 2),
    captured_at   TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT user_locations_latitude_check CHECK (latitude BETWEEN -90 AND 90),
    CONSTRAINT user_locations_longitude_check CHECK (longitude BETWEEN -180 AND 180),
    CONSTRAINT user_locations_accuracy_check CHECK (accuracy_m IS NULL OR accuracy_m >= 0)
);

CREATE INDEX IF NOT EXISTS user_locations_updated_idx ON user_locations (updated_at DESC);

CREATE TABLE IF NOT EXISTS incident_events (
    id            BIGSERIAL PRIMARY KEY,
    code          VARCHAR(32) NOT NULL,
    description   TEXT NOT NULL,
    username      VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE RESTRICT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    latitude      NUMERIC(9, 6),
    longitude     NUMERIC(9, 6),
    accuracy_m    NUMERIC(10, 2),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT incident_latitude_check CHECK (latitude IS NULL OR latitude BETWEEN -90 AND 90),
    CONSTRAINT incident_longitude_check CHECK (longitude IS NULL OR longitude BETWEEN -180 AND 180),
    CONSTRAINT incident_accuracy_check CHECK (accuracy_m IS NULL OR accuracy_m >= 0)
);

CREATE INDEX IF NOT EXISTS incident_events_created_idx ON incident_events (created_at DESC);
CREATE INDEX IF NOT EXISTS incident_events_username_idx ON incident_events (username, created_at DESC);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key   VARCHAR(64) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_credentials (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    pin_hash      TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE OR REPLACE FUNCTION set_credentials_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS credentials_updated_at_trigger ON user_credentials;
CREATE TRIGGER credentials_updated_at_trigger
BEFORE UPDATE ON user_credentials
FOR EACH ROW EXECUTE FUNCTION set_credentials_updated_at();

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


-- Alpha_Team_Intercom security operations extension.
CREATE TABLE IF NOT EXISTS security_incidents (
    id BIGSERIAL PRIMARY KEY,
    incident_type VARCHAR(32) NOT NULL DEFAULT 'incident',
    title VARCHAR(160) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity VARCHAR(16) NOT NULL DEFAULT 'medium',
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    source VARCHAR(24) NOT NULL DEFAULT 'manual',
    reported_by VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE RESTRICT,
    assigned_to VARCHAR(32) REFERENCES users(username) ON DELETE SET NULL,
    latitude NUMERIC(9,6), longitude NUMERIC(9,6), accuracy_m NUMERIC(10,2),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), resolved_at TIMESTAMPTZ,
    CONSTRAINT security_incident_severity CHECK (severity IN ('low','medium','high','critical')),
    CONSTRAINT security_incident_status CHECK (status IN ('open','acknowledged','in_progress','resolved','cancelled')),
    CONSTRAINT security_incident_type CHECK (incident_type IN ('incident','sos','panic','geofence','checkpoint')),
    CONSTRAINT security_incident_location CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180))
);
CREATE INDEX IF NOT EXISTS security_incidents_status_idx ON security_incidents(status, created_at DESC);
CREATE INDEX IF NOT EXISTS security_incidents_reporter_idx ON security_incidents(reported_by, created_at DESC);

CREATE TABLE IF NOT EXISTS security_shifts (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    site VARCHAR(160) NOT NULL DEFAULT '',
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    supervisor VARCHAR(32) REFERENCES users(username) ON DELETE SET NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'scheduled',
    notes TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT security_shift_status CHECK (status IN ('scheduled','active','completed','cancelled')),
    CONSTRAINT security_shift_times CHECK (ends_at > starts_at)
);
CREATE TABLE IF NOT EXISTS security_shift_members (
    shift_id BIGINT REFERENCES security_shifts(id) ON DELETE CASCADE,
    username VARCHAR(32) REFERENCES users(username) ON DELETE CASCADE,
    checked_in_at TIMESTAMPTZ,
    checked_out_at TIMESTAMPTZ,
    PRIMARY KEY (shift_id, username)
);
CREATE INDEX IF NOT EXISTS security_shifts_time_idx ON security_shifts(starts_at, ends_at);

CREATE TABLE IF NOT EXISTS security_checkpoints (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    site VARCHAR(160) NOT NULL DEFAULT '',
    latitude NUMERIC(9,6) NOT NULL, longitude NUMERIC(9,6) NOT NULL,
    radius_m NUMERIC(10,2) NOT NULL DEFAULT 75,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(32) REFERENCES users(username) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT checkpoint_radius CHECK (radius_m > 0 AND radius_m <= 10000)
);
CREATE TABLE IF NOT EXISTS security_checkpoint_scans (
    id BIGSERIAL PRIMARY KEY,
    checkpoint_id BIGINT REFERENCES security_checkpoints(id) ON DELETE CASCADE,
    username VARCHAR(32) REFERENCES users(username) ON DELETE RESTRICT,
    latitude NUMERIC(9,6), longitude NUMERIC(9,6), distance_m NUMERIC(10,2),
    scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS checkpoint_scans_time_idx ON security_checkpoint_scans(scanned_at DESC);

CREATE TABLE IF NOT EXISTS security_geofences (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    center_latitude NUMERIC(9,6) NOT NULL, center_longitude NUMERIC(9,6) NOT NULL,
    radius_m NUMERIC(10,2) NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by VARCHAR(32) REFERENCES users(username) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT geofence_radius CHECK (radius_m > 0 AND radius_m <= 100000)
);
CREATE TABLE IF NOT EXISTS security_geofence_events (
    id BIGSERIAL PRIMARY KEY,
    geofence_id BIGINT REFERENCES security_geofences(id) ON DELETE CASCADE,
    username VARCHAR(32) REFERENCES users(username) ON DELETE RESTRICT,
    event_type VARCHAR(16) NOT NULL,
    latitude NUMERIC(9,6), longitude NUMERIC(9,6), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT geofence_event_type CHECK (event_type IN ('entry','exit'))
);
CREATE TABLE IF NOT EXISTS security_notifications (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(32) REFERENCES users(username) ON DELETE CASCADE,
    title VARCHAR(160) NOT NULL, message TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'info', read_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS security_notifications_user_idx ON security_notifications(username, created_at DESC);


-- Phase 1 hardening: passkeys, push subscriptions, and revocable sessions.
ALTER TABLE users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS user_passkeys (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports JSONB NOT NULL DEFAULT '[]'::JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS user_passkeys_user_idx ON user_passkeys(user_id);
CREATE TABLE IF NOT EXISTS push_subscriptions (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint TEXT NOT NULL UNIQUE,
    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- Phase 2: consented live tracking and route history for field guards.
CREATE TABLE IF NOT EXISTS tracking_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stopped_at TIMESTAMPTZ,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    consent_text VARCHAR(240) NOT NULL DEFAULT 'User enabled live GPS tracking'
);
CREATE UNIQUE INDEX IF NOT EXISTS tracking_sessions_active_user_idx ON tracking_sessions(user_id) WHERE active=TRUE;
CREATE INDEX IF NOT EXISTS tracking_sessions_time_idx ON tracking_sessions(started_at DESC);
CREATE TABLE IF NOT EXISTS location_history (
    id BIGSERIAL PRIMARY KEY,
    tracking_session_id BIGINT REFERENCES tracking_sessions(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    latitude NUMERIC(9,6) NOT NULL,
    longitude NUMERIC(9,6) NOT NULL,
    accuracy_m NUMERIC(10,2),
    speed_mps NUMERIC(10,2),
    heading_deg NUMERIC(7,2),
    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS location_history_user_time_idx ON location_history(username, captured_at DESC);
CREATE INDEX IF NOT EXISTS location_history_session_time_idx ON location_history(tracking_session_id, captured_at ASC);

-- Operational safety: wellbeing check-ins, SOS acknowledgement/escalation, and emergency mode.
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMPTZ;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS first_response_at TIMESTAMPTZ;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS escalated_at TIMESTAMPTZ;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS escalation_level INTEGER NOT NULL DEFAULT 0;
ALTER TABLE security_incidents ADD COLUMN IF NOT EXISTS last_escalation_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS security_incidents_escalation_idx ON security_incidents(incident_type, status, escalation_level, created_at);

CREATE TABLE IF NOT EXISTS wellbeing_checkins (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    latitude NUMERIC(9,6), longitude NUMERIC(9,6), accuracy_m NUMERIC(10,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT wellbeing_location CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180))
);
CREATE INDEX IF NOT EXISTS wellbeing_checkins_user_time_idx ON wellbeing_checkins(username, created_at DESC);

CREATE TABLE IF NOT EXISTS emergency_modes (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(160) NOT NULL,
    message TEXT NOT NULL,
    severity VARCHAR(16) NOT NULL DEFAULT 'critical',
    active BOOLEAN NOT NULL DEFAULT TRUE,
    activated_by VARCHAR(32) NOT NULL REFERENCES users(username) ON DELETE RESTRICT,
    activated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ended_at TIMESTAMPTZ,
    ended_by VARCHAR(32) REFERENCES users(username) ON DELETE SET NULL,
    CONSTRAINT emergency_mode_severity CHECK (severity IN ('high','critical'))
);
CREATE UNIQUE INDEX IF NOT EXISTS emergency_modes_one_active_idx ON emergency_modes(active) WHERE active=TRUE;
CREATE INDEX IF NOT EXISTS emergency_modes_time_idx ON emergency_modes(activated_at DESC);
COMMIT;


-- Phase 3 hardening: canonical geo/radius bounds, cursor indexes, and retention support.
-- This migration is idempotent and can be re-run after taking a verified backup.
BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'users_session_version_check') THEN
        ALTER TABLE users ADD CONSTRAINT users_session_version_check CHECK (session_version >= 0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'user_locations_accuracy_max_check') THEN
        ALTER TABLE user_locations ADD CONSTRAINT user_locations_accuracy_max_check CHECK (accuracy_m IS NULL OR accuracy_m <= 100000);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_events_location_pair_check') THEN
        ALTER TABLE incident_events ADD CONSTRAINT incident_events_location_pair_check CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude IS NOT NULL AND longitude IS NOT NULL));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'incident_events_accuracy_max_check') THEN
        ALTER TABLE incident_events ADD CONSTRAINT incident_events_accuracy_max_check CHECK (accuracy_m IS NULL OR (accuracy_m >= 0 AND accuracy_m <= 100000));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_incidents_accuracy_check') THEN
        ALTER TABLE security_incidents ADD CONSTRAINT security_incidents_accuracy_check CHECK (accuracy_m IS NULL OR (accuracy_m >= 0 AND accuracy_m <= 100000));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_checkpoints_location_check') THEN
        ALTER TABLE security_checkpoints ADD CONSTRAINT security_checkpoints_location_check CHECK (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkpoint_scans_location_check') THEN
        ALTER TABLE security_checkpoint_scans ADD CONSTRAINT checkpoint_scans_location_check CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'checkpoint_scans_distance_check') THEN
        ALTER TABLE security_checkpoint_scans ADD CONSTRAINT checkpoint_scans_distance_check CHECK (distance_m IS NULL OR distance_m >= 0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'security_geofences_center_check') THEN
        ALTER TABLE security_geofences ADD CONSTRAINT security_geofences_center_check CHECK (center_latitude BETWEEN -90 AND 90 AND center_longitude BETWEEN -180 AND 180);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'geofence_events_location_check') THEN
        ALTER TABLE security_geofence_events ADD CONSTRAINT geofence_events_location_check CHECK ((latitude IS NULL AND longitude IS NULL) OR (latitude BETWEEN -90 AND 90 AND longitude BETWEEN -180 AND 180));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'location_history_accuracy_check') THEN
        ALTER TABLE location_history ADD CONSTRAINT location_history_accuracy_check CHECK (accuracy_m IS NULL OR (accuracy_m >= 0 AND accuracy_m <= 100000));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'location_history_speed_check') THEN
        ALTER TABLE location_history ADD CONSTRAINT location_history_speed_check CHECK (speed_mps IS NULL OR (speed_mps >= 0 AND speed_mps <= 150));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'location_history_heading_check') THEN
        ALTER TABLE location_history ADD CONSTRAINT location_history_heading_check CHECK (heading_deg IS NULL OR (heading_deg >= 0 AND heading_deg <= 360));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'wellbeing_checkins_accuracy_check') THEN
        ALTER TABLE wellbeing_checkins ADD CONSTRAINT wellbeing_checkins_accuracy_check CHECK (accuracy_m IS NULL OR (accuracy_m >= 0 AND accuracy_m <= 100000));
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS security_incidents_cursor_idx ON security_incidents (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS security_notifications_cursor_idx ON security_notifications (username, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS location_history_cursor_idx ON location_history (captured_at ASC, id ASC);
CREATE INDEX IF NOT EXISTS tracking_sessions_retention_idx ON tracking_sessions (stopped_at) WHERE stopped_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS user_locations_retention_idx ON user_locations (updated_at);
CREATE INDEX IF NOT EXISTS push_subscriptions_retention_idx ON push_subscriptions (last_seen_at);

COMMIT;
