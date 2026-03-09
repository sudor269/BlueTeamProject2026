CREATE TABLE IF NOT EXISTS hosts (
    id SERIAL PRIMARY KEY,
    hostname TEXT UNIQUE NOT NULL,
    last_seen TIMESTAMPTZ,
    status TEXT DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS policy (
    id INTEGER PRIMARY KEY DEFAULT 1,
    version INTEGER NOT NULL DEFAULT 1,
    audit_only BOOLEAN NOT NULL DEFAULT FALSE,
    default_allow_if_no_serial BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO policy (id, version, audit_only, default_allow_if_no_serial)
VALUES (1, 1, FALSE, FALSE)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS devices (
    id SERIAL PRIMARY KEY,
    hash_hex CHAR(16) UNIQUE NOT NULL,
    serial_normalized TEXT,
    comment TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    host TEXT,
    action TEXT NOT NULL,
    reason TEXT,
    hash_hex CHAR(16),
    serial_normalized TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);