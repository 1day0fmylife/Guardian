CREATE TABLE IF NOT EXISTS device_credentials (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at TEXT,
    expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_device_credentials_device ON device_credentials(device_id);
CREATE INDEX IF NOT EXISTS idx_device_credentials_token ON device_credentials(token_hash);

ALTER TABLE device_commands ADD COLUMN result TEXT NOT NULL DEFAULT '{}';
ALTER TABLE device_telemetry ADD COLUMN assigned_address TEXT NOT NULL DEFAULT '';
ALTER TABLE device_telemetry ADD COLUMN config_revision BIGINT NOT NULL DEFAULT 0;
