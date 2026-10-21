-- VPN profile revisions with a retained previous server key/endpoint, and the
-- WireGuard public keys of revoked enrollments. Expand-only: the previous
-- release ignores these columns and keeps working on this schema (rollback of
-- the image without a database rollback). Portable across SQLite and PostgreSQL.
ALTER TABLE vpn_profiles ADD COLUMN revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE vpn_profiles ADD COLUMN previous_server_public_key TEXT NOT NULL DEFAULT '';
ALTER TABLE vpn_profiles ADD COLUMN previous_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE vpn_profiles ADD COLUMN previous_valid_until TEXT;
CREATE TABLE IF NOT EXISTS retired_wireguard_keys (
    public_key TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    retired_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wireguard_peers_profile ON wireguard_peers(profile_id);
