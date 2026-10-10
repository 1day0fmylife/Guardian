-- G-01: versioned service catalog, per-scope grants and device scope membership.
-- Access is deny-by-default: the three seeded services are disabled and no grants exist.

CREATE TABLE IF NOT EXISTS service_policy_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL,
    updated_at TEXT NOT NULL
);

INSERT INTO service_policy_state(id, revision, updated_at)
VALUES(1, 1, '2026-10-10T00:00:00Z');

CREATE TABLE IF NOT EXISTS service_definitions (
    id TEXT PRIMARY KEY,
    current_revision BIGINT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS service_definition_revisions (
    service_id TEXT NOT NULL REFERENCES service_definitions(id),
    revision BIGINT NOT NULL,
    display_name TEXT NOT NULL,
    internal_dns_name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL,
    tls_policy TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    created_by_user_id TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY (service_id, revision)
);

CREATE TABLE IF NOT EXISTS service_grants (
    id TEXT PRIMARY KEY,
    service_id TEXT NOT NULL REFERENCES service_definitions(id),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'site', 'group', 'device')),
    scope_id TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
    policy_revision BIGINT NOT NULL,
    created_by_user_id TEXT REFERENCES users(id),
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by_user_id TEXT REFERENCES users(id),
    revoked_policy_revision BIGINT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_service_grants_active
    ON service_grants(service_id, scope_type, scope_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_service_grants_scope ON service_grants(scope_type, scope_id);

CREATE TABLE IF NOT EXISTS device_scope_memberships (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'site', 'group')),
    scope_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (device_id, scope_type, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_device_scope_memberships_scope ON device_scope_memberships(scope_type, scope_id);

INSERT INTO service_definitions(id, current_revision, created_at, updated_at) VALUES
    ('sunkardav', 1, '2026-10-10T00:00:00Z', '2026-10-10T00:00:00Z'),
    ('admiral-device', 1, '2026-10-10T00:00:00Z', '2026-10-10T00:00:00Z'),
    ('sunkarcwmp-acs', 1, '2026-10-10T00:00:00Z', '2026-10-10T00:00:00Z');

INSERT INTO service_definition_revisions(
    service_id, revision, display_name, internal_dns_name, protocol, port,
    tls_policy, allowed_scopes, enabled, created_at
) VALUES
    ('sunkardav', 1, 'SunkarDAV', 'dav.internal', 'https', 443, 'required', 'tenant,site,group,device', 0, '2026-10-10T00:00:00Z'),
    ('admiral-device', 1, 'Admiral device API', 'fleet.internal', 'https', 443, 'required', 'tenant,site,group,device', 0, '2026-10-10T00:00:00Z'),
    ('sunkarcwmp-acs', 1, 'SunkarCWMP ACS', 'acs.internal', 'https', 443, 'required', 'tenant,site,group,device', 0, '2026-10-10T00:00:00Z')
