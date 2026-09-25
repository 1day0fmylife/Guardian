CREATE TABLE IF NOT EXISTS system_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    system INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    device_uuid TEXT NOT NULL UNIQUE,
    serial_number TEXT NOT NULL DEFAULT '',
    primary_mac TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending',
    suspended INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS device_identities (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(kind, value)
);

CREATE INDEX IF NOT EXISTS idx_device_identities_device ON device_identities(device_id);

CREATE TABLE IF NOT EXISTS address_pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    cidr TEXT NOT NULL,
    gateway TEXT NOT NULL DEFAULT '',
    dns_servers TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vpn_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    server_public_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0',
    dns_servers TEXT NOT NULL DEFAULT '',
    persistent_keepalive INTEGER NOT NULL DEFAULT 25,
    address_pool_id TEXT NOT NULL REFERENCES address_pools(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS address_leases (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES address_pools(id),
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    allocated_at TEXT NOT NULL,
    released_at TEXT,
    UNIQUE(pool_id, address),
    UNIQUE(pool_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_address_leases_device ON address_leases(device_id);

CREATE TABLE IF NOT EXISTS wireguard_peers (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL UNIQUE REFERENCES devices(id) ON DELETE CASCADE,
    profile_id TEXT NOT NULL REFERENCES vpn_profiles(id),
    public_key TEXT NOT NULL UNIQUE,
    assigned_address TEXT NOT NULL,
    desired_state TEXT NOT NULL DEFAULT 'connected',
    observed_state TEXT NOT NULL DEFAULT 'unknown',
    config_revision BIGINT NOT NULL DEFAULT 1,
    revoked_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_wireguard_peers_profile ON wireguard_peers(profile_id);

CREATE TABLE IF NOT EXISTS enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    profile_id TEXT NOT NULL REFERENCES vpn_profiles(id),
    bound_device_uuid TEXT NOT NULL DEFAULT '',
    bound_serial_number TEXT NOT NULL DEFAULT '',
    bound_mac TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    consumed_at TEXT,
    revoked_at TEXT,
    created_by_user_id TEXT REFERENCES users(id),
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_expiry ON enrollment_tokens(expires_at);

CREATE TABLE IF NOT EXISTS device_commands (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    idempotency_key TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    delivered_at TEXT,
    acknowledged_at TEXT,
    finished_at TEXT,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_commands_pending ON device_commands(device_id, status, created_at);

CREATE TABLE IF NOT EXISTS device_telemetry (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    observed_at TEXT NOT NULL,
    tunnel_state TEXT NOT NULL DEFAULT 'unknown',
    latest_handshake_at TEXT,
    endpoint TEXT NOT NULL DEFAULT '',
    rx_bytes BIGINT NOT NULL DEFAULT 0,
    tx_bytes BIGINT NOT NULL DEFAULT 0,
    tunnel_uptime_seconds BIGINT NOT NULL DEFAULT 0,
    latency_ms BIGINT,
    arlanphone_version TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    wireguard_version TEXT NOT NULL DEFAULT '',
    error_code TEXT NOT NULL DEFAULT '',
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_device_telemetry_device_time ON device_telemetry(device_id, observed_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor_user_id TEXT REFERENCES users(id),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created ON audit_events(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_events_resource ON audit_events(resource_type, resource_id);
