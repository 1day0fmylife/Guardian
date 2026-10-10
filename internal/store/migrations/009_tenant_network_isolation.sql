-- Site/group identifiers are global and have one immutable tenant owner.
-- Empty tenant denotes the existing standalone namespace.
CREATE TABLE scope_owners (
    scope_type TEXT NOT NULL CHECK (scope_type IN ('site', 'group')),
    scope_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    PRIMARY KEY (scope_type, scope_id)
);
INSERT INTO scope_owners(scope_type, scope_id, tenant_id)
SELECT m.scope_type, m.scope_id, MIN(COALESCE(t.scope_id, ''))
FROM device_scope_memberships m
LEFT JOIN device_scope_memberships t ON t.device_id = m.device_id AND t.scope_type = 'tenant'
WHERE m.scope_type IN ('site', 'group')
GROUP BY m.scope_type, m.scope_id;

CREATE UNIQUE INDEX idx_device_single_tenant ON device_scope_memberships(device_id) WHERE scope_type = 'tenant';
CREATE UNIQUE INDEX idx_device_single_site ON device_scope_memberships(device_id) WHERE scope_type = 'site';
CREATE UNIQUE INDEX idx_address_leases_global_active ON address_leases(address) WHERE status IN ('active', 'revoking');

-- One row serializes pool validation/creation on both database dialects.
CREATE TABLE network_allocation_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    revision BIGINT NOT NULL
);
INSERT INTO network_allocation_state(id, revision) VALUES (1, 1);
