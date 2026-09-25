CREATE TABLE IF NOT EXISTS address_lease_history (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    address TEXT NOT NULL,
    allocated_at TEXT NOT NULL,
    released_at TEXT NOT NULL,
    release_reason TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_address_lease_history_pool_address
    ON address_lease_history(pool_id, address, released_at);
CREATE INDEX IF NOT EXISTS idx_address_lease_history_device
    ON address_lease_history(device_id, released_at);

INSERT INTO address_lease_history(
    id, pool_id, device_id, address, allocated_at, released_at, release_reason
)
SELECT id, pool_id, device_id, address, allocated_at, COALESCE(released_at, allocated_at), 'legacy_release'
FROM address_leases
WHERE status = 'released'
ON CONFLICT(id) DO NOTHING;

DELETE FROM address_leases WHERE status = 'released';
