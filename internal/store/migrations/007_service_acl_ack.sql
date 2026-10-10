-- A revoked peer's address cannot be reused until its deny policy reached nft.
ALTER TABLE wireguard_peers ADD COLUMN service_revocation_revision BIGINT NOT NULL DEFAULT 0;
CREATE TABLE service_acl_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    required INTEGER NOT NULL DEFAULT 0,
    applied_revision BIGINT NOT NULL DEFAULT 0
);
INSERT INTO service_acl_state(id, required, applied_revision) VALUES(1, 0, 0);
UPDATE wireguard_peers
SET service_revocation_revision = (SELECT revision FROM service_policy_state WHERE id = 1)
WHERE desired_state = 'revoked' AND device_id IN (SELECT id FROM devices WHERE status = 'revoking');
