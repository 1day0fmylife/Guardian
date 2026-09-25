ALTER TABLE wireguard_peers ADD COLUMN reconcile_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE wireguard_peers ADD COLUMN applied_revision BIGINT NOT NULL DEFAULT 0;
ALTER TABLE wireguard_peers ADD COLUMN reconcile_error TEXT NOT NULL DEFAULT '';
ALTER TABLE wireguard_peers ADD COLUMN reconciled_at TEXT;
