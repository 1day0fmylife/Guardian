-- Existing immutable revisions remain unchanged and disabled by default.
ALTER TABLE service_definition_revisions ADD COLUMN connection_request TEXT NOT NULL DEFAULT '';
