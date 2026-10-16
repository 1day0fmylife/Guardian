-- Human-account password lifecycle. Portable across SQLite and PostgreSQL.
-- must_change_password gates every API except password change, /me and logout
-- until the user replaces an administrator-issued or bootstrap password.
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN password_changed_at TEXT;
CREATE INDEX IF NOT EXISTS idx_users_created ON users(created_at);
