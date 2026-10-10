CREATE INDEX IF NOT EXISTS idx_device_telemetry_retention ON device_telemetry(observed_at, id);
