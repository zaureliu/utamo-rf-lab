CREATE TABLE IF NOT EXISTS proxmark_runtime_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_version TEXT,
    firmware_version TEXT,
    bootrom_version TEXT,
    source_command TEXT,
    raw_excerpt TEXT,
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pm3_versions_time ON proxmark_runtime_versions(observed_at);
