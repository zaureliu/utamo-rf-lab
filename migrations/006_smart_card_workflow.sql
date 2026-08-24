CREATE TABLE IF NOT EXISTS smart_scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    progress INTEGER NOT NULL DEFAULT 0,
    uid TEXT,
    family TEXT,
    card_type TEXT,
    acquisition_status TEXT,
    dump_id INTEGER REFERENCES rfid_card_dumps(id) ON DELETE SET NULL,
    error TEXT,
    options_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT NOT NULL DEFAULT '{}',
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS smart_scan_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL REFERENCES smart_scan_jobs(id) ON DELETE CASCADE,
    step_index INTEGER NOT NULL,
    stage TEXT NOT NULL,
    command TEXT NOT NULL,
    status TEXT NOT NULL,
    output TEXT,
    output_excerpt TEXT,
    parsed_json TEXT NOT NULL DEFAULT '{}',
    started_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(job_id, step_index)
);
CREATE INDEX IF NOT EXISTS idx_smart_scan_status ON smart_scan_jobs(status, updated_at);
CREATE INDEX IF NOT EXISTS idx_smart_scan_uid ON smart_scan_jobs(uid);
CREATE INDEX IF NOT EXISTS idx_smart_steps_job ON smart_scan_steps(job_id, step_index);
