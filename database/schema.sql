CREATE TABLE IF NOT EXISTS analyses (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    analyzed_at TEXT NOT NULL,
    md5 TEXT NOT NULL,
    sha1 TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    sha512 TEXT NOT NULL,
    result_json TEXT NOT NULL,
    report_path TEXT,
    risk_level TEXT NOT NULL DEFAULT 'UNKNOWN',
    anomaly_count_high INTEGER DEFAULT 0,
    anomaly_count_medium INTEGER DEFAULT 0,
    anomaly_count_low INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS comparisons (
    id TEXT PRIMARY KEY,
    compared_at TEXT NOT NULL,
    analysis_ids TEXT NOT NULL,
    result_json TEXT NOT NULL,
    report_path TEXT
);

CREATE INDEX IF NOT EXISTS idx_analyses_analyzed_at ON analyses(analyzed_at DESC);
CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256);
CREATE INDEX IF NOT EXISTS idx_analyses_risk_level ON analyses(risk_level);
