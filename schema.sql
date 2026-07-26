CREATE TABLE IF NOT EXISTS reflections (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    scripture TEXT,
    youtube_url TEXT,
    music_url TEXT,
    posted_by TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    expires_at TEXT DEFAULT (datetime('now', '+24 hours'))
);

CREATE TABLE IF NOT EXISTS reflection_reads (
    id TEXT PRIMARY KEY,
    student_id TEXT NOT NULL,
    reflection_id TEXT NOT NULL,
    read_at TEXT DEFAULT (datetime('now')),
    listened INTEGER DEFAULT 0,
    prayed INTEGER DEFAULT 0,
    UNIQUE(student_id, reflection_id)
);