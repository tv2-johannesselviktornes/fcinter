-- D1 schema for native supporter-club signup form.
-- Apply with: wrangler d1 execute <database-name> --file=d1/schema.sql --remote

CREATE TABLE IF NOT EXISTS signups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  birth_date TEXT NOT NULL, -- ISO 8601 date (YYYY-MM-DD)
  membership_type TEXT NOT NULL, -- 'junior' (0-12 aar) or 'senior', derived from birth_date
  address TEXT NOT NULL,
  consent INTEGER NOT NULL DEFAULT 0,
  ip_hash TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- One signup per email address.
CREATE UNIQUE INDEX IF NOT EXISTS idx_signups_email ON signups(email);
CREATE INDEX IF NOT EXISTS idx_signups_created_at ON signups(created_at);

-- Fixed-window IP rate limiting, keyed by hashed IP + window bucket.
-- No raw IP addresses are stored (see functions/api/signup.js).
CREATE TABLE IF NOT EXISTS rate_limits (
  ip_hash TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (ip_hash, window_start)
);
