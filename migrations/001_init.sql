-- Mirror of NVD. `raw` keeps the untouched cve object so reprocessing never needs a refetch.
CREATE TABLE cves (
  id             TEXT PRIMARY KEY,
  published      TEXT NOT NULL,
  last_modified  TEXT NOT NULL,
  vuln_status    TEXT,
  description    TEXT,
  cvss_version   TEXT,
  cvss_score     REAL,
  cvss_severity  TEXT,
  cvss_vector    TEXT,
  cwes           TEXT,
  raw            TEXT NOT NULL,
  -- 1 when the row was created by KEV ingest ahead of NVD; NVD fills it in later.
  placeholder    INTEGER NOT NULL DEFAULT 0,
  first_seen     TEXT NOT NULL,
  updated_at     TEXT NOT NULL
);
CREATE INDEX cves_last_modified ON cves(last_modified);
CREATE INDEX cves_published     ON cves(published);

-- Flattened from configurations[].nodes[].cpeMatch[], vulnerable=true only.
CREATE TABLE cve_cpes (
  cve_id          TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
  part            TEXT NOT NULL,
  vendor          TEXT NOT NULL,
  product         TEXT NOT NULL,
  version         TEXT,
  criteria        TEXT NOT NULL,
  ver_start       TEXT,
  ver_start_incl  INTEGER,
  ver_end         TEXT,
  ver_end_incl    INTEGER
);
CREATE INDEX cve_cpes_vp  ON cve_cpes(vendor, product);
CREATE INDEX cve_cpes_cve ON cve_cpes(cve_id);

CREATE TABLE cve_refs (
  cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
  url    TEXT NOT NULL,
  tags   TEXT,
  PRIMARY KEY (cve_id, url)
);

CREATE TABLE kev (
  cve_id             TEXT PRIMARY KEY,
  vendor_project     TEXT,
  product            TEXT,
  vulnerability_name TEXT,
  date_added         TEXT,
  due_date           TEXT,
  short_description  TEXT,
  required_action    TEXT,
  known_ransomware   TEXT,
  forensic_triage    TEXT,
  notes              TEXT,
  cwes               TEXT,
  first_seen         TEXT NOT NULL
);

-- watches.toml is the source of truth; this is a cache for attribution + FK integrity.
CREATE TABLE watches (
  name        TEXT PRIMARY KEY,
  enabled     INTEGER NOT NULL DEFAULT 1,
  definition  TEXT NOT NULL,
  def_hash    TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE matches (
  id               INTEGER PRIMARY KEY,
  watch_name       TEXT NOT NULL REFERENCES watches(name) ON DELETE CASCADE,
  cve_id           TEXT NOT NULL,
  match_kind       TEXT NOT NULL,
  confidence       TEXT NOT NULL,
  evidence         TEXT NOT NULL,
  first_matched_at TEXT NOT NULL,
  muted            INTEGER NOT NULL DEFAULT 0,
  UNIQUE (watch_name, cve_id)
);
CREATE INDEX matches_cve ON matches(cve_id);

-- Durable outbox. The UNIQUE constraint is the idempotency guarantee: a crash mid-send
-- can neither lose an alert nor deliver it twice.
CREATE TABLE notifications (
  id                INTEGER PRIMARY KEY,
  match_id          INTEGER NOT NULL REFERENCES matches(id) ON DELETE CASCADE,
  channel           TEXT NOT NULL,
  event_kind        TEXT NOT NULL,
  event_fingerprint TEXT NOT NULL,
  payload           TEXT NOT NULL,
  state             TEXT NOT NULL DEFAULT 'pending',
  attempts          INTEGER NOT NULL DEFAULT 0,
  next_attempt_at   TEXT,
  last_error        TEXT,
  created_at        TEXT NOT NULL,
  sent_at           TEXT,
  UNIQUE (match_id, channel, event_fingerprint)
);
CREATE INDEX notif_pending ON notifications(state, next_attempt_at);

CREATE TABLE sync_state (
  source       TEXT PRIMARY KEY,
  cursor       TEXT,
  extra        TEXT,
  last_success TEXT,
  last_error   TEXT,
  last_attempt TEXT
);
