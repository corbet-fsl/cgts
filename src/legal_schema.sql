CREATE TABLE clbs_orders (
    community_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject TEXT NOT NULL,
    reference TEXT NOT NULL,
    entered_by TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('legal', 'self_ban')),
    authority TEXT,
    scope TEXT NOT NULL,
    starts_at INTEGER NOT NULL CHECK (starts_at >= 0),
    ends_at INTEGER CHECK (ends_at > starts_at),
    PRIMARY KEY (community_id, id),
    CHECK ((kind = 'legal' AND authority IS NOT NULL) OR
           (kind = 'self_ban' AND authority IS NULL AND ends_at IS NULL
            AND entered_by = subject AND scope = '"All"'))
) WITHOUT ROWID;
CREATE INDEX clbs_subject_period ON clbs_orders (community_id, subject, starts_at, ends_at);
CREATE INDEX clbs_period ON clbs_orders (community_id, starts_at, ends_at);
CREATE INDEX clbs_counts ON clbs_orders (community_id, kind, starts_at, ends_at);
