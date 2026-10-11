CREATE TABLE clbs_orders (
    community_id TEXT NOT NULL,
    id TEXT NOT NULL,
    subject TEXT NOT NULL,
    reference TEXT NOT NULL,
    entered_by TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('legal', 'self_ban')),
    authority TEXT,
    PRIMARY KEY (community_id, id),
    CHECK ((kind = 'legal' AND authority IS NOT NULL) OR
           (kind = 'self_ban' AND authority IS NULL AND entered_by = subject))
) WITHOUT ROWID;
CREATE INDEX clbs_subject ON clbs_orders (community_id, subject, id);
CREATE INDEX clbs_counts ON clbs_orders (community_id, kind);
