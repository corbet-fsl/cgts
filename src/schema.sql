CREATE TABLE cgts_results (
    community_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    gate TEXT NOT NULL,
    provider TEXT NOT NULL,
    valid_until INTEGER NOT NULL CHECK (valid_until > 0 AND valid_until % 86400 = 0),
    PRIMARY KEY (community_id, subject, gate, provider)
) WITHOUT ROWID;
CREATE TABLE cgts_spent (
    community_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    marker BLOB NOT NULL,
    PRIMARY KEY (community_id, domain, marker)
) WITHOUT ROWID;
