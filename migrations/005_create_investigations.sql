CREATE TABLE IF NOT EXISTS investigations (
    investigation_id TEXT PRIMARY KEY,

    authorized_namespace TEXT NOT NULL
        CHECK (length(authorized_namespace) > 0),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (
            status IN (
                'pending',
                'running',
                'completed',
                'failed'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,

    stop_reason TEXT,

    report JSONB,

    CONSTRAINT investigations_id_nonempty
        CHECK (length(investigation_id) > 0),

    CONSTRAINT investigations_lifecycle_consistent
        CHECK (
            (
                status = 'pending'
                AND started_at IS NULL
                AND finished_at IS NULL
                AND stop_reason IS NULL
                AND report IS NULL
            )
            OR
            (
                status = 'running'
                AND started_at IS NOT NULL
                AND finished_at IS NULL
                AND stop_reason IS NULL
                AND report IS NULL
            )
            OR
            (
                status = 'completed'
                AND started_at IS NOT NULL
                AND finished_at IS NOT NULL
                AND report IS NOT NULL
            )
            OR
            (
                status = 'failed'
                AND started_at IS NOT NULL
                AND finished_at IS NOT NULL
                AND report IS NULL
            )
        )
);

CREATE INDEX IF NOT EXISTS idx_investigations_namespace_created
    ON investigations (authorized_namespace, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_investigations_status
    ON investigations (status);