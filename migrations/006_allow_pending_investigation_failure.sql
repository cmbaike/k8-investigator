ALTER TABLE investigations
DROP CONSTRAINT investigations_lifecycle_consistent;

ALTER TABLE investigations
ADD CONSTRAINT investigations_lifecycle_consistent
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
        AND finished_at IS NOT NULL
        AND stop_reason IS NOT NULL
        AND report IS NULL
    )
);
