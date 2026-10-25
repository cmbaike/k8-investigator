ALTER TABLE investigations
    ADD COLUMN lease_token UUID,
    ADD COLUMN lease_expires_at TIMESTAMPTZ;

ALTER TABLE investigations
    ADD CONSTRAINT investigations_lease_consistent
    CHECK (
        (lease_token IS NULL AND lease_expires_at IS NULL)
        OR
        (
            status = 'running'
            AND lease_token IS NOT NULL
            AND lease_expires_at IS NOT NULL
        )
    );

CREATE INDEX idx_investigations_expired_leases
    ON investigations (lease_expires_at)
    WHERE status = 'running';
