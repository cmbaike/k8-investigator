-- One row per on-demand resource health request.
-- Internal Kubernetes reads made for that request are not stored separately.
-- No event messages, logs, environment values, or credentials.
CREATE TABLE IF NOT EXISTS resource_health_checks (
    id BIGSERIAL PRIMARY KEY,
    check_id UUID NOT NULL UNIQUE,
    principal_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    resource_uid TEXT,
    category TEXT,
    status TEXT NOT NULL,
    error_code TEXT,
    discovered INTEGER,
    examined INTEGER,
    coverage_complete BOOLEAN,
    observed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_resource_health_checks_principal
    ON resource_health_checks (principal_id, observed_at DESC);
