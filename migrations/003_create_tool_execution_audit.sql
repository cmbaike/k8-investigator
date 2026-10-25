CREATE TABLE IF NOT EXISTS tool_execution_audit (
    id BIGSERIAL PRIMARY KEY,
    tool_call_id UUID NOT NULL UNIQUE,
    request_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    tool_name TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,

    risk TEXT,
    policy_status TEXT NOT NULL,
    execution_status TEXT NOT NULL,

    duration_ms DOUBLE PRECISION NOT NULL
        CHECK (duration_ms >= 0),

    output_bytes BIGINT
        CHECK (output_bytes IS NULL OR output_bytes >= 0),

    error_type TEXT,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_tool_execution_audit_request_id
    ON tool_execution_audit (request_id);

CREATE INDEX IF NOT EXISTS idx_tool_execution_audit_created_at
    ON tool_execution_audit (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tool_execution_audit_tool_name
    ON tool_execution_audit (tool_name);

CREATE INDEX IF NOT EXISTS idx_tool_execution_audit_execution_status
    ON tool_execution_audit (execution_status);
