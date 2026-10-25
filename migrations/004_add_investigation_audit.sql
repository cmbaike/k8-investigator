-- Separate investigation lifecycle events from completed tool execution records.
-- TEXT IDs support existing investigation/request IDs (e.g. inv-001, req-1).
CREATE TABLE IF NOT EXISTS investigation_audit_events (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL UNIQUE,
    investigation_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    tool_call_id UUID,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'proposed', 'authorized', 'rejected', 'execution_started', 'completed'
    )),
    tool_name TEXT NOT NULL,
    arguments JSONB NOT NULL DEFAULT '{}'::jsonb,
    status TEXT NOT NULL,
    detail TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_investigation_audit_investigation
    ON investigation_audit_events (investigation_id, id);
CREATE INDEX IF NOT EXISTS idx_investigation_audit_request
    ON investigation_audit_events (request_id);
CREATE INDEX IF NOT EXISTS idx_investigation_audit_tool_call
    ON investigation_audit_events (tool_call_id);
