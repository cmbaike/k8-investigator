CREATE TABLE IF NOT EXISTS ask_audit (
    id BIGSERIAL PRIMARY KEY,
    request_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    question TEXT NOT NULL,

    status TEXT NOT NULL
        CHECK (
            status IN (
                'answered',
                'insufficient_evidence',
                'error'
            )
        ),

    answer TEXT,

    sufficient BOOLEAN,

    source_labels JSONB NOT NULL DEFAULT '[]'::jsonb,

    model TEXT,

    error_type TEXT
);

CREATE INDEX IF NOT EXISTS
    idx_ask_audit_created_at
ON ask_audit (created_at DESC);

CREATE INDEX IF NOT EXISTS
    idx_ask_audit_status
ON ask_audit (status);
