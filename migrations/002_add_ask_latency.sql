ALTER TABLE ask_audit
    ADD COLUMN IF NOT EXISTS retrieval_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS sufficiency_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS generation_ms DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS total_ms DOUBLE PRECISION;

ALTER TABLE ask_audit
    ADD CONSTRAINT ask_audit_retrieval_ms_nonnegative
        CHECK (retrieval_ms IS NULL OR retrieval_ms >= 0),
    ADD CONSTRAINT ask_audit_sufficiency_ms_nonnegative
        CHECK (sufficiency_ms IS NULL OR sufficiency_ms >= 0),
    ADD CONSTRAINT ask_audit_generation_ms_nonnegative
        CHECK (generation_ms IS NULL OR generation_ms >= 0),
    ADD CONSTRAINT ask_audit_total_ms_nonnegative
        CHECK (total_ms IS NULL OR total_ms >= 0);
