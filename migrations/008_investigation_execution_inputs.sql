ALTER TABLE investigations
    ADD COLUMN user_text TEXT,
    ADD COLUMN max_steps INTEGER;

ALTER TABLE investigations
    ADD CONSTRAINT investigations_user_text_valid
    CHECK (
        user_text IS NULL
        OR (
            length(user_text) BETWEEN 1 AND 4000
        )
    );

ALTER TABLE investigations
    ADD CONSTRAINT investigations_max_steps_valid
    CHECK (
        max_steps IS NULL
        OR max_steps BETWEEN 1 AND 10
    );

ALTER TABLE investigations
    ADD CONSTRAINT investigations_execution_inputs_together
    CHECK (
        (user_text IS NULL AND max_steps IS NULL)
        OR
        (user_text IS NOT NULL AND max_steps IS NOT NULL)
    );
