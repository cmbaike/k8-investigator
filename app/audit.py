import json
import os
from uuid import UUID

import psycopg
from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.environ["DATABASE_URL"]


def write_ask_audit(
    *,
    request_id: UUID | str,
    question: str,
    status: str,
    answer: str | None,
    sufficient: bool | None,
    source_labels: list[str],
    model: str | None,
    error_type: str | None = None,
    retrieval_ms: float | None = None,
    sufficiency_ms: float | None = None,
    generation_ms: float | None = None,
    total_ms: float | None = None,
) -> None:
    """
    Persist one completed /ask request.

    Audit writes are intentionally synchronous. Callers may treat an
    audit-write failure as a request failure rather than silently returning
    an unaudited result.
    """

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ask_audit (
                    request_id,
                    question,
                    status,
                    answer,
                    sufficient,
                    source_labels,
                    model,
                    error_type,
                    retrieval_ms,
                    sufficiency_ms,
                    generation_ms,
                    total_ms
                )
                VALUES (
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s::jsonb,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s,
                    %s
                )
                """,
                (
                    str(request_id),
                    question,
                    status,
                    answer,
                    sufficient,
                    json.dumps(source_labels),
                    model,
                    error_type,
                    retrieval_ms,
                    sufficiency_ms,
                    generation_ms,
                    total_ms,
                ),
            )

        conn.commit()
