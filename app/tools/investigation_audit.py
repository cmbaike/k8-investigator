"""Durable PostgreSQL sink for investigation lifecycle audit events.

Each call is committed in its own transaction. Database errors propagate.
Do not use this writer for unredacted secrets or arbitrary model output.
"""

import json
import os
from uuid import uuid4

import psycopg
from dotenv import load_dotenv

from app.tools.orchestrator import InvestigationAuditEvent

load_dotenv()

MAX_ARGUMENTS_BYTES = 16_384
MAX_DETAIL_LENGTH = 2_048


def write_investigation_audit_event(event: InvestigationAuditEvent) -> None:
    """Persist one event or raise; never silently drop an event."""
    if event.phase not in {
        "proposed", "authorized", "rejected", "execution_started", "completed"
    }:
        raise ValueError(f"Unsupported investigation audit phase: {event.phase!r}")
    if not event.investigation_id or not event.request_id or not event.tool:
        raise ValueError("Investigation, request and tool identifiers are required.")

    # Only the known Kubernetes operational identifier keys are persisted.
    # This deliberately excludes unknown keys that could contain secrets.
    safe_arguments = {
        key: value
        for key, value in event.arguments.items()
        if key in {"namespace", "pod", "deployment", "container", "tail_lines"}
        and isinstance(value, (str, int))
        and not isinstance(value, bool)
    }
    encoded = json.dumps(safe_arguments, ensure_ascii=False, allow_nan=False)
    if len(encoded.encode("utf-8")) > MAX_ARGUMENTS_BYTES:
        raise ValueError("Investigation audit arguments exceed size limit.")
    # Details can contain exception strings from dependencies; avoid persisting
    # them verbatim. Store only a bounded classification in the database.
    detail = event.detail
    if detail is not None:
        detail = detail.split(":", 1)[0][:MAX_DETAIL_LENGTH]

    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO investigation_audit_events (
                    event_id, investigation_id, request_id, event_type,
                    tool_name, arguments, status, detail
                ) VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (
                    str(uuid4()), event.investigation_id, event.request_id,
                    event.phase, event.tool, encoded, event.status, detail,
                ),
            )
