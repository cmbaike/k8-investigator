"""One audit row per health-check request.

Internal Kubernetes reads made while answering that request are not separate
rows. The row stores identifiers and fixed codes only: no event messages, no
logs, no environment values, and no API keys.
"""

import os
from uuid import uuid4

import psycopg
from dotenv import load_dotenv

from app.health.types import HealthAuditRecord

load_dotenv()

_STATUSES = frozenset(
    {
        "recorded",
        "not_found",
        "namespace_denied",
        "permission_denied",
        "unsupported_kind",
        "invalid_name",
        "observation_failed",
    }
)


def write_health_audit(record: HealthAuditRecord) -> None:
    status = record.status if record.status in _STATUSES else "observation_failed"
    category = record.category if record.category in {"healthy", "degraded", "unhealthy", "unknown"} else None
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO resource_health_checks (
                    check_id, principal_id, namespace, kind, name, resource_uid,
                    category, status, error_code, discovered, examined, coverage_complete
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid4()),
                    record.principal_id,
                    record.namespace,
                    record.kind,
                    record.name,
                    record.resource_uid,
                    category,
                    status,
                    record.error_code,
                    record.discovered,
                    record.examined,
                    record.coverage_complete,
                ),
            )
        conn.commit()
