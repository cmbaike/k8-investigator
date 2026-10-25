import json
import os
from typing import Any

from dotenv import load_dotenv
import psycopg

load_dotenv()


def record_tool_execution(
    *,
    tool_call_id: str,
    request_id: str | None,
    tool_name: str,
    arguments: dict[str, Any],
    risk: str | None,
    policy_status: str,
    execution_status: str,
    duration_ms: float,
    output_bytes: int | None,
    error_type: str | None,
    error_message: str | None,
) -> None:
    with psycopg.connect(os.environ["DATABASE_URL"]) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO tool_execution_audit (
                    tool_call_id,
                    request_id,
                    tool_name,
                    arguments,
                    risk,
                    policy_status,
                    execution_status,
                    duration_ms,
                    output_bytes,
                    error_type,
                    error_message
                )
                VALUES (
                    %s, %s, %s, %s::jsonb, %s, %s, %s,
                    %s, %s, %s, %s
                )
                """,
                (
                    tool_call_id,
                    request_id,
                    tool_name,
                    json.dumps(arguments),
                    risk,
                    policy_status,
                    execution_status,
                    duration_ms,
                    output_bytes,
                    error_type,
                    error_message,
                ),
            )
