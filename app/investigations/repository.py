"""PostgreSQL persistence for investigation lifecycle records."""

import json
import os

import psycopg
from psycopg.rows import dict_row

from uuid import UUID, uuid4
from app.investigations.models import InvestigationRecord
from app.reports.models import InvestigationReport


class InvestigationTransitionError(RuntimeError):
    """The requested lifecycle transition was not permitted."""


class InvestigationRepository:
    def __init__(
        self,
        database_url: str | None = None,
        *,
        connect_timeout_seconds: int = 5,
        statement_timeout_ms: int = 5000,
        lock_timeout_ms: int = 2000,
    ):
     if connect_timeout_seconds < 1:
        raise ValueError("Connection timeout must be positive.")

     if statement_timeout_ms < 1:
        raise ValueError("Statement timeout must be positive.")

     if lock_timeout_ms < 1:
        raise ValueError("Lock timeout must be positive.")

     self.database_url = database_url or os.environ["DATABASE_URL"]

     self.connect_timeout_seconds = connect_timeout_seconds
     self.statement_timeout_ms = statement_timeout_ms
     self.lock_timeout_ms = lock_timeout_ms
     
    def _connect(self, *, row_factory=None):
          kwargs = {
           "connect_timeout": self.connect_timeout_seconds,
           "options": (
             f"-c statement_timeout={self.statement_timeout_ms} "
             f"-c lock_timeout={self.lock_timeout_ms}"
             ),
        }

          if row_factory is not None:
              kwargs["row_factory"] = row_factory

          return psycopg.connect(self.database_url, **kwargs)

    def create_investigation(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        user_text: str | None = None,
        max_steps: int | None = None,
    ) -> InvestigationRecord:
        if not investigation_id or not authorized_namespace:
            raise ValueError("Investigation ID and namespace are required.")
        
        if (user_text is None) != (max_steps is None):
            raise ValueError("Investigation execution inputs must be supplied together.")
        
        if user_text is not None:
            if not isinstance(user_text, str) or not 1 <= len(user_text) <= 4000:
                raise ValueError("Invalid investigation question.")
            
            if type(max_steps) is not int or not 1 <= max_steps <= 10:
                raise ValueError("Invalid investigation step budget.")

        with psycopg.connect(self.database_url, row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO investigations (
                        investigation_id,
                        authorized_namespace,
                        status,
                        user_text,
                        max_steps
                    )
                    VALUES (%s, %s, 'pending', %s, %s)
                    RETURNING
                        investigation_id,
                        authorized_namespace,
                        status,
                        created_at,
                        started_at,
                        finished_at,
                        stop_reason,
                        user_text,
                        max_steps
                    """,
                    (investigation_id, authorized_namespace, user_text, max_steps),
                )
                row = cur.fetchone()

        return InvestigationRecord.model_validate(row)

    def get_investigation(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
    ) -> InvestigationRecord | None:
        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        investigation_id,
                        authorized_namespace,
                        status,
                        created_at,
                        started_at,
                        finished_at,
                        stop_reason,
                        user_text,
                        max_steps
                    FROM investigations
                    WHERE investigation_id = %s
                      AND authorized_namespace = %s
                    """,
                    (investigation_id, authorized_namespace),
                )
                row = cur.fetchone()

        return InvestigationRecord.model_validate(row) if row else None

    def start_investigation(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
    ) -> InvestigationRecord:
        return self._transition(
            investigation_id=investigation_id,
            authorized_namespace=authorized_namespace,
            sql="""
                UPDATE investigations
                SET status = 'running',
                    started_at = NOW()
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'pending'
                RETURNING
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
            """,
        )

    def complete_investigation(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        report: InvestigationReport,
        stop_reason: str,
    ) -> InvestigationRecord:
        if report.investigation_id != investigation_id:
            raise ValueError("Report investigation ID does not match.")

        if not stop_reason:
            raise ValueError("Stop reason is required.")

        report_json = json.dumps(
            report.model_dump(mode="json"),
            allow_nan=False,
        )

        return self._transition(
            investigation_id=investigation_id,
            authorized_namespace=authorized_namespace,
            sql="""
                UPDATE investigations
                SET status = 'completed',
                    finished_at = NOW(),
                    stop_reason = %s,
                    report = %s::jsonb
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'running'
                  AND lease_token IS NULL
                RETURNING
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
            """,
            prefix_params=(stop_reason, report_json),
        )

    def fail_investigation(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        stop_reason: str,
    ) -> InvestigationRecord:
        if not stop_reason:
            raise ValueError("Stop reason is required.")

        return self._transition(
            investigation_id=investigation_id,
            authorized_namespace=authorized_namespace,
            sql="""
                UPDATE investigations
                SET status = 'failed',
                    finished_at = NOW(),
                    stop_reason = %s
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status IN ('pending', 'running')
                  AND lease_token IS NULL
                RETURNING
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
            """,
            prefix_params=(stop_reason,),
        )

    def get_report(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
    ) -> InvestigationReport | None:
        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT report
                    FROM investigations
                    WHERE investigation_id = %s
                      AND authorized_namespace = %s
                      AND status = 'completed'
                    """,
                    (investigation_id, authorized_namespace),
                )
                row = cur.fetchone()

        if row is None or row["report"] is None:
            return None

        return InvestigationReport.model_validate(row["report"])
    
    def start_investigation_with_lease(
      self,
      *,
      investigation_id: str,
      authorized_namespace: str,
      lease_seconds: int = 120,
    ) -> UUID:
     if not 1 <= lease_seconds <= 3600:
        raise ValueError("Lease duration must be between 1 and 3600 seconds.")

     token = uuid4()

     with self._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET status = 'running',
                    started_at = NOW(),
                    lease_token = %s::uuid,
                    lease_expires_at =
                        NOW() + (%s * INTERVAL '1 second')
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'pending'
                RETURNING investigation_id
                """,
                (
                    str(token),
                    lease_seconds,
                    investigation_id,
                    authorized_namespace,
                ),
            )

            if cur.fetchone() is None:
                raise InvestigationTransitionError(
                    "Investigation cannot acquire an execution lease."
                )

     return token

    
    def renew_investigation_lease(
       self,
       *,
       investigation_id: str,
       authorized_namespace: str,
       lease_token: UUID,
       lease_seconds: int = 120,
    ) -> None:
      if not 1 <= lease_seconds <= 3600:
        raise ValueError("Lease duration must be between 1 and 3600 seconds.")

      with self._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET lease_expires_at =
                    NOW() + (%s * INTERVAL '1 second')
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'running'
                  AND lease_token = %s::uuid
                  AND lease_expires_at > NOW()
                RETURNING investigation_id
                """,
                (
                    lease_seconds,
                    investigation_id,
                    authorized_namespace,
                    str(lease_token),
                ),
            )

            if cur.fetchone() is None:
                raise InvestigationTransitionError(
                    "Investigation lease is missing, expired, or not owned."
                )
                
    def complete_investigation_with_lease(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        lease_token: UUID,
        report: InvestigationReport,
        stop_reason: str,
    ) -> InvestigationRecord:
     if report.investigation_id != investigation_id:
        raise ValueError("Report investigation ID does not match.")

     if not stop_reason:
        raise ValueError("Stop reason is required.")

     report_json = json.dumps(
        report.model_dump(mode="json"),
        allow_nan=False,
     )

     with self._connect(row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET status = 'completed',
                    finished_at = NOW(),
                    stop_reason = %s,
                    report = %s::jsonb,
                    lease_token = NULL,
                    lease_expires_at = NULL
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'running'
                  AND lease_token = %s::uuid
                  AND lease_expires_at > NOW()
                RETURNING
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
                """,
                (
                    stop_reason,
                    report_json,
                    investigation_id,
                    authorized_namespace,
                    str(lease_token),
                ),
            )

            row = cur.fetchone()

            if row is None:
                raise InvestigationTransitionError(
                    "Investigation completion rejected: lease is not valid."
                )

     return InvestigationRecord.model_validate(row)
 
    
    def fail_expired_investigations(self) -> int:
     """Fail abandoned leased runs; never affect unexpired runs."""

     with self._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET status = 'failed',
                    finished_at = NOW(),
                    stop_reason = 'execution_lease_expired',
                    lease_token = NULL,
                    lease_expires_at = NULL
                WHERE status = 'running'
                  AND lease_token IS NOT NULL
                  AND lease_expires_at <= NOW()
                RETURNING investigation_id
                """
            )

            return len(cur.fetchall())
        
    def fail_investigation_with_lease(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        lease_token: UUID,
        stop_reason: str,
    ) -> InvestigationRecord:
      if not stop_reason:
        raise ValueError("Stop reason is required.")

      with self._connect(row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET status = 'failed',
                    finished_at = NOW(),
                    stop_reason = %s,
                    lease_token = NULL,
                    lease_expires_at = NULL
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'running'
                  AND lease_token = %s::uuid
                  AND lease_expires_at > NOW()
                RETURNING
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
                """,
                (
                    stop_reason,
                    investigation_id,
                    authorized_namespace,
                    str(lease_token),
                ),
            )

            row = cur.fetchone()

            if row is None:
                raise InvestigationTransitionError(
                    "Investigation failure rejected: lease is not valid."
                )

      return InvestigationRecord.model_validate(row)
  
    def assert_investigation_lease(
       self,
       *,
       investigation_id: str,
       authorized_namespace: str,
       lease_token: UUID,
    ) -> None:
     """Verify current execution ownership using PostgreSQL's clock."""
     with self._connect() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 1
                FROM investigations
                WHERE investigation_id = %s
                  AND authorized_namespace = %s
                  AND status = 'running'
                  AND lease_token = %s::uuid
                  AND lease_expires_at > NOW()
                """,
                (
                    investigation_id,
                    authorized_namespace,
                    str(lease_token),
                ),
            )

            if cur.fetchone() is None:
                raise InvestigationTransitionError(
                    "Investigation execution lease is not valid."
                )
                
    def get_investigation_for_namespaces(
        self,
        *,
        investigation_id: str,
        allowed_namespaces: frozenset[str],
        ) -> InvestigationRecord | None:
     if not allowed_namespaces:
        return None

     with self._connect() as connection:
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """
                SELECT
                    investigation_id,
                    authorized_namespace,
                    status,
                    created_at,
                    started_at,
                    finished_at,
                    stop_reason,
                    user_text,
                    max_steps
                FROM investigations
                WHERE investigation_id = %s
                  AND authorized_namespace = ANY(%s)
                """,
                (
                    investigation_id,
                    list(sorted(allowed_namespaces)),
                ),
            )

            row = cursor.fetchone()

     if row is None:
        return None

     return InvestigationRecord.model_validate(row)    

    # ---- read-only browsing (UI) -------------------------------------------
    # Every query is bounded and restricted to the caller's namespaces.

    _SUMMARY_COLUMNS = """
        investigation_id, authorized_namespace, status, created_at,
        started_at, finished_at, stop_reason, user_text, max_steps
    """

    def list_investigations(
        self,
        *,
        allowed_namespaces: frozenset[str],
        limit: int,
        offset: int,
        status: str | None = None,
    ) -> tuple[list[dict], int]:
        """(rows, total). Each row has the record columns plus the persisted
        report's `findings` (None unless completed)."""
        if not allowed_namespaces:
            return [], 0

        if not 1 <= limit <= 100 or offset < 0:
            raise ValueError("Invalid page bounds.")

        namespaces = list(sorted(allowed_namespaces))
        where = "authorized_namespace = ANY(%s)"
        params: list = [namespaces]

        if status is not None:
            where += " AND status = %s"
            params.append(status)

        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"SELECT count(*) AS total FROM investigations WHERE {where}",
                    params,
                )
                total = cur.fetchone()["total"]
                cur.execute(
                    f"""
                    SELECT {self._SUMMARY_COLUMNS},
                           report->'findings' AS findings
                    FROM investigations
                    WHERE {where}
                    ORDER BY created_at DESC, investigation_id
                    LIMIT %s OFFSET %s
                    """,
                    [*params, limit, offset],
                )
                rows = cur.fetchall()

        return rows, total

    def get_investigation_row_for_namespaces(
        self,
        *,
        investigation_id: str,
        allowed_namespaces: frozenset[str],
    ) -> dict | None:
        """The record columns plus the report's `findings`, or None when the
        investigation does not exist or is outside `allowed_namespaces`."""
        if not allowed_namespaces:
            return None

        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"""
                    SELECT {self._SUMMARY_COLUMNS},
                           report->'findings' AS findings
                    FROM investigations
                    WHERE investigation_id = %s
                      AND authorized_namespace = ANY(%s)
                    """,
                    (investigation_id, list(sorted(allowed_namespaces))),
                )
                return cur.fetchone()

    def investigation_stats(
        self, *, allowed_namespaces: frozenset[str]
    ) -> dict:
        """Counts and the mean duration over the caller's namespaces."""
        empty = {
            "total": 0, "completed": 0, "failed": 0, "in_progress": 0,
            "completed_with_warning_or_higher": 0, "average_duration_seconds": None,
        }

        if not allowed_namespaces:
            return empty

        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT
                        count(*) AS total,
                        count(*) FILTER (WHERE status = 'completed') AS completed,
                        count(*) FILTER (WHERE status = 'failed') AS failed,
                        count(*) FILTER (WHERE status IN ('pending', 'running'))
                            AS in_progress,
                        count(*) FILTER (
                            WHERE status = 'completed' AND EXISTS (
                                SELECT 1
                                FROM jsonb_array_elements(
                                    COALESCE(report->'findings', '[]'::jsonb)
                                ) AS finding
                                WHERE finding->>'severity' IN ('warning', 'critical')
                            )
                        ) AS completed_with_warning_or_higher,
                        avg(EXTRACT(EPOCH FROM (finished_at - started_at)))
                            FILTER (
                                WHERE status = 'completed'
                                  AND started_at IS NOT NULL
                                  AND finished_at IS NOT NULL
                            ) AS average_duration_seconds
                    FROM investigations
                    WHERE authorized_namespace = ANY(%s)
                    """,
                    (list(sorted(allowed_namespaces)),),
                )
                row = cur.fetchone()

        average = row["average_duration_seconds"]

        return {
            **{key: int(row[key]) for key in empty if key != "average_duration_seconds"},
            "average_duration_seconds": None if average is None else float(average),
        }

    def list_audit_events(
        self, *, investigation_id: str, limit: int
    ) -> tuple[list[dict], bool]:
        """Raw audit rows in write order (the caller sanitises them) and
        whether more rows exist beyond `limit`. Authorise the investigation
        BEFORE calling this."""
        if not 1 <= limit <= 500:
            raise ValueError("Invalid audit page size.")

        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT event_id, request_id, tool_call_id, event_type,
                           tool_name, arguments, status, detail, created_at
                    FROM investigation_audit_events
                    WHERE investigation_id = %s
                    ORDER BY id
                    LIMIT %s
                    """,
                    (investigation_id, limit + 1),
                )
                rows = cur.fetchall()

        return rows[:limit], len(rows) > limit

    def _transition(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        sql: str,
        prefix_params: tuple = (),
    ) -> InvestigationRecord:
        if not investigation_id or not authorized_namespace:
            raise ValueError("Investigation ID and namespace are required.")

        params = (
            *prefix_params,
            investigation_id,
            authorized_namespace,
        )

        with self._connect(row_factory=dict_row) as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                row = cur.fetchone()

                if row is None:
                    raise InvestigationTransitionError(
                        "Investigation not found, namespace mismatch, "
                        "or lifecycle transition not permitted."
                    )

        return InvestigationRecord.model_validate(row)
