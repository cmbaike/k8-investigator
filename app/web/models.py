"""Response models for the browser-facing API. Read-only views over persisted
investigations; nothing here is computed from model output or report prose."""

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from app.investigations.models import InvestigationStatus

Severity = Literal["info", "warning", "critical", "unknown"]
_SEVERITY_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "info": 3}

AUDIT_EVENT_TYPES = ("proposed", "authorized", "rejected", "execution_started", "completed")
_FIXED_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TOOL_NAME = re.compile(r"^[a-z0-9_.]{1,64}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_ARGUMENT_KEYS = ("namespace", "pod", "deployment", "container", "tail_lines")


class WebModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AccessInfo(WebModel):
    allowed_namespaces: list[str]


class HealthInfo(WebModel):
    status: Literal["ok", "degraded"]
    database: bool


class ScopeSummary(WebModel):
    """What the persisted question asks for, as classified by the application's
    own deterministic classifier. `kind` is a hint, not a verified kind."""

    mode: Literal["workload", "namespace", "unspecified"]
    kind: str | None = None
    name: str | None = None


class PrimaryFinding(WebModel):
    title: str
    severity: Severity


class FindingCounts(WebModel):
    critical: int = 0
    warning: int = 0
    info: int = 0
    unknown: int = 0


class InvestigationSummary(WebModel):
    investigation_id: str
    authorized_namespace: str
    status: InvestigationStatus
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    stop_reason: str | None = None
    user_text: str | None = None
    max_steps: int | None = None
    duration_seconds: float | None = None
    scope: ScopeSummary
    # Present only for completed investigations (taken from the persisted report).
    primary_finding: PrimaryFinding | None = None
    finding_counts: FindingCounts | None = None


class InvestigationPage(WebModel):
    items: list[InvestigationSummary]
    total: int
    limit: int
    offset: int


class InvestigationStats(WebModel):
    total: int
    completed: int
    failed: int
    in_progress: int
    completed_with_warning_or_higher: int
    average_duration_seconds: float | None


class AuditEventView(WebModel):
    event_id: str
    request_id: str | None
    tool_call_id: str | None
    event_type: Literal["proposed", "authorized", "rejected", "execution_started", "completed"]
    tool_name: str
    arguments: dict[str, str | int]
    status: str
    # A fixed machine code (for example a rejection reason); anything else in
    # storage is withheld.
    reason_code: str | None
    created_at: datetime


class AuditTrail(WebModel):
    investigation_id: str
    events: list[AuditEventView]
    truncated: bool


def summarize_findings(findings: Any) -> tuple[PrimaryFinding | None, FindingCounts | None]:
    """Highest-severity persisted finding (first among equals) and counts."""
    if not isinstance(findings, list):
        return None, None

    counts = FindingCounts()
    best: tuple[int, int, PrimaryFinding] | None = None

    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            continue

        severity, title = item.get("severity"), item.get("title")

        if severity not in _SEVERITY_ORDER or not isinstance(title, str):
            continue

        setattr(counts, severity, getattr(counts, severity) + 1)
        rank = (_SEVERITY_ORDER[severity], index)

        if best is None or rank < best[:2]:
            best = (*rank, PrimaryFinding(title=title[:200], severity=severity))

    return (best[2] if best else None), counts


def sanitize_audit_row(row: dict) -> AuditEventView | None:
    """A browser-safe view of one stored audit row, or None if it is malformed."""
    event_type = row.get("event_type")

    if event_type not in AUDIT_EVENT_TYPES:
        return None

    tool = row.get("tool_name")
    request_id = row.get("request_id")
    detail = row.get("detail")
    status = row.get("status")
    raw_arguments = row.get("arguments") if isinstance(row.get("arguments"), dict) else {}

    arguments: dict[str, str | int] = {}

    for key in _ARGUMENT_KEYS:
        value = raw_arguments.get(key)

        if isinstance(value, bool):
            continue

        if isinstance(value, int) and 0 <= value <= 100_000:
            arguments[key] = value
        elif isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", value):
            arguments[key] = value

    tool_call_id = row.get("tool_call_id")

    return AuditEventView(
        event_id=str(row["event_id"]),
        request_id=request_id if isinstance(request_id, str) and _REQUEST_ID.fullmatch(request_id) else None,
        tool_call_id=str(tool_call_id) if tool_call_id else None,
        event_type=event_type,
        tool_name=tool if isinstance(tool, str) and _TOOL_NAME.fullmatch(tool) else "unknown",
        arguments=arguments,
        status=status if isinstance(status, str) and _FIXED_CODE.fullmatch(status) else "unknown",
        reason_code=detail if isinstance(detail, str) and _FIXED_CODE.fullmatch(detail) else None,
        created_at=row["created_at"],
    )
