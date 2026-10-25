"""Browser-facing API for the demo UI, mounted under /api.

The console is open. Routes use the demo namespace allow-list; there is no
login, session cookie, or API key.
"""

from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile

from app.investigations.create_request import InvestigationCreateRequest
from app.investigations.models import InvestigationRecord
from app.investigations.repository import InvestigationRepository
from app.reports.models import InvestigationReport
from app.security.api_keys import APIKeyPrincipal
from app.speech.audio import ALLOWED_MEDIA_TYPES, MAX_AUDIO_BYTES, decode_wav, media_type
from app.speech.briefing import build_spoken_briefing
from app.speech.models import SpeechProposalRequest, SpeechProposalResponse, SpokenBriefingResponse, TranscriptResponse
from app.speech.proposal import propose_speech_scope
from app.speech.problems import (
    TOO_LARGE,
    UNSUPPORTED_TYPE,
    SpeechProblem,
)
from app.health.models import ResourceHealthResponse
from app.speech.runtime import get_runtime
from app.security.dependencies import get_demo_principal
from app.tools.workload_target import ScopeIntent, TargetQuestionError, classify_question_target
from app.web.models import (
    AccessInfo,
    AuditTrail,
    HealthInfo,
    InvestigationPage,
    InvestigationStats,
    InvestigationSummary,
    ScopeSummary,
    sanitize_audit_row,
    summarize_findings,
)

router = APIRouter(prefix="/api")

MAX_AUDIT_EVENTS = 300
PAGE_LIMIT_MAX = 50


@router.get("/access", response_model=AccessInfo)
def access(principal: APIKeyPrincipal = Depends(get_demo_principal)):
    return AccessInfo(allowed_namespaces=sorted(principal.allowed_namespaces))


@router.get("/health", response_model=HealthInfo)
def api_health():
    from app import api as core

    return core.health()


def get_health_reader():
    from app.health.kubernetes import kubernetes_reader

    return kubernetes_reader()


def get_health_audit():
    from app.health.audit import write_health_audit

    return write_health_audit


@router.get("/resources/health", response_model=ResourceHealthResponse)
def resource_health(
    response: Response,
    namespace: str = Query(min_length=1, max_length=63),
    kind: str = Query(min_length=1, max_length=32),
    name: str = Query(min_length=1, max_length=63),
    principal: APIKeyPrincipal = Depends(get_demo_principal),
    reader=Depends(get_health_reader),
    audit=Depends(get_health_audit),
):
    """One point-in-time health read. Not a watch and not an investigation."""
    from app.health.service import run_health_check
    from app.health.types import HealthRequestError

    response.headers["Cache-Control"] = "no-store"
    try:
        return run_health_check(
            principal=principal,
            namespace=namespace,
            kind=kind,
            name=name,
            reader=reader,
            audit=audit,
        )
    except HealthRequestError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.code) from None


# ------------------------------------------------------------ investigations


def _scope(user_text: str | None, namespace: str) -> ScopeSummary:
    if not user_text:
        return ScopeSummary(mode="unspecified")

    try:
        intent = classify_question_target(user_text, namespace=namespace)
    except TargetQuestionError:
        return ScopeSummary(mode="unspecified")

    if intent.scope is ScopeIntent.TARGETED and intent.target is not None:
        return ScopeSummary(mode="workload", kind=intent.target.kind, name=intent.target.name)

    if intent.scope is ScopeIntent.BROAD_EXPLICIT:
        return ScopeSummary(mode="namespace")

    return ScopeSummary(mode="unspecified")


def _summary(row: dict) -> InvestigationSummary:
    started, finished = row.get("started_at"), row.get("finished_at")
    completed = row["status"] == "completed"
    primary, counts = summarize_findings(row.get("findings")) if completed else (None, None)

    return InvestigationSummary(
        investigation_id=row["investigation_id"],
        authorized_namespace=row["authorized_namespace"],
        status=row["status"],
        created_at=row["created_at"],
        started_at=started,
        finished_at=finished,
        stop_reason=row.get("stop_reason"),
        user_text=row.get("user_text"),
        max_steps=row.get("max_steps"),
        duration_seconds=(
            (finished - started).total_seconds() if started and finished else None
        ),
        scope=_scope(row.get("user_text"), row["authorized_namespace"]),
        primary_finding=primary,
        finding_counts=counts,
    )


@router.get("/investigations/stats", response_model=InvestigationStats)
def investigation_stats(principal: APIKeyPrincipal = Depends(get_demo_principal)):
    try:
        return InvestigationStats(
            **InvestigationRepository().investigation_stats(
                allowed_namespaces=principal.allowed_namespaces
            )
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation lookup failed.") from None


@router.get("/investigations", response_model=InvestigationPage)
def list_investigations(
    limit: int = Query(default=10, ge=1, le=PAGE_LIMIT_MAX),
    offset: int = Query(default=0, ge=0, le=100_000),
    status: Literal["pending", "running", "completed", "failed"] | None = None,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    try:
        rows, total = InvestigationRepository().list_investigations(
            allowed_namespaces=principal.allowed_namespaces,
            limit=limit,
            offset=offset,
            status=status,
        )

        return InvestigationPage(
            items=[_summary(row) for row in rows], total=total, limit=limit, offset=offset
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation lookup failed.") from None


@router.post("/investigations", response_model=InvestigationRecord, status_code=201)
def create_investigation(
    request: InvestigationCreateRequest,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    from app import api as core

    return core.create_investigation(request, principal)


@router.post("/investigations/{investigation_id}/execute", response_model=InvestigationRecord)
def execute_investigation(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    from app import api as core

    return core.execute_investigation(investigation_id, principal)


def _get_row(investigation_id: str, principal: APIKeyPrincipal) -> dict:
    try:
        row = InvestigationRepository().get_investigation_row_for_namespaces(
            investigation_id=investigation_id,
            allowed_namespaces=principal.allowed_namespaces,
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation lookup failed.") from None

    # Out-of-scope and nonexistent investigations are indistinguishable.
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found.")

    return row


@router.get("/investigations/{investigation_id}/summary", response_model=InvestigationSummary)
def investigation_summary(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    return _summary(_get_row(investigation_id, principal))


@router.get("/investigations/{investigation_id}/report", response_model=InvestigationReport)
def investigation_report(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    from app import api as core

    return core.get_investigation_report(investigation_id, principal)


@router.get("/investigations/{investigation_id}/audit", response_model=AuditTrail)
def investigation_audit(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    # Authorise through the namespace-scoped lookup BEFORE reading audit rows.
    record = _get_row(investigation_id, principal)

    try:
        rows, truncated = InvestigationRepository().list_audit_events(
            investigation_id=record["investigation_id"], limit=MAX_AUDIT_EVENTS
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Audit retrieval failed.") from None

    events = [event for row in rows if (event := sanitize_audit_row(row)) is not None]

    return AuditTrail(
        investigation_id=record["investigation_id"], events=events, truncated=truncated
    )


# ---------------------------------------------------------------- speech


def _speech_error(problem: SpeechProblem) -> HTTPException:
    return HTTPException(status_code=problem.status, detail=problem.detail)


def _load_completed_report(row: dict) -> InvestigationReport | None:
    if row["status"] != "completed":
        return None

    try:
        return InvestigationRepository().get_report(
            investigation_id=row["investigation_id"],
            authorized_namespace=row["authorized_namespace"],
        )
    except Exception:
        raise HTTPException(status_code=500, detail="Investigation lookup failed.") from None


def _briefing_text(row: dict, report: InvestigationReport | None) -> str:
    scope = _scope(row.get("user_text"), row["authorized_namespace"])

    return build_spoken_briefing(
        status=row["status"],
        stop_reason=row.get("stop_reason"),
        namespace=row["authorized_namespace"],
        scope_mode=scope.mode,
        scope_kind=scope.kind,
        scope_name=scope.name,
        report=report,
    )


async def _read_bounded(upload: UploadFile) -> bytes:
    try:
        data = await upload.read(MAX_AUDIO_BYTES + 1)
    finally:
        await upload.close()

    if len(data) > MAX_AUDIO_BYTES:
        raise SpeechProblem(413, TOO_LARGE)

    return data


@router.post("/speech/transcribe", response_model=TranscriptResponse)
async def transcribe_speech(
    response: Response,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
    audio: UploadFile = File(...),
):
    """Turn one short recording into text. Does not start an investigation."""
    _ = principal.principal_id
    response.headers["Cache-Control"] = "no-store"

    try:
        if media_type(audio.content_type) not in ALLOWED_MEDIA_TYPES:
            await audio.close()
            raise SpeechProblem(415, UNSUPPORTED_TYPE)

        payload = await _read_bounded(audio)
        samples = decode_wav(payload)
        del payload
        # Samples exist only for this call. They are not written or logged.
        transcript = get_runtime().transcribe(samples, 16_000)
    except SpeechProblem as problem:
        raise _speech_error(problem) from None

    return TranscriptResponse(transcript=transcript)


@router.post("/speech/proposal", response_model=SpeechProposalResponse)
def propose_speech(
    body: SpeechProposalRequest,
    response: Response,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    """Classify a transcript with the investigation intent rules.

    The namespace is the one selected in the form. It is checked against the
    session and is never taken from the transcript. Nothing is executed.
    """
    response.headers["Cache-Control"] = "no-store"

    if body.namespace not in principal.allowed_namespaces:
        raise HTTPException(status_code=403, detail="Namespace access denied.")

    proposal = propose_speech_scope(body.transcript, namespace=body.namespace)

    return SpeechProposalResponse(
        outcome=proposal.outcome,
        name=proposal.name,
        kind=proposal.kind,
        code=proposal.code,
    )


@router.get(
    "/investigations/{investigation_id}/briefing",
    response_model=SpokenBriefingResponse,
)
def investigation_briefing(
    investigation_id: str,
    response: Response,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    row = _get_row(investigation_id, principal)
    text = _briefing_text(row, _load_completed_report(row))
    response.headers["Cache-Control"] = "no-store"

    return SpokenBriefingResponse(
        text=text,
        speech_available=get_runtime().synthesis_available(),
    )


@router.get("/investigations/{investigation_id}/briefing/audio")
def investigation_briefing_audio(
    investigation_id: str,
    principal: APIKeyPrincipal = Depends(get_demo_principal),
):
    """WAV for the same briefing text. The client cannot choose the words."""
    row = _get_row(investigation_id, principal)

    try:
        audio = get_runtime().synthesize(_briefing_text(row, _load_completed_report(row)))
    except SpeechProblem as problem:
        raise _speech_error(problem) from None

    return Response(
        content=audio,
        media_type="audio/wav",
        headers={
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )
