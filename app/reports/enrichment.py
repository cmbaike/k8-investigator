"""Optional AI enrichment of a finished deterministic report.

The deterministic report is built first and is never modified here. Only the
separate `ai_hypotheses` and `ai_analysis` fields are populated. Failure of
this stage is expected and harmless: it produces a bounded, non-sensitive
"unavailable" disclosure and leaves everything else untouched.
"""

from collections.abc import Callable

from app.reports.hypotheses import (
    categorize_rejection,
    HypothesisBatch,
    HypothesisEvidenceRegistry,
    HypothesisGenerationError,
    HypothesisInput,
    HypothesisValidationError,
    revalidate_hypotheses,
)
from app.reports.hypothesis_ranking import rank_hypotheses
from app.reports.models import AIAnalysisStatus, AIHypothesis, InvestigationReport
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.investigation import InvestigationContext

HypothesisProvider = Callable[[HypothesisInput], HypothesisBatch | list[AIHypothesis]]

# Application-controlled text only. Never interpolate model or log content.
_MESSAGES = {
    "generated": "AI-generated hypotheses are unverified interpretations.",
    "generated_omitted": (
        "AI-generated hypotheses are unverified interpretations. "
        "{n} other proposed hypothesis(es) omitted by validation."
    ),
    "all_omitted": (
        "AI analysis ran, but all {n} proposed hypothesis(es) were omitted "
        "by validation; none are shown. See omission_reasons."
    ),
    "all_omitted_no_logs": (
        "AI analysis ran, but all {n} proposed hypothesis(es) were omitted: "
        "they described log content, yet no log excerpts were available."
    ),
    "none_proposed": "AI analysis ran and proposed no hypotheses.",
    "timeout": "AI analysis was unavailable: the model request timed out.",
    "provider_error": "AI analysis was unavailable: the model request failed.",
    "malformed_response": "AI analysis was unavailable: the response was malformed.",
    "validation_failed": "AI analysis was unavailable: the response failed validation.",
    "validation_failed_provenance": (
        "AI analysis was unavailable: the response failed provenance "
        "validation (citations or resources did not check out)."
    ),
    "validation_failed_security": (
        "AI analysis was unavailable: the response failed security validation."
    ),
    "validation_failed_structure": (
        "AI analysis was unavailable: the response failed structural validation."
    ),
    "no_evidence": "AI analysis was not attempted: no trusted evidence was available.",
}

_KNOWN_REASONS = frozenset(
    {"timeout", "provider_error", "malformed_response", "validation_failed"}
)


def _with_ai(
    report: InvestigationReport,
    *,
    analysis: AIAnalysisStatus,
    hypotheses: list[AIHypothesis] | None = None,
) -> InvestigationReport:
    # Only AI fields change; deterministic fields are carried over as-is.
    return report.model_copy(
        update={
            "ai_hypotheses": hypotheses or [],
            "ai_analysis": analysis,
        }
    )


def add_ai_hypotheses(
    report: InvestigationReport,
    *,
    snapshot: InvestigationEvidenceSnapshot,
    context: InvestigationContext,
    provider: HypothesisProvider | None,
) -> InvestigationReport:
    """Return `report` plus validated unverified hypotheses, or an honest
    'unavailable' disclosure. Never raises for provider/validation failure."""

    if provider is None:
        return report

    if report.ai_hypotheses or report.ai_analysis is not None:
        raise ValueError("Report already contains AI enrichment.")

    log_entries = context.log_entries
    used = len(log_entries)
    omitted = context.log_entries_omitted

    def status(
        state,
        reason=None,
        message_key=None,
        hypotheses_omitted=0,
        hypotheses_proposed=0,
        omission_reasons=None,
        rejection_category=None,
    ) -> AIAnalysisStatus:
        message = _MESSAGES[message_key or reason or state].format(
            n=hypotheses_omitted
        )

        return AIAnalysisStatus(
            state=state,
            reason=reason,
            message=message,
            log_excerpts_used=used,
            log_excerpts_omitted=min(omitted, 1000),
            hypotheses_omitted=min(hypotheses_omitted, 10),
            hypotheses_proposed=min(hypotheses_proposed, 10),
            omission_reasons={
                code: min(count, 10)
                for code, count in (omission_reasons or {}).items()
            },
            rejection_category=rejection_category,
        )

    if not snapshot.evidence:
        return _with_ai(
            report, analysis=status("not_attempted", "no_evidence")
        )

    def unavailable(reason: str, category: str | None = None) -> InvestigationReport:
        reason = reason if reason in _KNOWN_REASONS else "provider_error"
        category = (
            category
            if reason == "validation_failed"
            and category in {"provenance", "security", "structure"}
            else None
        )
        return _with_ai(
            report,
            analysis=status(
                "unavailable",
                reason,
                message_key=f"validation_failed_{category}" if category else None,
                rejection_category=category,
            ),
        )

    try:
        # Registry is built from THIS investigation's data only.
        registry = HypothesisEvidenceRegistry(
            investigation_id=context.investigation_id,
            authorized_namespace=context.require_authorized_namespace(),
            snapshot=snapshot,
            log_entries=log_entries,
        )

        proposed = provider(
            HypothesisInput(
                snapshot=snapshot,
                log_entries=log_entries,
                omitted_log_entries=omitted,
                authorized_namespace=context.require_authorized_namespace(),
            )
        )

        # Provider output is untrusted regardless of its implementation:
        # re-run citation, resource, and text validation independently.
        proposed_list = (
            proposed.hypotheses if isinstance(proposed, HypothesisBatch) else proposed
        )
        already_omitted = proposed.omitted if isinstance(proposed, HypothesisBatch) else 0
        reasons: dict[str, int] = dict(
            proposed.omission_reasons if isinstance(proposed, HypothesisBatch) else {}
        )
        batch = revalidate_hypotheses(proposed_list, registry=registry)
        # Presentation order only: grouped per container, evidence-aware,
        # deterministic. Runs after (never instead of) validation.
        validated = rank_hypotheses(batch.hypotheses, registry)
        omitted_for_tone = already_omitted + batch.omitted

        for code, count in batch.omission_reasons.items():
            reasons[code] = reasons.get(code, 0) + count
    except HypothesisGenerationError as exc:
        return unavailable(exc.reason, exc.category)
    except HypothesisValidationError as exc:
        return unavailable("validation_failed", categorize_rejection(exc.code))
    except Exception:
        return unavailable("provider_error")

    total = len(validated) + omitted_for_tone

    if validated:
        state, key = "generated", (
            "generated_omitted" if omitted_for_tone else "generated"
        )
    elif omitted_for_tone:
        log_claims = {"reported_without_log_evidence", "unattributed_log_claim"}
        state = "all_omitted"
        key = (
            "all_omitted_no_logs"
            if used == 0 and set(reasons) <= log_claims
            else "all_omitted"
        )
    else:
        state, key = "none_proposed", "none_proposed"

    return _with_ai(
        report,
        analysis=status(
            state,
            message_key=key,
            hypotheses_omitted=omitted_for_tone,
            hypotheses_proposed=total,
            omission_reasons=reasons,
        ),
        hypotheses=validated,
    )
