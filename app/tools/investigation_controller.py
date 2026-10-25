"""Sequential, bounded investigation controller (scripted provider milestone).

The provider proposes calls; execute_investigation_step is the sole execution
boundary. A context-level run lease rejects overlapping controller runs.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Callable
from uuid import uuid4

from app.tools.investigation import InvestigationContext, TargetScopeError
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.orchestrator import (
    AuditSink,
    Executor,
    audit_rejected_proposal,
    execute_investigation_step,
)
from app.tools.executor import execute_tool_call


class InvestigationStopReason(StrEnum):
    PROVIDER_FINISHED = "provider_finished"
    STEP_BUDGET_EXHAUSTED = "step_budget_exhausted"
    TOOL_FAILED = "tool_failed"


def is_credential_failure(result: ToolExecutionResult) -> bool:
    """True when Kubernetes rejected this identity's credentials (HTTP 401).

    Every later call would fail the same way and a report built on the gap
    would look like missing evidence rather than a broken identity, so this
    always fails the run, whatever the tool's failure tolerance. (HTTP 403 is
    an authorization decision for one resource and is handled per tool.)
    """
    return (
        result.status != ToolExecutionStatus.SUCCESS
        and (result.error or "").startswith("UnauthorizedException")
    )


@dataclass(frozen=True)
class InvestigationStep:
    request_id: str
    proposed_call: ToolCall
    result: ToolExecutionResult


@dataclass(frozen=True)
class InvestigationRunResult:
    investigation_id: str
    stop_reason: InvestigationStopReason
    steps: tuple[InvestigationStep, ...]


# The provider sees prior outcomes and the context's read-only observation view.
# It must not be treated as an authorization source.
ProposalProvider = Callable[
    [InvestigationContext, tuple[InvestigationStep, ...]], ToolCall | None
]
RequestIdFactory = Callable[[], str]


def run_investigation(
    *,
    context: InvestigationContext,
    provider: ProposalProvider,
    audit: AuditSink,
    executor: Executor = execute_tool_call,
    request_id_factory: RequestIdFactory = lambda: str(uuid4()),
    tolerated_failure_tools: frozenset[str] = frozenset(),
) -> InvestigationRunResult:
    """Run sequential proposed steps until completion, failure, or budget limit.

    Authorization, audit, or provider errors propagate and stop the run.
    The one exception is a proposal outside the bound workload: it is audited
    (proposed, then rejected with a fixed reason code), counted on the context,
    never executed and consumes no step; the run continues, up to
    MAX_REJECTED_PROPOSALS such refusals.
    Never retry automatically after an exception: dispatch may have occurred.
    A non-success tool result stops the run without granting new observations,
    EXCEPT for tools named in `tolerated_failure_tools` (default: none). A
    failed tolerated tool still consumed budget, was audited, and minted no
    observations; the run simply continues. A credential failure (HTTP 401)
    is never tolerated. Used for supplementary evidence
    whose absence the report discloses rather than failing the investigation.
    Overlapping callers on one context are rejected by the run lease.
    """
    with context.run_lease():
        steps: list[InvestigationStep] = []
        run_request_id: str | None = None

        def run_id() -> str:
            nonlocal run_request_id

            if run_request_id is None:
                run_request_id = request_id_factory()
                if not isinstance(run_request_id, str) or not run_request_id:
                    raise ValueError("Request ID factory must return a nonempty string.")

            return run_request_id

        if getattr(context, "namespace_health_discovery", False):
            from app.tools.coverage import discover_namespace_health

            discovered, fatal = discover_namespace_health(
                context,
                audit=audit,
                executor=executor,
                request_id_factory=request_id_factory,
            )
            steps.extend(discovered)

            if fatal is not None:
                return InvestigationRunResult(
                    context.investigation_id,
                    fatal,
                    tuple(steps),
                )

        while context.has_step_budget:
            proposed = provider(context, tuple(steps))

            # Proposals the coverage policy refused before they reached the
            # execution boundary are audited here, before anything else runs.
            for rejection in context.drain_unaudited_rejections():
                audit_rejected_proposal(
                    context=context,
                    request_id=f"{run_id()}-rejected-{rejection.ordinal}",
                    rejection=rejection,
                    audit=audit,
                )

            if proposed is None:
                return InvestigationRunResult(
                    context.investigation_id,
                    InvestigationStopReason.PROVIDER_FINISHED,
                    tuple(steps),
                )
            if not isinstance(proposed, ToolCall):
                raise TypeError("Proposal provider must return ToolCall or None.")

            # A boundary rejection consumes no step, so the next attempt would
            # reuse this number. Qualify the id by the rejections so far, so
            # each proposal's audit events correlate under their own request id.
            step_request_id = f"{run_id()}-step-{context.completed_steps + 1}"
            if context.rejected_proposal_count:
                step_request_id += f"-after-{context.rejected_proposal_count}"

            try:
                result = execute_investigation_step(
                    context=context,
                    request_id=step_request_id,
                    proposed_call=proposed,
                    audit=audit,
                    executor=executor,
                )
            except TargetScopeError as exc:
                # Refused at the boundary (already audited there), never
                # executed, no step consumed. The workload confinement held;
                # the run may continue, but only a bounded number of times.
                context.note_rejected_proposal(proposed, exc.reason, audited=True)

                if context.rejection_limit_reached:
                    return InvestigationRunResult(
                        context.investigation_id,
                        InvestigationStopReason.PROVIDER_FINISHED,
                        tuple(steps),
                    )

                continue

            steps.append(InvestigationStep(step_request_id, proposed, result))
            if (
                result.status != ToolExecutionStatus.SUCCESS
                and (
                    proposed.name not in tolerated_failure_tools
                    or is_credential_failure(result)
                )
            ):
                return InvestigationRunResult(
                    context.investigation_id,
                    InvestigationStopReason.TOOL_FAILED,
                    tuple(steps),
                )

        return InvestigationRunResult(
            context.investigation_id,
            InvestigationStopReason.STEP_BUDGET_EXHAUSTED,
            tuple(steps),
        )
