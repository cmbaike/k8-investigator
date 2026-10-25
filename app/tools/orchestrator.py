"""One-step, read-only investigation execution boundary.

The caller must create context using the validated investigation-context factory.
An audit sink is required; it must durably persist events or raise.
"""

from dataclasses import dataclass
from typing import Callable

from app.tools.binder import bind_proposed_user_tool_call
from app.tools.executor import execute_tool_call
from app.tools.investigation import (
    InvestigationContext,
    InvestigationConcurrentExecutionError,
    InvestigationScopeError,
    InvestigationStepLimitError,
    TargetScopeError,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.policy import authorize_tool_call
from app.tools.models import ToolResultStatus
from app.tools.proposal_rejection import RejectedProposal


@dataclass(frozen=True)
class InvestigationAuditEvent:
    investigation_id: str
    request_id: str
    phase: str  # proposed, authorized, rejected, completed
    tool: str
    arguments: dict[str, object]
    status: str
    detail: str | None = None


AuditSink = Callable[[InvestigationAuditEvent], None]
Executor = Callable[[ToolCall], ToolExecutionResult]


class InvestigationExecutionError(RuntimeError):
    """A proposed step was rejected before execution."""


# Explicit read-only allowlist; policy is an additional, independent gate.
READ_ONLY_INVESTIGATION_TOOLS = frozenset({
    "k8s.get_pods",
    "k8s.describe_pod",
    "k8s.get_events",
    "k8s.get_logs",
    "k8s.describe_workload_config",
})


def execute_investigation_step(
    *,
    context: InvestigationContext,
    request_id: str,
    proposed_call: ToolCall,
    audit: AuditSink,
    executor: Executor = execute_tool_call,
    consume_step: bool = True,
) -> ToolExecutionResult:
    """Authorize, execute and record one bounded investigation step.

    An audit write failure aborts execution when it occurs before dispatch.
    An audit failure after dispatch propagates; callers must not retry blindly.
    Concurrent calls on the same context fail immediately.
    """
    def emit(phase: str, call: ToolCall, status: str, detail: str | None = None) -> None:
        audit(InvestigationAuditEvent(
            investigation_id=context.investigation_id,
            request_id=request_id,
            phase=phase,
            tool=call.name,
            arguments=dict(call.arguments),
            status=status,
            detail=detail,
        ))

    with context.execution_lease():
        emit("proposed", proposed_call, "received")
        try:
            if consume_step and not context.has_step_budget:
                raise InvestigationStepLimitError("Investigation step budget exhausted.")
            if context.user_text == "":
                raise InvestigationExecutionError("Missing original user request.")
            if proposed_call.name not in READ_ONLY_INVESTIGATION_TOOLS:
                raise InvestigationExecutionError("Tool is not in the read-only investigation allowlist.")
            bound = bind_proposed_user_tool_call(
                proposed_call, context.user_text, context=context
            )
            context.validate_execution_scope(bound)
            # A targeted question can only inspect its resolved workload.
            context.validate_target_scope(bound)
            decision = authorize_tool_call(bound)
            if decision.status != ToolResultStatus.ALLOWED:
                raise InvestigationExecutionError(f"Tool policy rejected call: {decision.reason}")
        except TargetScopeError as exc:
            # Fixed reason code only: the durable writer keeps the text before
            # the first colon, so this is what is stored.
            emit("rejected", proposed_call, "denied", exc.reason)
            raise
        except Exception as exc:
            emit("rejected", proposed_call, "denied", f"{type(exc).__name__}: {exc}")
            raise

        emit("authorized", bound, "allowed")
        # This committed pre-dispatch event is mandatory: audit failure blocks execution.
        emit("execution_started", bound, "started")
        # Executor may raise unexpectedly. Convert this to a recorded failure,
        # without exposing a fake successful observation.
        try:
            result = executor(bound)
            if result.tool != bound.name:
                result = ToolExecutionResult(
                    tool=bound.name,
                    status=ToolExecutionStatus.ERROR,
                    error="Executor returned a result for a different tool.",
                )
        except Exception as exc:
            result = ToolExecutionResult(
                tool=bound.name,
                status=ToolExecutionStatus.ERROR,
                error=f"Executor raised {type(exc).__name__}.",
            )

        context.record_execution(
            request_id=request_id,
            call=bound,
            result=result,
            consume_step=consume_step,
        )
        emit("completed", bound, str(result.status), result.error)
        return result


def audit_rejected_proposal(
    *,
    context: InvestigationContext,
    request_id: str,
    rejection: RejectedProposal,
    audit: AuditSink,
) -> None:
    """Write the audit trail of a proposal refused BEFORE the execution boundary.

    The same two phases a refusal at the boundary produces ("proposed", then
    "rejected"), with the audit-safe argument subset and the fixed reason code
    as the detail. Nothing is authorized, started or executed. A failed write
    propagates and stops the run: a refusal that cannot be recorded must not be
    silently absorbed.
    """
    for phase, status, detail in (
        ("proposed", "received", None),
        ("rejected", "denied", rejection.reason),
    ):
        audit(InvestigationAuditEvent(
            investigation_id=context.investigation_id,
            request_id=request_id,
            phase=phase,
            tool=rejection.tool,
            arguments=dict(rejection.arguments),
            status=status,
            detail=detail,
        ))
