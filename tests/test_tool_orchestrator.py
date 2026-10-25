"""Isolated boundary tests; no Kubernetes cluster or database required."""

import pytest

from app.tools.investigation import InvestigationContext, InvestigationStepLimitError
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.orchestrator import execute_investigation_step


USER_TEXT = "Investigate the failing workload in namespace ai-ops-demo."


def context(max_steps=6):
    return InvestigationContext(
        investigation_id="inv-test",
        user_text=USER_TEXT,
        authorized_namespace="ai-ops-demo",
        max_steps=max_steps,
    )


def proposed(namespace="ai-ops-demo"):
    return ToolCall(name="k8s.get_pods", arguments={"namespace": namespace})


def test_successful_step_records_result_and_audit():
    events, executed = [], []

    def executor(call):
        executed.append(call)
        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.SUCCESS, output={"pods": []}
        )

    ctx = context()
    result = execute_investigation_step(
        context=ctx, request_id="req-1", proposed_call=proposed(),
        audit=events.append, executor=executor,
    )
    assert result.status == ToolExecutionStatus.SUCCESS
    assert ctx.completed_steps == 1
    assert len(executed) == 1
    assert [event.phase for event in events] == ["proposed", "authorized", "execution_started", "completed"]


def test_cross_namespace_never_executes():
    executed, events = [], []
    with pytest.raises(Exception):
        execute_investigation_step(
            context=context(), request_id="req-2", proposed_call=proposed("production"),
            audit=events.append, executor=lambda call: executed.append(call),
        )
    assert not executed
    assert events[-1].phase == "rejected"


def test_budget_checked_before_execution():
    ctx = context(max_steps=1)
    executed = []

    def executor(call):
        executed.append(call)
        return ToolExecutionResult(tool=call.name, status=ToolExecutionStatus.ERROR)

    execute_investigation_step(
        context=ctx, request_id="req-1", proposed_call=proposed(),
        audit=lambda event: None, executor=executor,
    )
    with pytest.raises(InvestigationStepLimitError):
        execute_investigation_step(
            context=ctx, request_id="req-2", proposed_call=proposed(),
            audit=lambda event: None, executor=executor,
        )
    assert len(executed) == 1


def test_audit_failure_prevents_dispatch():
    executed = []

    def broken_audit(event):
        raise OSError("audit unavailable")

    with pytest.raises(OSError):
        execute_investigation_step(
            context=context(), request_id="req-3", proposed_call=proposed(),
            audit=broken_audit, executor=lambda call: executed.append(call),
        )
    assert executed == []


def test_mismatched_executor_result_cannot_mint_observations():
    ctx = context()
    result = execute_investigation_step(
        context=ctx, request_id="req-4", proposed_call=proposed(),
        audit=lambda event: None,
        executor=lambda call: ToolExecutionResult(
            tool="k8s.describe_pod", status=ToolExecutionStatus.SUCCESS,
            output={"pods": [{"name": "forged"}]},
        ),
    )
    assert result.status == ToolExecutionStatus.ERROR
    assert ctx.observations == ()


def test_execution_started_audit_failure_blocks_executor():
    executed = []
    ctx = context()

    def audit(event):
        if event.phase == "execution_started":
            raise OSError("database unavailable")

    with pytest.raises(OSError, match="database unavailable"):
        execute_investigation_step(
            context=ctx, request_id="req-audit", proposed_call=proposed(),
            audit=audit, executor=lambda call: executed.append(call),
        )
    assert executed == []
    assert ctx.completed_steps == 0
