"""Controller tests: no real database, Kubernetes cluster, or model required."""

import pytest

from app.tools.investigation import InvestigationContext
from app.tools.investigation_controller import (
    InvestigationStopReason,
    run_investigation,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus


USER_TEXT = "Investigate the failing workload in namespace ai-ops-demo."


def context(max_steps=6):
    return InvestigationContext(
        investigation_id="inv-controller",
        user_text=USER_TEXT,
        authorized_namespace="ai-ops-demo",
        max_steps=max_steps,
    )


def pods():
    return ToolCall(name="k8s.get_pods", arguments={"namespace": "ai-ops-demo"})


def describe(pod):
    return ToolCall(
        name="k8s.describe_pod",
        arguments={"namespace": "ai-ops-demo", "pod": pod},
    )


def success(call):
    output = {"namespace": "ai-ops-demo", "pods": [{"name": "payments-abc"}]} if call.name == "k8s.get_pods" else {}
    return ToolExecutionResult(tool=call.name, status=ToolExecutionStatus.SUCCESS, output=output)


def run(ctx, provider, *, executor=success, audit=lambda _: None):
    return run_investigation(
        context=ctx, provider=provider, executor=executor, audit=audit,
        request_id_factory=lambda: "req-controller",
    )


def test_discovery_then_describe_observed_pod():
    ctx = context()
    calls = []

    def provider(state, history):
        if not history:
            return pods()
        if len(history) == 1:
            assert state.find_observations(field="pods[].name", value="payments-abc")
            return describe("payments-abc")
        return None

    result = run(ctx, provider, executor=lambda call: (calls.append(call), success(call))[1])
    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert [call.name for call in calls] == ["k8s.get_pods", "k8s.describe_pod"]
    assert ctx.completed_steps == 2


def test_invented_pod_rejected_without_second_execution():
    ctx = context()
    calls = []

    def provider(_, history):
        return pods() if not history else describe("invented-pod")

    with pytest.raises(Exception):
        run(ctx, provider, executor=lambda call: (calls.append(call), success(call))[1])
    assert len(calls) == 1
    assert ctx.completed_steps == 1


def test_cross_namespace_proposal_rejected_without_execution():
    ctx = context()
    calls = []
    with pytest.raises(Exception):
        run(ctx, lambda *_: ToolCall(name="k8s.get_pods", arguments={"namespace": "production"}),
            executor=lambda call: (calls.append(call), success(call))[1])
    assert calls == []
    assert ctx.completed_steps == 0


def test_budget_stops_without_requesting_extra_proposal():
    ctx = context(max_steps=2)
    proposed_count = 0

    def provider(*_):
        nonlocal proposed_count
        proposed_count += 1
        return pods()

    result = run(ctx, provider)
    assert result.stop_reason == InvestigationStopReason.STEP_BUDGET_EXHAUSTED
    assert len(result.steps) == 2
    assert proposed_count == 2
    assert ctx.completed_steps == 2


def test_failed_tool_stops_and_does_not_mint_observations():
    ctx = context()
    calls = []

    def executor(call):
        calls.append(call)
        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.ERROR,
            output={"pods": [{"name": "untrusted"}]}, error="cluster unavailable",
        )

    result = run(ctx, lambda *_: pods(), executor=executor)
    assert result.stop_reason == InvestigationStopReason.TOOL_FAILED
    assert len(calls) == 1
    assert ctx.completed_steps == 1
    assert ctx.observations == ()


def test_pre_execution_audit_failure_prevents_dispatch():
    ctx = context()
    calls = []

    def audit(event):
        if event.phase == "execution_started":
            raise OSError("audit database unavailable")

    with pytest.raises(OSError, match="audit database unavailable"):
        run(ctx, lambda *_: pods(), audit=audit,
            executor=lambda call: (calls.append(call), success(call))[1])
    assert calls == []
    assert ctx.completed_steps == 0


def test_provider_completion_without_execution():
    ctx = context()
    result = run(ctx, lambda *_: None)
    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert result.steps == ()
    assert ctx.completed_steps == 0


def test_invalid_provider_response_fails_without_execution():
    ctx = context()
    with pytest.raises(TypeError, match="ToolCall or None"):
        run(ctx, lambda *_: {"name": "k8s.get_pods"})
    assert ctx.completed_steps == 0
