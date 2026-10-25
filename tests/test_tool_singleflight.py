"""Single-flight tests using real threads, no database or Kubernetes required."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

import pytest

from app.tools.investigation import (
    InvestigationConcurrentExecutionError,
    InvestigationContext,
    InvestigationStepLimitError,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.orchestrator import execute_investigation_step


USER_TEXT = "Investigate the failing workload in namespace ai-ops-demo."


def make_context(max_steps=6):
    return InvestigationContext(
        investigation_id="inv-singleflight",
        user_text=USER_TEXT,
        authorized_namespace="ai-ops-demo",
        max_steps=max_steps,
    )


def call():
    return ToolCall(name="k8s.get_pods", arguments={"namespace": "ai-ops-demo"})


def result():
    return ToolExecutionResult(
        tool="k8s.get_pods", status=ToolExecutionStatus.SUCCESS, output={"pods": []}
    )


def run(ctx, *, executor=lambda _: result(), audit=lambda _: None, request_id="req-1"):
    return execute_investigation_step(
        context=ctx, request_id=request_id, proposed_call=call(),
        executor=executor, audit=audit,
    )


def test_second_execution_rejected_while_first_is_in_executor():
    ctx = make_context(max_steps=1)
    entered, release = Event(), Event()
    executed = []

    def blocking_executor(bound):
        executed.append(bound)
        entered.set()
        assert release.wait(timeout=5), "Test timed out waiting to release executor"
        return result()

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(run, ctx, executor=blocking_executor)
        try:
            assert entered.wait(timeout=5)
            with pytest.raises(InvestigationConcurrentExecutionError):
                run(ctx, executor=lambda bound: executed.append(bound), request_id="req-2")
        finally:
            release.set()
        assert first.result(timeout=5).status == ToolExecutionStatus.SUCCESS

    assert len(executed) == 1
    assert ctx.completed_steps == 1
    with pytest.raises(InvestigationStepLimitError):
        run(ctx, request_id="req-3")


def test_pre_execution_audit_failure_releases_lease():
    ctx = make_context()

    def failing_audit(event):
        if event.phase == "execution_started":
            raise OSError("audit unavailable")

    with pytest.raises(OSError, match="audit unavailable"):
        run(ctx, audit=failing_audit)
    assert ctx.completed_steps == 0
    assert run(ctx).status == ToolExecutionStatus.SUCCESS
    assert ctx.completed_steps == 1


def test_executor_failure_releases_lease_and_consumes_step():
    ctx = make_context(max_steps=2)

    def failing_executor(_):
        raise RuntimeError("cluster unavailable")

    first = run(ctx, executor=failing_executor)
    assert first.status == ToolExecutionStatus.ERROR
    assert ctx.completed_steps == 1
    assert run(ctx, request_id="req-2").status == ToolExecutionStatus.SUCCESS
    assert ctx.completed_steps == 2


def test_completion_audit_failure_releases_lease_but_does_not_undo_execution():
    ctx = make_context(max_steps=2)

    def failing_audit(event):
        if event.phase == "completed":
            raise OSError("completion audit unavailable")

    with pytest.raises(OSError, match="completion audit unavailable"):
        run(ctx, audit=failing_audit)
    assert ctx.completed_steps == 1
    assert run(ctx, request_id="req-2").status == ToolExecutionStatus.SUCCESS
    assert ctx.completed_steps == 2


def test_lease_released_when_authorization_rejects_call():
    ctx = make_context()
    with pytest.raises(Exception):
        execute_investigation_step(
            context=ctx, request_id="req-bad",
            proposed_call=ToolCall(name="k8s.get_pods", arguments={"namespace": "production"}),
            audit=lambda _: None,
        )
    assert run(ctx).status == ToolExecutionStatus.SUCCESS
