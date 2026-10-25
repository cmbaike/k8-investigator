"""Run-level lease tests; no live model, Kubernetes, or database needed."""
from threading import Event, Thread

import pytest

from app.tools.investigation import InvestigationConcurrentRunError, InvestigationContext
from app.tools.investigation_controller import InvestigationStopReason, run_investigation
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus


def context():
    return InvestigationContext(
        investigation_id="inv-run-lease", user_text="Investigate pods in namespace ai-ops-demo",
        authorized_namespace="ai-ops-demo", max_steps=3,
    )


def pods():
    return ToolCall(name="k8s.get_pods", arguments={"namespace": "ai-ops-demo"})


def success(call):
    return ToolExecutionResult(tool=call.name, status=ToolExecutionStatus.SUCCESS, output={"pods": []})


def run(ctx, provider, *, audit=lambda _: None, executor=success):
    return run_investigation(context=ctx, provider=provider, audit=audit, executor=executor)


def test_second_run_rejected_while_first_provider_is_active():
    ctx = context()
    entered, release = Event(), Event()
    errors = []
    calls = []

    def blocked_provider(*_):
        entered.set()
        if not release.wait(timeout=5):
            raise TimeoutError("test provider wait timed out")
        return None

    def worker():
        try:
            run(ctx, blocked_provider)
        except Exception as exc:
            errors.append(exc)

    thread = Thread(target=worker)
    thread.start()
    try:
        assert entered.wait(timeout=5)
        with pytest.raises(InvestigationConcurrentRunError):
            run(ctx, lambda *_: (calls.append("proposed"), pods())[1])
        assert calls == []
        assert ctx.completed_steps == 0
    finally:
        release.set()
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert errors == []


def test_run_lease_released_after_provider_error():
    ctx = context()

    def fail(*_):
        raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        run(ctx, fail)
    assert run(ctx, lambda *_: None).stop_reason == InvestigationStopReason.PROVIDER_FINISHED


def test_run_lease_released_after_pre_dispatch_audit_error():
    ctx = context()

    def fail_audit(event):
        if event.phase == "execution_started":
            raise OSError("audit unavailable")

    with pytest.raises(OSError, match="audit unavailable"):
        run(ctx, lambda *_: pods(), audit=fail_audit)
    assert ctx.completed_steps == 0
    assert run(ctx, lambda *_: None).stop_reason == InvestigationStopReason.PROVIDER_FINISHED


def test_run_lease_released_after_success_and_budget_preserved():
    ctx = context()
    first = run(ctx, lambda _, history: pods() if not history else None)
    assert first.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert ctx.completed_steps == 1
    second = run(ctx, lambda *_: pods())
    assert second.stop_reason == InvestigationStopReason.STEP_BUDGET_EXHAUSTED
    assert ctx.completed_steps == 3


def test_run_lease_released_after_rejected_proposal():
    ctx = context()
    bad = ToolCall(name="k8s.get_pods", arguments={"namespace": "production"})
    with pytest.raises(Exception):
        run(ctx, lambda *_: bad)
    assert ctx.completed_steps == 0
    assert run(ctx, lambda *_: None).stop_reason == InvestigationStopReason.PROVIDER_FINISHED
