import pytest

from dataclasses import replace
from app.reports.grounding import build_grounded_report
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.tools.investigation import InvestigationContext
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.tools.observations import observations_from_execution


def make_call(*, previous=False):
    return ToolCall(
        name=(
            "k8s.get_previous_logs"
            if previous
            else "k8s.get_logs"
        ),
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "example-pod",
            "container": "app",
            "tail": 50,
        },
    )


def make_result(call, *, completeness="bounded_unknown", **overrides):
    output = {
        "namespace": "ai-ops-demo",
        "pod": "example-pod",
        "container": "app",
        "tail": 50,
        "previous": call.name == "k8s.get_previous_logs",
        "logs": "example log",
        "completeness": completeness,
    }
    output.update(overrides)

    return ToolExecutionResult(
        tool=call.name,
        status=ToolExecutionStatus.SUCCESS,
        output=output,
    )


@pytest.mark.parametrize("previous", [False, True])
def test_bounded_logs_produce_trusted_completeness_observation(previous):
    call = make_call(previous=previous)
    result = make_result(call)

    observations = observations_from_execution(
        request_id="req-logs-1",
        call=call,
        result=result,
    )

    assert [(item.field, item.value) for item in observations] == [
        ("logs.retrieved", True),
        ("logs.completeness", "bounded_unknown"),
    ]

    assert all(
        item.namespace == "ai-ops-demo"
        and item.pod == "example-pod"
        and item.request_id == "req-logs-1"
        and item.tool == call.name
        for item in observations
    )


@pytest.mark.parametrize("previous", [False, True])
def test_log_extractor_rejects_wrong_previous_flag(previous):
    call = make_call(previous=previous)

    result = make_result(
        call,
        previous=not previous,
    )

    assert observations_from_execution(
        request_id="req-logs-1",
        call=call,
        result=result,
    ) == []


@pytest.mark.parametrize("previous", [False, True])
def test_unknown_completeness_does_not_become_evidence(previous):
    call = make_call(previous=previous)
    result = make_result(call, completeness="complete")

    observations = observations_from_execution(
        request_id="req-logs-1",
        call=call,
        result=result,
    )

    assert [(item.field, item.value) for item in observations] == [
        ("logs.retrieved", True),
    ]


def test_mismatched_resource_produces_no_log_observations():
    call = make_call()

    result = make_result(
        call,
        namespace="other-namespace",
    )

    assert observations_from_execution(
        request_id="req-logs-1",
        call=call,
        result=result,
    ) == []
    

def test_bounded_log_result_reaches_grounded_report():
    call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "example-pod",
            "container": "app",
            "tail": 50,
        },
    )

    result = ToolExecutionResult(
        tool="k8s.get_logs",
        status=ToolExecutionStatus.SUCCESS,
        output={
            "namespace": "ai-ops-demo",
            "pod": "example-pod",
            "container": "app",
            "tail": 50,
            "previous": False,
            "logs": "example log",
            "retrieval_limits": {
                "tail_lines": 50,
                "limit_bytes": 32768,
            },
            "completeness": "bounded_unknown",
        },
    )

    context = InvestigationContext(
        investigation_id="inv-test",
        user_text="Investigate example-pod logs.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )
    
    minted = context.record_execution(
        request_id="req-logs-1",
        call=call,
        result=result,
    )
    
    assert [(item.field, item.value) for item in minted] == [
      ("logs.retrieved", True),
      ("logs.completeness", "bounded_unknown"),
    ]

    assert context.completed_steps == 1

    snapshot = build_investigation_evidence_snapshot(context)
    report = build_grounded_report(snapshot)

    assert any(
        item.field == "logs.completeness"
        and item.value == "bounded_unknown"
        for item in snapshot.evidence
    )

    assert any(
        "retrieved excerpt may omit relevant log entries"
        in uncertainty
        for uncertainty in report.uncertainties
    )    
