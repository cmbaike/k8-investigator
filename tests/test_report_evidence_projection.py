from app.reports.evidence import build_report_evidence
from app.tools.investigation import InvestigationContext
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)


def make_context():
    return InvestigationContext(
        investigation_id="investigation-1",
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )


def test_successful_get_pods_creates_report_evidence():
    context = make_context()

    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={
            "namespace": "ai-ops-demo",
            "pods": [
                {"name": "frontend-abc"},
                {"name": "backend-xyz"},
            ]
        },
    )

    context.record_execution(
        request_id="request-1",
        call=call,
        result=result,
    )

    evidence = build_report_evidence(context)

    assert len(evidence) == 2

    assert evidence[0].evidence_id == "ev-0001"
    assert evidence[0].request_id == "request-1"
    assert evidence[0].tool == "k8s.get_pods"
    assert evidence[0].field == "pods[].name"
    assert evidence[0].value == "frontend-abc"

    assert evidence[1].evidence_id == "ev-0002"
    assert evidence[1].value == "backend-xyz"


def test_failed_get_pods_creates_no_report_evidence():
    context = make_context()

    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.ERROR,
        output={
            "pods": [
                {"name": "untrusted-pod"},
            ]
        },
    )

    context.record_execution(
        request_id="request-1",
        call=call,
        result=result,
    )

    assert build_report_evidence(context) == ()


def test_successful_unsupported_tool_creates_no_report_evidence():
    context = make_context()

    call = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "frontend-abc",
        },
    )

    result = ToolExecutionResult(
        tool="k8s.describe_pod",
        status=ToolExecutionStatus.SUCCESS,
        output={
            "phase": "Running",
        },
    )

    context.record_execution(
        request_id="request-1",
        call=call,
        result=result,
    )

    assert build_report_evidence(context) == ()
    
    
def test_evidence_snapshot_does_not_change_after_later_execution():
    context = make_context()

    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    first_result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={"namespace": "ai-ops-demo", "pods": [{"name": "frontend-abc"}]},
    )

    context.record_execution(
        request_id="request-1",
        call=call,
        result=first_result,
    )

    first_snapshot = build_report_evidence(context)

    second_result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={"namespace": "ai-ops-demo", "pods": [{"name": "backend-xyz"}]},
    )

    context.record_execution(
        request_id="request-2",
        call=call,
        result=second_result,
    )

    assert len(first_snapshot) == 1
    assert first_snapshot[0].value == "frontend-abc"

    second_snapshot = build_report_evidence(context)

    assert len(second_snapshot) == 2
    assert second_snapshot[1].value == "backend-xyz"    