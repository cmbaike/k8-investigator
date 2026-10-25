from app.reports.evidence import (
    ReportEvidence,
    build_report_evidence,
)
from app.reports.grounding import build_grounded_report
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.investigation import InvestigationContext
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)


def make_context():
    return InvestigationContext(
        investigation_id="investigation-1",
        user_text="Investigate pod health in namespace demo.",
        authorized_namespace="demo",
    )


def record_describe(context, *, pod, restart_count, request_id):
    context.record_execution(
        request_id=request_id,
        call=ToolCall(
            name="k8s.describe_pod",
            arguments={
                "namespace": "demo",
                "pod": pod,
            },
        ),
        result=ToolExecutionResult(
            tool="k8s.describe_pod",
            status=ToolExecutionStatus.SUCCESS,
            output={
                "namespace": "demo",
                "name": pod,
                "phase": "Running",
                "containers": [
                    {
                        "name": "app",
                        "ready": True,
                        "restart_count": restart_count,
                        "state": "running",
                        "reason": None,
                    }
                ],
            },
        ),
    )


def test_describe_observations_preserve_resource_identity():
    context = make_context()

    record_describe(
        context,
        pod="payments-123",
        restart_count=3,
        request_id="request-1",
    )

    evidence = build_report_evidence(context)

    restart = next(
        item
        for item in evidence
        if item.field == "containers[app].restart_count"
    )

    assert restart.namespace == "demo"
    assert restart.pod == "payments-123"
    assert restart.value == 3


def test_identical_container_names_remain_bound_to_distinct_pods():
    context = make_context()

    record_describe(
        context,
        pod="payments-123",
        restart_count=3,
        request_id="request-1",
    )

    record_describe(
        context,
        pod="payments-456",
        restart_count=0,
        request_id="request-2",
    )

    evidence = build_report_evidence(context)

    restarts = [
        item
        for item in evidence
        if item.field == "containers[app].restart_count"
    ]

    assert len(restarts) == 2

    assert {
        (item.pod, item.value)
        for item in restarts
    } == {
        ("payments-123", 3),
        ("payments-456", 0),
    }


def test_report_identifies_pod_for_container_finding():
    context = make_context()

    record_describe(
        context,
        pod="payments-123",
        restart_count=3,
        request_id="request-1",
    )

    evidence = build_report_evidence(context)

    snapshot = InvestigationEvidenceSnapshot(
        investigation_id=context.investigation_id,
        evidence=evidence,
    )

    report = build_grounded_report(snapshot)

    restart_finding = next(
        finding
        for finding in report.findings
        if finding.title == "Container restart count observed"
    )

    assert "payments-123" in restart_finding.description
    assert "demo" in restart_finding.description
    assert "3" in restart_finding.description


def test_mismatched_describe_identity_produces_no_evidence():
    context = make_context()

    context.record_execution(
        request_id="request-1",
        call=ToolCall(
            name="k8s.describe_pod",
            arguments={
                "namespace": "demo",
                "pod": "payments-123",
            },
        ),
        result=ToolExecutionResult(
            tool="k8s.describe_pod",
            status=ToolExecutionStatus.SUCCESS,
            output={
                "namespace": "demo",
                "name": "different-pod",
                "phase": "Running",
                "containers": [],
            },
        ),
    )

    assert build_report_evidence(context) == ()
    
import pytest


@pytest.mark.parametrize(
    ("namespace", "pod"),
    [
        (None, "payments-123"),
        ("demo", None),
        (None, None),
    ],
)
def test_unbound_describe_evidence_produces_no_findings(
    namespace,
    pod,
):
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        field="containers[app].restart_count",
        value=3,
        namespace=namespace,
        pod=pod,
    )

    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(evidence,),
    )

    report = build_grounded_report(snapshot)

    assert report.findings == []
    
    
def test_observed_health_fields_are_not_reported_as_unknown():
    context = make_context()

    record_describe(
        context,
        pod="payments-123",
        restart_count=3,
        request_id="request-1",
    )

    snapshot = InvestigationEvidenceSnapshot(
        investigation_id=context.investigation_id,
        evidence=build_report_evidence(context),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "Pod phase has not been established" not in uncertainties
    assert "Container readiness has not been established" not in uncertainties
    assert "Container restart counts have not been established" not in uncertainties

    assert "Underlying failure causes" in uncertainties


def test_missing_health_fields_remain_uncertain():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "Pod phase has not been established" in uncertainties
    assert "Container readiness has not been established" in uncertainties
    assert "Container restart counts have not been established" in uncertainties
    assert "Underlying failure causes" in uncertainties        
    
    
def test_uncertainties_are_tracked_per_pod():
    context = make_context()

    record_describe(
        context,
        pod="payments-123",
        restart_count=3,
        request_id="request-1",
    )

    # A second pod is discovered but not described.
    context.record_execution(
        request_id="request-2",
        call=ToolCall(
            name="k8s.get_pods",
            arguments={"namespace": "demo"},
        ),
        result=ToolExecutionResult(
            tool="k8s.get_pods",
            status=ToolExecutionStatus.SUCCESS,
            output={
                "namespace": "demo",
                "pods": [
                    {"name": "payments-456"},
                ],
            },
        ),
    )

    snapshot = InvestigationEvidenceSnapshot(
        investigation_id=context.investigation_id,
        evidence=build_report_evidence(context),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "payments-456" in uncertainties
    # The described pod is not reported as uninspected. Its recorded restarts
    # do owe a disclosure that the Kubernetes events were not retrieved, and
    # that is the only thing said about it.
    about_123 = [u for u in report.uncertainties if "payments-123" in u]
    assert all("events for the pod were not retrieved" in u for u in about_123)
    assert "container readiness has not been established" in uncertainties


def test_invalid_health_evidence_does_not_establish_coverage():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].restart_count",
                value=-5,
                namespace="demo",
                pod="payments-123",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "payments-123" in uncertainties
    assert "container restart counts have not been established" in uncertainties  


def test_container_coverage_is_tracked_independently():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="app",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0002",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=True,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0003",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].restart_count",
                value=0,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0004",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="sidecar",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0005",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[sidecar].ready",
                value=True,
                namespace="demo",
                pod="payments-123",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "sidecar" in uncertainties
    assert "restart count" in uncertainties
    assert "app" not in uncertainties  
    
    
def test_latest_describe_execution_does_not_inherit_older_health_fields():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="app",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0002",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=False,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0003",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].restart_count",
                value=3,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0004",
                request_id="request-2",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="app",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0005",
                request_id="request-2",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=True,
                namespace="demo",
                pod="payments-123",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "container 'app': restart count has not been established" in uncertainties 
    

def test_historical_findings_include_execution_attribution():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-1",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=False,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0002",
                request_id="request-2",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=True,
                namespace="demo",
                pod="payments-123",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    readiness_findings = [
        finding
        for finding in report.findings
        if finding.title == "Container readiness observed"
    ]

    assert len(readiness_findings) == 2

    descriptions = [
        finding.description
        for finding in readiness_findings
    ]

    assert any(
        "request-1" in description
        and "False" in description
        for description in descriptions
    )

    assert any(
        "request-2" in description
        and "True" in description
        for description in descriptions
    )

    assert all(
        "payments-123" in description
        and "demo" in description
        for description in descriptions
    )
    
    
def test_latest_execution_follows_snapshot_evidence_order():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-9",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="app",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0002",
                request_id="request-9",
                tool="k8s.describe_pod",
                field="containers[app].restart_count",
                value=3,
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0003",
                request_id="request-2",
                tool="k8s.describe_pod",
                field="containers[].name",
                value="app",
                namespace="demo",
                pod="payments-123",
            ),
            ReportEvidence(
                evidence_id="ev-0004",
                request_id="request-2",
                tool="k8s.describe_pod",
                field="containers[app].ready",
                value=True,
                namespace="demo",
                pod="payments-123",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    uncertainties = " ".join(report.uncertainties)

    assert "container 'app': restart count has not been established" in uncertainties
    assert "container 'app': readiness has not been established" not in uncertainties       