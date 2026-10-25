from app.reports.evidence import ReportEvidence
from app.reports.grounding import (
    build_grounded_report,
)
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.validation import validate_report_snapshot
from app.reports.evidence import ReportEvidence
from app.reports.grounding import describe_verified_observation


def make_snapshot(evidence=()):
    return InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=evidence,
    )


def pod_evidence(
    *,
    evidence_id="ev-0001",
    value="payments-api-123",
):
    return ReportEvidence(
        evidence_id=evidence_id,
        request_id="request-1",
        tool="k8s.get_pods",
        field="pods[].name",
        value=value,
    )


def test_pod_discovery_produces_verified_finding():
    snapshot = make_snapshot((pod_evidence(),))

    report = build_grounded_report(snapshot)

    assert report.investigation_id == snapshot.investigation_id
    assert len(report.findings) == 1

    finding = report.findings[0]

    assert finding.title == "Pod discovered"
    assert finding.severity == "info"
    assert "payments-api-123" in finding.description
    assert finding.evidence[0].evidence_id == "ev-0001"

    validate_report_snapshot(
        report,
        snapshot,
        expected_investigation_id="investigation-1",
    )


def test_discovery_report_explicitly_records_health_uncertainty():
    report = build_grounded_report(
        make_snapshot((pod_evidence(),))
    )

    assert (
        "Pod phase has not been established by trusted report evidence."
        in report.uncertainties
    )
    assert (
        "Container readiness has not been established by trusted report evidence."
        in report.uncertainties
    )
    assert (
        "Container restart counts have not been established by trusted report evidence."
        in report.uncertainties
    )
    assert any(
        "Underlying failure causes" in uncertainty
        for uncertainty in report.uncertainties
    )


def test_unknown_evidence_field_cannot_produce_verified_finding():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.get_logs",
        field="log.message",
        value="CrashLoopBackOff",
    )

    report = build_grounded_report(
        make_snapshot((evidence,))
    )

    assert report.findings == []


def test_multiple_pods_have_distinct_evidence_references():
    snapshot = make_snapshot(
        (
            pod_evidence(
                evidence_id="ev-0001",
                value="frontend-123",
            ),
            pod_evidence(
                evidence_id="ev-0002",
                value="backend-456",
            ),
        )
    )

    report = build_grounded_report(snapshot)

    assert len(report.findings) == 2

    assert [
        finding.evidence[0].evidence_id
        for finding in report.findings
    ] == ["ev-0001", "ev-0002"]
    
    
import pytest


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("pod.phase", "Running", "Running"),
        ("containers[payments].ready", False, "False"),
        ("containers[payments].restart_count", 3, "3"),
        ("containers[payments].state", "waiting", "waiting"),
        (
            "containers[payments].reason",
            "CrashLoopBackOff",
            "CrashLoopBackOff",
        ),
    ],
)
def test_structured_health_observation_produces_finding(
    field,
    value,
    expected,
):
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        namespace="demo",
        pod="payments-123",
        field=field,
        value=value,
    )

    snapshot = make_snapshot((evidence,))
    report = build_grounded_report(snapshot)

    assert len(report.findings) == 1

    finding = report.findings[0]

    assert finding.severity == "info"
    assert expected in finding.description
    assert finding.evidence[0].evidence_id == "ev-0001"

    validate_report_snapshot(
        report,
        snapshot,
        expected_investigation_id="investigation-1",
    )


def test_unknown_health_field_is_not_rendered():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        namespace="demo",
        pod="payments-123",
        field="containers[payments].secret",
        value="sensitive",
    )

    report = build_grounded_report(
        make_snapshot((evidence,))
    )

    assert report.findings == []


def test_invalid_restart_count_is_not_rendered():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        namespace="demo",
        pod="payments-123",
        field="containers[payments].restart_count",
        value=-1,
    )

    report = build_grounded_report(
        make_snapshot((evidence,))
    )

    assert report.findings == []


def test_malformed_container_field_is_not_rendered():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        namespace="demo",
        pod="payments-123",
        field="containers[payments].ready.extra",
        value=True,
    )

    report = build_grounded_report(
        make_snapshot((evidence,))
    )

    assert report.findings == []  
    
def test_empty_evidence_produces_no_findings():
    report = build_grounded_report(make_snapshot())

    assert report.findings == []

    assert (
        "Pod phase has not been established by trusted report evidence."
        in report.uncertainties
    )
    assert (
        "Container readiness has not been established by trusted report evidence."
        in report.uncertainties
    )
    assert (
        "Container restart counts have not been established by trusted report evidence."
        in report.uncertainties
    )
    assert any(
        "Underlying failure causes" in uncertainty
        for uncertainty in report.uncertainties
    ) 
    
def test_grounded_report_discloses_truncated_evidence():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-truncated",
        evidence=(),
        truncated=True,
    )

    report = build_grounded_report(snapshot)

    assert any(
        "truncated at 100 observations" in uncertainty
        for uncertainty in report.uncertainties
    )
    
def test_truncated_snapshot_does_not_claim_latest_execution_coverage():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-truncated",
        evidence=(),
        truncated=True,
    )

    report = build_grounded_report(snapshot)

    assert any(
        "Latest-execution health coverage cannot be established"
        in uncertainty
        for uncertainty in report.uncertainties
    )
    
def test_grounded_report_includes_verified_log_retrieval():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-log-retrieval",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="req-investigation-step-3",
                tool="k8s.get_logs",
                field="logs.retrieved",
                value=True,
                namespace="ai-ops-demo",
                pod="payments-api",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    assert report.investigation_id == "inv-log-retrieval"

    assert len(report.findings) == 1

    finding = report.findings[0]

    assert finding.title == "Container logs retrieved"
    assert finding.severity == "info"

    assert len(finding.evidence) == 1
    assert finding.evidence[0].evidence_id == "ev-0001"

    # Resource attribution must be preserved.
    assert "ai-ops-demo" in finding.description
    assert "payments-api" in finding.description

    # The originating execution must remain traceable.
    assert "req-investigation-step-3" in finding.description

    # Retrieval is not equivalent to verified diagnosis.
    assert "retrieved successfully" in finding.description
    assert "root-cause evidence" in finding.description

    # The report must retain uncertainty about the underlying cause.
    assert any(
        "Underlying failure causes" in uncertainty
        for uncertainty in report.uncertainties
    )
    
    
def test_bounded_log_evidence_adds_report_uncertainty():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-test",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="req-logs-1",
                tool="k8s.get_logs",
                field="logs.completeness",
                value="bounded_unknown",
                namespace="ai-ops-demo",
                pod="example-pod",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    assert any(
        "retrieved excerpt may omit relevant log entries" in uncertainty
        for uncertainty in report.uncertainties
    )
    
def test_log_retrieval_alone_does_not_establish_completeness():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-test",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="req-logs-1",
                tool="k8s.get_logs",
                field="logs.retrieved",
                value=True,
                namespace="ai-ops-demo",
                pod="example-pod",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    assert not any(
        "retrieved excerpt may omit relevant log entries" in uncertainty
        for uncertainty in report.uncertainties
    )
    
def test_log_retrieval_alone_does_not_establish_completeness():
    snapshot = InvestigationEvidenceSnapshot(
        investigation_id="inv-test",
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="req-logs-1",
                tool="k8s.get_logs",
                field="logs.retrieved",
                value=True,
                namespace="ai-ops-demo",
                pod="example-pod",
            ),
        ),
    )

    report = build_grounded_report(snapshot)

    assert not any(
        "retrieved excerpt may omit relevant log entries" in uncertainty
        for uncertainty in report.uncertainties
    )

def test_grounding_previous_container_exit_code():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        field="containers[payments].last_termination.exit_code",
        value=1,
        namespace="demo",
        pod="payments-api-123",
    )

    observation = describe_verified_observation(evidence)

    assert observation is not None

    title, description = observation

    assert title == "Previous container exit code observed"
    assert "exit code 1" in description


def test_grounding_rejects_boolean_exit_code():
    evidence = ReportEvidence(
        evidence_id="ev-0001",
        request_id="request-1",
        tool="k8s.describe_pod",
        field="containers[payments].last_termination.exit_code",
        value=True,
        namespace="demo",
        pod="payments-api-123",
    )

    assert describe_verified_observation(evidence) is None                