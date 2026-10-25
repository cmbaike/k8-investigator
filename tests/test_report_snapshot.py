import pytest

from app.reports.evidence import ReportEvidence
from app.reports.models import (
    EvidenceReference,
    InvestigationFinding,
    InvestigationReport,
)
from app.reports.snapshot import InvestigationEvidenceSnapshot, build_investigation_evidence_snapshot
from app.reports.validation import (
    ReportEvidenceError,
    validate_report_snapshot,
)
from app.tools.investigation import InvestigationContext
from app.tools.observations import TrustedToolObservation


def make_snapshot(investigation_id="investigation-1"):
    return InvestigationEvidenceSnapshot(
        investigation_id=investigation_id,
        evidence=(
            ReportEvidence(
                evidence_id="ev-0001",
                request_id="request-1",
                tool="k8s.get_pods",
                field="pods[].name",
                value="frontend-abc",
            ),
        ),
    )


def make_report(investigation_id="investigation-1"):
    return InvestigationReport(
        investigation_id=investigation_id,
        summary="Pod discovery completed.",
        findings=[
            InvestigationFinding(
                title="Pod discovered",
                description="frontend-abc was returned by the pod listing.",
                severity="info",
                evidence=[
                    EvidenceReference(evidence_id="ev-0001"),
                ],
            )
        ],
    )


def test_report_matches_snapshot():
    validate_report_snapshot(
        make_report(),
        make_snapshot(),
        expected_investigation_id="investigation-1",
    )


def test_rejects_snapshot_from_another_investigation():
    with pytest.raises(
        ReportEvidenceError,
        match="another investigation",
    ):
        validate_report_snapshot(
            make_report(),
            make_snapshot(investigation_id="investigation-2"),
            expected_investigation_id="investigation-1",
        )


def test_rejects_report_from_another_investigation():
    with pytest.raises(
        ReportEvidenceError,
        match="Report investigation ID",
    ):
        validate_report_snapshot(
            make_report(investigation_id="investigation-2"),
            make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_rejects_unknown_evidence_reference():
    report = make_report()

    report = report.model_copy(
        update={
            "findings": [
                report.findings[0].model_copy(
                    update={
                        "evidence": [
                            EvidenceReference(evidence_id="ev-9999")
                        ]
                    }
                )
            ]
        }
    )

    with pytest.raises(
        ReportEvidenceError,
        match="outside the trusted snapshot",
    ):
        validate_report_snapshot(
            report,
            make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_rejects_duplicate_evidence_ids():
    evidence = make_snapshot().evidence[0]

    with pytest.raises(ValueError, match="duplicate identifiers"):
        InvestigationEvidenceSnapshot(
            investigation_id="investigation-1",
            evidence=(evidence, evidence),
        )
        
        
def test_snapshot_reports_truncation_when_evidence_limit_is_exceeded():
    context = InvestigationContext(
        investigation_id="inv-truncated",
        user_text="Investigate workloads.",
        authorized_namespace="ai-ops-demo",
    )

    for index in range(101):
        context._observations.append(
            TrustedToolObservation(
                request_id=f"request-{index}",
                tool="k8s.get_pods",
                field="pods[].name",
                value=f"pod-{index}",
                namespace="ai-ops-demo",
                pod=f"pod-{index}",
            )
        )

    snapshot = build_investigation_evidence_snapshot(context)

    assert len(snapshot.evidence) == 100
    assert snapshot.truncated is True        