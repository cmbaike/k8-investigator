import pytest

from app.reports.evidence import ReportEvidence
from app.reports.models import (
    EvidenceReference,
    InvestigationFinding,
    InvestigationReport,
)
from app.reports.validation import (
    ReportEvidenceError,
    validate_report_evidence,
)


def make_evidence():
    return (
        ReportEvidence(
            evidence_id="ev-0001",
            request_id="request-1",
            tool="k8s.get_pods",
            field="pods[].name",
            value="example-pod",
        ),
    )


def make_report(evidence_id="ev-0001", investigation_id="investigation-1"):
    return InvestigationReport(
        investigation_id=investigation_id,
        summary="Investigation completed.",
        findings=[
            InvestigationFinding(
                title="Pod discovered",
                description="The pod appeared in the pod listing.",
                severity="info",
                evidence=[
                    EvidenceReference(evidence_id=evidence_id),
                ],
            )
        ],
    )


def test_valid_evidence_reference():
    validate_report_evidence(
        make_report(),
        make_evidence(),
        investigation_id="investigation-1",
    )


def test_fabricated_evidence_reference_rejected():
    with pytest.raises(
        ReportEvidenceError,
        match="outside the trusted snapshot",
    ):
        validate_report_evidence(
            make_report(evidence_id="ev-9999"),
            make_evidence(),
            investigation_id="investigation-1",
        )


def test_cross_investigation_report_rejected():
    with pytest.raises(
        ReportEvidenceError,
        match="investigation ID",
    ):
        validate_report_evidence(
            make_report(investigation_id="another-investigation"),
            make_evidence(),
            investigation_id="investigation-1",
        )


def test_duplicate_evidence_identifiers_rejected():
    evidence = make_evidence()

    with pytest.raises(
        ReportEvidenceError,
        match="duplicate identifiers",
    ):
        validate_report_evidence(
            make_report(),
            evidence + evidence,
            investigation_id="investigation-1",
        )