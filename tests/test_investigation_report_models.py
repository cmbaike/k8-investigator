import pytest
from pydantic import ValidationError

from app.reports.models import (
    EvidenceReference,
    InvestigationFinding,
    InvestigationReport,
)


def test_valid_report():
    report = InvestigationReport(
        investigation_id="investigation-123",
        summary="Pod investigation completed.",
        findings=[
            InvestigationFinding(
                title="Pod inspected",
                description="The pod was inspected successfully.",
                severity="info",
                evidence=[
                    EvidenceReference(evidence_id="ev-0001")
                ],
            )
        ],
    )

    assert len(report.findings) == 1


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        InvestigationFinding(
            title="Pod unhealthy",
            description="The pod is unhealthy.",
            severity="critical",
            evidence=[],
        )


def test_report_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        InvestigationReport(
            investigation_id="investigation-123",
            summary="Investigation completed.",
            unexpected="not allowed",
        )


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        InvestigationFinding(
            title="Pod inspected",
            description="Inspection completed.",
            severity="urgent",
            evidence=[
                EvidenceReference(
                    observation_id="observation-123"
                )
            ],
        )