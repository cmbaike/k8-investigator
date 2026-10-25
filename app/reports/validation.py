import re
from collections.abc import Sequence

from app.reports.evidence import ReportEvidence
from app.reports.models import InvestigationReport
from app.reports.models import InvestigationReport
from app.reports.snapshot import InvestigationEvidenceSnapshot


class ReportEvidenceError(ValueError):
    pass


def validate_report_evidence(
    report: InvestigationReport,
    evidence: Sequence[ReportEvidence],
    *,
    investigation_id: str,
) -> None:
    """Reject reports citing evidence outside the supplied snapshot."""

    if report.investigation_id != investigation_id:
        raise ReportEvidenceError(
            "Report investigation ID does not match the investigation."
        )

    evidence_ids = [item.evidence_id for item in evidence]

    if len(evidence_ids) != len(set(evidence_ids)):
        raise ReportEvidenceError(
            "Evidence snapshot contains duplicate identifiers."
        )

    allowed_ids = set(evidence_ids)

    for finding in report.findings:
        for reference in finding.evidence:
            if reference.evidence_id not in allowed_ids:
                raise ReportEvidenceError(
                    "Report references evidence outside the trusted snapshot."
                )
                
def validate_report_snapshot(
    report: InvestigationReport,
    snapshot: InvestigationEvidenceSnapshot,
    *,
    expected_investigation_id: str,
) -> None:
    """Validate report identity and references against one trusted snapshot."""

    if snapshot.investigation_id != expected_investigation_id:
        raise ReportEvidenceError(
            "Evidence snapshot belongs to another investigation."
        )

    if report.investigation_id != expected_investigation_id:
        raise ReportEvidenceError(
            "Report investigation ID does not match the investigation."
        )

    allowed_ids = {
        item.evidence_id
        for item in snapshot.evidence
    }

    for finding in report.findings:
        for reference in finding.evidence:
            if reference.evidence_id not in allowed_ids:
                raise ReportEvidenceError(
                    "Report references evidence outside the trusted snapshot."
                )

    _validate_scheduling_constraints(report, snapshot)

    discovery_only = all(
        item.tool == "k8s.get_pods"
        and item.field == "pods[].name"
        for item in snapshot.evidence
    )

    if discovery_only:
        for finding in report.findings:
            if finding.severity != "info":
                raise ReportEvidenceError(
                    "Discovery-only evidence cannot support diagnostic severity."
                )                            

def _validate_scheduling_constraints(
    report: InvestigationReport, snapshot: InvestigationEvidenceSnapshot
) -> None:
    """A scheduling constraint row must rest on signal observations the
    application recorded: each cited observation is the matching classified
    signal and was True. The label is fixed by the model; nothing here trusts
    a report's own claim that a constraint exists."""
    observed = {item.evidence_id: item for item in snapshot.evidence}

    for finding in report.findings:
        for constraint in finding.scheduling_constraints:
            suffix = re.compile(rf"\.signal\[{re.escape(constraint.signal)}\]$")

            for reference in constraint.evidence_ids:
                item = observed.get(reference)

                if item is None or item.value is not True or not suffix.search(item.field):
                    raise ReportEvidenceError(
                        "Scheduling constraint is not supported by a recorded signal."
                    )
