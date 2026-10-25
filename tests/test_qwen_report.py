import json

import pytest

from app.reports.evidence import ReportEvidence
from app.reports.qwen_report import (
    QwenReportProvider,
    ReportFormatError,
    build_report_messages,
    parse_report,
)
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.validation import ReportEvidenceError
from tests.test_qwen_report_provider import make_response


def make_snapshot():
    return InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
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


def valid_payload():
    return {
        "investigation_id": "investigation-1",
        "summary": "One pod was discovered.",
        "findings": [
            {
                "title": "Pod discovered",
                "description": "frontend-abc appeared in the pod listing.",
                "severity": "info",
                "evidence": [{"evidence_id": "ev-0001"}],
            }
        ],
        "uncertainties": [
            "Pod health has not been established."
        ],
        "suggested_checks": [
            "Inspect pod status using an authorized read-only tool."
        ],
    }


def test_valid_report_parses():
    report = parse_report(
        json.dumps(valid_payload()),
        snapshot=make_snapshot(),
        expected_investigation_id="investigation-1",
    )

    assert report.findings[0].evidence[0].evidence_id == "ev-0001"


def test_invalid_json_rejected():
    with pytest.raises(ReportFormatError, match="valid JSON"):
        parse_report(
            "not-json",
            snapshot=make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_unknown_evidence_rejected():
    payload = valid_payload()
    payload["findings"][0]["evidence"][0]["evidence_id"] = "ev-9999"

    with pytest.raises(ReportEvidenceError):
        parse_report(
            json.dumps(payload),
            snapshot=make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_cross_investigation_report_rejected():
    payload = valid_payload()
    payload["investigation_id"] = "investigation-2"

    with pytest.raises(ReportEvidenceError):
        parse_report(
            json.dumps(payload),
            snapshot=make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_unknown_report_field_rejected():
    payload = valid_payload()
    payload["execute_command"] = "kubectl delete pod frontend-abc"

    with pytest.raises(ReportFormatError):
        parse_report(
            json.dumps(payload),
            snapshot=make_snapshot(),
            expected_investigation_id="investigation-1",
        )


def test_prompt_contains_only_snapshot_evidence():
    messages = build_report_messages(make_snapshot())

    assert len(messages) == 2

    user_payload = json.loads(messages[1]["content"])

    assert user_payload["investigation_id"] == "investigation-1"
    assert len(user_payload["evidence"]) == 1
    assert user_payload["evidence"][0]["value"] == "frontend-abc"
    

def test_provider_rejects_oversized_report():
    def fake_completion(**kwargs):
        return make_response("x" * 20_001)

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(
        ReportFormatError,
        match="invalid type or length",
    ):
        provider(make_snapshot())