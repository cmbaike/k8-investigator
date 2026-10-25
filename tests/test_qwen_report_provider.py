import json
from types import SimpleNamespace

import pytest

from app.reports.evidence import ReportEvidence
from app.reports.qwen_report import (
    QwenReportProvider,
    ReportFormatError,
)
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.validation import ReportEvidenceError


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


def make_response(content):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(content=content)
            )
        ]
    )


def make_payload(evidence_id="ev-0001"):
    return {
        "investigation_id": "investigation-1",
        "summary": "One pod was discovered.",
        "findings": [
            {
                "title": "Pod discovered",
                "description": "frontend-abc appeared in the pod listing.",
                "severity": "info",
                "evidence": [
                    {"evidence_id": evidence_id}
                ],
            }
        ],
        "uncertainties": [
            "Pod health has not been established."
        ],
        "suggested_checks": [],
    }


def test_provider_generates_valid_report_without_tools():
    captured = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return make_response(json.dumps(make_payload()))

    provider = QwenReportProvider(
        completion=fake_completion,
        model="test-model",
    )

    report = provider(make_snapshot())

    assert report.investigation_id == "investigation-1"
    assert report.findings[0].evidence[0].evidence_id == "ev-0001"

    assert captured["model"] == "test-model"
    assert captured["temperature"] == 0

    assert "tools" not in captured
    assert "tool_choice" not in captured

    assert captured["extra_body"] == {
        "chat_template_kwargs": {
            "enable_thinking": False
        }
    }


def test_provider_rejects_fabricated_evidence():
    def fake_completion(**kwargs):
        return make_response(
            json.dumps(make_payload(evidence_id="ev-9999"))
        )

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(ReportEvidenceError):
        provider(make_snapshot())


def test_provider_rejects_malformed_json():
    def fake_completion(**kwargs):
        return make_response("not-json")

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(ReportFormatError):
        provider(make_snapshot())


def test_provider_rejects_multiple_choices():
    def fake_completion(**kwargs):
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="{}")
                ),
                SimpleNamespace(
                    message=SimpleNamespace(content="{}")
                ),
            ]
        )

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(
        ReportFormatError,
        match="exactly one",
    ):
        provider(make_snapshot())


def test_provider_rejects_missing_content():
    def fake_completion(**kwargs):
        return make_response(None)

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(
        ReportFormatError,
        match="no textual report",
    ):
        provider(make_snapshot())


def test_provider_rejects_invalid_timeout():
    with pytest.raises(ValueError, match="Timeout"):
        QwenReportProvider(
            completion=lambda **kwargs: None,
            timeout=0,
        )


def test_provider_sanitizes_model_request_failure():
    def fake_completion(**kwargs):
        raise RuntimeError("Sensitive internal error")

    provider = QwenReportProvider(completion=fake_completion)

    with pytest.raises(
        ReportFormatError,
        match=r"request failed \(RuntimeError\)",
    ) as exc_info:
        provider(make_snapshot())

    assert "Sensitive internal error" not in str(exc_info.value)