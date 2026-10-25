import json
from typing import Any

from pydantic import ValidationError

from app.reports.models import InvestigationReport
from app.reports.scheduling_semantics import inverted_taint_toleration
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.validation import validate_report_snapshot
from typing import Callable

from app.llm import VLLM_MODEL, client
from app.reports.validation import ReportEvidenceError


MAX_REPORT_RESPONSE_CHARS = 20_000

Completion = Callable[..., Any]


class QwenReportProvider:
    """Generate a report from an existing trusted evidence snapshot.

    This provider has no Kubernetes executor, tool registry, or
    investigation-controller dependency.
    """

    def __init__(
        self,
        *,
        completion: Completion | None = None,
        model: str = VLLM_MODEL,
        timeout: float = 20.0,
    ) -> None:
        if timeout <= 0:
            raise ValueError("Timeout must be positive.")

        self._completion = (
            completion
            if completion is not None
            else client.chat.completions.create
        )
        self._model = model
        self._timeout = timeout

    def __call__(
        self,
        snapshot: InvestigationEvidenceSnapshot,
    ) -> InvestigationReport:
        messages = build_report_messages(snapshot)

        try:
            response = self._completion(
                model=self._model,
                messages=messages,
                temperature=0,
                max_tokens=800,
                timeout=self._timeout,
                extra_body={
                    "chat_template_kwargs": {
                        "enable_thinking": False,
                    },
                },
            )
        except Exception as exc:
            raise ReportFormatError(
                f"Report generation request failed ({type(exc).__name__})."
            ) from exc

        try:
            choices = response.choices

            if len(choices) != 1:
                raise ReportFormatError(
                    "Expected exactly one report response."
                )

            content = choices[0].message.content

            if not isinstance(content, str):
                raise ReportFormatError(
                    "Model returned no textual report."
                )

        except ReportFormatError:
            raise
        except (AttributeError, TypeError) as exc:
            raise ReportFormatError(
                "Malformed report completion response."
            ) from exc

        return parse_report(
            content,
            snapshot=snapshot,
            expected_investigation_id=snapshot.investigation_id,
        )

class ReportFormatError(ValueError):
    """Qwen returned an invalid investigation report."""


REPORT_SYSTEM_PROMPT = """
You are a Kubernetes investigation report writer.

You receive a trusted evidence snapshot from a completed investigation.

Rules:
- Use only the supplied evidence.
- Never invent Kubernetes resources, failures, events, or log messages.
- Never claim a pod is healthy or unhealthy based only on its name.
- Every finding must cite one or more supplied evidence IDs.
- Do not cite evidence IDs that are not supplied.
- If the evidence is insufficient, explain the uncertainty.
- Suggested checks are recommendations only, not executable commands.
- Do not propose remediation as an executed action.
- Return exactly one JSON object.
- Do not include Markdown or explanatory text outside the JSON.

Required JSON structure:
{
  "investigation_id": "string",
  "summary": "string",
  "findings": [
    {
      "title": "string",
      "description": "string",
      "severity": "info",
      "evidence": [
        {"evidence_id": "ev-0001"}
      ]
    }
  ],
  "uncertainties": ["string"],
  "suggested_checks": ["string"]
}

Allowed severity values:
info, warning, critical, unknown.

If no findings are supported, return an empty findings array.
"""


def parse_report(
    content: str,
    *,
    snapshot: InvestigationEvidenceSnapshot,
    expected_investigation_id: str,
) -> InvestigationReport:
    """Parse and validate a model-generated report."""

    if (
    not isinstance(content, str)
    or len(content) > MAX_REPORT_RESPONSE_CHARS
   ):
     raise ReportFormatError(
        "Report content has an invalid type or length."
    )

    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ReportFormatError("Report is not valid JSON.") from exc

    if not isinstance(payload, dict):
        raise ReportFormatError("Report must be a JSON object.")

    try:
        report = InvestigationReport.model_validate(payload)
    except ValidationError as exc:
        raise ReportFormatError(
            "Report does not match the required schema."
        ) from exc

    # A model-written report may never carry AI-hypothesis sections; those are
    # produced and validated only by the separate hypothesis stage.
    if report.ai_hypotheses or report.ai_analysis is not None:
        raise ReportFormatError(
            "Report must not contain AI hypothesis sections."
        )

    # Scheduling constraint rows are minted by the application from recorded
    # signals; a model-written report may not supply them.
    if any(finding.scheduling_constraints for finding in report.findings):
        raise ReportFormatError(
            "Report must not contain scheduling constraint rows."
        )

    # Taints belong to nodes and tolerations to pods. A model-written
    # recommendation that reverses them is refused rather than shown.
    if inverted_taint_toleration(
        [
            report.summary,
            *report.uncertainties,
            *report.suggested_checks,
            *(f.title for f in report.findings),
            *(f.description for f in report.findings),
        ]
    ):
        raise ReportFormatError(
            "Report attributes taints to pods or tolerations to nodes."
        )

    validate_report_snapshot(
        report,
        snapshot,
        expected_investigation_id=expected_investigation_id,
    )

    return report


def build_report_messages(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[dict[str, str]]:
    """Build a bounded, evidence-only prompt."""

    evidence_payload: dict[str, Any] = {
        "investigation_id": snapshot.investigation_id,
        "evidence": [
            item.model_dump(mode="json")
            for item in snapshot.evidence
        ],
    }

    return [
        {
            "role": "system",
            "content": REPORT_SYSTEM_PROMPT,
        },
        {
            "role": "user",
            "content": json.dumps(
                evidence_payload,
                ensure_ascii=True,
                separators=(",", ":"),
            ),
        },
    ]