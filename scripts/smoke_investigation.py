"""Opt-in live smoke test of the production investigation API lifecycle.

    POST /investigations -> POST /investigations/{id}/execute
        -> GET /investigations/{id}/report

Run from the repository root against a running API server:

    # No API key. The demo console and API are open.
    uv run python scripts/smoke_investigation.py \\
        --live --namespace ai-ops-demo --base-url http://127.0.0.1:8080

The server needs a reachable vLLM endpoint, Kubernetes access, and PostgreSQL.
This script only validates structure. It does not hardcode pod names, finding
counts, or log messages, and it never prints raw logs, API keys, or response
bodies beyond bounded, sanitized error details.
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any

# Allow `python scripts/smoke_investigation.py` from any directory.
_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import httpx  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.reports.models import InvestigationReport  # noqa: E402

BASE_URL_ENV = "PRIVATE_AI_BASE_URL"
DEFAULT_BASE_URL = "http://127.0.0.1:8080"
# The namespace is sent as a structured request field, not inside the text.
DEFAULT_QUESTION = "Investigate why the payments-api workload is failing."

_NAMESPACE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_EVIDENCE_ID = re.compile(r"^ev-[0-9]{4}$")


class SmokeFailure(RuntimeError):
    """A smoke check failed. The message is safe to print."""


def _safe_detail(response: httpx.Response) -> str:
    """Return a short sanitized server error detail, never the raw body."""
    try:
        detail = response.json().get("detail")
    except Exception:
        return ""

    if not isinstance(detail, str):
        return ""

    return re.sub(r"[^\x20-\x7e]", "?", detail)[:120]


def _call(
    client: httpx.Client,
    method: str,
    path: str,
    *,
    expected: int,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        response = client.request(method, path, json=json_body)
    except httpx.HTTPError as exc:
        raise SmokeFailure(
            f"{method} {_route_label(path)} request failed "
            f"({type(exc).__name__})."
        ) from None

    if response.status_code != expected:
        suffix = _safe_detail(response)
        raise SmokeFailure(
            f"{method} {_route_label(path)} returned HTTP "
            f"{response.status_code}, expected {expected}"
            + (f": {suffix}" if suffix else ".")
        )

    try:
        body = response.json()
    except ValueError:
        raise SmokeFailure(
            f"{method} {_route_label(path)} returned a non-JSON body."
        ) from None

    if not isinstance(body, dict):
        raise SmokeFailure(
            f"{method} {_route_label(path)} returned an unexpected body."
        )

    return body


def _route_label(path: str) -> str:
    parts = path.strip("/").split("/")
    return "/" + "/".join("{id}" if i == 1 else p for i, p in enumerate(parts))


def validate_report(
    payload: dict[str, Any],
    *,
    investigation_id: str,
) -> InvestigationReport:
    """Structurally validate a persisted report without content assumptions."""
    try:
        report = InvestigationReport.model_validate(payload)
    except ValidationError:
        raise SmokeFailure("Report does not match the report schema.") from None

    if report.investigation_id != investigation_id:
        raise SmokeFailure("Report belongs to a different investigation.")

    if not report.summary.strip():
        raise SmokeFailure("Report summary is empty.")

    if not report.findings:
        raise SmokeFailure("Report contains no evidence-backed findings.")

    cited: set[str] = set()

    for finding in report.findings:
        if not finding.evidence:
            raise SmokeFailure("A finding has no evidence references.")

        for reference in finding.evidence:
            if not _EVIDENCE_ID.fullmatch(reference.evidence_id):
                raise SmokeFailure("A finding has a malformed evidence reference.")

            cited.add(reference.evidence_id)

    if not report.uncertainties:
        raise SmokeFailure("Report states no uncertainties.")

    return report


def run_smoke(
    *,
    namespace: str,
    live: bool,
    base_url: str = DEFAULT_BASE_URL,
    max_steps: int = 6,
    api_key: str | None = None,
    timeout_seconds: float = 180.0,
    transport: httpx.BaseTransport | None = None,
    out=print,
) -> int:
    if not live:
        raise ValueError("Live execution requires --live.")

    if not _NAMESPACE.fullmatch(namespace or ""):
        raise ValueError("Namespace must be a valid Kubernetes namespace name.")

    if not 1 <= max_steps <= 10:
        raise ValueError("max-steps must be between 1 and 10.")

    del api_key

    with httpx.Client(
        base_url=base_url,
        timeout=httpx.Timeout(timeout_seconds, connect=5.0),
        transport=transport,
    ) as client:
        created = _call(
            client,
            "POST",
            "/investigations",
            expected=201,
            json_body={
                "question": DEFAULT_QUESTION,
                "namespace": namespace,
                "max_steps": max_steps,
            },
        )

        investigation_id = created.get("investigation_id")

        if not isinstance(investigation_id, str) or not investigation_id:
            raise SmokeFailure("Create response had no investigation ID.")

        if created.get("authorized_namespace") != namespace:
            raise SmokeFailure("Authorized namespace does not match the request.")

        if created.get("status") != "pending":
            raise SmokeFailure("New investigation was not pending.")

        out(f"Created investigation {investigation_id} ({namespace}).")

        executed = _call(
            client,
            "POST",
            f"/investigations/{investigation_id}/execute",
            expected=200,
        )

        if executed.get("investigation_id") != investigation_id:
            raise SmokeFailure("Execute response is for another investigation.")

        if executed.get("status") != "completed":
            raise SmokeFailure(
                f"Investigation ended as {executed.get('status')!r} "
                f"(stop reason {executed.get('stop_reason')!r})."
            )

        if executed.get("user_text") is None or executed.get("max_steps") is None:
            raise SmokeFailure("Execute response omitted persisted inputs.")

        out(f"Execution completed (stop reason: {executed.get('stop_reason')}).")

        status = _call(
            client, "GET", f"/investigations/{investigation_id}", expected=200
        )

        if status.get("status") != "completed":
            raise SmokeFailure("Persisted status is not completed.")

        payload = _call(
            client,
            "GET",
            f"/investigations/{investigation_id}/report",
            expected=200,
        )

    report = validate_report(payload, investigation_id=investigation_id)
    cited = {r.evidence_id for f in report.findings for r in f.evidence}

    out(f"Report validated: {len(report.findings)} finding(s), "
        f"{len(cited)} distinct evidence reference(s), "
        f"{len(report.uncertainties)} uncertaint(ies), "
        f"{len(report.suggested_checks)} suggested check(s).")
    # AI enrichment is optional: report only application-controlled fields.
    analysis = report.ai_analysis
    if analysis is not None:
        detail = ""
        if analysis.hypotheses_proposed:
            reasons = ", ".join(
                f"{code}={count}"
                for code, count in sorted(analysis.omission_reasons.items())
            )
            detail = (
                f" Proposed {analysis.hypotheses_proposed}, "
                f"omitted {analysis.hypotheses_omitted}"
                + (f" [{reasons}]" if reasons else "")
                + f"; log excerpts used {analysis.log_excerpts_used}."
            )
        out(f"AI analysis: {analysis.state}"
            + (f" ({analysis.reason}"
               + (f": {analysis.rejection_category}"
                  if analysis.rejection_category else "")
               + ")" if analysis.reason else "")
            + f", {len(report.ai_hypotheses)} unverified hypothesis(es)."
            + detail)
    else:
        out("AI analysis: not present in this report.")

    out("Smoke test passed.")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--live", action="store_true", help="Explicitly allow live calls")
    parser.add_argument("--namespace", required=True, help="Authorized demo namespace")
    parser.add_argument(
        "--base-url",
        default=os.environ.get(BASE_URL_ENV, DEFAULT_BASE_URL),
        help=f"API base URL (default: ${BASE_URL_ENV} or {DEFAULT_BASE_URL})",
    )
    parser.add_argument("--max-steps", type=int, default=6)
    parser.add_argument("--timeout", type=float, default=180.0, help="Seconds per request")
    args = parser.parse_args(argv)

    try:
        return run_smoke(
            namespace=args.namespace,
            live=args.live,
            base_url=args.base_url,
            max_steps=args.max_steps,
            timeout_seconds=args.timeout,
        )
    except SmokeFailure as exc:
        print(f"Smoke test FAILED: {exc}", file=sys.stderr)
    except (ValueError, RuntimeError) as exc:
        print(f"Smoke test not run: {exc}", file=sys.stderr)
    except Exception as exc:  # never print messages that may embed data
        print(f"Smoke test stopped: {type(exc).__name__}", file=sys.stderr)

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
