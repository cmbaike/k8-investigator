"""Controlled-presentation CLI viewer for Kubernetes investigations.

A thin client of the SAME authenticated HTTP API that normal users call:

    POST /investigations                  create (question + structured namespace)
    POST /investigations/{id}/execute     run
    GET  /investigations/{id}             record: question, namespace, status
    GET  /investigations/{id}/report      persisted report

It has no controller, report generator, database access or Kubernetes client,
and it modifies nothing in the cluster.

    # No API key. Open http://127.0.0.1:8080/console/

    # A. start a new investigation
    uv run python scripts/demo_investigation.py \\
        --namespace ai-ops-demo \\
        --question "Investigate the health of the platform" --live

    # B. display an existing investigation
    uv run python scripts/demo_investigation.py --investigation-id <uuid>

Safety: text from the API is treated as untrusted. Terminal escape sequences
and control/format characters are removed, secret-like strings are redacted
again, and nothing here ever prints raw logs, startup commands, environment
values, Secret contents or raw exception messages. Error output uses fixed
messages only.

Exit codes: 0 report displayed; 1 usage/configuration; 2 investigation not
completed (pending, running or failed); 3 API, network or response problem.
"""

import argparse
import os
import re
import sys
import textwrap
import time
import unicodedata
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlparse

_REPO_ROOT = str(Path(__file__).resolve().parents[1])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import httpx  # noqa: E402
from pydantic import ValidationError  # noqa: E402

from app.investigations.models import (  # noqa: E402
    InvestigationRecord,
    InvestigationStatus,
)
from app.reports.models import InvestigationReport  # noqa: E402
from app.tools.investigation_scope import SCOPE_REJECTION_MESSAGES  # noqa: E402
from app.tools.log_context import sanitize_log_text  # noqa: E402

API_KEY_ENV = "PRIVATE_AI_API_KEY"
BASE_URL_ENV = "PRIVATE_AI_BASE_URL"
DEFAULT_BASE_URL = "http://127.0.0.1:8080"

EXIT_OK, EXIT_USAGE, EXIT_NOT_COMPLETED, EXIT_API = 0, 1, 2, 3

WIDTH = 100
_NAMESPACE = re.compile(r"^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$")
_EVIDENCE_REF = re.compile(r"^ev-[0-9]{4}$")
_LOG_REF = re.compile(r"^log-[0-9]{4}$")
_STOP_REASON = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}


class ViewerError(Exception):
    """Carries a FIXED, safe message and an exit code. Never wraps another
    exception's text."""

    def __init__(self, message: str, exit_code: int = EXIT_API) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


# ----------------------------------------------------------------- sanitizing

_ESCAPES = re.compile(
    r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC (even unterminated)
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"  # DCS / SOS / PM / APC
    r"|\x1b\[[0-?]*[ -/]*[@-~]?"  # CSI (even unterminated)
    r"|\x1b[ -/]*[0-~]?"  # any other ESC sequence
    r"|\x9d[^\x07\x9c]*(?:\x07|\x9c)?"  # C1 OSC
    r"|\x9b[0-?]*[ -/]*[@-~]?"  # C1 CSI
)
_LINE_BREAKS = re.compile(r"[\t\n\r\v\f\u2028\u2029\x85]+")
_DROPPED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn"})


def safe(value: Any, limit: int = 600) -> str:
    """Render untrusted API text as one safe, bounded line.

    Removes terminal escape sequences, then control/format characters
    (including bidi overrides and zero-width characters), re-applies the
    platform's credential redaction, and collapses whitespace.
    """
    if not isinstance(value, str):
        return ""

    text = _ESCAPES.sub("", value)
    text = _LINE_BREAKS.sub(" ", text)
    text = "".join(
        ch for ch in text if unicodedata.category(ch) not in _DROPPED_CATEGORIES
    )
    text, _ = sanitize_log_text(text)
    text = " ".join(text.split())

    return text if len(text) <= limit else text[: limit - 1] + "..."


# ------------------------------------------------------------------- styling


class Style:
    """ANSI styling applied ONLY to this program's own fixed labels, never to
    API-returned text."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    def warn(self, text: str) -> str:
        return self._wrap("1;33", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)


# ------------------------------------------------------------ finding buckets

# The engine's fixed, deterministic finding-title vocabulary (see
# app/reports/grounding.py and config_grounding.py). Used only to place
# findings in presentation sections. Unknown titles fall in "other" and are
# shown in --verbose. tests/test_demo_viewer.py fails if the engine adds a
# title that is not listed here.
BUCKET_BY_TITLE = {
    "Pod discovered": "discovery",
    "Pod identified": "discovery",
    "Container logs retrieved": "discovery",
    "Pod phase observed": "symptom",
    "Container readiness observed": "symptom",
    "Container restart count observed": "symptom",
    "Container state observed": "symptom",
    "Container state reason observed": "symptom",
    "Previous container exit code observed": "symptom",
    "Previous container termination reason observed": "symptom",
    "Owning workload identified": "config",
    "Container configuration observed": "config",
    "Startup command exits unconditionally (static analysis)": "config",
    "Observed exit code matches the startup command's unconditional exit": "established",
    # Failures established from Kubernetes state are high-priority findings,
    # shown once in section 2; "other" keeps them out of the symptom list.
    "Container could not be started": "other",
    "Container is crash-looping": "other",
    "Container is running but not ready": "other",
    "Container failed at runtime": "other",
    "Container previously terminated as OOMKilled": "other",
    "Kubernetes events recorded for the pod": "symptom",
}

_TRAILING_DETAIL = re.compile(
    r"\s*Observed during tool execution '[^']*'\."
    r"|\s*Resource: namespace '[^']*', pod '[^']*'\."
)


_EXECUTION_DETAIL = re.compile(r"\s+during execution '[^']*'")

_SUMMARY_ITEM = re.compile(r"^\d+\.\s+\[[a-z]+\]\s")


def bucket_of(finding) -> str:
    return BUCKET_BY_TITLE.get(finding.title, "other")


def _is_high_priority(finding) -> bool:
    return finding.severity != "info"


def _trim_detail(description: str) -> str:
    return _TRAILING_DETAIL.sub("", description).strip()


# ------------------------------------------------------------------ rendering


def _wrap(text: str, indent: str = "", first: str | None = None) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first if first is not None else indent,
        subsequent_indent=indent,
        break_long_words=True,
        break_on_hyphens=False,
    ) or [first if first is not None else indent]


def _refs(finding_or_refs) -> str:
    refs = (
        [r.evidence_id for r in finding_or_refs.evidence]
        if hasattr(finding_or_refs, "evidence")
        else list(finding_or_refs)
    )
    shown = [r for r in refs if _EVIDENCE_REF.fullmatch(r)]
    return f" [{', '.join(shown)}]" if shown else ""


def _section(lines: list[str], number: int, title: str, style: Style) -> None:
    lines.append("")
    lines.append(style.bold(f"{number}. {title}"))
    lines.append("-" * min(WIDTH, len(f"{number}. {title}") + 2))


def _duration(record: InvestigationRecord) -> str | None:
    if record.started_at and record.finished_at:
        seconds = (record.finished_at - record.started_at).total_seconds()
        if 0 <= seconds < 86_400:
            return f"{seconds:.1f}s"
    return None


def render_header(
    record: InvestigationRecord, style: Style, *, verbose: bool = False
) -> list[str]:
    lines = [style.bold("=" * WIDTH), style.bold("KUBERNETES INVESTIGATION"), "=" * WIDTH]
    lines.append(style.bold("1. INVESTIGATION"))
    lines.extend(
        _wrap(
            safe(record.user_text, 1000) or "(question not recorded)",
            "   ",
            "   Question:  ",
        )
    )
    lines.append(f"   Namespace: {safe(record.authorized_namespace, 100)}")
    lines.append(f"   ID:        {safe(record.investigation_id, 64)}")
    status = record.status.value
    lines.append(f"   Status:    {status}")

    # The internal stop reason is implementation detail: verbose only (and
    # shown when there is no report, where it is the only explanation).
    stop = record.stop_reason
    if verbose and isinstance(stop, str) and _STOP_REASON.fullmatch(stop):
        lines.append(f"   Stop:      {stop}")

    duration = _duration(record)
    if duration:
        lines.append(f"   Duration:  {duration}")

    return lines


def render_report(
    record: InvestigationRecord,
    report: InvestigationReport,
    *,
    verbose: bool = False,
    style: Style | None = None,
    ai_display_error: bool = False,
    timings: dict[str, float] | None = None,
) -> str:
    style = style or Style(False)
    lines = render_header(record, style, verbose=verbose)

    findings = list(report.findings)
    high = [f for f in findings if _is_high_priority(f)]
    by_bucket: dict[str, list] = {}
    for finding in findings:
        by_bucket.setdefault(bucket_of(finding), []).append(finding)

    # 2 ---------------------------------------------------------------------
    _section(lines, 2, "HIGH-PRIORITY VERIFIED FINDINGS", style)
    lines.append("   (Established by the application from authorized read-only Kubernetes calls.)")

    headline, tail = _split_summary(report.summary)

    for raw in headline:
        text = safe(raw, 700)
        if text:
            lines.extend(_wrap(text, "   ", "   "))

    # Each high-priority finding appears once, here, with its full description.
    # Later sections point back to it instead of repeating it.
    if high:
        for f in high:
            lines.append("")
            lines.extend(
                _wrap(
                    style.warn(f"[{safe(f.severity, 20)}] {safe(f.title, 200)}"),
                    "      ",
                    "   >> ",
                )
            )
            lines.extend(
                _wrap(
                    safe(_trim_detail(f.description), 900) + _refs(f),
                    "      ",
                )
            )
    else:
        lines.append("")
        lines.append("   No warning-level findings were established.")

    if tail:
        lines.append("")
        for raw in tail:
            text = safe(raw, 700)
            if text:
                lines.extend(_wrap(text, "   ", "   "))

    if not verbose and findings:
        lines.append(f"   Use --verbose to list all {len(findings)} findings with their evidence.")

    # 3 ---------------------------------------------------------------------
    _section(lines, 3, "RELEVANT KUBERNETES SYMPTOMS", style)
    symptoms = by_bucket.get("symptom", [])
    limit = len(symptoms) if verbose else 8
    if symptoms:
        for f in symptoms[:limit]:
            lines.extend(
                _wrap(
                    safe(_trim_detail(f.description), 500) + _refs(f),
                    "     ",
                    "   - ",
                )
            )
        if len(symptoms) > limit:
            lines.append(f"   ... {len(symptoms) - limit} more (use --verbose)")
    else:
        lines.append("   No container symptoms were recorded in this report.")

    # 4 ---------------------------------------------------------------------
    _section(lines, 4, "VERIFIED WORKLOAD CONFIGURATION", style)
    configs = by_bucket.get("config", [])
    if configs:
        for f in configs:
            lines.extend(
                _wrap(
                    safe(_trim_detail(f.description), 700) + _refs(f),
                    "     ",
                    "   - ",
                )
            )
    else:
        lines.append("   Workload configuration was not inspected in this investigation.")

    # 5 ---------------------------------------------------------------------
    hypotheses = list(report.ai_hypotheses)
    _section(lines, 5, "AI DIAGNOSTIC HYPOTHESES  --  UNVERIFIED", style)
    lines.append(
        "   " + style.warn("UNVERIFIED") + ": model-generated interpretations, NOT findings."
    )
    lines.append("   They may be wrong. A cited reference shows where a claim came from, not")
    lines.append("   that it is true.")
    lines.extend(_render_ai_status(report, hypotheses, ai_display_error, verbose))

    for number, h in enumerate(hypotheses, start=1):
        resource = "/".join(
            safe(part, 100)
            for part in (h.resource.pod, h.resource.container)
            if part
        )
        lines.append("")
        lines.append(
            "   " + style.warn(f"Hypothesis {number} of {len(hypotheses)} [UNVERIFIED]")
            + (f"  ({resource})" if resource else "")
        )
        if h.reported:
            lines.extend(
                _wrap(
                    safe(h.reported, 300),
                    "        ",
                    "     Application reported (a claim, not verified): ",
                )
            )
        lines.extend(
            _wrap(safe(h.possible_explanation, 400), "        ", "     Possible explanation: ")
        )
        lines.extend(
            _wrap(safe(h.not_yet_verified, 500), "        ", "     Not yet verified:     ")
        )
        lines.extend(
            _wrap(_describe_citations(h.evidence_refs), "            ", "     Cites: ")
        )
        if h.independently_established:
            lines.extend(
                _wrap(
                    _independent_label(h, by_bucket.get("established", []))
                    + _refs(h.established_refs),
                    "            ",
                    "     Independent evidence: ",
                )
            )

    # 6 ---------------------------------------------------------------------
    _section(lines, 6, "APPLICATION-WRITTEN CONFIGURATION CONTEXT", style)
    contexts = _unique(
        (h.configuration_context, h.configuration_refs, i)
        for i, h in enumerate(hypotheses, start=1)
        if h.configuration_context
    )
    if contexts:
        lines.append("   Written by the application from verified evidence, not by the model.")
        for text, refs, numbers in contexts:
            lines.extend(
                _wrap(
                    safe(text, 1100) + _refs(refs),
                    "     ",
                    f"   - (hypothesis {_join_numbers(numbers)}) ",
                )
            )
    else:
        lines.append("   None attached (it accompanies accepted AI hypotheses).")

    # 7 ---------------------------------------------------------------------
    _section(lines, 7, "INDEPENDENTLY ESTABLISHED FINDINGS", style)
    lines.append("   Facts corroborated by the application from separate evidence sources.")
    shown = False
    established_findings = by_bucket.get("established", [])
    annotations = _unique(
        (h.independently_established, h.established_refs, i)
        for i, h in enumerate(hypotheses, start=1)
        if h.independently_established
    )

    def ref_set(refs) -> frozenset[str]:
        return frozenset(refs)

    folded: set[str] = set()

    for f in established_findings:
        shown = True
        finding_refs = ref_set(r.evidence_id for r in f.evidence)
        # An application annotation resting on the same evidence is the same
        # fact: fold it into this entry instead of printing it again.
        accompanying = [
            numbers
            for text, refs, numbers in annotations
            if ref_set(refs) == finding_refs
        ]
        for text, refs, _numbers in annotations:
            if ref_set(refs) == finding_refs:
                folded.add(text)
        note = (
            " Accompanies hypothesis "
            + _join_numbers(sorted({n for numbers in accompanying for n in numbers}))
            + "."
            if accompanying
            else ""
        )
        if _is_high_priority(f):
            body = f"[{safe(f.severity, 20)}] {safe(f.title, 200)} (described in section 2)"
        else:
            body = f"[{safe(f.severity, 20)}] " + safe(_trim_detail(f.description), 700)
        lines.extend(_wrap(body + _refs(f) + note, "     ", "   - "))

    for text, refs, numbers in annotations:
        if text in folded:
            continue
        shown = True
        lines.extend(
            _wrap(
                safe(text, 800) + _refs(refs),
                "     ",
                f"   - (alongside hypothesis {_join_numbers(numbers)}) ",
            )
        )
    if not shown:
        lines.append("   No corroborated findings were established.")

    # 8 ---------------------------------------------------------------------
    _section(lines, 8, "RECOMMENDED VERIFICATION CHECKS", style)
    lines.append("   Read-only suggestions. None has been performed.")
    number = 0
    for check in report.suggested_checks:
        number += 1
        lines.extend(_wrap(safe(check, 700), "      ", f"   {number}. "))
    for i, h in enumerate(hypotheses, start=1):
        number += 1
        lines.extend(
            _wrap(
                safe(h.verification_check, 400)
                + f" (from unverified hypothesis {i})",
                "      ",
                f"   {number}. ",
            )
        )
    if number == 0:
        lines.append("   None recommended.")

    # 9 ---------------------------------------------------------------------
    _section(lines, 9, "EVIDENCE REFERENCES AND LIMITATIONS", style)
    cited = sorted(
        {
            r.evidence_id
            for f in findings
            for r in f.evidence
            if _EVIDENCE_REF.fullmatch(r.evidence_id)
        }
    )
    lines.append(
        f"   Verified evidence cited by findings: {len(cited)} reference(s)."
        + ("" if verbose or not cited else " (--verbose lists them per finding)")
    )
    if cited and len(cited) <= 40:
        lines.extend(_wrap(", ".join(cited), "     ", "     "))
    lines.extend(_wrap(_log_disclosure(report), "         ", "   "))

    lines.append("   Uncertainties:")
    if report.uncertainties:
        for item in report.uncertainties:
            # Internal execution identifiers are implementation detail.
            cleaned = _EXECUTION_DETAIL.sub("", item)
            lines.extend(_wrap(safe(cleaned, 500), "       ", "   - "))
    else:
        lines.append("   - (none recorded)")

    lines.extend(
        _wrap(
            "This viewer never shows raw logs, startup commands, environment "
            "values or Secret contents, and sanitizes all API text for the terminal.",
            "   ",
            "   Note: ",
        )
    )

    if verbose:
        lines.extend(_render_verbose(report, findings))

    if timings:
        lines.append("")
        lines.append(
            "   Timing: "
            + ", ".join(f"{name} {seconds:.1f}s" for name, seconds in timings.items())
        )

    lines.append("=" * WIDTH)
    return "\n".join(lines) + "\n"


def _render_ai_status(report, hypotheses, display_error: bool, verbose: bool) -> list[str]:
    analysis = report.ai_analysis
    out: list[str] = []

    if display_error:
        out.append("   AI section could not be displayed (unexpected format). Verified")
        out.append("   findings above and below are unaffected.")
        return out

    if analysis is None:
        out.append("   AI analysis is not part of this report.")
        return out

    state = analysis.state
    if state == "generated":
        out.append(f"   AI analysis: {len(hypotheses)} hypothesis(es) accepted after validation.")
    elif state == "all_omitted":
        out.append(
            f"   No AI hypotheses accepted: all {analysis.hypotheses_proposed} proposed "
            "were omitted by validation."
        )
    elif state == "none_proposed":
        out.append("   AI analysis ran and proposed no hypotheses.")
    elif state == "unavailable":
        reason = safe(analysis.reason or "unknown", 40)
        category = f", {safe(analysis.rejection_category, 20)} validation" if analysis.rejection_category else ""
        out.append(f"   AI analysis was unavailable ({reason}{category}); no hypotheses shown.")
    else:
        out.append("   AI analysis was not attempted.")

    if state in {"all_omitted", "generated"} and analysis.hypotheses_omitted:
        reasons = ", ".join(
            f"{safe(code, 60)} x{count}"
            for code, count in sorted(analysis.omission_reasons.items())
        )
        out.append(
            f"   Omitted by validation: {analysis.hypotheses_omitted}"
            + (f" ({reasons})" if reasons else "")
        )

    if not hypotheses:
        out.append("   Deterministic findings are complete and shown regardless.")

    return out


def _describe_citations(refs: Sequence[str]) -> str:
    verified = [r for r in refs if _EVIDENCE_REF.fullmatch(r)]
    logs = [r for r in refs if _LOG_REF.fullmatch(r)]
    parts = []
    if verified:
        parts.append("verified evidence " + ", ".join(verified))
    if logs:
        parts.append(
            f"{len(logs)} transient log excerpt(s) ({', '.join(logs)}; not retained, not shown)"
        )
    return "; ".join(parts) or "no recognizable references"


def _log_disclosure(report: InvestigationReport) -> str:
    analysis = report.ai_analysis
    used = analysis.log_excerpts_used if analysis else 0
    omitted = analysis.log_excerpts_omitted if analysis else 0

    if used:
        text = (
            f"Logs: {used} bounded log excerpt(s) were read transiently in memory "
            "for AI analysis and discarded. They are not stored in the report and "
            "are never displayed here."
        )
    else:
        text = "Logs: no log excerpts were used by AI analysis."

    if omitted:
        text += f" {omitted} further excerpt(s) were omitted by bounds."

    return text


def _split_summary(summary: str) -> tuple[list[str], list[str]]:
    """Split the engine summary into its headline and closing caveat, dropping
    the numbered "most significant findings" list: those findings are shown in
    full below, so repeating them is noise. Falls back to the whole summary if
    the expected shape is absent."""
    lines = [line for line in (summary or "").splitlines() if line.strip()]
    items = [i for i, line in enumerate(lines) if _SUMMARY_ITEM.match(line)]

    if not items:
        return lines, []

    marker = next(
        (i for i, line in enumerate(lines) if line.startswith("Most significant findings")),
        items[0],
    )
    headline = lines[:marker]
    tail = [line for i, line in enumerate(lines) if i > items[-1]]

    return headline, tail


def _independent_label(h, established_findings) -> str:
    """A compact pointer to the independently established fact, never its
    description."""
    wanted = frozenset(h.established_refs)

    for f in established_findings:
        if frozenset(r.evidence_id for r in f.evidence) == wanted:
            return safe(f.title, 200) + " (section 7)"

    return "application-written corroboration (section 7)"


def _unique(items) -> list[tuple[str, list[str], list[int]]]:
    merged: dict[str, tuple[str, list[str], list[int]]] = {}
    for text, refs, number in items:
        entry = merged.setdefault(text, (text, list(refs), []))
        entry[2].append(number)
    return list(merged.values())


def _join_numbers(numbers: list[int]) -> str:
    return ", ".join(str(n) for n in numbers)


def _render_verbose(report: InvestigationReport, findings) -> list[str]:
    lines = ["", "ALL VERIFIED FINDINGS (verbose)", "-" * 34]

    for number, f in enumerate(findings, start=1):
        lines.extend(
            _wrap(
                f"[{safe(f.severity, 20)}] {safe(f.title, 200)}",
                "      ",
                f"   {number:>2}. ",
            )
        )
        lines.extend(_wrap(safe(f.description, 900), "       "))
        lines.append("       Evidence: " + ", ".join(
            r.evidence_id for r in f.evidence if _EVIDENCE_REF.fullmatch(r.evidence_id)
        ))

    analysis = report.ai_analysis
    if analysis:
        lines.append("")
        lines.append(
            f"   AI analysis detail: state={analysis.state}, "
            f"proposed={analysis.hypotheses_proposed}, omitted={analysis.hypotheses_omitted}, "
            f"log excerpts used={analysis.log_excerpts_used}"
        )
        lines.extend(_wrap(safe(analysis.message, 300), "     ", "   Message: "))

    return lines


def render_not_completed(
    record: InvestigationRecord, style: Style, *, waited: bool = False
) -> str:
    lines = render_header(record, style, verbose=True)
    lines.append("")

    if record.status == InvestigationStatus.FAILED:
        lines.append("   This investigation FAILED. No report is available.")
        lines.append("   The API does not expose failure details. Start a new investigation to retry.")
    elif record.status == InvestigationStatus.RUNNING:
        lines.append("   This investigation is still RUNNING; no report exists yet.")
        lines.append(
            "   Run this command again shortly" + (" (the wait elapsed)." if waited else ", or use --wait SECONDS.")
        )
    else:
        lines.append("   This investigation is PENDING (created, not started); no report exists yet.")

    lines.append("=" * WIDTH)
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ API layer


class Api:
    """The only network code. Every failure becomes a fixed-message
    ViewerError; response bodies and exception text are never echoed."""

    def __init__(self, client: httpx.Client, base_url: str) -> None:
        self._client = client
        self._base = base_url

    def _request(self, method: str, path: str, *, json_body=None, expected=(200,)) -> Any:
        try:
            response = self._client.request(method, path, json=json_body)
        except httpx.ConnectError:
            raise ViewerError(
                f"The API is unavailable at {safe(self._base, 100)}. Is the server running?"
            ) from None
        except httpx.TimeoutException:
            raise ViewerError("The API request timed out.") from None
        except httpx.HTTPError as exc:
            raise ViewerError(
                f"The API request failed ({type(exc).__name__})."
            ) from None

        code = response.status_code

        if code in expected:
            try:
                body = response.json()
            except ValueError:
                raise ViewerError("The API returned a response that is not valid JSON.") from None

            if not isinstance(body, dict):
                raise ViewerError("The API returned an unexpected response shape.")

            return body

        raise ViewerError(*_status_message(code, method, path, _known_detail(response)))

    def create(
        self, question: str, namespace: str, max_steps: int
    ) -> InvestigationRecord:
        # The namespace is a structured field, authenticated and authorized by
        # the server. The question is sent exactly as the user wrote it.
        body = self._request(
            "POST",
            "/investigations",
            json_body={
                "question": question,
                "namespace": namespace,
                "max_steps": max_steps,
            },
            expected=(201,),
        )
        return _record(body)

    def execute(self, investigation_id: str) -> InvestigationRecord:
        return _record(
            self._request("POST", f"/investigations/{investigation_id}/execute")
        )

    def record(self, investigation_id: str) -> InvestigationRecord:
        return _record(self._request("GET", f"/investigations/{investigation_id}"))

    def report_payload(self, investigation_id: str) -> dict[str, Any]:
        return self._request("GET", f"/investigations/{investigation_id}/report")


def _known_detail(response: httpx.Response) -> str | None:
    """The API's `detail` ONLY if it is exactly one of the server's fixed scope
    messages. Anything else is untrusted and never shown."""
    try:
        detail = response.json().get("detail")
    except (ValueError, AttributeError):
        return None

    return detail if detail in SCOPE_REJECTION_MESSAGES.values() else None


def _status_message(
    code: int, method: str, path: str, detail: str | None = None
) -> tuple[str, int]:
    if code == 401:
        return ("The API refused the request (HTTP 401).", EXIT_API)
    if code == 403:
        return ("Access denied for that namespace (HTTP 403).", EXIT_API)
    if code == 404:
        return ("Investigation not found (HTTP 404).", EXIT_API)
    if code == 409:
        return ("The investigation is not in a state that allows this action (HTTP 409).", EXIT_API)
    if code == 422:
        reason = detail if detail else "Check the namespace and the question."
        return (f"The API did not accept the request (HTTP 422): {reason}", EXIT_API)
    if code >= 500:
        return (f"The API reported a server error (HTTP {code}).", EXIT_API)
    return (f"The API returned an unexpected status (HTTP {code}).", EXIT_API)


def _record(body: dict[str, Any]) -> InvestigationRecord:
    try:
        return InvestigationRecord.model_validate(body)
    except ValidationError:
        raise ViewerError("The API returned an investigation record in an unexpected format.") from None


def parse_report(payload: dict[str, Any]) -> tuple[InvestigationReport, bool]:
    """Validate a report. If ONLY the optional AI section is malformed, show the
    deterministic report anyway (flagged), never the reverse."""
    try:
        return InvestigationReport.model_validate(payload), False
    except ValidationError:
        pass

    stripped = {
        k: v for k, v in payload.items() if k not in {"ai_hypotheses", "ai_analysis"}
    }

    try:
        return InvestigationReport.model_validate(stripped), True
    except ValidationError:
        raise ViewerError("The API returned a report in an unexpected format.") from None


_TERMINAL = {InvestigationStatus.COMPLETED, InvestigationStatus.FAILED}


def wait_for_terminal(
    api: Api,
    record: InvestigationRecord,
    wait_seconds: float,
    *,
    interval: float = 2.0,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> InvestigationRecord:
    """Poll until the investigation is terminal or the deadline passes."""
    deadline = clock() + max(0.0, wait_seconds)

    while record.status not in _TERMINAL and clock() < deadline:
        sleep(interval)
        record = api.record(record.investigation_id)

    return record


# ------------------------------------------------------------------ workflows


def validate_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ViewerError("--base-url must be an http(s) URL.", EXIT_USAGE)

    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK:
        raise ViewerError(
            "Refusing to send the API key over plain http to a non-local host. Use https.",
            EXIT_USAGE,
        )


def present(
    api: Api,
    record: InvestigationRecord,
    *,
    verbose: bool,
    style: Style,
    out: TextIO,
    wait_seconds: float = 0,
    timings: dict[str, float] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    if record.status not in _TERMINAL and wait_seconds > 0:
        record = wait_for_terminal(
            api, record, wait_seconds, sleep=sleep, clock=clock
        )

    if record.status != InvestigationStatus.COMPLETED:
        out.write(render_not_completed(record, style, waited=wait_seconds > 0))
        return EXIT_NOT_COMPLETED

    started = time.monotonic()
    payload = api.report_payload(record.investigation_id)
    if timings is not None:
        timings["report fetch"] = time.monotonic() - started

    report, ai_error = parse_report(payload)

    if report.investigation_id != record.investigation_id:
        raise ViewerError("The report belongs to a different investigation.")

    out.write(
        render_report(
            record,
            report,
            verbose=verbose,
            style=style,
            ai_display_error=ai_error,
            timings=timings,
        )
    )
    return EXIT_OK


def run_new(
    api: Api,
    *,
    namespace: str,
    question: str,
    max_steps: int,
    verbose: bool,
    style: Style,
    out: TextIO,
    wait_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    if not question.strip():
        raise ViewerError("The question must not be empty.", EXIT_USAGE)

    timings: dict[str, float] = {}

    started = time.monotonic()
    record = api.create(question, namespace, max_steps)
    timings["create"] = time.monotonic() - started

    if record.authorized_namespace != namespace:
        raise ViewerError("The API authorized a different namespace than requested.")

    print(
        f"Investigation {safe(record.investigation_id, 64)} created in namespace "
        f"{safe(namespace, 100)}; running read-only checks...",
        file=out,
        flush=True,
    )

    started = time.monotonic()
    investigation_id = record.investigation_id
    execute_error: ViewerError | None = None
    try:
        api.execute(investigation_id)
    except ViewerError as exc:
        # A timeout, conflict or server error may still leave a real
        # investigation (running or failed). Show its true state if we can.
        execute_error = exc
    timings["execute"] = time.monotonic() - started

    try:
        record = api.record(investigation_id)
    except ViewerError:
        raise execute_error or ViewerError("The investigation status could not be read.") from None

    if execute_error is not None and record.status == InvestigationStatus.PENDING:
        raise execute_error

    return present(
        api,
        record,
        verbose=verbose,
        style=style,
        out=out,
        wait_seconds=wait_seconds,
        timings=timings,
        sleep=sleep,
        clock=clock,
    )


def run_existing(
    api: Api,
    *,
    investigation_id: str,
    verbose: bool,
    style: Style,
    out: TextIO,
    wait_seconds: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    record = api.record(investigation_id)

    return present(
        api,
        record,
        verbose=verbose,
        style=style,
        out=out,
        wait_seconds=wait_seconds,
        sleep=sleep,
        clock=clock,
    )


# ------------------------------------------------------------------------ CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Present a Kubernetes investigation from the authenticated API.",
        epilog="The demo API does not require a key.",
    )
    parser.add_argument("--investigation-id", help="Display an existing investigation (UUID).")
    parser.add_argument("--namespace", help="Namespace to investigate (starts a new investigation).")
    parser.add_argument("--question", help="Investigation question (starts a new investigation).")
    parser.add_argument("--live", action="store_true",
                        help="Required to start an investigation (runs read-only Kubernetes tools).")
    parser.add_argument("--max-steps", type=int, default=6, help="Tool step budget (1-10).")
    parser.add_argument("--base-url", default=None,
                        help=f"API base URL (default: ${BASE_URL_ENV} or {DEFAULT_BASE_URL}).")
    parser.add_argument("--timeout", type=float, default=180.0, help="Seconds per API request.")
    parser.add_argument("--wait", type=float, default=0.0,
                        help="Seconds to wait for a running investigation to finish.")
    parser.add_argument("--verbose", action="store_true",
                        help="Show every finding with its evidence references.")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    env: dict[str, str] | None = None,
    out: TextIO | None = None,
    err: TextIO | None = None,
    transport: httpx.BaseTransport | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    env = env if env is not None else dict(os.environ)

    def fail(message: str, code: int) -> int:
        print(f"Error: {message}", file=err)
        return code

    args = build_parser().parse_args(argv)

    new_run = bool(args.namespace or args.question)

    try:
        if args.investigation_id and new_run:
            raise ViewerError(
                "Use either --investigation-id, or --namespace with --question.", EXIT_USAGE
            )

        if not args.investigation_id and not (args.namespace and args.question):
            raise ViewerError(
                "Provide --investigation-id, or both --namespace and --question.", EXIT_USAGE
            )

        if new_run:
            if not args.live:
                raise ViewerError(
                    "Starting an investigation runs live read-only Kubernetes tools. Pass --live.",
                    EXIT_USAGE,
                )
            if not _NAMESPACE.fullmatch(args.namespace):
                raise ViewerError("--namespace must be a valid Kubernetes namespace name.", EXIT_USAGE)
            if not 1 <= args.max_steps <= 10:
                raise ViewerError("--max-steps must be between 1 and 10.", EXIT_USAGE)
            if len(args.question) > 3500:
                raise ViewerError("The question is too long.", EXIT_USAGE)
        else:
            try:
                args.investigation_id = str(uuid.UUID(args.investigation_id))
            except ValueError:
                raise ViewerError("--investigation-id must be a UUID.", EXIT_USAGE) from None

        if args.timeout <= 0 or args.wait < 0:
            raise ViewerError("--timeout must be positive and --wait must not be negative.", EXIT_USAGE)

        base_url = (args.base_url or env.get(BASE_URL_ENV) or DEFAULT_BASE_URL).rstrip("/")
        validate_base_url(base_url)

        color = args.color == "always" or (
            args.color == "auto"
            and not env.get("NO_COLOR")
            and getattr(out, "isatty", lambda: False)()
        )
        style = Style(color)

        with httpx.Client(
            base_url=base_url,
            timeout=httpx.Timeout(args.timeout, connect=5.0),
            transport=transport,
        ) as client:
            api = Api(client, base_url)

            if new_run:
                return run_new(
                    api,
                    namespace=args.namespace,
                    question=args.question,
                    max_steps=args.max_steps,
                    verbose=args.verbose,
                    style=style,
                    out=out,
                    wait_seconds=args.wait,
                    sleep=sleep,
                    clock=clock,
                )

            return run_existing(
                api,
                investigation_id=args.investigation_id,
                verbose=args.verbose,
                style=style,
                out=out,
                wait_seconds=args.wait,
                sleep=sleep,
                clock=clock,
            )
    except ViewerError as exc:
        return fail(exc.message, exc.exit_code)
    except KeyboardInterrupt:
        return fail("Interrupted.", EXIT_USAGE)
    except Exception as exc:  # never print messages that may embed data
        return fail(f"Unexpected failure ({type(exc).__name__}).", EXIT_API)


if __name__ == "__main__":
    raise SystemExit(main())
