"""Deterministic, evidence-prioritized investigation summary.

Built only from verified findings and the trusted evidence snapshot, before any
AI stage runs, so an unverified model claim can never appear in (or be promoted
by) the summary. Ranking uses structural properties of each finding, not
titles or workload names:

  1. severity (critical > warning > unknown > info);
  2. corroboration: supported by evidence from more than one independent tool;
  3. whether its evidence shows an abnormal observation (non-zero exit, error
     termination, restarts, not ready, a statically established
     unconditional exit);
  4. pure discovery findings (pod listing) rank last.

A second pass prefers findings resting on a different set of tools than ones
already chosen, so the headline covers distinct kinds of evidence instead of
several near-duplicates.
"""

from collections.abc import Sequence

from app.reports.models import InvestigationFinding
from app.reports.scope_grounding import scope_summary_line
from app.reports.snapshot import InvestigationEvidenceSnapshot

MAX_KEY_FINDINGS = 4
MAX_ITEM_CHARS = 380
MAX_REFS_SHOWN = 4

_SEVERITY_RANK = {"critical": 0, "warning": 1, "unknown": 2, "info": 3}

_DISCOVERY_TOOL = "k8s.get_pods"

_TOOL_LABELS = {
    "k8s.get_pods": "pod listing",
    "k8s.describe_pod": "pod state",
    "k8s.get_events": "events",
    "k8s.get_logs": "container logs",
    "k8s.get_previous_logs": "previous container logs",
    "k8s.describe_workload_config": "workload configuration",
}

_ERROR_TERMINATIONS = frozenset({"Error", "OOMKilled", "ContainerCannotRun"})


def _abnormal_weight(item) -> int | None:
    """None for a normal observation; otherwise how informative the abnormal
    signal is (lower = more informative)."""
    field, value = item.field, item.value

    if field.endswith("last_termination.exit_code"):
        return 0 if type(value) is int and value != 0 else None

    if field.endswith("startup.static_analysis"):
        return 0 if value == "unconditional_exit" else None

    if field.endswith("last_termination.reason"):
        return 1 if value in _ERROR_TERMINATIONS else None

    if field.endswith(".restart_count"):
        return 2 if type(value) is int and value >= 1 else None

    if field.endswith(".reason") and item.tool == "k8s.describe_pod":
        return 3 if isinstance(value, str) and value else None

    if field.endswith(".ready"):
        return 4 if value is False else None

    return None


def _label(tool: str) -> str:
    return _TOOL_LABELS.get(tool, tool.rsplit(".", 1)[-1].replace("_", " "))


def _first_sentence(text: str) -> str:
    head = text.split(". ")[0].strip().rstrip(".")
    return head if len(head) <= MAX_ITEM_CHARS else head[: MAX_ITEM_CHARS - 1] + "…"


def rank_findings(
    findings: Sequence[InvestigationFinding],
    snapshot: InvestigationEvidenceSnapshot,
) -> list[tuple[InvestigationFinding, frozenset[str], bool]]:
    """Findings in priority order with (tools supporting them, abnormal)."""
    by_id = {item.evidence_id: item for item in snapshot.evidence}
    scored = []

    for index, finding in enumerate(findings):
        cited = [by_id[r.evidence_id] for r in finding.evidence if r.evidence_id in by_id]
        tools = frozenset(item.tool for item in cited)
        weights = [w for w in map(_abnormal_weight, cited) if w is not None]
        abnormal = bool(weights)
        strength = min(weights) if weights else 9
        corroborated = len(tools) > 1
        discovery_only = bool(tools) and tools == {_DISCOVERY_TOOL}
        key = (
            _SEVERITY_RANK.get(finding.severity, 3),
            0 if corroborated else 1,
            0 if abnormal else 1,
            1 if discovery_only else 0,
            strength,
            index,
        )
        scored.append((key, finding, tools, abnormal))

    scored.sort(key=lambda row: row[0])
    return [(f, tools, abnormal) for _, f, tools, abnormal in scored]


def _select_key(ranked):
    chosen, seen_tool_sets = [], set()

    # Diversity applies only to significant findings (above info severity or
    # showing an abnormal observation). Routine observations such as "logs
    # were retrieved" never jump ahead of further abnormal evidence.
    for finding, tools, abnormal in ranked:
        if len(chosen) >= MAX_KEY_FINDINGS:
            break

        significant = finding.severity != "info" or abnormal

        if significant and tools not in seen_tool_sets:
            chosen.append((finding, tools, abnormal))
            seen_tool_sets.add(tools)

    for row in ranked:
        if len(chosen) >= MAX_KEY_FINDINGS:
            break

        if row not in chosen:
            chosen.append(row)

    # Keep priority order in the output.
    return [row for row in ranked if row in chosen]


def scope_statement(scope: str) -> str:
    """Deterministic, application-written. A broad question ("the health of the
    platform") must not read as a statement about the whole cluster."""
    return (
        f"Scope: only {scope} and the resources observed during this "
        "investigation. This is not an assessment of the rest of the cluster "
        "or of other namespaces."
    )


def build_summary(
    findings: Sequence[InvestigationFinding],
    snapshot: InvestigationEvidenceSnapshot,
    uncertainties: Sequence[str],
) -> str:
    namespaces = sorted({i.namespace for i in snapshot.evidence if i.namespace})
    scope = (
        f"namespace {namespaces[0]!r}"
        if len(namespaces) == 1
        else f"{len(namespaces)} namespaces"
        if namespaces
        else "the authorized namespace"
    )

    target_line = scope_summary_line(snapshot.scope)

    if not findings:
        return (
            "No supported operational findings could be established "
            "from the trusted evidence snapshot. "
            + scope_statement(scope)
            + (f" {target_line}" if target_line else "")
        )

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    mix = ", ".join(
        f"{counts[s]} {s}" for s in _SEVERITY_RANK if s in counts
    )

    ranked = rank_findings(findings, snapshot)
    key = _select_key(ranked)
    lines = [
        f"Investigation of {scope}: {len(findings)} verified finding(s) "
        f"({mix}) from {len(snapshot.evidence)} trusted evidence item(s).",
        scope_statement(scope),
        *([target_line] if target_line else []),
        "Most significant findings, in priority order:",
    ]

    for number, (finding, tools, abnormal) in enumerate(key, start=1):
        if len(tools) > 1:
            support = "corroborated by independent evidence from " + " and ".join(
                sorted(_label(t) for t in tools)
            )
        elif tools:
            support = f"single source: {_label(next(iter(tools)))}"
        else:
            support = "no resolvable evidence"

        refs = ", ".join(r.evidence_id for r in finding.evidence[:MAX_REFS_SHOWN])
        more = len(finding.evidence) - MAX_REFS_SHOWN
        refs += f" and {more} more" if more > 0 else ""
        lines.append(
            f"{number}. [{finding.severity}] {finding.title}: "
            f"{_first_sentence(finding.description)} ({support}; evidence {refs})."
        )

    rest = len(findings) - len(key)
    if rest > 0:
        lines.append(
            f"{rest} further finding(s), including informational observations "
            "such as pod discovery, are listed in the report."
        )

    lines.append(
        f"{len(uncertainties)} uncertaint(ies) are recorded. These findings "
        "describe observed behavior only: the underlying cause is not "
        "established by this report, and any AI-generated hypotheses are "
        "listed separately and remain unverified."
    )

    return "\n".join(lines)[:3000]
