"""Declared liveness and readiness probes, and whether each was observed.

A probe is in exactly one of three states, and only the first two are facts:

  * DECLARED         - the Pod's (or its workload's) container specification
                       declares it;
  * verified ABSENT  - the specification was read and declares no such probe;
  * UNKNOWN          - the specification was not read, so nothing is known.

UNKNOWN is never treated as absent: an explanation that blames a probe is
contradicted only by a VERIFIED absence.

Two sources exist for a readiness probe:

  1. the Pod's own container specification (`k8s.describe_pod`), which needs
     no controlling workload and so covers a standalone Pod;
  2. the owning workload's pod template (`k8s.describe_workload_config`),
     available only when ownership was verified.

The Pod's own specification is what actually runs, so it is preferred; the
workload template is the fallback. Only declared/kind/port/path/timings are
ever read (never a header, host or command).
"""

import re

from app.reports.config_grounding import describe_readiness_probe
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.workload_config import (
    PORT_NAME_PATTERN,
    PROBE_KINDS,
    PROBE_PATH_PATTERN,
)

DESCRIBE_POD_TOOL = "k8s.describe_pod"

_PROBE_FIELD = re.compile(
    r"^containers\[(?P<container>[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)\]"
    r"\.(?P<probe>liveness|readiness)_probe\."
    r"(?P<attr>declared|kind|port|path|initial_delay_seconds|"
    r"period_seconds|timeout_seconds|failure_threshold)$"
)
_TIMINGS = (
    ("initial_delay_seconds", "initial delay {}s"),
    ("period_seconds", "period {}s"),
    ("timeout_seconds", "timeout {}s"),
    ("failure_threshold", "failure threshold {}"),
)


def describe_pod_probe(
    snapshot: InvestigationEvidenceSnapshot,
    key: tuple[str, str],
    container: str,
    probe: str,
) -> tuple[str, list[str]] | None:
    """(statement, refs) for the declared `probe` ("liveness" or "readiness")
    read from the POD's own container specification, or None when it was not
    collected (unknown, never assumed absent)."""
    values: dict[str, tuple[object, str]] = {}

    for item in snapshot.evidence:
        if item.tool != DESCRIBE_POD_TOOL or (item.namespace, item.pod) != key:
            continue

        match = _PROBE_FIELD.fullmatch(item.field)

        if (
            match is not None
            and match.group("container") == container
            and match.group("probe") == probe
        ):
            values[match.group("attr")] = (item.value, item.evidence_id)

    declared = values.get("declared")

    if declared is None or type(declared[0]) is not bool:
        return None

    if declared[0] is False:
        return f"declares no {probe} probe", [declared[1]]

    parts, refs = [], [declared[1]]
    kind = values.get("kind")

    if kind and kind[0] in PROBE_KINDS:
        parts.append(f"{kind[0]} handler")
        refs.append(kind[1])

    port = values.get("port")

    if port and (
        (type(port[0]) is int and 1 <= port[0] <= 65535)
        or (isinstance(port[0], str) and PORT_NAME_PATTERN.fullmatch(port[0]))
    ):
        parts.append(f"port {port[0]}")
        refs.append(port[1])

    path = values.get("path")

    if path and isinstance(path[0], str) and PROBE_PATH_PATTERN.fullmatch(path[0]):
        parts.append(f"path {path[0]!r}")
        refs.append(path[1])

    for attr, label in _TIMINGS:
        value = values.get(attr)

        if value and type(value[0]) is int and 0 <= value[0] <= 100_000:
            parts.append(label.format(value[0]))
            refs.append(value[1])

    return (
        f"declares a {probe} probe" + (f" ({', '.join(parts)})" if parts else ""),
        refs,
    )


def describe_readiness(
    snapshot: InvestigationEvidenceSnapshot,
    key: tuple[str, str],
    container: str,
    workload_config=None,
) -> tuple[str, list[str]] | None:
    """The declared readiness probe of `container`: the Pod's own specification
    first, the owning workload's template otherwise, None when neither was
    collected."""
    found = describe_pod_probe(snapshot, key, container, "readiness")

    if found is not None:
        return found

    return describe_readiness_probe(workload_config) if workload_config else None


def readiness_declared(
    snapshot: InvestigationEvidenceSnapshot,
    key: tuple[str, str],
    container: str,
    workload_config=None,
) -> bool | None:
    """True / False when the readiness probe declaration was observed, None
    (unknown) when it was not."""
    found = describe_readiness(snapshot, key, container, workload_config)

    if found is None:
        return None

    return not found[0].startswith("declares no ")
