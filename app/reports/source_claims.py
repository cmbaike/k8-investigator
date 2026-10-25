"""Source-aware checks of hypothesis wording.

A hypothesis can draw on three kinds of source, and each needs evidence of its
own kind:

  application logs            what the application PRINTED. A claim about them
                              goes only in the log-claim field and needs a
                              cited log reference (else the hypothesis is
                              omitted as `reported_without_log_evidence`). It
                              may never carry a Kubernetes state.
  structured Kubernetes       states, reasons, exit codes, restart counts and
  observations                declared configuration: cited by evidence id.
  Kubernetes events           reason, type, count and the application's fixed
                              signals: cited by evidence id. The messages are
                              never available, so nothing a message might say
                              (a status code, a path, a port) can be claimed
                              from them.

None of this verifies an explanation. It only stops a claim from borrowing the
provenance of a source it did not come from, and stops specific details from
appearing that no cited evidence supplies. Results are fixed codes; no text is
retained. These are conservative wording heuristics, like the other checks in
`hypotheses`.
"""

import re
from collections.abc import Iterable, Mapping
from typing import Any

from app.reports.state_consistency import _claims

MISATTRIBUTED_SOURCE = "misattributed_source"
UNSUPPORTED_SPECIFIC_CLAIM = "unsupported_specific_claim"

# Names that exist only in Kubernetes: an application never prints these about
# itself, so a "log claim" containing one is a Kubernetes state relabelled.
_STATE_NAMES = (
    r"CrashLoopBackOff|ImagePullBackOff|ErrImagePull|ErrImageNeverPull|OOMKilled|"
    r"ContainerCreating|CreateContainerConfigError|CreateContainerError|"
    r"FailedScheduling|FailedMount|FailedAttachVolume|Unschedulable|restart\s+count"
)
_KUBERNETES_STATE = re.compile(rf"\b(?:{_STATE_NAMES})\b", re.IGNORECASE)

# Probe targets. A specific path or port may be named only when a cited field
# supplies that very value.
_PORT = re.compile(r"\bports?\s+(\d{1,5})\b", re.IGNORECASE)
_PATH = re.compile(r"(?<![\w.:/])(/[A-Za-z0-9._~\-]+(?:/[A-Za-z0-9._~\-]*)*)")
# Event messages are never available, so a status code cannot come from them.
_STATUS_CODE = re.compile(
    r"\b(?:status(?:\s+code)?|HTTP|returns?|returned|responds?\s+with|responded\s+with)"
    r"\s+(?:code\s+)?[1-5]\d{2}\b",
    re.IGNORECASE,
)

_EVENT_CLAIM = re.compile(
    r"\bevents?\b[^.;]{0,60}\b(?:show\w*|indicat\w*|record\w*|report\w*|"
    r"log(?:s|ged)|confirm\w*|reveal\w*|demonstrat\w*)\b"
    r"|\b(?:recorded|logged|reported)\s+(?:by\s+(?:the\s+)?(?:kubelet|kubernetes|"
    r"scheduler)|events?)\b"
    r"|\b(?:probe\s+failure|unhealthy|warning|scheduler|mount|liveness|readiness)"
    r"\s+events?\b",
    re.IGNORECASE,
)
_LIVENESS_EVENT = re.compile(r"\bliveness\b", re.IGNORECASE)
_READINESS_EVENT = re.compile(r"\breadiness\b", re.IGNORECASE)
_LIVENESS_SIGNALS = frozenset({"liveness_probe_failed", "liveness_restart"})
_READINESS_SIGNALS = frozenset({"readiness_probe_failed"})

_SIGNAL_FIELD = re.compile(r"^events\[[^\]]+\]\.signal\[([a-z_]+)\]$")
_PROBE_TARGET_FIELD = re.compile(r"\.(?:liveness|readiness|startup)_probe\.(?:path|port)$")


def reported_violation(reported: str | None, *, cites_logs: bool) -> str | None:
    """Source of the log-claim field when a log IS cited.

    It may not restate a Kubernetes state as something the application
    printed. (With no log cited at all, the field is rejected by the caller as
    `reported_without_log_evidence`, whatever it says.)
    """
    if reported is not None and cites_logs and _KUBERNETES_STATE.search(reported):
        return MISATTRIBUTED_SOURCE

    return None


def _cited_values(cited: Mapping[str, Any]) -> tuple[set[str], set[str], set[str]]:
    """Probe target values, signal names and event fields among cited evidence.
    `cited` maps evidence id -> (field, value)."""
    targets: set[str] = set()
    signals: set[str] = set()
    events: set[str] = set()

    for field, value in cited.values():
        if _PROBE_TARGET_FIELD.search(field) and isinstance(value, (str, int)):
            targets.add(str(value))

        match = _SIGNAL_FIELD.match(field)

        if match:
            signals.add(match.group(1))

        if field.startswith("events["):
            events.add(field)

    return targets, signals, events


def unsupported_claim(
    texts: Iterable[str], cited: Mapping[str, tuple[str, Any]]
) -> str | None:
    """A fixed code when the wording states a specific detail that no cited
    evidence supplies, else None. `cited` maps each cited evidence id to its
    (field, value)."""
    texts = tuple(texts)
    targets, signals, events = _cited_values(cited)

    for text in texts:
        if _STATUS_CODE.search(text):
            return UNSUPPORTED_SPECIFIC_CLAIM

        for match in _PORT.finditer(text):
            if match.group(1) not in targets:
                return UNSUPPORTED_SPECIFIC_CLAIM

        for match in _PATH.finditer(text):
            if match.group(1).rstrip("/") not in {t.rstrip("/") for t in targets}:
                return UNSUPPORTED_SPECIFIC_CLAIM

    if _claims(_EVENT_CLAIM, texts):
        if not events:
            return UNSUPPORTED_SPECIFIC_CLAIM

        for text in texts:
            if not _claims(_EVENT_CLAIM, (text,)):
                continue

            if _LIVENESS_EVENT.search(text) and not signals & _LIVENESS_SIGNALS:
                return UNSUPPORTED_SPECIFIC_CLAIM

            if _READINESS_EVENT.search(text) and not signals & _READINESS_SIGNALS:
                return UNSUPPORTED_SPECIFIC_CLAIM

    return None
