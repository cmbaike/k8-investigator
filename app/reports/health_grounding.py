"""Deterministic container-health findings and coverage disclosure.

Derived only from application-minted observations of k8s.describe_pod and
k8s.get_pods. No model output, log text, command text or environment values are
involved, and nothing here needs log text: an OOMKilled termination is
established by what Kubernetes reports, independently of anything the
application logged.

Memory requests and limits are values CONFIGURED in the pod spec. They are
never presented as observed memory usage.

Pre-start failures (ImagePullBackOff, CreateContainerConfigError, ...) are
reported from the Kubernetes waiting reason alone: the container never ran, so
there are no application logs, and the report states what Kubernetes reports
without asserting why. Kubernetes event reason/type/count (never the message)
add context; they record that events occurred, not their cause.
"""

import re
from dataclasses import dataclass, field

from app.reports.config_grounding import collect_configuration
from app.reports.models import EvidenceReference, InvestigationFinding
from app.reports.probe_declarations import describe_readiness
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.container_health import (
    PRE_START_REASONS,
    HealthCategory,
    classify_container,
)
from app.tools.event_signals import SIGNAL_NAME, VOLUME_NAME, signals_allowed
from app.tools.observations import (
    EVENT_REASON,
    EVENT_TYPES,
    MEMORY_QUANTITY,
    POD_UID,
)
from app.tools.workload_config import safe_image

DESCRIBE_POD_TOOL = "k8s.describe_pod"
POD_DISCOVERY_TOOL = "k8s.get_pods"

_CONTAINER = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"

_FIELD = re.compile(
    rf"^containers\[(?P<container>{_CONTAINER})\]\."
    r"(?P<attr>ready|restart_count|state|reason"
    r"|last_termination\.(?:exit_code|reason)"
    r"|resources\.memory_(?:request|limit))$"
)

EVENTS_TOOL = "k8s.get_events"

_EVENT_FIELD = re.compile(
    r"^events\[(?P<reason>[A-Za-z][A-Za-z0-9]{0,63})\]\."
    r"(?P<attr>type|count|signal\[(?P<signal>[a-z][a-z_]{2,40})\]"
    r"|volume\[(?P<volume>[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)\])$"
)
_EVENT_IDENTITY_FIELD = re.compile(
    r"^events\.(?P<attr>identity|pod_uid|excluded_identity_mismatch)$"
)

MAX_LISTED_PODS = 5
MAX_EVENT_REASONS_SHOWN = 6


@dataclass
class _Container:
    values: dict[str, object] = field(default_factory=dict)
    refs: dict[str, str] = field(default_factory=dict)


def _collect(snapshot: InvestigationEvidenceSnapshot):
    """Latest validated value (and its evidence id) per container attribute."""
    containers: dict[tuple[str, str, str], _Container] = {}

    for item in snapshot.evidence:
        if item.tool != DESCRIBE_POD_TOOL or not item.namespace or not item.pod:
            continue

        match = _FIELD.fullmatch(item.field)

        if match is None:
            continue

        attribute = match.group("attr")
        value = item.value

        if attribute == "restart_count":
            valid = type(value) is int and 0 <= value <= 1_000_000
        elif attribute == "ready":
            valid = type(value) is bool
        elif attribute == "last_termination.exit_code":
            valid = type(value) is int and 0 <= value <= 255
        elif attribute.startswith("resources."):
            valid = isinstance(value, str) and MEMORY_QUANTITY.fullmatch(value) is not None
        else:  # state, reason, last_termination.reason
            valid = isinstance(value, str) and 0 < len(value) <= 100

        if not valid:
            continue

        entry = containers.setdefault(
            (item.namespace, item.pod, match.group("container")), _Container()
        )
        entry.values[attribute] = value
        entry.refs[attribute] = item.evidence_id

    return containers


@dataclass(frozen=True)
class PodEvent:
    """One event reason for a pod: validated type and count, never a message."""

    reason: str
    type: str
    count: int
    type_ref: str
    count_ref: str
    # Fixed-vocabulary classifications of the (never retained) message, each
    # with its evidence id: (signal, ref). Volume names are only those the
    # pod's own spec declares.
    signals: tuple[tuple[str, str], ...] = ()
    volumes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class EventIdentity:
    """How the events of one pod were tied to that pod."""

    uid_verified: bool
    uid_ref: str | None
    pod_uid: str | None
    excluded: int
    excluded_ref: str | None


def collect_event_identity(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], EventIdentity]:
    """Per pod: whether its events were UID-verified, and how many events of a
    different pod (same name, different UID) were excluded."""
    found: dict[tuple[str, str], dict[str, tuple[object, str]]] = {}

    for item in snapshot.evidence:
        if item.tool != EVENTS_TOOL or not item.namespace or not item.pod:
            continue

        match = _EVENT_IDENTITY_FIELD.fullmatch(item.field)

        if match is not None:
            found.setdefault((item.namespace, item.pod), {})[match.group("attr")] = (
                item.value,
                item.evidence_id,
            )

    result: dict[tuple[str, str], EventIdentity] = {}

    for key, attrs in found.items():
        identity, uid = attrs.get("identity"), attrs.get("pod_uid")
        excluded = attrs.get("excluded_identity_mismatch")
        uid_ok = (
            identity is not None
            and identity[0] == "uid_verified"
            and uid is not None
            and isinstance(uid[0], str)
            and POD_UID.fullmatch(uid[0]) is not None
        )
        count = (
            excluded[0]
            if excluded is not None
            and type(excluded[0]) is int
            and 1 <= excluded[0] <= 1_000
            else 0
        )
        result[key] = EventIdentity(
            uid_verified=uid_ok,
            uid_ref=identity[1] if uid_ok else None,
            pod_uid=uid[0] if uid_ok else None,
            excluded=count,
            excluded_ref=excluded[1] if count else None,
        )

    return result


def _described_uids(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], tuple[str, str]]:
    uids = {}

    for item in snapshot.evidence:
        if (
            item.tool == DESCRIBE_POD_TOOL
            and item.field == "pod.uid"
            and item.namespace
            and item.pod
            and isinstance(item.value, str)
            and POD_UID.fullmatch(item.value)
        ):
            uids[(item.namespace, item.pod)] = (item.value, item.evidence_id)

    return uids


def identity_conflicts(
    snapshot: InvestigationEvidenceSnapshot,
) -> set[tuple[str, str]]:
    """Pods whose events were verified against a DIFFERENT pod object than the
    one described (the pod was replaced between the two reads). Their events
    do not describe the inspected pod and are not used."""
    described = _described_uids(snapshot)

    return {
        key
        for key, identity in collect_event_identity(snapshot).items()
        if identity.uid_verified
        and key in described
        and described[key][0] != identity.pod_uid
    }


def collect_pod_events(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], list[PodEvent]]:
    """Validated event observations per (namespace, pod). Warnings first."""
    raw: dict[tuple[str, str], dict[str, dict[str, object]]] = {}
    conflicts = identity_conflicts(snapshot)

    for item in snapshot.evidence:
        if item.tool != EVENTS_TOOL or not item.namespace or not item.pod:
            continue

        if (item.namespace, item.pod) in conflicts:
            continue

        match = _EVENT_FIELD.fullmatch(item.field)

        if match is None or not EVENT_REASON.fullmatch(match.group("reason")):
            continue

        reason = match.group("reason")
        attrs = raw.setdefault((item.namespace, item.pod), {}).setdefault(reason, {})
        signal, volume = match.group("signal"), match.group("volume")

        if signal is not None:
            if (
                item.value is True
                and SIGNAL_NAME.fullmatch(signal)
                and signals_allowed(reason, signal)
            ):
                attrs.setdefault("signals", {})[signal] = item.evidence_id
        elif volume is not None:
            if item.value is True and VOLUME_NAME.fullmatch(volume):
                attrs.setdefault("volumes", {})[volume] = item.evidence_id
        else:
            attrs[match.group("attr")] = (item.value, item.evidence_id)

    result: dict[tuple[str, str], list[PodEvent]] = {}

    for key, reasons in raw.items():
        events = []

        for reason, attrs in reasons.items():
            kind, count = attrs.get("type"), attrs.get("count")

            if (
                kind is None
                or count is None
                or kind[0] not in EVENT_TYPES
                or type(count[0]) is not int
                or not 1 <= count[0] <= 1_000_000
            ):
                continue

            events.append(
                PodEvent(
                    reason,
                    kind[0],
                    count[0],
                    kind[1],
                    count[1],
                    tuple(sorted(attrs.get("signals", {}).items())),
                    tuple(sorted(attrs.get("volumes", {}).items())),
                )
            )

        events.sort(key=lambda e: (e.type != "Warning", -e.count, e.reason))

        if events:
            result[key] = events

    return result


def collect_container_values(snapshot: InvestigationEvidenceSnapshot):
    """Validated observed values per (namespace, pod, container)."""
    return {key: dict(c.values) for key, c in _collect(snapshot).items()}


def collect_container_classifications(snapshot: InvestigationEvidenceSnapshot):
    """Deterministic health classification per (namespace, pod, container)."""
    return {
        key: classify_container(container.values)
        for key, container in _collect(snapshot).items()
    }


def _collect_phases(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], tuple[str, str]]:
    phases = {}

    for item in snapshot.evidence:
        if (
            item.tool == DESCRIBE_POD_TOOL
            and item.field == "pod.phase"
            and item.namespace
            and item.pod
            and isinstance(item.value, str)
            and 0 < len(item.value) <= 30
        ):
            phases[(item.namespace, item.pod)] = (item.value, item.evidence_id)

    return phases


_CONDITION_FIELD = re.compile(
    r"^conditions\[(?P<kind>[A-Za-z]{1,40})\]\.(?P<attr>status|reason)$"
)
READINESS_CONDITIONS = ("Ready", "ContainersReady")


def collect_pod_conditions(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], dict[str, dict[str, tuple[str, str]]]]:
    """Validated pod conditions: (ns, pod) -> type -> attr -> (value, evidence id)."""
    result: dict = {}

    for item in snapshot.evidence:
        if item.tool != DESCRIBE_POD_TOOL or not item.namespace or not item.pod:
            continue

        match = _CONDITION_FIELD.fullmatch(item.field)

        if match is None or not isinstance(item.value, str):
            continue

        if match.group("attr") == "status" and item.value not in {"True", "False", "Unknown"}:
            continue

        if match.group("attr") == "reason" and not EVENT_REASON.fullmatch(item.value):
            continue

        result.setdefault((item.namespace, item.pod), {}).setdefault(
            match.group("kind"), {}
        )[match.group("attr")] = (item.value, item.evidence_id)

    return result


def _describe_events(events: list[PodEvent]) -> str:
    shown = ", ".join(
        f"{e.type} {e.reason!r} (x{e.count})"
        for e in events[:MAX_EVENT_REASONS_SHOWN]
    )
    more = len(events) - MAX_EVENT_REASONS_SHOWN

    return shown + (f" and {more} more" if more > 0 else "")


MAX_DESCRIPTION_CHARS = 1_990


def fit_description(sentences: list[str], *, closing: int = 2) -> str:
    """Join sentences within the report model's description limit.

    The first sentence and the last `closing` sentences (the standing
    disclaimer and the resource line) are kept. Optional sentences between them
    are dropped from the back until the text fits, so a long finding loses
    optional detail, never its meaning, and never fails validation.
    """
    kept = list(sentences)

    while len(" ".join(kept)) > MAX_DESCRIPTION_CHARS and len(kept) > 1 + closing:
        del kept[len(kept) - closing - 1]

    return " ".join(kept)[:MAX_DESCRIPTION_CHARS]


def _failure_finding(
    namespace: str,
    pod: str,
    name: str,
    container: _Container,
    phase: tuple[str, str] | None,
    image: tuple[str, str] | None,
    events: list[PodEvent],
    probe: tuple[str, list[str]] | None = None,
    conditions: dict[str, dict[str, tuple[str, str]]] | None = None,
) -> InvestigationFinding | None:
    """Finding for a runtime or pre-start failure established by Kubernetes.

    States what Kubernetes reports (reason, restarts, phase) and the configured
    image. It does not assert why the failure occurred: the reason names the
    failed operation, not its cause.
    """
    values = container.values
    assessment = classify_container(values)

    if not assessment.is_failure or assessment.severity is None:
        return None

    pre_start = assessment.category is HealthCategory.PRE_START_FAILURE
    not_ready = assessment.category is HealthCategory.NOT_READY
    reason = assessment.reason
    restarts = values.get("restart_count")
    wanted: list[str] = []
    sentences: list[str] = []

    if pre_start:
        title = "Container could not be started"
        sentences.append(
            f"Container {name!r} has not started: Kubernetes reports it "
            f"waiting with reason {reason!r}."
        )

        if reason in PRE_START_REASONS:
            sentences.append(PRE_START_REASONS[reason].meaning + ".")

        wanted.extend(["state", "reason"])
    elif not_ready:
        title = "Container is running but not ready"
        sentences.append(
            f"Container {name!r} is running but not ready: Kubernetes reports "
            "its state as 'running' and its readiness as False."
        )
        wanted.extend(["state", "ready"])
    else:
        looping = values.get("state") == "waiting" and reason == "CrashLoopBackOff"
        title = (
            "Container is crash-looping"
            if looping
            else "Container failed at runtime"
        )
        sentences.append(
            f"Container {name!r} started and then failed: Kubernetes reports "
            f"it not ready, state {values.get('state')!r}"
            + (f", reason {reason!r}" if reason else "")
            + "."
        )
        wanted.extend(
            attr for attr in ("ready", "state", "reason") if attr in values
        )

        if "last_termination.reason" in values or "last_termination.exit_code" in values:
            previous = []

            if "last_termination.reason" in values:
                previous.append(f"reason {values['last_termination.reason']!r}")
                wanted.append("last_termination.reason")

            if "last_termination.exit_code" in values:
                previous.append(f"exit code {values['last_termination.exit_code']}")
                wanted.append("last_termination.exit_code")

            sentences.append(
                f"Its previous termination reported {' and '.join(previous)}."
            )

    if type(restarts) is int:
        sentences.append(
            f"It has restarted {restarts} time{'' if restarts == 1 else 's'}."
        )
        wanted.append("restart_count")

    refs = [container.refs[a] for a in wanted if a in container.refs]

    if phase is not None:
        sentences.append(f"The pod phase is {phase[0]!r}.")
        refs.append(phase[1])

    if not_ready:
        failed = [
            (kind, c)
            for kind in READINESS_CONDITIONS
            if (c := (conditions or {}).get(kind, {})).get("status", ("",))[0]
            == "False"
        ]

        for kind, condition in failed:
            detail = condition.get("reason")
            sentences.append(
                f"Kubernetes marks the pod condition {kind!r} as False"
                + (f" (reason {detail[0]!r})" if detail else "")
                + "."
            )
            refs.append(condition["status"][1])

            if detail:
                refs.append(detail[1])

        if probe is not None:
            sentences.append(f"Its spec {probe[0]}.")
            refs.extend(probe[1])

    if pre_start and image is not None:
        sentences.append(
            f"The configured image reference is {image[0]!r} (from the "
            "Deployment spec)."
        )
        refs.append(image[1])

    warnings = [e for e in events if e.type == "Warning"]

    if warnings:
        sentences.append(
            "Kubernetes also recorded Warning events for this pod: "
            + ", ".join(f"{e.reason!r} (x{e.count})" for e in warnings[:4])
            + "."
        )

        for event in warnings[:4]:
            refs.extend([event.type_ref, event.count_ref])

    if not (pre_start or not_ready):
        liveness = [
            (event, ref)
            for event in events
            if event.reason in {"Unhealthy", "Killing"}
            for signal, ref in event.signals
            if signal in {"liveness_probe_failed", "liveness_restart"}
        ]

        if liveness:
            sentences.append(
                "Kubernetes also recorded events for this pod that were "
                "classified (fixed patterns; the messages are untrusted and "
                "not retained) as liveness-probe failures. They belong to the "
                "pod, not to one container, and do not by themselves "
                "establish that the probe caused this failure or why it failed."
            )

            for event, ref in liveness[:2]:
                refs.extend([event.type_ref, event.count_ref, ref])

    if not_ready:
        unhealthy = next((e for e in events if e.reason == "Unhealthy"), None)

        if unhealthy is not None:
            classified = {name: ref for name, ref in unhealthy.signals}
            kinds = [
                (name, label)
                for name, label in (
                    ("readiness_probe_failed", "readiness"),
                    ("liveness_probe_failed", "liveness"),
                    ("startup_probe_failed", "startup"),
                )
                if name in classified
            ]

            if kinds:
                sentences.append(
                    f"The {unhealthy.type} event reason 'Unhealthy' "
                    f"(x{unhealthy.count}) was classified from its message "
                    "(fixed patterns; the message itself is untrusted and not "
                    "retained) as "
                    + " and ".join(f"{label}-probe" for _, label in kinds)
                    + " failures."
                )
                refs.extend([unhealthy.type_ref, unhealthy.count_ref])
                refs.extend(classified[name] for name, _ in kinds)
            else:
                sentences.append(
                    f"The {unhealthy.type} event reason 'Unhealthy' "
                    f"(x{unhealthy.count}) is the reason Kubernetes uses when a "
                    "probe fails; the event message, which would say which "
                    "probe, is untrusted and not retained."
                )
                refs.extend([unhealthy.type_ref, unhealthy.count_ref])

        if assessment.has_restart_history and type(restarts) is int:
            sentences.append(
                f"Its {restarts} earlier restart{'' if restarts == 1 else 's'} "
                "are history: they are separate from, and do not explain, the "
                "container being not ready now."
            )

        sentences.append(
            "Kubernetes does not report why the container is not ready. This "
            "finding establishes that it is not ready, not the cause, and it "
            "does not by itself show that a readiness probe failed."
        )
    elif pre_start:
        sentences.append(
            "This report establishes the state Kubernetes reports, not its "
            "cause: it does not by itself show that the image does not exist "
            "or that the configuration is wrong."
        )
    else:
        sentences.append("The cause of the failure is not established by this finding.")

    sentences.append(f"Resource: namespace {namespace!r}, pod {pod!r}.")

    return InvestigationFinding(
        title=title,
        description=fit_description(sentences),
        severity=assessment.severity,
        evidence=[EvidenceReference(evidence_id=r) for r in dict.fromkeys(refs)],
    )


def _events_finding(
    namespace: str, pod: str, events: list[PodEvent]
) -> InvestigationFinding:
    refs = []

    for event in events[:MAX_EVENT_REASONS_SHOWN]:
        refs.extend([event.type_ref, event.count_ref])

    return InvestigationFinding(
        title="Kubernetes events recorded for the pod",
        description=(
            f"Kubernetes recorded {len(events)} event reason"
            f"{'' if len(events) == 1 else 's'} for pod {pod!r}: "
            f"{_describe_events(events)}. Only each event's reason, type and "
            "count are used. The event messages are untrusted text and are "
            "not part of this report. These records show that Kubernetes "
            "logged the events, not why they occurred. "
            f"Resource: namespace {namespace!r}, pod {pod!r}."
        ),
        severity="info",
        evidence=[EvidenceReference(evidence_id=r) for r in refs],
    )


def build_container_health_findings(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[InvestigationFinding]:
    """Findings for containers Kubernetes reports as failing.

    OOMKilled terminations get a dedicated finding (below); every other
    runtime or pre-start failure gets a generic finding from its reason. An
    events summary is added for each pod whose events were retrieved.

    Severity (deterministic, from Kubernetes-reported facts only):
      critical - the container is not ready and is in a CrashLoopBackOff
                 after that termination: it is repeatedly being killed and is
                 not running now;
      warning  - it was OOMKilled but is not reported in a crash loop.
    """
    findings: list[InvestigationFinding] = []
    phases = _collect_phases(snapshot)
    events_by_pod = collect_pod_events(snapshot)
    configuration, _ = collect_configuration(snapshot)
    conditions = collect_pod_conditions(snapshot)

    for (namespace, pod, name), container in sorted(_collect(snapshot).items()):
        values = container.values

        if values.get("last_termination.reason") != "OOMKilled":
            pod_config = configuration.get((namespace, pod))
            config = pod_config.containers.get(name) if pod_config else None
            configured = safe_image(config.attrs.get("image")) if config else None
            failure = _failure_finding(
                namespace,
                pod,
                name,
                container,
                phases.get((namespace, pod)),
                (configured, config.refs["image"]) if configured else None,
                events_by_pod.get((namespace, pod), []),
                describe_readiness(snapshot, (namespace, pod), name, config),
                conditions.get((namespace, pod)),
            )

            if failure is not None:
                findings.append(failure)

            continue

        restarts = values.get("restart_count")
        looping = (
            values.get("ready") is False
            and values.get("state") == "waiting"
            and values.get("reason") == "CrashLoopBackOff"
            and type(restarts) is int
            and restarts >= 1
        )
        severity = "critical" if looping else "warning"

        parts = [
            f"Kubernetes reported that container {name!r} was previously "
            "terminated with reason 'OOMKilled'"
        ]
        wanted = ["last_termination.reason"]

        if "last_termination.exit_code" in values:
            parts[0] += f" (exit code {values['last_termination.exit_code']})"
            wanted.append("last_termination.exit_code")

        sentences = [parts[0] + ", meaning it was killed for running out of memory."]

        if type(restarts) is int:
            sentences.append(
                f"It has restarted {restarts} time{'' if restarts == 1 else 's'}."
            )
            wanted.append("restart_count")

        if looping:
            sentences.append(
                "It is currently not ready and waiting with reason "
                "'CrashLoopBackOff'."
            )
            wanted.extend(["ready", "state", "reason"])

        limit = values.get("resources.memory_limit")
        request = values.get("resources.memory_request")

        if limit is not None or request is not None:
            declared = []

            if limit is not None:
                declared.append(f"a memory limit of {limit}")
                wanted.append("resources.memory_limit")

            if request is not None:
                declared.append(f"a memory request of {request}")
                wanted.append("resources.memory_request")

            sentences.append(
                f"The pod spec declares {' and '.join(declared)}. These are "
                "configured values, not measured memory usage; this report "
                "does not establish how much memory the application used or "
                "why."
            )

        sentences.append(f"Resource: namespace {namespace!r}, pod {pod!r}.")

        findings.append(
            InvestigationFinding(
                title="Container previously terminated as OOMKilled",
                description=" ".join(sentences),
                severity=severity,
                evidence=[
                    EvidenceReference(evidence_id=container.refs[attribute])
                    for attribute in wanted
                ],
            )
        )

    for (namespace, pod), events in sorted(events_by_pod.items()):
        findings.append(_events_finding(namespace, pod, events))

    return findings


def build_health_inspection_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    """Disclose discovered pods whose health was never inspected.

    A pod discovered by get_pods with no describe_pod evidence was not
    inspected (step budget, inspection limit, or a failed/denied call). Its
    health is UNKNOWN; it is never implied to be healthy.
    """
    discovered: set[tuple[str, str]] = set()
    inspected: set[tuple[str, str]] = set()

    for item in snapshot.evidence:
        if not item.namespace or not item.pod:
            continue

        if item.tool == POD_DISCOVERY_TOOL and item.field == "pods[].name":
            discovered.add((item.namespace, item.pod))
        elif item.tool == DESCRIBE_POD_TOOL:
            inspected.add((item.namespace, item.pod))

    missing = sorted(discovered - inspected)
    scope = snapshot.scope
    notes: list[str] = []

    if scope is not None and scope.listing_truncated:
        notes.append(
            "The pod listing was longer than one API page. Pods beyond that "
            "page were not discovered and are unknown, not healthy."
        )

    # Scope counts are the inspection record. Report evidence is capped, so a
    # pod can be absent from the snapshot after it was actually described.
    scope_records_coverage = scope is not None and (
        scope.uninspected > 0
        or scope.unsuccessful > 0
        or scope.inspected >= scope.listed
    )

    if scope_records_coverage:
        total_missing = scope.uninspected + scope.unsuccessful

        if total_missing == 0:
            return notes

        ordered = list(scope.uninspected_pods) + [
            name for name in scope.unsuccessful_pods
            if name not in scope.uninspected_pods
        ]
        shown = ordered[:MAX_LISTED_PODS]
        names = ", ".join(repr(pod) for pod in shown)
        hidden = total_missing - len(shown)

        if hidden > 0:
            names += f" and {hidden} more"

        reported_missing = total_missing
        reported_listed = scope.listed
        namespaces = sorted({
            item.namespace for item in snapshot.evidence if item.namespace
        })
    elif not missing:
        return notes
    else:
        names = ", ".join(repr(pod) for _, pod in missing[:MAX_LISTED_PODS])

        if len(missing) > MAX_LISTED_PODS:
            names += f" and {len(missing) - MAX_LISTED_PODS} more"

        reported_missing = len(missing)
        reported_listed = len(discovered)
        namespaces = sorted({namespace for namespace, _ in missing})

    where = (
        f"namespace {namespaces[0]!r}"
        if len(namespaces) == 1
        else "the investigated namespaces"
    )

    notes.append(
        f"{reported_missing} of {reported_listed} pod(s) discovered in {where} "
        f"were not health-inspected ({names}): the inspection limit, deadline "
        "or step budget was reached, or the inspection failed or was denied. "
        "Their health is unknown and must not be read as healthy."
    )

    if scope is not None and scope.unsuccessful:
        notes.append(
            f"{scope.unsuccessful} pod inspection(s) were attempted and did "
            "not succeed. That is not a healthy result."
        )

    return notes
