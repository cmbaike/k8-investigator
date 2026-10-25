"""Deterministic findings for failures that live at the pod level or in history.

  * an unschedulable pod (structured PodScheduled condition, plus the
    scheduler's FailedScheduling events);
  * a pod whose containers cannot be created because a volume cannot be
    mounted (structured pod/container state, plus kubelet FailedMount events);
  * a container that restarted after a failed termination and is running now
    (restart history, reported separately from current readiness, with liveness
    probe events when Kubernetes recorded them).

Every statement rests on application-minted observations only. An event counts
only when it was tied to the inspected pod (name, and UID where the cluster
supplied one). A message-derived classification is worded as exactly that: the
message is untrusted and never shown or stored, and a classification says what
Kubernetes reported, never what caused it.
"""

import re
from dataclasses import dataclass, field

from app.reports.health_grounding import (
    PodEvent,
    collect_event_identity,
    collect_pod_conditions,
    collect_pod_events,
    fit_description,
    _collect,
    _collect_phases,
    identity_conflicts,
)
from app.reports.models import (
    SCHEDULING_CONSTRAINT_LABELS,
    EvidenceReference,
    InvestigationFinding,
    SchedulingConstraint,
)
from app.reports.probe_declarations import describe_pod_probe
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.container_health import HealthCategory, classify_container
from app.tools.event_signals import SCHEDULING_CONSTRAINTS
from app.tools.observations import MEMORY_QUANTITY, VOLUME_SOURCES
from app.tools.pod_health import PodAssessment, PodCategory, classify_pod

DESCRIBE_POD_TOOL = "k8s.describe_pod"

SCHEDULING_LABELS = {
    "insufficient_cpu": "insufficient CPU",
    "insufficient_memory": "insufficient memory",
    "insufficient_ephemeral_storage": "insufficient ephemeral storage",
    "too_many_pods": "nodes already at their pod limit",
    "untolerated_taint": "node taints the pod does not tolerate",
    "node_selector_mismatch": "nodes that do not match the pod's node selector or affinity",
    "pod_affinity_mismatch": "pod affinity, anti-affinity or topology-spread rules the nodes do not satisfy",
    "node_unschedulable": "nodes marked unschedulable",
    "unbound_volume_claim": "a PersistentVolumeClaim that is missing or not bound",
    "volume_node_conflict": "a volume whose node affinity conflicts with the available nodes",
}

MOUNT_LABELS = {
    "config_map_not_found": "a referenced ConfigMap was reported as not found",
    "secret_not_found": "a referenced Secret was reported as not found",
    "claim_not_found": "a referenced PersistentVolumeClaim was reported as not found",
    "mount_timeout": "the mount timed out waiting for its condition",
    "attach_failed": "attaching the volume failed",
    "mount_device_failed": "mounting the volume's device failed",
    "mount_setup_failed": "setting up the volume mount failed",
}

VOLUME_SOURCE_LABELS = {
    "config_map": "ConfigMap",
    "secret": "Secret",
    "persistent_volume_claim": "PersistentVolumeClaim",
    "empty_dir": "emptyDir",
    "host_path": "hostPath",
    "projected": "projected",
    "downward_api": "downwardAPI",
    "csi": "CSI",
    "nfs": "NFS",
    "ephemeral": "ephemeral",
    "other": "other",
}

_VOLUME_FIELD = re.compile(
    r"^volumes\[(?P<name>[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?)\]\.source$"
)
_CONDITION_SIGNAL = re.compile(
    r"^conditions\[PodScheduled\]\.signal\[(?P<signal>[a-z][a-z_]{2,40})\]$"
)
MAX_REFS = 14


@dataclass
class PodFacts:
    """Validated structured facts about one pod, each with its evidence id."""

    namespace: str
    pod: str
    phase: tuple[str, str] | None = None
    scheduled_status: tuple[str, str] | None = None
    scheduled_reason: tuple[str, str] | None = None
    scheduling_signals: dict[str, str] = field(default_factory=dict)
    volumes: dict[str, tuple[str, str]] = field(default_factory=dict)
    node_selector: tuple[bool, str] | None = None
    affinity: tuple[bool, str] | None = None
    events: list[PodEvent] = field(default_factory=list)


def collect_pod_facts(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], PodFacts]:
    facts: dict[tuple[str, str], PodFacts] = {}
    phases = _collect_phases(snapshot)
    conditions = collect_pod_conditions(snapshot)
    events = collect_pod_events(snapshot)

    def entry(namespace: str, pod: str) -> PodFacts:
        return facts.setdefault((namespace, pod), PodFacts(namespace, pod))

    for (namespace, pod), phase in phases.items():
        entry(namespace, pod).phase = phase

    for (namespace, pod), by_type in conditions.items():
        scheduled = by_type.get("PodScheduled", {})
        item = entry(namespace, pod)
        item.scheduled_status = scheduled.get("status")
        item.scheduled_reason = scheduled.get("reason")

    for key, listed in events.items():
        entry(*key).events = listed

    for item in snapshot.evidence:
        if item.tool != DESCRIBE_POD_TOOL or not item.namespace or not item.pod:
            continue

        match = _CONDITION_SIGNAL.fullmatch(item.field)

        if match is not None:
            if item.value is True and match.group("signal") in SCHEDULING_CONSTRAINTS:
                entry(item.namespace, item.pod).scheduling_signals[
                    match.group("signal")
                ] = item.evidence_id
            continue

        match = _VOLUME_FIELD.fullmatch(item.field)

        if match is not None:
            if item.value in VOLUME_SOURCES:
                entry(item.namespace, item.pod).volumes[match.group("name")] = (
                    item.value,
                    item.evidence_id,
                )
            continue

        if item.field in {"scheduling.node_selector_declared", "scheduling.affinity_declared"}:
            if type(item.value) is bool:
                target = entry(item.namespace, item.pod)

                if item.field.endswith("node_selector_declared"):
                    target.node_selector = (item.value, item.evidence_id)
                else:
                    target.affinity = (item.value, item.evidence_id)

    return facts


def _scheduled(facts: PodFacts) -> tuple[str, str | None] | None:
    if facts.scheduled_status is None:
        return None

    reason = facts.scheduled_reason[0] if facts.scheduled_reason else None

    return facts.scheduled_status[0], reason


def classify_pods(
    snapshot: InvestigationEvidenceSnapshot,
) -> dict[tuple[str, str], tuple[PodAssessment, PodFacts]]:
    """Pod-level assessment per (namespace, pod), where one is established."""
    containers = _collect(snapshot)
    result: dict[tuple[str, str], tuple[PodAssessment, PodFacts]] = {}

    for key, facts in collect_pod_facts(snapshot).items():
        states = [
            (c.values.get("state"), c.values.get("reason"))
            for (namespace, pod, _), c in containers.items()
            if (namespace, pod) == key
        ]
        assessment = classify_pod(
            phase=facts.phase[0] if facts.phase else None,
            scheduled=_scheduled(facts),
            container_states=states,
            event_counts={event.reason: event.count for event in facts.events},
        )

        if assessment is not None:
            result[key] = (assessment, facts)

    return result


def unschedulable_pods(snapshot: InvestigationEvidenceSnapshot) -> set[tuple[str, str]]:
    return {
        key
        for key, (assessment, _) in classify_pods(snapshot).items()
        if assessment.category is PodCategory.UNSCHEDULABLE
    }


def _identity_sentence(snapshot, key, refs: list[str]) -> str:
    identity = collect_event_identity(snapshot).get(key)
    parts = []

    if identity is not None and identity.uid_verified and identity.uid_ref:
        refs.append(identity.uid_ref)
        parts.append(
            "These events were tied to this pod by namespace, name and "
            "Kubernetes UID."
        )
    else:
        parts.append(
            "These events were tied to this pod by namespace and pod name; "
            "no Kubernetes UID check was possible."
        )

    if identity is not None and identity.excluded and identity.excluded_ref:
        refs.append(identity.excluded_ref)
        parts.append(
            f"{identity.excluded} event(s) naming a different pod UID under "
            "the same pod name were excluded as belonging to another pod."
        )

    return " ".join(parts)


def _event_sentences(
    events: list[PodEvent], reasons: tuple[str, ...], refs: list[str]
) -> list[str]:
    sentences = []

    for event in events:
        if event.reason not in reasons:
            continue

        sentences.append(
            f"Kubernetes recorded {event.type} event {event.reason!r} "
            f"(x{event.count}) for this pod."
        )
        refs.extend([event.type_ref, event.count_ref])

    return sentences


def _signal_sentence(
    prefix: str,
    labels: dict[str, str],
    signals: dict[str, str],
    refs: list[str],
) -> str | None:
    known = [name for name in labels if name in signals]

    if not known:
        return None

    refs.extend(signals[name] for name in known)

    return (
        f"{prefix} (classified by fixed patterns; the message itself is "
        f"untrusted and not retained): {'; '.join(labels[n] for n in known)}."
    )


MAX_CONSTRAINT_REFS = 4


def _scheduling_constraints(
    facts: PodFacts, refs: list[str]
) -> list[SchedulingConstraint]:
    """The classified scheduler constraints as structured, fixed-vocabulary
    rows, each with the observations that establish it.

    Derived only from validated signal observations (never a message), in the
    vocabulary's display order. `refs` gains each row's evidence ids so the
    finding's own evidence always includes them."""
    by_signal: dict[str, list[str]] = {}

    for name, ref in facts.scheduling_signals.items():
        by_signal.setdefault(name, []).append(ref)

    for event in facts.events:
        if event.reason != "FailedScheduling":
            continue

        for name, ref in event.signals:
            if name in SCHEDULING_CONSTRAINTS:
                by_signal.setdefault(name, []).append(ref)

    rows: list[SchedulingConstraint] = []

    for name, label in SCHEDULING_CONSTRAINT_LABELS.items():
        found = list(dict.fromkeys(by_signal.get(name, ())))[:MAX_CONSTRAINT_REFS]

        if not found:
            continue

        refs.extend(found)
        rows.append(
            SchedulingConstraint(signal=name, label=label, evidence_ids=found)
        )

    return rows


def _unschedulable_finding(snapshot, key, facts: PodFacts, assessment) -> InvestigationFinding:
    namespace, pod = key
    refs: list[str] = []
    sentences = [
        f"Pod {pod!r} is {facts.phase[0]!r} and Kubernetes marks its "
        "PodScheduled condition False with reason 'Unschedulable': "
        + assessment.meaning
        + "."
    ]

    if facts.phase:
        refs.append(facts.phase[1])

    if facts.scheduled_status:
        refs.append(facts.scheduled_status[1])

    if facts.scheduled_reason:
        refs.append(facts.scheduled_reason[1])

    signals = dict(facts.scheduling_signals)

    for event in facts.events:
        if event.reason == "FailedScheduling":
            signals.update(dict(event.signals))

    sentence = _signal_sentence(
        "The scheduler's status message reports", SCHEDULING_LABELS, signals, refs
    )

    if sentence:
        sentences.append(sentence)

    constraints = _scheduling_constraints(facts, refs)

    event_sentences = _event_sentences(facts.events, ("FailedScheduling",), refs)
    sentences.extend(event_sentences)

    if event_sentences:
        sentences.append(_identity_sentence(snapshot, key, refs))

    containers = {
        name: c for (n, p, name), c in _collect(snapshot).items() if (n, p) == key
    }
    declared = []

    for name, container in sorted(containers.items()):
        memory = container.values.get("resources.memory_request")

        if isinstance(memory, str) and MEMORY_QUANTITY.fullmatch(memory):
            declared.append(f"container {name!r} a memory request of {memory}")
            refs.append(container.refs["resources.memory_request"])

    if declared:
        sentences.append(
            f"The pod spec declares {' and '.join(declared)} (configured "
            "values, not usage)."
        )

    placement = []

    for label, fact in (
        ("a node selector", facts.node_selector),
        ("node or pod affinity rules", facts.affinity),
    ):
        if fact is not None and fact[0] is True:
            placement.append(label)
            refs.append(fact[1])

    if placement:
        sentences.append(f"The pod spec declares {' and '.join(placement)}.")

    sentences.append(
        "This establishes that Kubernetes could not place the pod and, where "
        "classified, which constraint the scheduler reported. It does not "
        "establish why the cluster cannot meet that constraint, and no "
        "container has run, so there are no logs, restarts or probe results."
    )
    sentences.append(f"Resource: namespace {namespace!r}, pod {pod!r}.")

    evidence = [EvidenceReference(evidence_id=r) for r in dict.fromkeys(refs)][:MAX_REFS]
    cited = {reference.evidence_id for reference in evidence}

    return InvestigationFinding(
        title="Pod could not be scheduled",
        description=fit_description(sentences),
        severity=assessment.severity,
        evidence=evidence,
        # Only constraints whose observations all fit the finding's evidence.
        scheduling_constraints=[
            c for c in constraints if set(c.evidence_ids) <= cited
        ],
    )


def _volume_finding(snapshot, key, facts: PodFacts, assessment) -> InvestigationFinding:
    namespace, pod = key
    refs: list[str] = []
    creating = sorted(
        name
        for (n, p, name), c in _collect(snapshot).items()
        if (n, p) == key
        and c.values.get("state") == "waiting"
        and c.values.get("reason") == "ContainerCreating"
    )
    containers = _collect(snapshot)
    sentences = [
        f"Pod {pod!r} is {facts.phase[0]!r}. It was scheduled (PodScheduled "
        f"is True), but its container{'s' if len(creating) != 1 else ''} "
        + ", ".join(repr(name) for name in creating)
        + " cannot be created: Kubernetes reports "
        + ("them" if len(creating) != 1 else "it")
        + " waiting in 'ContainerCreating' while it records volume mount "
        "failures for the pod."
    ]

    if facts.phase:
        refs.append(facts.phase[1])

    if facts.scheduled_status:
        refs.append(facts.scheduled_status[1])

    for name in creating[:2]:
        container = containers[(namespace, pod, name)]
        refs.extend(
            container.refs[a] for a in ("state", "reason") if a in container.refs
        )

    mount_events = [e for e in facts.events if e.reason in {"FailedMount", "FailedAttachVolume"}]
    sentences.extend(_event_sentences(facts.events, ("FailedMount", "FailedAttachVolume"), refs))
    sentences.append(_identity_sentence(snapshot, key, refs))

    signals: dict[str, str] = {}
    volumes: dict[str, str] = {}

    for event in mount_events:
        signals.update(dict(event.signals))
        volumes.update(dict(event.volumes))

    sentence = _signal_sentence(
        "The kubelet's message reports", MOUNT_LABELS, signals, refs
    )

    if sentence:
        sentences.append(sentence)

    named = []

    for name, ref in sorted(volumes.items()):
        declared = facts.volumes.get(name)

        if declared is None:
            continue  # only volumes the pod's own spec declares are named

        named.append(f"{name!r} ({VOLUME_SOURCE_LABELS.get(declared[0], 'other')} volume)")
        refs.extend([ref, declared[1]])

    if named:
        sentences.append(
            "The mount events concern the declared volume(s) "
            + ", ".join(named)
            + ". Only the volume name and source type come from the pod spec; "
            "no referenced object, key or content was read."
        )
    elif facts.volumes:
        listed = ", ".join(
            f"{name!r} ({VOLUME_SOURCE_LABELS.get(source, 'other')})"
            for name, (source, _) in sorted(facts.volumes.items())[:4]
        )
        refs.extend(ref for _, (_, ref) in sorted(facts.volumes.items())[:4])
        sentences.append(
            f"The pod spec declares volume(s) {listed}; the events do not "
            "identify which one failed."
        )

    sentences.append(
        "This establishes that Kubernetes cannot mount the pod's volumes and "
        "what it reported; it does not establish why (for example whether a "
        "referenced object is missing, or a storage or permission problem "
        "exists). The containers never started, so there are no application "
        "logs, restarts or probe results."
    )
    sentences.append(f"Resource: namespace {namespace!r}, pod {pod!r}.")

    return InvestigationFinding(
        title="Pod containers cannot be created: volume mount failure",
        description=fit_description(sentences),
        severity=assessment.severity,
        evidence=[EvidenceReference(evidence_id=r) for r in dict.fromkeys(refs)][:MAX_REFS],
    )


def describe_liveness_probe(snapshot, key, container: str):
    """(statement, refs) for the declared liveness probe, or None when probe
    configuration was not collected (unknown, never assumed absent)."""
    return describe_pod_probe(snapshot, key, container, "liveness")


def _restart_finding(snapshot, key, name, container, events: list[PodEvent]):
    namespace, pod = key
    values, refs_by = container.values, container.refs
    restarts = values.get("restart_count")
    refs = [refs_by[a] for a in ("ready", "state", "restart_count") if a in refs_by]
    sentences = [
        f"Container {name!r} is running and ready now, but Kubernetes reports "
        f"it has restarted {restarts} time{'' if restarts == 1 else 's'}."
    ]
    previous = []

    if "last_termination.reason" in values:
        previous.append(f"reason {values['last_termination.reason']!r}")
        refs.append(refs_by["last_termination.reason"])

    if "last_termination.exit_code" in values:
        previous.append(f"exit code {values['last_termination.exit_code']}")
        refs.append(refs_by["last_termination.exit_code"])

    if previous:
        sentences.append(
            f"Its previous termination reported {' and '.join(previous)}."
        )

    sentences.append(
        "Current readiness and past restarts are separate facts: being ready "
        "now does not show that the earlier failures stopped, and the "
        "restarts do not show that it is failing now."
    )

    liveness = {}

    for event in events:
        if event.reason in {"Unhealthy", "Killing"}:
            for signal, ref in event.signals:
                if signal in {"liveness_probe_failed", "liveness_restart"}:
                    liveness[(event.reason, signal)] = (event, ref)

    if liveness:
        for (reason, signal), (event, ref) in sorted(liveness.items()):
            wording = (
                "whose message was classified as a liveness-probe failure"
                if signal == "liveness_probe_failed"
                else "whose message was classified as 'failed liveness probe, "
                "will be restarted'"
            )
            sentences.append(
                f"The kubelet recorded {event.type} event {reason!r} "
                f"(x{event.count}) for this pod, {wording} (the message "
                "itself is untrusted and not retained)."
            )
            refs.extend([event.type_ref, event.count_ref, ref])

        sentences.append(
            "These events belong to the pod, not to one container. They show "
            "that Kubernetes recorded liveness-probe failures for the pod; "
            "the restarts are consistent with them, but this report does not "
            "establish that they caused the restarts or why the probes failed."
        )
        sentences.append(_identity_sentence(snapshot, key, refs))
        title = "Container was restarted after liveness probe failures"
    else:
        sentences.append(
            "No liveness-probe failure event was found for this pod, so this "
            "report does not establish what caused the restarts (Kubernetes "
            "events expire, so their absence is not proof)."
        )
        title = "Container restarted earlier and is running now"

    probe = describe_liveness_probe(snapshot, key, name)

    if probe is not None:
        sentences.append(f"Its spec {probe[0]}.")
        refs.extend(probe[1])

    sentences.append("The cause of the earlier failures is not established by this finding.")
    sentences.append(f"Resource: namespace {namespace!r}, pod {pod!r}.")

    return InvestigationFinding(
        title=title,
        description=fit_description(sentences),
        severity="warning",
        evidence=[EvidenceReference(evidence_id=r) for r in dict.fromkeys(refs)][:MAX_REFS],
    )


def restart_history(snapshot) -> list[tuple[str, str, str, int]]:
    """(namespace, pod, container, restarts) for every container Kubernetes
    records as restarted. Current health is a separate fact, so a container
    that is running and ready now is listed too."""
    history = []

    for (namespace, pod, name), container in sorted(_collect(snapshot).items()):
        restarts = container.values.get("restart_count")

        if (
            classify_container(container.values).has_restart_history
            and type(restarts) is int
        ):
            history.append((namespace, pod, name, restarts))

    return history


def build_pod_health_findings(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[InvestigationFinding]:
    findings: list[InvestigationFinding] = []

    for key, (assessment, facts) in sorted(classify_pods(snapshot).items()):
        if assessment.category is PodCategory.UNSCHEDULABLE:
            findings.append(_unschedulable_finding(snapshot, key, facts, assessment))
        else:
            findings.append(_volume_finding(snapshot, key, facts, assessment))

    events = collect_pod_events(snapshot)

    for (namespace, pod, name), container in sorted(_collect(snapshot).items()):
        assessment = classify_container(container.values)

        # An OOM kill has its own dedicated finding.
        if (
            assessment.category is not HealthCategory.RESTARTED_RUNNING
            or container.values.get("last_termination.reason") == "OOMKilled"
        ):
            continue

        findings.append(
            _restart_finding(
                snapshot, (namespace, pod), name, container,
                events.get((namespace, pod), []),
            )
        )

    return findings


def _stuck_pods_without_events(snapshot) -> list[tuple[str, str]]:
    """Pods Pending before their containers run whose events were never read."""
    from app.tools.coverage import pods_wanting_events

    with_events = {
        (item.namespace, item.pod)
        for item in snapshot.evidence
        if item.tool == "k8s.get_events" and item.namespace and item.pod
    }

    return [
        key
        for key in pods_wanting_events(snapshot.evidence)
        if key not in with_events
    ]


def build_pod_health_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    """Disclose pod-level evidence that should exist but was not obtained."""
    notes = []

    for namespace, pod in _stuck_pods_without_events(snapshot):
        notes.append(
            f"Pod {pod!r}, namespace {namespace!r}: the pod is stuck before "
            "its containers run (unschedulable, or still creating) or was "
            "restarted earlier, but the Kubernetes events for the pod were not "
            "retrieved, so the scheduler and kubelet records that explain it "
            "have not been examined."
        )

    for key in sorted(collect_pod_facts(snapshot)):
        identity = collect_event_identity(snapshot).get(key)

        if identity is not None and identity.excluded:
            notes.append(
                f"Pod {key[1]!r}: {identity.excluded} Kubernetes event(s) named "
                "this pod's name but a different pod UID and were excluded as "
                "belonging to another pod."
            )

    for namespace, pod in sorted(identity_conflicts(snapshot)):
        notes.append(
            f"Pod {pod!r}, namespace {namespace!r}: its events were verified "
            "against a different pod UID than the one inspected (the pod was "
            "replaced between reads), so those events are not used."
        )

    return notes


_SCHEDULING_CHECKS = {
    "insufficient_cpu": (
        "Compare the CPU the pod requests with the allocatable CPU of the "
        "cluster's nodes (read-only node inspection)."
    ),
    "insufficient_memory": (
        "Compare the memory the pod requests with the allocatable memory of "
        "the cluster's nodes (read-only node inspection)."
    ),
    "untolerated_taint": (
        "Review the taints on the nodes and the tolerations the pod declares "
        "(read-only)."
    ),
    "node_selector_mismatch": (
        "Compare the pod's node selector and affinity with the labels the "
        "nodes actually carry (read-only)."
    ),
    "unbound_volume_claim": (
        "Confirm that each PersistentVolumeClaim the pod references exists in "
        "the namespace and is bound (names and status only)."
    ),
}


def pod_health_check_items(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[tuple[str, str | None, str | None, str | None]]:
    """Read-only checks with the pod they were written for.

    Each item is (text, namespace, pod, container). The pod and container
    come from the classification the check was generated for, not from the
    wording. A check with no single pod has null resource fields.
    """
    items: list[tuple[str, str | None, str | None, str | None]] = []

    for key, (assessment, facts) in sorted(classify_pods(snapshot).items()):
        namespace, pod = key

        if assessment.category is PodCategory.UNSCHEDULABLE:
            signals = set(facts.scheduling_signals)

            for event in facts.events:
                if event.reason == "FailedScheduling":
                    signals.update(name for name, _ in event.signals)

            for text in (
                text for name, text in _SCHEDULING_CHECKS.items() if name in signals
            ):
                items.append((text, namespace, pod, None))

            items.append((
                f"Compare the resource requests, node selector and tolerations "
                f"declared for pod {pod!r} with what the cluster's nodes can "
                "offer (read-only, for example kubectl describe pod and "
                "kubectl describe nodes).",
                namespace,
                pod,
                None,
            ))
        else:
            items.append((
                f"Confirm that every volume declared for pod {pod!r} refers to "
                "an object that exists in the namespace and that its source is "
                "reachable (names and existence only; never read Secret "
                "values).",
                namespace,
                pod,
                None,
            ))

    events = collect_pod_events(snapshot)

    for (namespace, pod, name), container in sorted(_collect(snapshot).items()):
        assessment = classify_container(container.values)

        if (
            assessment.category is not HealthCategory.RESTARTED_RUNNING
            or container.values.get("last_termination.reason") == "OOMKilled"
        ):
            continue

        liveness = any(
            signal in {"liveness_probe_failed", "liveness_restart"}
            for event in events.get((namespace, pod), [])
            for signal, _ in event.signals
        )
        probe = describe_liveness_probe(snapshot, (namespace, pod), name)

        if liveness:
            items.append((
                f"Compare the liveness probe declared for container {name!r} "
                f"in pod {pod!r} (path, port, timing) with what the "
                "application serves and how long it needs to start (read-only).",
                namespace,
                pod,
                name,
            ))
        else:
            items.append((
                f"Review the previous termination of container {name!r} in "
                f"pod {pod!r}: read its previous-container logs and, if a "
                "liveness probe is declared"
                + (" (it is)" if probe and "no liveness" not in probe[0] else "")
                + ", the probe configuration. Restart history is not a "
                "current failure.",
                namespace,
                pod,
                name,
            ))

    return items


def build_pod_health_checks(snapshot: InvestigationEvidenceSnapshot) -> list[str]:
    """Read-only checks for pod-level failures and for restart history."""
    return list(dict.fromkeys(text for text, *_rest in pod_health_check_items(snapshot)))
