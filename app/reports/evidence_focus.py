"""Application-curated evidence focus for the hypothesis stage.

Given a flat list of every observation, a model tends to cite far too many of
them, and a hypothesis that cites more than MAX_REFERENCES is discarded. This
module selects, per pod and container, the few observations that bear on each
TOPIC of the failure the application established (current state, previous
termination, events, probe configuration, scheduling, volumes), so a useful
hypothesis can be supported by one group of at most MAX_REFERENCES ids.

This is relevance guidance, never authority. Selection is a pure function of
the evidence snapshot and the application's own classification:
  * every id it offers already exists in the snapshot and belongs to the same
    pod as its group, so a group can never smuggle in a foreign reference;
  * it grants no trust and changes no validation: the registry still checks
    every cited id, and unknown, duplicate or cross-resource citations are
    still rejected;
  * nothing is cut from the report or the evidence: only the model's payload is
    organised, and ids outside every group remain citable.
"""

import re
from typing import Any

from app.reports.config_grounding import collect_configuration
from app.reports.health_grounding import (
    _collect,
    collect_pod_events,
)
from app.reports.hypotheses import MAX_REFERENCES
from app.reports.pod_health_grounding import (
    classify_pods,
    collect_pod_facts,
    describe_liveness_probe,
)
from app.reports.probe_declarations import describe_readiness
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.container_health import HealthCategory, classify_container
from app.tools.pod_health import PodCategory

MAX_GROUPS = 12
LIVENESS_SIGNALS = frozenset({"liveness_probe_failed", "liveness_restart"})

# Observations that only establish identity, age or event provenance. They are
# never useful to cite in an explanation and are left out of the model's list.
STRUCTURAL_FIELDS = frozenset(
    {
        "pod.uid",
        "pod.age_seconds",
        "events.pod_uid",
        "events.identity",
        "logs.completeness",
    }
)


def is_structural(field: str) -> bool:
    return field in STRUCTURAL_FIELDS


_CONTAINER_FIELD = re.compile(r"^containers\[([^\]]+)\]\.")


def _bounded(refs: list[str]) -> list[str]:
    return list(dict.fromkeys(refs))[:MAX_REFERENCES]


def _group(
    fields: dict[str, str], focus: str, pod: str, refs: list[str]
) -> dict[str, Any] | None:
    """`fields` maps evidence id -> field. The group's `container` is the one
    the registry will DERIVE from its ids (a container named by exactly one
    cited field), else None: it is what 'resource.container' must be for a
    hypothesis citing this group. It is never taken from the model."""
    ids = [i for i in _bounded([r for r in refs if r]) if i in fields]

    if not ids:
        return None

    named = {m.group(1) for i in ids if (m := _CONTAINER_FIELD.match(fields[i]))}

    return {
        "focus": focus,
        "pod": pod,
        "container": next(iter(named)) if len(named) == 1 else None,
        "evidence_ids": ids,
    }


def _event_refs(events, reasons: tuple[str, ...] | None = None, limit: int = 3) -> list[str]:
    """Event observations, those carrying classified signals first, then
    warnings by count. Each event contributes its type, count and signals."""
    chosen = [e for e in events if reasons is None or e.reason in reasons]
    chosen.sort(key=lambda e: (not e.signals, e.type != "Warning", -e.count, e.reason))
    refs: list[str] = []

    for event in chosen[:limit]:
        refs.extend([event.count_ref, *(ref for _, ref in event.signals)])

        if not event.signals:
            refs.append(event.type_ref)

    return refs


def build_focus_groups(snapshot: InvestigationEvidenceSnapshot) -> list[dict[str, Any]]:
    groups: list[dict[str, Any]] = []
    containers = _collect(snapshot)
    events = collect_pod_events(snapshot)
    pods, _ = collect_configuration(snapshot)
    pod_facts = collect_pod_facts(snapshot)
    pod_assessments = classify_pods(snapshot)

    fields = {item.evidence_id: item.field for item in snapshot.evidence}

    def _g(focus: str, pod: str, _unused, refs: list[str]) -> dict[str, Any] | None:
        return _group(fields, focus, pod, refs)

    def add(group: dict[str, Any] | None) -> None:
        if group is not None and len(groups) < MAX_GROUPS:
            groups.append(group)

    # Pod-level failures: no container has run, so only these groups apply.
    for key, (assessment, facts) in sorted(pod_assessments.items()):
        pod = key[1]
        pod_events = events.get(key, [])

        if assessment.category is PodCategory.UNSCHEDULABLE:
            refs = [r for r in (facts.phase and facts.phase[1],
                                facts.scheduled_status and facts.scheduled_status[1],
                                facts.scheduled_reason and facts.scheduled_reason[1]) if r]
            refs.extend(facts.scheduling_signals.values())
            add(_g("scheduling_status", pod, None, refs))
            add(_g("scheduler_events", pod, None,
                       _event_refs(pod_events, ("FailedScheduling",), limit=2)))
            declared = [
                c.refs["resources.memory_request"]
                for (n, p, _), c in sorted(containers.items())
                if (n, p) == key and "resources.memory_request" in c.refs
            ]
            declared.extend(
                fact[1] for fact in (facts.node_selector, facts.affinity)
                if fact is not None and fact[0] is True
            )
            add(_g("declared_placement_requirements", pod, None, declared))
        else:
            states = [
                ref
                for (n, p, _), c in sorted(containers.items())
                if (n, p) == key
                for ref in (c.refs.get("state"), c.refs.get("reason"))
            ]
            add(_g("volume_mount_events", pod, None,
                       _event_refs(pod_events, ("FailedMount", "FailedAttachVolume"), limit=2)
                       + [ref for event in pod_events
                          if event.reason in {"FailedMount", "FailedAttachVolume"}
                          for _, ref in event.volumes]))
            add(_g("pod_creation_state", pod, None,
                       [facts.phase and facts.phase[1], *states]))
            add(_g("declared_volumes", pod, None,
                       [ref for _, (_, ref) in sorted(facts.volumes.items())]))

    # Container-level: only the topics that apply to the established category.
    for (namespace, pod, name), container in sorted(containers.items()):
        key = (namespace, pod)
        assessment = classify_container(container.values)

        if assessment.category in {HealthCategory.HEALTHY, HealthCategory.UNKNOWN}:
            continue

        refs = container.refs
        state = [refs.get(a) for a in ("ready", "state", "reason", "restart_count")]
        add(_g("current_container_state", pod, name, state))

        termination = [refs.get(a) for a in ("last_termination.reason", "last_termination.exit_code")]

        if any(termination):
            memory = [refs.get("resources.memory_limit")] if (
                container.values.get("last_termination.reason") == "OOMKilled"
            ) else []
            add(_g("previous_termination", pod, name,
                       [*termination, refs.get("restart_count"), *memory]))

        pod_events = events.get(key, [])
        add(_g("kubernetes_events", pod, name, _event_refs(pod_events, None, limit=3)))

        config = pods.get(key)
        cfg = config.containers.get(name) if config else None
        probe = None

        if assessment.category in {HealthCategory.NOT_READY}:
            probe = describe_readiness(snapshot, key, name, cfg)
            label = "readiness_probe_configuration"
        elif assessment.category is HealthCategory.RESTARTED_RUNNING:
            probe = describe_liveness_probe(snapshot, key, name)
            label = "liveness_probe_configuration"
        else:
            label = ""

        if probe is not None:
            add(_g(label, pod, name, probe[1]))

        # A container that restarted, or is crash-looping, while declaring a
        # liveness probe: the liveness events (pod-level), the restart history
        # and the declared probe are the compact set a hypothesis needs, and no
        # log is part of it.
        if assessment.category in {
            HealthCategory.RESTARTED_RUNNING,
            HealthCategory.RUNTIME_FAILURE,
        }:
            liveness_events = [
                (event, ref)
                for event in pod_events
                if event.reason in {"Unhealthy", "Killing"}
                for signal, ref in event.signals
                if signal in LIVENESS_SIGNALS
            ]
            declared = describe_liveness_probe(snapshot, key, name)

            probe_declared = declared is not None and declared[0].startswith("declares a liveness probe")

            if liveness_events and probe_declared:
                history = [
                    ref for event, signal_ref in liveness_events[:2]
                    for ref in (event.count_ref, signal_ref)
                ]
                history += [refs.get("restart_count"), refs.get("last_termination.reason"),
                            declared[1][0]]
                add(_g("liveness_failure_history", pod, name, history))

        if assessment.category is HealthCategory.PRE_START_FAILURE and cfg is not None:
            add(_g("declared_image_and_environment", pod, name,
                       [cfg.refs.get("image"), cfg.refs.get("env.count"),
                        cfg.refs.get("env.names_complete")]))

    return groups
