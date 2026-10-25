"""Deterministic, evidence-aware ordering of VALIDATED hypotheses.

Ranking is presentation order, not a probability: nothing here scores or
displays confidence, and every hypothesis keeps its "unverified" status and
wording. It runs only on hypotheses that already passed provenance, tone and
state-consistency validation, and it is a pure function of the application's
own facts plus the hypothesis text and the model's own generation order.

Order:
 1. Hypotheses are GROUPED by (pod, container), never interleaved. (For a
    pod-level failure, where no container ran, the group is the pod alone.)
    Groups are ordered by the severity of the abnormality the application
    established for that container (critical, warning, then nothing
    established), then by name.
 2. Within a group, a hypothesis ranks higher when it
      - addresses the established abnormality (topic match for its
        classification), and
      - cites evidence of a kind relevant to that abnormality (events,
        readiness configuration, termination or resource data...), as opposed
        to only the generic state observations that established the concern.
    The tiers are: topical + relevant evidence; topical; relevant evidence
    only; neither. Evidence quality is a yes/no property of the KIND cited, so
    adding more citations never raises a rank.
 3. Hypotheses the application cannot distinguish (same group, same tier)
    KEEP THE ORDER THE MODEL GENERATED THEM IN. The application has no evidence
    that makes one of them better, so it does not invent a preference: an
    earlier tie-break on alphabetical wording measurably reordered hypotheses
    against the model's own ordering (see the evaluation in the change notes)
    and was removed. The result is deterministic for a given model output,
    but is deliberately not independent of that output's order.
"""

import re
from collections.abc import Iterable

from app.reports.models import AIHypothesis
from app.tools.container_health import ContainerAssessment, HealthCategory
from app.tools.pod_health import PodCategory

_SEVERITY_ORDER = {"critical": 0, "warning": 1}
_NO_ABNORMALITY = 2

_IMAGE_REASONS = frozenset(
    {
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "ImageInspectError",
        "RegistryUnavailable",
    }
)

_NOT_READY_TOPIC = re.compile(
    r"readiness|probe|not\s+ready|health[\s-]?check|listen|\bports?\b|endpoint|"
    r"accept\w*\s+(?:traffic|connections?)|initiali[sz]|warm|dependenc|start-?up",
    re.IGNORECASE,
)
_IMAGE_TOPIC = re.compile(
    r"image|pull|registry|\btag\b|credential|authenticat|network|dns", re.IGNORECASE
)
_CREATE_TOPIC = re.compile(
    r"config|secret|\bkeys?\b|volume|mount|\benv|reference|permission|command|"
    r"entrypoint",
    re.IGNORECASE,
)
_OOM_TOPIC = re.compile(r"memory|\boom|limit|leak|resource", re.IGNORECASE)
_RUNTIME_TOPIC = re.compile(
    r"crash|exit|error|exception|memory|\boom|restart|config|dependenc|start-?up|"
    r"command|connect",
    re.IGNORECASE,
)

# Evidence kinds relevant per classification (the field names application
# extractors mint). The state/ready/restart observations that established the
# concern are deliberately not listed: they are the baseline every hypothesis
# about the container already has.
_CONDITION = re.compile(r"^conditions\[")
_EVENT = re.compile(r"^events\[")
_READINESS = re.compile(r"\.readiness_probe\.")
_IMAGE = re.compile(r"\.image$")
_ENV = re.compile(r"\.env\[")
_TERMINATION = re.compile(r"\.last_termination\.")
_RESOURCES = re.compile(r"\.resources\.")
_STARTUP = re.compile(r"\.startup\.")
_SCHEDULING = re.compile(r"^scheduling\.|\.resources\.memory_request$")
_VOLUMES = re.compile(r"^volumes\[")
_LIVENESS = re.compile(r"\.liveness_probe\.")

_SCHEDULING_TOPIC = re.compile(
    r"schedul|\bnodes?\b|taint|toleration|affinity|selector|capacity|"
    r"resources?|\bcpu|memory|request|quota|insufficient|fit|volume|claim",
    re.IGNORECASE,
)
# What a hypothesis must talk about to address a constraint the scheduler
# actually reported (classified signals). Used only to order, never to omit.
_RESOURCE_SIGNAL_TOPIC = re.compile(
    r"\bcpu|memory|resources?|requests?|capacity|allocatable|ephemeral|storage|"
    r"\bfit\b|too\s+many\s+pods|pod\s+(?:limit|count)",
    re.IGNORECASE,
)
_TAINT_SIGNAL_TOPIC = re.compile(
    r"taint|toleration|\btolerat|cordon", re.IGNORECASE
)
_PLACEMENT_SIGNAL_TOPIC = re.compile(
    r"selector|affinity|label|topology|spread", re.IGNORECASE
)
_VOLUME_SIGNAL_TOPIC = re.compile(
    r"volume|claim|\bpvc\b|storage|persistent", re.IGNORECASE
)
_SIGNAL_TOPICS = {
    "insufficient_cpu": _RESOURCE_SIGNAL_TOPIC,
    "insufficient_memory": _RESOURCE_SIGNAL_TOPIC,
    "insufficient_ephemeral_storage": _RESOURCE_SIGNAL_TOPIC,
    "too_many_pods": _RESOURCE_SIGNAL_TOPIC,
    "untolerated_taint": _TAINT_SIGNAL_TOPIC,
    "node_unschedulable": _TAINT_SIGNAL_TOPIC,
    "node_selector_mismatch": _PLACEMENT_SIGNAL_TOPIC,
    "pod_affinity_mismatch": _PLACEMENT_SIGNAL_TOPIC,
    "unbound_volume_claim": _VOLUME_SIGNAL_TOPIC,
    "volume_node_conflict": _VOLUME_SIGNAL_TOPIC,
}
_VOLUME_TOPIC = re.compile(
    r"volume|mount|config\s*map|configmap|secret|\bclaim|storage|permission|"
    r"attach|exist|missing|reference",
    re.IGNORECASE,
)
_LIVENESS_TOPIC = re.compile(
    r"liveness|probe|health[\s-]?check|restart|kill|endpoint|\bpath\b|"
    r"\bports?\b|timeout|slow|start-?up|deadlock|unresponsive|crash",
    re.IGNORECASE,
)


_RUNTIME_LIVENESS_TOPIC = re.compile(
    _RUNTIME_TOPIC.pattern + "|" + _LIVENESS_TOPIC.pattern, re.IGNORECASE
)


def _topic(assessment: ContainerAssessment | None) -> re.Pattern[str] | None:
    if assessment is None:
        return None

    if assessment.category is HealthCategory.NOT_READY:
        return _NOT_READY_TOPIC

    if assessment.category is HealthCategory.PRE_START_FAILURE:
        return _IMAGE_TOPIC if assessment.reason in _IMAGE_REASONS else _CREATE_TOPIC

    if assessment.category is HealthCategory.RUNTIME_FAILURE:
        return _OOM_TOPIC if assessment.reason == "OOMKilled" else _RUNTIME_TOPIC

    if assessment.category is HealthCategory.RESTARTED_RUNNING:
        return _OOM_TOPIC if assessment.reason == "OOMKilled" else _LIVENESS_TOPIC

    return None


def _relevant_evidence(
    assessment: ContainerAssessment | None,
) -> tuple[re.Pattern[str], ...]:
    if assessment is None:
        return ()

    if assessment.category is HealthCategory.NOT_READY:
        return (_CONDITION, _EVENT, _READINESS)

    if assessment.category is HealthCategory.PRE_START_FAILURE:
        return (_EVENT, _IMAGE, _ENV)

    if assessment.category is HealthCategory.RUNTIME_FAILURE:
        return (_EVENT, _TERMINATION, _RESOURCES, _STARTUP, _ENV)

    if assessment.category is HealthCategory.RESTARTED_RUNNING:
        return (_EVENT, _TERMINATION, _LIVENESS, _RESOURCES)

    return ()


def _pod_topic(category: PodCategory) -> re.Pattern[str]:
    return (
        _SCHEDULING_TOPIC
        if category is PodCategory.UNSCHEDULABLE
        else _VOLUME_TOPIC
    )


def _pod_relevant(category: PodCategory) -> tuple[re.Pattern[str], ...]:
    if category is PodCategory.UNSCHEDULABLE:
        return (_CONDITION, _EVENT, _SCHEDULING)

    return (_EVENT, _VOLUMES)


def rank_hypotheses(hypotheses: Iterable[AIHypothesis], registry) -> list[AIHypothesis]:
    """Return `hypotheses` grouped by container and ordered by evidence tier.

    The sort is stable and its key contains no text: equal-tier hypotheses
    keep their input (model generation) order.
    """
    keyed = []

    for hypothesis in hypotheses:
        pod = hypothesis.resource.pod
        container = hypothesis.resource.container
        assessment = registry.assessment(pod, container)
        # A pod that never ran has no container abnormality; its pod-level
        # assessment (unschedulable, volume mount failure) orders it instead.
        pod_level = (
            registry.pod_assessment(pod)
            if assessment is None or assessment.severity is None
            else None
        )
        topic = (
            _pod_topic(pod_level.category) if pod_level is not None else _topic(assessment)
        )

        # An unschedulable pod whose scheduler constraints were classified: a
        # hypothesis is on topic when it addresses a constraint Kubernetes
        # actually reported (CPU or memory, taints, selector or affinity,
        # volumes), not merely anything about scheduling. A hypothesis about a
        # constraint no signal reports is ordered lower, never dropped.
        if pod_level is not None and pod_level.category is PodCategory.UNSCHEDULABLE:
            reported = [
                _SIGNAL_TOPICS[name]
                for name in sorted(registry.scheduling_signals(pod))
                if name in _SIGNAL_TOPICS
            ]

            if reported:
                topic = re.compile(
                    "|".join(dict.fromkeys(p.pattern for p in reported)), re.IGNORECASE
                )
        # Liveness-probe failures recorded for the pod of a container that
        # failed or restarted: probe vocabulary and probe evidence are on topic.
        liveness = (
            assessment is not None
            and assessment.category
            in {HealthCategory.RUNTIME_FAILURE, HealthCategory.RESTARTED_RUNNING}
            and assessment.reason != "OOMKilled"
            and registry.liveness_failures_recorded(pod)
        )

        if liveness and topic is not None:
            topic = _RUNTIME_LIVENESS_TOPIC
        # Only the explanation itself decides topicality: the suggested check
        # is a separate field and must not lend an unrelated explanation its
        # vocabulary.
        topical = (
            topic is not None
            and topic.search(hypothesis.possible_explanation) is not None
        )
        kinds = (
            _pod_relevant(pod_level.category)
            if pod_level is not None
            else _relevant_evidence(assessment)
        )
        if liveness:
            kinds = (*kinds, _LIVENESS)

        cited = [registry.evidence_field(ref) for ref in hypothesis.evidence_refs]
        specific = any(
            field is not None and pattern.search(field)
            for field in cited
            for pattern in kinds
        )

        if pod_level is not None:
            abnormality = _SEVERITY_ORDER[pod_level.severity]
        elif assessment is not None and assessment.severity in _SEVERITY_ORDER:
            abnormality = _SEVERITY_ORDER[assessment.severity]
        else:
            abnormality = _NO_ABNORMALITY

        tier = 0 if topical and specific else 1 if topical else 2 if specific else 3
        # A pod-level failure (unschedulable, volume mount failure) belongs to
        # the POD: no container ran. Which container's field a hypothesis
        # happens to cite (for example a memory request) must not split the
        # pod's hypotheses into separate groups, or the one that cites
        # container-scoped evidence would always rank below the others
        # whatever its topic.
        group = "" if pod_level is not None else container or ""
        keyed.append(((abnormality, pod or "", group, tier), hypothesis))

    # list.sort is stable: ties keep the model's order.
    keyed.sort(key=lambda entry: entry[0])

    return [hypothesis for _key, hypothesis in keyed]
