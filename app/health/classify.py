"""Roll a pod's existing classifiers up into one health category.

`container_health.classify_container` and `pod_health.classify_pod` stay the
source of container and pod facts. This module only selects which of those
facts to present and never reads event messages, logs, or spec text.
"""

from app.health.types import (
    MAX_CONTAINERS,
    ObservedContainer,
    ObservedPod,
    valid_container_name,
    valid_quantity,
)
from app.tools.container_health import (
    PRE_START_REASONS,
    RUNTIME_FAILURE_REASONS,
    TRANSITIONAL_REASONS,
    HealthCategory,
    classify_container,
)
from app.tools.pod_health import CREATING, MOUNT_EVENT_REASONS, PodCategory, classify_pod

# Kubernetes reasons we are willing to repeat. Anything else is dropped.
_REASONS = (
    set(PRE_START_REASONS)
    | set(RUNTIME_FAILURE_REASONS)
    | set(TRANSITIONAL_REASONS)
    | {"Completed"}
)

_REASON_CODE = {
    "ImagePullBackOff": "image_pull_backoff",
    "ErrImagePull": "err_image_pull",
    "ErrImageNeverPull": "err_image_never_pull",
    "InvalidImageName": "invalid_image_name",
    "ImageInspectError": "image_inspect_error",
    "RegistryUnavailable": "registry_unavailable",
    "CreateContainerConfigError": "create_container_config_error",
    "CreateContainerError": "create_container_error",
    "RunContainerError": "run_container_error",
    "CrashLoopBackOff": "crash_loop_backoff",
    "OOMKilled": "oom_killed",
    "Error": "container_error",
    "ContainerCannotRun": "container_cannot_run",
    "StartError": "start_error",
}

SIGNAL_LABELS = {
    "image_pull_backoff": "Image pull is backing off",
    "err_image_pull": "Image pull failed",
    "err_image_never_pull": "The image is not present and the pull policy forbids pulling it",
    "invalid_image_name": "The image reference is not valid",
    "image_inspect_error": "The image could not be inspected",
    "registry_unavailable": "The image registry could not be reached",
    "create_container_config_error": "The container could not be created from its configuration",
    "create_container_error": "Creating the container failed",
    "run_container_error": "Starting the container failed",
    "crash_loop_backoff": "The container is crash-looping",
    "oom_killed": "A container was killed for running out of memory",
    "container_error": "A container exited with an error",
    "container_cannot_run": "A container cannot run",
    "start_error": "Starting the container failed",
    "running_not_ready": "A container is running but not ready",
    "restarted_before": "A container restarted earlier and is ready now",
    "unschedulable": "The pod could not be scheduled",
    "volume_mount_failure": "A volume failed to mount before the container could start",
    "scaled_to_zero": "The workload is scaled to zero",
    "replicas_not_ready": "Not every desired replica is ready",
    "partial_failure": "Some replicas are failing while others are not",
}

_CRITICAL = frozenset(
    {
        "image_pull_backoff",
        "err_image_never_pull",
        "invalid_image_name",
        "image_inspect_error",
        "create_container_config_error",
        "create_container_error",
        "run_container_error",
        "crash_loop_backoff",
        "unschedulable",
        "volume_mount_failure",
        "container_cannot_run",
        "start_error",
    }
)

LIMITATION_LABELS = {
    "pod_list_truncated": "The pod listing was truncated, so later pods were not inspected.",
    "pod_cap": "Only the first matching pods were inspected.",
    "owner_lookup_cap": "Owner verification stopped at its read cap.",
    "owner_unverified": "Some pods were excluded because their owner could not be verified.",
    "pod_list_failed": "The pod listing could not be read.",
    "events_unavailable": "Volume events could not be read, so a mount failure was not ruled in or out.",
    "events_truncated": "The event listing was truncated.",
    "deadline_exceeded": "The check stopped at its time limit.",
    "replica_status_missing": "Deployment replica counts were not reported.",
    "observation_failed": "The resource could not be read.",
}


def signal_label(code: str) -> str:
    return SIGNAL_LABELS[code]


def limitation_label(code: str) -> str:
    return LIMITATION_LABELS[code]


class Signal:
    def __init__(self, code: str, *, critical: bool) -> None:
        self.code = code
        self.label = SIGNAL_LABELS[code]
        self.critical = critical

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Signal) and self.code == other.code

    def __hash__(self) -> int:
        return hash(self.code)


class ContainerView:
    def __init__(
        self,
        *,
        name: str,
        ready: bool | None,
        state: str | None,
        waiting_reason: str | None,
        last_termination_reason: str | None,
        last_exit_code: int | None,
        restart_count: int | None,
        configured_memory_request: str | None,
        configured_memory_limit: str | None,
    ) -> None:
        self.name = name
        self.ready = ready
        self.state = state
        self.waiting_reason = waiting_reason
        self.last_termination_reason = last_termination_reason
        self.last_exit_code = last_exit_code
        self.restart_count = restart_count
        self.configured_memory_request = configured_memory_request
        self.configured_memory_limit = configured_memory_limit


class PodVerdict:
    def __init__(
        self,
        *,
        name: str,
        uid: str | None,
        phase: str | None,
        category: str,
        signals: tuple[Signal, ...],
        containers: tuple[ContainerView, ...],
        events_unmet: bool,
    ) -> None:
        self.name = name
        self.uid = uid
        self.phase = phase
        self.category = category
        self.signals = signals
        self.containers = containers
        self.events_unmet = events_unmet

    @property
    def ready(self) -> bool | None:
        if not self.containers:
            return None
        flags = [item.ready for item in self.containers]
        if any(flag is None for flag in flags):
            return None
        return all(flag is True for flag in flags)


def _reason(value: object) -> str | None:
    return value if isinstance(value, str) and value in _REASONS else None


def _count(value: object) -> int | None:
    if type(value) is not int or isinstance(value, bool):
        return None
    if value < 0 or value > 100_000:
        return None
    return value


def _exit(value: object) -> int | None:
    if type(value) is not int or isinstance(value, bool):
        return None
    if value < 0 or value > 255:
        return None
    return value


def _container_view(container: ObservedContainer) -> ContainerView | None:
    name = valid_container_name(container.name)
    if name is None:
        return None
    reason = _reason(container.reason)
    last = _reason(container.last_reason)
    state = container.state if container.state in {"waiting", "running", "terminated"} else None
    ready = container.ready if type(container.ready) is bool else None
    return ContainerView(
        name=name,
        ready=ready,
        state=state,
        waiting_reason=reason if state == "waiting" else None,
        last_termination_reason=last,
        last_exit_code=_exit(container.last_exit_code),
        restart_count=_count(container.restart_count),
        configured_memory_request=valid_quantity(container.memory_request),
        configured_memory_limit=valid_quantity(container.memory_limit),
    )


def _fields(container: ObservedContainer) -> dict:
    state = container.state if container.state in {"waiting", "running", "terminated"} else None
    last_reason = _reason(container.last_reason)
    last_exit = _exit(container.last_exit_code)
    if state == "terminated":
        last_reason = last_reason or _reason(container.reason)
        if last_exit is None:
            last_exit = _exit(container.exit_code)
    return {
        "ready": container.ready if type(container.ready) is bool else None,
        "restart_count": _count(container.restart_count),
        "state": state,
        "reason": _reason(container.reason),
        "last_termination.exit_code": last_exit,
        "last_termination.reason": last_reason,
    }


def _add(signals: list[Signal], code: str, *, critical: bool) -> None:
    if code not in SIGNAL_LABELS:
        return
    if any(item.code == code for item in signals):
        return
    signals.append(Signal(code, critical=critical or code in _CRITICAL))


def _creating(pod: ObservedPod) -> bool:
    return any(
        container.state == "waiting" and container.reason == CREATING
        for container in pod.containers
    )


def needs_mount_events(pod: ObservedPod) -> bool:
    """Volume-mount classification needs identity-checked events. An
    unschedulable pod is classified from its condition and does not."""
    if pod.phase != "Pending" or pod.scheduled_status != "True":
        return False
    if type(pod.age_seconds) is not int:
        return False
    from app.tools.pod_health import CREATING_GRACE_SECONDS

    return pod.age_seconds >= CREATING_GRACE_SECONDS and _creating(pod)


def classify_observed_pod(
    pod: ObservedPod,
    event_counts: dict[str, int] | None,
    *,
    events_inconclusive: bool,
) -> PodVerdict:
    views = tuple(
        view
        for view in (_container_view(item) for item in pod.containers[:MAX_CONTAINERS])
        if view is not None
    )
    signals: list[Signal] = []
    assessments = [classify_container(_fields(item)) for item in pod.containers[:MAX_CONTAINERS]]

    scheduled = None
    if pod.scheduled_status in {"True", "False"}:
        reason = pod.scheduled_reason if isinstance(pod.scheduled_reason, str) else None
        scheduled = (pod.scheduled_status, reason)

    counts = {
        key: value
        for key, value in (event_counts or {}).items()
        if key in MOUNT_EVENT_REASONS and type(value) is int and value > 0
    }
    events_unmet = bool(events_inconclusive and needs_mount_events(pod) and not counts)
    pod_assessment = None
    if not events_unmet:
        pod_assessment = classify_pod(
            phase=pod.phase,
            scheduled=scheduled,
            container_states=((item.state, _reason(item.reason)) for item in pod.containers),
            event_counts=counts,
        )

    if pod_assessment is not None and pod_assessment.category is PodCategory.UNSCHEDULABLE:
        _add(signals, "unschedulable", critical=True)
    if pod_assessment is not None and pod_assessment.category is PodCategory.VOLUME_MOUNT_FAILURE:
        _add(signals, "volume_mount_failure", critical=True)

    categories: list[str] = []
    if pod_assessment is not None:
        categories.append("unhealthy")

    for assessment in assessments:
        if assessment.category is HealthCategory.PRE_START_FAILURE:
            categories.append("unhealthy" if assessment.severity == "critical" else "degraded")
        elif assessment.category is HealthCategory.RUNTIME_FAILURE:
            categories.append("unhealthy" if assessment.severity == "critical" else "degraded")
        elif assessment.category is HealthCategory.NOT_READY:
            categories.append("degraded")
            _add(signals, "running_not_ready", critical=False)
        elif assessment.category is HealthCategory.RESTARTED_RUNNING:
            categories.append("degraded")
            _add(signals, "restarted_before", critical=False)
        elif assessment.category is HealthCategory.HEALTHY:
            categories.append("healthy")
        else:
            categories.append("unknown")

        code = _REASON_CODE.get(assessment.reason or "")
        if code:
            _add(signals, code, critical=assessment.severity == "critical")

    for item in pod.containers[:MAX_CONTAINERS]:
        if _reason(item.last_reason) == "OOMKilled" or _reason(item.reason) == "OOMKilled":
            current = item.state == "waiting" and _reason(item.reason) in RUNTIME_FAILURE_REASONS
            _add(signals, "oom_killed", critical=current)

    if "unhealthy" in categories:
        category = "unhealthy"
    elif "degraded" in categories:
        category = "degraded"
    elif "unknown" in categories or not categories:
        category = "unknown"
    else:
        category = "healthy"

    if events_unmet and category == "healthy":
        category = "unknown"

    return PodVerdict(
        name=pod.name,
        uid=pod.uid,
        phase=pod.phase if isinstance(pod.phase, str) and pod.phase in {
            "Pending", "Running", "Succeeded", "Failed", "Unknown"
        } else None,
        category=category,
        signals=tuple(signals),
        containers=views,
        events_unmet=events_unmet,
    )
