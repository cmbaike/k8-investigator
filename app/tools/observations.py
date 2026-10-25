import re
from typing import Any, Callable, NamedTuple

from pydantic import BaseModel, ConfigDict

from app.tools.event_signals import (
    MAX_SIGNALS,
    SCHEDULING_CONSTRAINTS,
    VOLUME_NAME,
    signals_allowed,
    source_allowed,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.workload_config import (
    CONTAINER_NAME_PATTERN,
    ENTRYPOINT_KINDS,
    ENV_NAME_PATTERN,
    ENV_SOURCES,
    MAX_CONTAINERS,
    MAX_ENV_REPORTED,
    STATIC_ANALYSES,
    WORKLOAD_CONFIG_TOOL,
    safe_image,
    PORT_NAME_PATTERN,
    PROBE_KINDS,
    PROBE_PATH_PATTERN,
    PROBE_TIMINGS,
)


# Kubernetes resource quantity (e.g. 16Mi, 1Gi, 128974848, 129e6, 0.5Gi).
# Validated strictly: only a well-formed quantity may become evidence.
MEMORY_QUANTITY = re.compile(
    r"^[0-9]{1,15}(?:\.[0-9]{1,6})?(?:Ki|Mi|Gi|Ti|Pi|Ei|m|k|M|G|T|P|E|e[0-9]{1,2})?$"
)


class TrustedToolObservation(BaseModel):
    """
    A value minted from a successful, structured tool execution.

    Trust is conferred by this application's observation extraction path,
    not by model-provided labels or free-form text.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: str
    tool: str
    field: str
    value: Any
    
    namespace: str | None = None
    pod: str | None = None


def _extract_get_pods(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    output = result.output

    if not isinstance(output, dict):
        return []

    pods = output.get("pods")
    if not isinstance(pods, list):
        return []

    observations: list[TrustedToolObservation] = []
    
    requested_namespace = call.arguments.get("namespace")
    if (
       not isinstance(requested_namespace, str)
       or not requested_namespace
       or output.get("namespace") != requested_namespace):
     return [] 

    for pod in pods:
        if not isinstance(pod, dict):
            continue

        name = pod.get("name")

        if not isinstance(name, str) or not name:
            continue

        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field="pods[].name",
                value=name,
                namespace=requested_namespace,
                pod=name,
            )
        )
        owner = _workload_owner_value(pod.get("workload"))

        if owner is not None:
            observations.append(
                TrustedToolObservation(
                    request_id=request_id,
                    tool=call.name,
                    field="workload.owner",
                    value=owner,
                    namespace=requested_namespace,
                    pod=name,
                )
            )

    if output.get("listing_truncated") is True:
        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field="listing.truncated",
                value=True,
                namespace=requested_namespace,
                pod=None,
            )
        )

    return observations


_OWNER_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}
)
_OWNER_NAME = re.compile(
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
)


def _workload_owner_value(workload: object) -> str | None:
    """Closed value for a pod's verified owner, or 'unverified'.

    Nothing is inferred from the pod's name. A missing or malformed workload
    record is omitted rather than turned into a guessed Deployment.
    """
    if not isinstance(workload, dict):
        return None

    if workload.get("verified") is False:
        return "unverified"

    if workload.get("verified") is not True:
        return None

    if workload.get("kind") == "Pod":
        return "pod"

    kind, name = workload.get("kind"), workload.get("name")

    if (
        kind in _OWNER_KINDS
        and isinstance(name, str)
        and len(name) <= 253
        and _OWNER_NAME.fullmatch(name)
    ):
        return f"{kind}/{name}"

    return None

MAX_DESCRIBE_OBSERVATIONS = 40
# Pod conditions get their own small allowance, so a pod with many containers
# can never crowd them out (or be crowded out by them).
MAX_CONDITION_OBSERVATIONS = 8
# Declared-spec facts (volume source types, scheduling flags, and each
# container's liveness and readiness probe declarations) are bounded
# separately for the same reason.
MAX_SPEC_OBSERVATIONS = 40
# The probes read from the Pod's own container specification.
DECLARED_PROBES = ("liveness_probe", "readiness_probe")
MAX_VOLUME_OBSERVATIONS = 8

# Kubernetes UIDs are lower-case UUID strings.
POD_UID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
VOLUME_SOURCES = frozenset(
    {
        "config_map", "secret", "persistent_volume_claim", "empty_dir",
        "host_path", "projected", "downward_api", "csi", "nfs", "ephemeral",
        "other",
    }
)

# Pod condition types and reasons. A condition's MESSAGE is untrusted free text
# and is never read; type, status and a CamelCase reason are enough to state
# that Kubernetes marked the pod not ready.
POD_CONDITION_TYPES = frozenset(
    {
        "Ready",
        "ContainersReady",
        "Initialized",
        "PodScheduled",
        "PodReadyToStartContainers",
    }
)
CONDITION_STATUSES = frozenset({"True", "False", "Unknown"})
CONDITION_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")


def _add_conditions(output: dict, add) -> None:
    """Condition type/status/reason only. Capped separately from containers."""
    conditions = output.get("conditions")

    if not isinstance(conditions, list):
        return

    seen: set[str] = set()

    for condition in conditions[:20]:
        if not isinstance(condition, dict):
            continue

        kind, status = condition.get("type"), condition.get("status")

        if (
            kind not in POD_CONDITION_TYPES
            or status not in CONDITION_STATUSES
            or kind in seen
        ):
            continue

        seen.add(kind)
        cap = MAX_DESCRIBE_OBSERVATIONS + MAX_CONDITION_OBSERVATIONS
        add(f"conditions[{kind}].status", status, cap)
        reason = condition.get("reason")

        if isinstance(reason, str) and CONDITION_REASON.fullmatch(reason):
            add(f"conditions[{kind}].reason", reason, cap)

        # Fixed-vocabulary classification of the scheduler's status message,
        # accepted only for the scheduler's own "Unschedulable" verdict. The
        # message itself never reaches this point.
        if (
            kind == "PodScheduled"
            and status == "False"
            and reason == "Unschedulable"
            and isinstance(condition.get("signals"), list)
        ):
            for signal in condition["signals"][:MAX_SIGNALS]:
                if signal in SCHEDULING_CONSTRAINTS:
                    add(f"conditions[{kind}].signal[{signal}]", True, cap)


def _extract_describe_pod(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    """Extract bounded scalar observations from a described pod."""

    output = result.output

    if not isinstance(output, dict):
        return []

    requested_namespace = call.arguments.get("namespace")
    requested_pod = call.arguments.get("pod")

    if (
        not isinstance(requested_namespace, str)
        or not requested_namespace
        or not isinstance(requested_pod, str)
        or not requested_pod
    ):
        return []

    # Never mint observations for a different resource.
    if (
        output.get("namespace") != requested_namespace
        or output.get("name") != requested_pod
    ):
        return []

    observations: list[TrustedToolObservation] = []

    def add(field: str, value: object, cap: int = MAX_DESCRIBE_OBSERVATIONS) -> None:
        if len(observations) >= cap:
            return

        if type(value) not in (str, int, bool):
            return

        if isinstance(value, str):
            if not value or len(value) > 200:
                return

        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field=field,
                value=value,
                namespace=requested_namespace,
                pod=requested_pod,
            )
        )

    add("pod.name", requested_pod)

    uid = output.get("uid")
    if isinstance(uid, str) and POD_UID.fullmatch(uid):
        add("pod.uid", uid)

    age = output.get("age_seconds")
    if type(age) is int and 0 <= age <= 10_000_000:
        add("pod.age_seconds", age)

    phase = output.get("phase")
    if isinstance(phase, str) and phase in {
        "Pending",
        "Running",
        "Succeeded",
        "Failed",
        "Unknown",
    }:
        add("pod.phase", phase)

    containers = output.get("containers")

    if not isinstance(containers, list):
        _add_conditions(output, add)
        _add_spec(output, [], add)
        return observations

    for container in containers[:10]:
        if len(observations) >= MAX_DESCRIBE_OBSERVATIONS:
            break

        if not isinstance(container, dict):
            continue

        name = container.get("name")

        if (
            not isinstance(name, str)
            or not name
            or len(name) > 200
        ):
            continue

        add("containers[].name", name)

        ready = container.get("ready")
        if type(ready) is bool:
            add(f"containers[{name}].ready", ready)

        restart_count = container.get("restart_count")
        if (
            type(restart_count) is int
            and 0 <= restart_count <= 1_000_000
        ):
            add(
                f"containers[{name}].restart_count",
                restart_count,
            )

        state = container.get("state")
        if state in {"waiting", "running", "terminated"}:
            add(f"containers[{name}].state", state)

        reason = container.get("reason")
        if (
            isinstance(reason, str)
            and reason
            and len(reason) <= 100
        ):
            add(f"containers[{name}].reason", reason)
            
        last_termination = container.get("last_termination")

        if isinstance(last_termination, dict):
            exit_code = last_termination.get("exit_code")

            if (
                type(exit_code) is int
                and 0 <= exit_code <= 255
            ):
                add(
                    f"containers[{name}].last_termination.exit_code",
                    exit_code,
                )

            termination_reason = last_termination.get("reason")

            if (
                isinstance(termination_reason, str)
                and termination_reason in {
                    "Completed",
                    "Error",
                    "OOMKilled",
                    "ContainerCannotRun",
                }
            ):
                add(
                    f"containers[{name}].last_termination.reason",
                    termination_reason,
                )    

        # Declared memory request/limit from the pod spec. These are
        # configured values, never observed usage.
        resources = container.get("resources")

        if isinstance(resources, dict):
            for key in ("memory_request", "memory_limit"):
                quantity = resources.get(key)

                if isinstance(quantity, str) and MEMORY_QUANTITY.fullmatch(quantity):
                    add(f"containers[{name}].resources.{key}", quantity)

    _add_conditions(output, add)
    _add_spec(output, containers[:10], add)

    return observations


def _add_spec(output: dict, containers: list, add) -> None:
    """Declared-spec facts: volume NAMES and source TYPES, scheduling flags and
    each container's liveness and readiness probe. Never a referenced object's name or
    content, a probe header, or a command."""
    cap = MAX_DESCRIBE_OBSERVATIONS + MAX_CONDITION_OBSERVATIONS + MAX_SPEC_OBSERVATIONS
    volumes = output.get("volumes")

    if isinstance(volumes, list):
        for volume in volumes[:MAX_VOLUME_OBSERVATIONS]:
            if not isinstance(volume, dict):
                continue

            name, source = volume.get("name"), volume.get("source")

            if (
                isinstance(name, str)
                and VOLUME_NAME.fullmatch(name)
                and source in VOLUME_SOURCES
            ):
                add(f"volumes[{name}].source", source, cap)

    scheduling = output.get("scheduling")

    if isinstance(scheduling, dict):
        for key in ("node_selector_declared", "affinity_declared"):
            if type(scheduling.get(key)) is bool:
                add(f"scheduling.{key}", scheduling[key], cap)

    for container in containers:
        if not isinstance(container, dict):
            continue

        name = container.get("name")
        declared = container.get("declared")

        if not isinstance(name, str) or not name or len(name) > 200:
            continue

        for kind in DECLARED_PROBES:
            probe = declared.get(kind) if isinstance(declared, dict) else None

            # A probe whose declaration was not read is simply not observed:
            # only a real boolean becomes evidence, never an assumed absence.
            if not isinstance(probe, dict) or type(probe.get("declared")) is not bool:
                continue

            _add_probe(f"containers[{name}].{kind}", probe, add, cap)


def _add_probe(prefix: str, probe: dict, add, cap: int) -> None:
    """One probe's declaration: declared or not and, when declared, its kind,
    port, path and timings. Never a header, host or command."""
    add(f"{prefix}.declared", probe["declared"], cap)

    if probe["declared"] is not True:
        return

    if probe.get("kind") in PROBE_KINDS:
        add(f"{prefix}.kind", probe["kind"], cap)

    port = probe.get("port")

    if (type(port) is int and 1 <= port <= 65535) or (
        isinstance(port, str) and PORT_NAME_PATTERN.fullmatch(port)
    ):
        add(f"{prefix}.port", port, cap)

    path = probe.get("path")

    if isinstance(path, str) and PROBE_PATH_PATTERN.fullmatch(path):
        add(f"{prefix}.path", path, cap)

    for timing in PROBE_TIMINGS:
        value = probe.get(timing)

        if type(value) is int and 0 <= value <= 100_000:
            add(f"{prefix}.{timing}", value, cap)


# Kubernetes event reasons are short CamelCase tokens (BackOff, Failed,
# FailedScheduling, Pulling...). Anything else is not accepted as evidence.
EVENT_REASON = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,63}$")
EVENT_TYPES = frozenset({"Normal", "Warning"})
MAX_EVENT_REASONS = 8


def _extract_get_events(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    """Bounded reason/type/count observations for ONE pod's events.

    Minted only for a pod-bound call, and only for events whose involved object
    is exactly that pod, in that namespace. Aggregated per reason (warnings
    first, then highest count) and capped. The event MESSAGE is untrusted free
    text and is never read here: it cannot become evidence, a finding or a
    persisted value.
    """
    output = result.output

    if not isinstance(output, dict):
        return []

    namespace = call.arguments.get("namespace")
    pod = call.arguments.get("pod")

    # A namespace-wide listing is not bound to any investigated pod: no
    # observations. (Fail closed rather than guess an association.)
    if (
        not isinstance(namespace, str)
        or not namespace
        or not isinstance(pod, str)
        or not pod
        or output.get("namespace") != namespace
        or output.get("pod") != pod
    ):
        return []

    events = output.get("events")

    if not isinstance(events, list):
        return []

    # The pod's own UID, as read by the handler. Where both it and an event's
    # involved-object UID are present they must be equal: an event naming a
    # different UID belongs to ANOTHER pod that merely shared this pod's name
    # (a replaced standalone or StatefulSet pod) and is excluded, not merged.
    raw_uid = output.get("pod_uid")
    pod_uid = raw_uid if isinstance(raw_uid, str) and POD_UID.fullmatch(raw_uid) else None
    excluded = 0
    all_verified = True
    aggregated: dict[str, list[Any]] = {}

    for event in events[:100]:
        if not isinstance(event, dict):
            continue

        if (
            event.get("object_kind") != "Pod"
            or event.get("object_name") != pod
            or event.get("object_namespace") != namespace
        ):
            continue

        reason, event_type = event.get("reason"), event.get("type")

        if (
            not isinstance(reason, str)
            or not EVENT_REASON.fullmatch(reason)
            or event_type not in EVENT_TYPES
        ):
            continue

        raw_event_uid = event.get("object_uid")
        event_uid = (
            raw_event_uid
            if isinstance(raw_event_uid, str) and POD_UID.fullmatch(raw_event_uid)
            else None
        )

        if pod_uid is not None and event_uid is not None and event_uid != pod_uid:
            excluded += 1
            continue

        all_verified = all_verified and pod_uid is not None and event_uid == pod_uid
        count = event.get("count")
        count = count if type(count) is int and 1 <= count <= 1_000_000 else 1
        current = aggregated.get(reason)

        if current is None:
            current = aggregated[reason] = [event_type, count, set(), set()]
        else:
            if event_type == "Warning":
                current[0] = "Warning"

            current[1] = max(current[1], count)

        # Fixed-vocabulary signals the handler derived from the (untrusted)
        # message. Accepted only when registered for THIS reason and emitted
        # by the Kubernetes component that emits it; anything else is ignored.
        if source_allowed(reason, event.get("source")):
            signals = event.get("signals")

            for signal in (signals if isinstance(signals, list) else [])[:MAX_SIGNALS]:
                if isinstance(signal, str) and signals_allowed(reason, signal):
                    current[2].add(signal)

            volumes = event.get("volumes")

            if reason in {"FailedMount", "FailedAttachVolume"}:
                for name in (volumes if isinstance(volumes, list) else [])[:4]:
                    if isinstance(name, str) and VOLUME_NAME.fullmatch(name):
                        current[3].add(name)

    ordered = sorted(
        aggregated.items(),
        key=lambda item: (item[1][0] != "Warning", -item[1][1], item[0]),
    )[:MAX_EVENT_REASONS]

    observations: list[TrustedToolObservation] = []

    def add(field: str, value: object) -> None:
        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field=field,
                value=value,
                namespace=namespace,
                pod=pod,
            )
        )

    for reason, (event_type, count, signals, volumes) in ordered:
        add(f"events[{reason}].type", event_type)
        add(f"events[{reason}].count", count)

        for signal in sorted(signals)[:MAX_SIGNALS]:
            add(f"events[{reason}].signal[{signal}]", True)

        for name in sorted(volumes)[:MAX_SIGNALS]:
            add(f"events[{reason}].volume[{name}]", True)

    # Only the stronger claim is recorded. Without it the events were matched
    # by namespace, kind and pod name alone (the prior behaviour), and the
    # report says so.
    if ordered and all_verified and pod_uid is not None:
        add("events.identity", "uid_verified")
        add("events.pod_uid", pod_uid)

    if excluded:
        add("events.excluded_identity_mismatch", min(excluded, 1_000))

    return observations


ObservationExtractor = Callable[
    ...,
    list[TrustedToolObservation],
]

def observations_from_execution(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    """
    Mint trusted observations only from successful, explicitly supported,
    structured tool results.

    Errors, timeouts, denied calls, unknown tools, malformed output, and
    arbitrary free-form text do not create trusted observations.
    """

    if result.status != ToolExecutionStatus.SUCCESS:
        return []

    if result.tool != call.name:
        return []

    extractor = _OBSERVATION_EXTRACTORS.get(call.name)

    if extractor is None:
        return []

    return extractor(
        request_id=request_id,
        call=call,
        result=result,
    )

LOG_TOOLS = frozenset({"k8s.get_logs", "k8s.get_previous_logs"})


class ValidatedLogOutput(NamedTuple):
    """Identity-checked log retrieval. `logs` is untrusted application data."""

    namespace: str
    pod: str
    container: str | None
    previous: bool
    logs: str | bytes
    output: dict


def validated_log_output(
    call: ToolCall,
    result: ToolExecutionResult,
) -> ValidatedLogOutput | None:
    """Apply the strict log-retrieval checks shared by observations and
    bounded log context. Returns None unless the result is a successful,
    structured retrieval for exactly the requested resource."""

    if result.status != ToolExecutionStatus.SUCCESS:
        return None

    if result.tool != call.name or call.name not in LOG_TOOLS:
        return None

    output = result.output

    if not isinstance(output, dict):
        return None

    requested_namespace = call.arguments.get("namespace")
    requested_pod = call.arguments.get("pod")
    requested_container = call.arguments.get("container")

    if (
        not isinstance(requested_namespace, str)
        or not requested_namespace
        or not isinstance(requested_pod, str)
        or not requested_pod
    ):
        return None

    # The tool result must identify the exact requested resource.
    if (
        output.get("namespace") != requested_namespace
        or output.get("pod") != requested_pod
    ):
        return None

    if requested_container is not None:
        if output.get("container") != requested_container:
            return None

    expected_previous = call.name == "k8s.get_previous_logs"

    # Require a real boolean, not merely a truthy/falsy value.
    if type(output.get("previous")) is not bool:
        return None

    if output["previous"] is not expected_previous:
        return None

    # Successful execution alone is insufficient: require the
    # structured handler result to contain log data.
    logs = output.get("logs")

    if not isinstance(logs, (str, bytes)):
        return None

    container = output.get("container")

    return ValidatedLogOutput(
        namespace=requested_namespace,
        pod=requested_pod,
        container=container if isinstance(container, str) else None,
        previous=expected_previous,
        logs=logs,
        output=output,
    )


def _extract_get_logs(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    """Record bounded log retrieval without trusting log contents."""

    validated = validated_log_output(call, result)

    if validated is None:
        return []

    output = validated.output
    requested_namespace = validated.namespace
    requested_pod = validated.pod

    observations = [
        TrustedToolObservation(
            request_id=request_id,
            tool=call.name,
            field="logs.retrieved",
            value=True,
            namespace=requested_namespace,
            pod=requested_pod,
        )
    ]

    # Only recognize the application's defined completeness value.
    if output.get("completeness") == "bounded_unknown":
        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field="logs.completeness",
                value="bounded_unknown",
                namespace=requested_namespace,
                pod=requested_pod,
            )
        )

    return observations
    
MAX_CONFIG_OBSERVATIONS = 120


def _extract_workload_config(
    *,
    request_id: str,
    call: ToolCall,
    result: ToolExecutionResult,
) -> list[TrustedToolObservation]:
    """Mint bounded observations from a workload-configuration summary.

    Only fixed-vocabulary or pattern-validated scalars are accepted, so even a
    misbehaving handler cannot smuggle free text (commands, values) into the
    evidence store. Identity must match the request and ownership must have
    been verified by the handler.
    """
    if result.status != ToolExecutionStatus.SUCCESS:
        return []

    output = result.output

    if not isinstance(output, dict):
        return []

    namespace = call.arguments.get("namespace")
    pod = call.arguments.get("pod")

    if (
        not isinstance(namespace, str)
        or not namespace
        or not isinstance(pod, str)
        or not pod
    ):
        return []

    if output.get("namespace") != namespace or output.get("pod") != pod:
        return []

    workload = output.get("workload")

    if (
        not isinstance(workload, dict)
        or workload.get("kind") != "Deployment"
        or workload.get("ownership_verified") is not True
    ):
        return []

    observations: list[TrustedToolObservation] = []

    def add(field: str, value: object) -> None:
        if len(observations) >= MAX_CONFIG_OBSERVATIONS:
            return

        if type(value) not in (str, int, bool):
            return

        if isinstance(value, str) and (not value or len(value) > 200):
            return

        observations.append(
            TrustedToolObservation(
                request_id=request_id,
                tool=call.name,
                field=field,
                value=value,
                namespace=namespace,
                pod=pod,
            )
        )

    name = workload.get("name")

    if not isinstance(name, str) or not name or len(name) > 253:
        return []

    add("workload.kind", "Deployment")
    add("workload.name", name)
    add("workload.ownership_verified", True)

    for key, field in (
        ("desired_replicas", "workload.replicas.desired"),
        ("ready_replicas", "workload.replicas.ready"),
        ("available_replicas", "workload.replicas.available"),
    ):
        count = workload.get(key)

        if type(count) is int and 0 <= count <= 100_000:
            add(field, count)

    containers = output.get("containers")

    if not isinstance(containers, list):
        return observations

    for container in containers[:MAX_CONTAINERS]:
        if not isinstance(container, dict):
            continue

        cname = container.get("name")

        if not isinstance(cname, str) or not CONTAINER_NAME_PATTERN.fullmatch(cname):
            continue

        prefix = f"containers[{cname}]"

        add(f"{prefix}.config.present", True)

        image = safe_image(container.get("image"))

        if image is not None:
            add(f"{prefix}.image", image)

        count = container.get("env_count")

        if type(count) is int and 0 <= count <= 10_000:
            add(f"{prefix}.env.count", count)

        complete = container.get("env_names_complete")

        if type(complete) is bool:
            add(f"{prefix}.env.names_complete", complete)

        env = container.get("env")

        if isinstance(env, list):
            for item in env[:MAX_ENV_REPORTED]:
                if not isinstance(item, dict):
                    continue

                env_name = item.get("name")
                source = item.get("source")

                if (
                    isinstance(env_name, str)
                    and ENV_NAME_PATTERN.fullmatch(env_name)
                    and source in ENV_SOURCES
                ):
                    add(f"{prefix}.env[{env_name}].source", source)

        probe = container.get("readiness_probe")

        if isinstance(probe, dict):
            declared = probe.get("declared")

            if type(declared) is bool:
                add(f"{prefix}.readiness_probe.declared", declared)

            if declared is True:
                if probe.get("kind") in PROBE_KINDS:
                    add(f"{prefix}.readiness_probe.kind", probe["kind"])

                port = probe.get("port")

                if (
                    type(port) is int and 1 <= port <= 65535
                ) or (isinstance(port, str) and PORT_NAME_PATTERN.fullmatch(port)):
                    add(f"{prefix}.readiness_probe.port", port)

                path = probe.get("path")

                if isinstance(path, str) and PROBE_PATH_PATTERN.fullmatch(path):
                    add(f"{prefix}.readiness_probe.path", path)

                for timing in PROBE_TIMINGS:
                    value = probe.get(timing)

                    if type(value) is int and 0 <= value <= 100_000:
                        add(f"{prefix}.readiness_probe.{timing}", value)

        startup = container.get("startup")

        if not isinstance(startup, dict):
            continue

        for key in ("command_declared", "args_declared"):
            if type(startup.get(key)) is bool:
                add(f"{prefix}.startup.{key}", startup[key])

        if startup.get("entrypoint_kind") in ENTRYPOINT_KINDS:
            add(f"{prefix}.startup.entrypoint_kind", startup["entrypoint_kind"])

        analysis = startup.get("static_analysis")

        if analysis in STATIC_ANALYSES:
            add(f"{prefix}.startup.static_analysis", analysis)

            code = startup.get("static_exit_code")

            if (
                analysis == "unconditional_exit"
                and type(code) is int
                and 0 <= code <= 255
            ):
                add(f"{prefix}.startup.static_exit_code", code)

    return observations


_OBSERVATION_EXTRACTORS: dict[str, ObservationExtractor] = {
    WORKLOAD_CONFIG_TOOL: _extract_workload_config,
    "k8s.get_pods": _extract_get_pods,
    "k8s.describe_pod": _extract_describe_pod,
    "k8s.get_events": _extract_get_events,
    "k8s.get_logs": _extract_get_logs,
    "k8s.get_previous_logs": _extract_get_logs,
}   