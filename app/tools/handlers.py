import ast
from typing import Any

import re
from datetime import datetime, timezone

from app.tools.event_signals import (
    classify_event,
    classify_scheduling_message,
    volume_names,
)
from app.tools.kubernetes_client import apps_v1, core_v1
from app.tools.workload_config import (
    WorkloadConfigError,
    build_workload_config,
    controller_reference,
    summarize_probe,
)
from kubernetes.client.exceptions import ApiException

from app.tools.limits import (
    K8S_EVENT_MAX_ITEMS,
    K8S_EVENT_MESSAGE_MAX_CHARS,
    K8S_LIST_PAGE_SIZE,
    K8S_LOG_LIMIT_BYTES,
    TOOL_TIMEOUT_SECONDS,
)

K8S_CONNECT_TIMEOUT_SECONDS = 3
K8S_READ_TIMEOUT_SECONDS = min(10, TOOL_TIMEOUT_SECONDS - 3)

if K8S_READ_TIMEOUT_SECONDS <= 0:
    raise ValueError(
        "TOOL_TIMEOUT_SECONDS must exceed the Kubernetes connection timeout."
    )

K8S_REQUEST_TIMEOUT = (
    K8S_CONNECT_TIMEOUT_SECONDS,
    K8S_READ_TIMEOUT_SECONDS,
)

class KubernetesToolError(RuntimeError):
    pass

_EMPTY_BYTES_REPR = frozenset({"b''", 'b""'})
# The whole log body is ONE bytes literal: the Kubernetes client returned
# str(bytes) instead of the decoded text (b'starting\\n').
_BYTES_LITERAL = re.compile(r"""\Ab(?P<q>['"]).*(?P=q)\Z""", re.DOTALL)


def _unwrap_bytes_repr(logs: str) -> str:
    """Decode a log body that is exactly the repr of a bytes object. Anything
    else (including text that merely contains such a literal) is returned
    unchanged, and so is a literal that does not evaluate to bytes. Only the
    literal grammar is evaluated; no code runs."""
    stripped = logs.strip()

    if not _BYTES_LITERAL.fullmatch(stripped):
        return logs

    try:
        value = ast.literal_eval(stripped)
    except (ValueError, SyntaxError, MemoryError, RecursionError):
        return logs

    if not isinstance(value, bytes):
        return logs

    return value.decode("utf-8", errors="replace")


def _read_logs(arguments, *, previous: bool) -> dict[str, Any]:
    try:
        logs = core_v1().read_namespaced_pod_log(
            name=arguments.pod,
            namespace=arguments.namespace,
            container=arguments.container,
            tail_lines=arguments.tail,
            previous=previous,
            follow=False,
            limit_bytes=K8S_LOG_LIMIT_BYTES,
            _request_timeout=K8S_REQUEST_TIMEOUT,
        )
    except ApiException as exc:
        raise KubernetesToolError(
            f"Kubernetes log request failed with HTTP {exc.status}: {exc.reason}"
        ) from exc

    if isinstance(logs, bytes):
        logs = logs.decode("utf-8", errors="replace")

    if not isinstance(logs, str):
        logs = str(logs)

    # The Kubernetes client returns the Python repr of empty bytes for a log
    # with no content. That is an artifact of the client, not application
    # output: an empty log must stay empty (and yield no log excerpt) instead of
    # becoming a one-line "log" that a reader could attribute claims to.
    if logs.strip() in _EMPTY_BYTES_REPR:
        logs = ""
    else:
        logs = _unwrap_bytes_repr(logs)

    lowered = logs.lower()

    if (
        "unable to retrieve container logs" in lowered
        or "failed to retrieve container logs" in lowered
    ):
        raise KubernetesToolError(
            "Kubernetes container runtime could not retrieve the requested logs."
        )

    return {
        "namespace": arguments.namespace,
        "pod": arguments.pod,
        "container": arguments.container,
        "tail": arguments.tail,
        "previous": previous,
        "logs": logs,
        "retrieval_limits": {
            "tail_lines": arguments.tail,
            "limit_bytes": K8S_LOG_LIMIT_BYTES,
        },
        "completeness": "bounded_unknown",
    }
    
    
def _container_state(status) -> dict[str, Any]:
    state = status.state

    result: dict[str, Any] = {
        "name": status.name,
        "ready": status.ready,
        "restart_count": status.restart_count,
        "state": None,
        "reason": None,
        "message": None,
        "exit_code": None,
    }

    if state is None:
        return result

    if state.waiting is not None:
        result.update(
            {
                "state": "waiting",
                "reason": state.waiting.reason,
                "message": state.waiting.message,
            }
        )
    elif state.running is not None:
        result["state"] = "running"
    elif state.terminated is not None:
        result.update(
            {
                "state": "terminated",
                "reason": state.terminated.reason,
                "message": state.terminated.message,
                "exit_code": state.terminated.exit_code,
            }
        )
        
    last_state = status.last_state
    
    if last_state and last_state.terminated:
        result["last_termination"] = {
            "reason": last_state.terminated.reason,
            "message": last_state.terminated.message,
            "exit_code": last_state.terminated.exit_code,
        }
    else:
        result["last_termination"] = None
        
    return result  

MAX_OWNER_LOOKUPS = 20


def _controller(obj, kind: str | None = None):
    """The single controlling owner reference of `obj` (optionally of `kind`)."""
    refs = [
        ref
        for ref in (getattr(obj.metadata, "owner_references", None) or [])
        if getattr(ref, "controller", False) is True
        and (kind is None or getattr(ref, "kind", None) == kind)
    ]

    return refs[0] if len(refs) == 1 else None


def _pod_workloads(namespace: str, pods) -> dict[str, dict[str, Any]]:
    """Verified controlling workload per pod, from owner references.

    Pod -> ReplicaSet -> Deployment is resolved with one bounded read per
    distinct ReplicaSet (the same read describe_workload_config performs). An
    owner that cannot be confirmed is reported `verified: false`, never
    guessed. Names are NOT parsed or pattern-matched.
    """
    replica_sets: dict[str, dict[str, Any]] = {}
    result: dict[str, dict[str, Any]] = {}

    for pod in pods:
        owner = _controller(pod)

        if owner is None:
            result[pod.metadata.name] = {
                "kind": "Pod", "name": pod.metadata.name, "verified": True,
            }
            continue

        kind, name = getattr(owner, "kind", None), getattr(owner, "name", None)

        if not isinstance(kind, str) or not isinstance(name, str):
            continue

        if kind != "ReplicaSet":
            result[pod.metadata.name] = {"kind": kind, "name": name, "verified": True}
            continue

        if name not in replica_sets:
            summary = {"kind": "ReplicaSet", "name": name, "verified": False}

            if len(replica_sets) < MAX_OWNER_LOOKUPS:
                try:
                    rs = apps_v1().read_namespaced_replica_set(
                        name=name,
                        namespace=namespace,
                        _request_timeout=K8S_REQUEST_TIMEOUT,
                    )
                    deployment = _controller(rs, "Deployment")
                    rs_uid = getattr(owner, "uid", None)

                    if (
                        rs.metadata.name == name
                        and rs.metadata.namespace == namespace
                        and rs_uid
                        and rs.metadata.uid == rs_uid
                    ):
                        summary = (
                            {"kind": "Deployment", "name": deployment.name,
                             "verified": True}
                            if deployment is not None
                            else {"kind": "ReplicaSet", "name": name,
                                  "verified": True}
                        )
                except Exception:
                    pass  # unverified: the pod can never match a target

            replica_sets[name] = summary

        result[pod.metadata.name] = replica_sets[name]

    return result


def get_pods(arguments) -> dict[str, Any]:
    response = core_v1().list_namespaced_pod(
        namespace=arguments.namespace,
        limit=K8S_LIST_PAGE_SIZE,
        _request_timeout=K8S_REQUEST_TIMEOUT,
    )
    
    # A continue token means this page is not the whole namespace. The pods
    # on the page are still real evidence. Pods beyond it are not discovered
    # and must be reported as unknown, not dropped by failing the listing.
    listing_truncated = bool(
        getattr(getattr(response, "metadata", None), "_continue", None)
    )

    pods = []
    workloads = _pod_workloads(arguments.namespace, response.items)

    for pod in response.items:
        # Counts only, from the same list response (no extra API call). They
        # let the coverage policy order health inspections deterministically.
        # They are NOT minted as observations and never become findings.
        statuses = getattr(pod.status, "container_statuses", None) or []

        pods.append(
            {
                "name": pod.metadata.name,
                "namespace": pod.metadata.namespace,
                "phase": pod.status.phase,
                "node": pod.spec.node_name,
                "pod_ip": pod.status.pod_ip,
                "containers_total": len(statuses),
                "containers_ready": sum(1 for s in statuses if s.ready),
                "restart_count": sum(int(s.restart_count or 0) for s in statuses),
                # Verified controlling workload (owner references), or None.
                "workload": workloads.get(pod.metadata.name),
            }
        )

    return {
        "namespace": arguments.namespace,
        "pods": pods,
        "listing_truncated": listing_truncated,
    }


def _memory_resources(pod) -> dict[str, dict[str, str | None]]:
    """Declared memory request/limit per container, from the pod SPEC.

    Configured values only: they are not observed usage. Nothing else from the
    spec (environment, commands, arguments) is read here. Values are validated
    again before they can become evidence.
    """
    declared: dict[str, dict[str, str | None]] = {}

    for spec in getattr(pod.spec, "containers", None) or []:
        resources = getattr(spec, "resources", None)
        requests = (getattr(resources, "requests", None) or {}) if resources else {}
        limits = (getattr(resources, "limits", None) or {}) if resources else {}

        def quantity(source) -> str | None:
            if not isinstance(source, dict):
                return None
            value = source.get("memory")
            if value is None:
                return None
            # The Kubernetes client may return a Quantity, not a str.
            return value if isinstance(value, str) else str(value)

        declared[spec.name] = {
            "memory_request": quantity(requests),
            "memory_limit": quantity(limits),
        }

    return declared


_UID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)

# Order matters only for determinism: a volume has exactly one source set.
_VOLUME_SOURCES = (
    ("config_map", "config_map"),
    ("secret", "secret"),
    ("persistent_volume_claim", "persistent_volume_claim"),
    ("empty_dir", "empty_dir"),
    ("host_path", "host_path"),
    ("projected", "projected"),
    ("downward_api", "downward_api"),
    ("csi", "csi"),
    ("nfs", "nfs"),
    ("ephemeral", "ephemeral"),
)
MAX_VOLUMES = 8


def _valid_uid(value) -> str | None:
    """A Kubernetes UID (a lower-case UUID string), else None."""
    return value if isinstance(value, str) and _UID.fullmatch(value) else None


def _volumes(pod) -> list[dict[str, str]]:
    """Declared volume NAMES and source TYPES only.

    Nothing is read from inside a source: not the referenced object's name, not
    its keys, items or contents. A Secret volume is reported as `secret`, and
    its contents are never requested.
    """
    declared: list[dict[str, str]] = []

    for volume in list(getattr(pod.spec, "volumes", None) or [])[:MAX_VOLUMES]:
        name = getattr(volume, "name", None)

        if not isinstance(name, str):
            continue

        source = next(
            (
                label
                for attribute, label in _VOLUME_SOURCES
                if getattr(volume, attribute, None) is not None
            ),
            "other",
        )
        declared.append({"name": name, "source": source})

    return declared


def _declared_container_spec(pod) -> dict[str, dict[str, Any]]:
    """Per-container DECLARED liveness and readiness probes (kind, port, path,
    timings; never headers or commands). Read from the Pod's own container
    specification, so a standalone Pod with no controlling workload is covered
    exactly like a Deployment's Pod. CPU is deliberately not read: configured
    values only, and none is observed usage."""
    declared: dict[str, dict[str, Any]] = {}

    for spec in getattr(pod.spec, "containers", None) or []:
        declared[spec.name] = {
            "liveness_probe": summarize_probe(getattr(spec, "liveness_probe", None)),
            "readiness_probe": summarize_probe(getattr(spec, "readiness_probe", None)),
        }

    return declared


def _age_seconds(pod) -> int | None:
    """Seconds since the pod object was created, or None if unknown."""
    created = getattr(pod.metadata, "creation_timestamp", None)

    if not isinstance(created, datetime):
        return None

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    age = int((datetime.now(timezone.utc) - created).total_seconds())

    return age if 0 <= age <= 10_000_000 else None


def describe_pod(arguments) -> dict[str, Any]:
    pod = core_v1().read_namespaced_pod(
        name=arguments.pod,
        namespace=arguments.namespace,
        _request_timeout=K8S_REQUEST_TIMEOUT,
    )

    memory = _memory_resources(pod)
    declared = _declared_container_spec(pod)
    containers = []

    for status in pod.status.container_statuses or []:
        container = _container_state(status)
        container["resources"] = memory.get(
            status.name, {"memory_request": None, "memory_limit": None}
        )
        container["declared"] = declared.get(status.name)
        containers.append(container)

    if not containers:
        # No container status exists yet (for example the pod was never
        # scheduled): report the DECLARED containers, with no observed state,
        # so the declared memory request and probes are still evidence. A
        # container with no state is never read as ready, running or healthy.
        for name, resources in memory.items():
            containers.append(
                {
                    "name": name,
                    "ready": None,
                    "restart_count": None,
                    "state": None,
                    "reason": None,
                    "message": None,
                    "exit_code": None,
                    "last_termination": None,
                    "resources": resources,
                    "declared": declared.get(name),
                }
            )

    conditions = [
        {
            "type": condition.type,
            "status": condition.status,
            "reason": condition.reason,
            "message": condition.message,
            # Fixed-vocabulary classification of the scheduler's status message
            # (never the message itself). Only for a pod the scheduler reports
            # as unschedulable.
            "signals": (
                list(classify_scheduling_message(condition.message))
                if condition.type == "PodScheduled"
                and condition.reason == "Unschedulable"
                else []
            ),
        }
        for condition in (pod.status.conditions or [])
    ]

    return {
        "name": pod.metadata.name,
        "namespace": pod.metadata.namespace,
        "uid": _valid_uid(getattr(pod.metadata, "uid", None)),
        "age_seconds": _age_seconds(pod),
        "phase": pod.status.phase,
        "node": pod.spec.node_name,
        "pod_ip": pod.status.pod_ip,
        "containers": containers,
        "conditions": conditions,
        "volumes": _volumes(pod),
        "scheduling": {
            "node_selector_declared": bool(getattr(pod.spec, "node_selector", None)),
            "affinity_declared": getattr(pod.spec, "affinity", None) is not None,
        },
    }


def _event_message(message) -> str | None:
    """Untrusted free text: printable characters only, hard length cap."""
    if not isinstance(message, str):
        return None

    printable = "".join(ch for ch in message if ch.isprintable())

    return printable[:K8S_EVENT_MESSAGE_MAX_CHARS] or None


def _pod_identity(arguments) -> tuple[str | None, list[str]]:
    """The pod's own UID and declared volume names, from one bounded read.

    Used only to check the identity of the events the cluster returned (an
    event whose UID names a DIFFERENT pod of the same name, for example a
    replaced StatefulSet or standalone pod, must not be attributed to this
    one). If the pod cannot be read, identity is simply unavailable and the
    events are treated as name-matched only, never as UID-verified.
    """
    try:
        pod = core_v1().read_namespaced_pod(
            name=arguments.pod,
            namespace=arguments.namespace,
            _request_timeout=K8S_REQUEST_TIMEOUT,
        )
    except Exception:
        return None, []

    metadata = getattr(pod, "metadata", None)

    if (
        getattr(metadata, "name", None) != arguments.pod
        or getattr(metadata, "namespace", None) != arguments.namespace
    ):
        return None, []

    return (
        _valid_uid(getattr(metadata, "uid", None)),
        [volume["name"] for volume in _volumes(pod)],
    )


def _event_source(event) -> str | None:
    source = getattr(getattr(event, "source", None), "component", None)

    if not isinstance(source, str) or not source:
        source = getattr(event, "reporting_component", None)

    return source if isinstance(source, str) and source else None


def get_events(arguments) -> dict[str, Any]:
    """Namespace events, optionally restricted to one pod.

    With a pod, the API server filters (involvedObject kind and name), so only
    that pod's events are returned. Output is bounded: warnings first, then by
    count, at most K8S_EVENT_MAX_ITEMS, messages truncated. The messages are
    UNTRUSTED text for a human; the application keeps only validated
    reason/type/count and fixed-vocabulary signals derived from the message
    (never the message) as evidence.

    For a pod-bound listing the pod's UID is read once, and each event carries
    its involved object's UID, so the application can exclude events that
    belong to a different pod of the same name.
    """
    pod = getattr(arguments, "pod", None)
    request: dict[str, Any] = {
        "namespace": arguments.namespace,
        "limit": K8S_LIST_PAGE_SIZE,
        "_request_timeout": K8S_REQUEST_TIMEOUT,
    }

    if pod:
        request["field_selector"] = (
            f"involvedObject.kind=Pod,involvedObject.name={pod}"
        )

    response = core_v1().list_namespaced_event(**request)

    if getattr(response.metadata, "_continue", None):
        raise KubernetesToolError(
            "Event listing exceeded the configured page limit; "
            "results are incomplete."
        )

    pod_uid, declared_volumes = _pod_identity(arguments) if pod else (None, [])
    events = []

    for event in response.items:
        involved = event.involved_object
        reason, source = event.reason, _event_source(event)

        entry = {
            "type": event.type,
            "reason": reason,
            "message": _event_message(event.message),
            "object_kind": involved.kind if involved else None,
            "object_name": involved.name if involved else None,
            "object_namespace": (
                getattr(involved, "namespace", None) if involved else None
            ),
            "object_uid": _valid_uid(getattr(involved, "uid", None)) if involved else None,
            "source": source,
            "count": event.count,
        }

        if pod:
            # Classified from the full (bounded) message, before truncation.
            entry["signals"] = list(classify_event(reason, event.message, source))
            entry["volumes"] = list(
                volume_names(event.message, declared_volumes)
                if reason in {"FailedMount", "FailedAttachVolume"}
                else ()
            )

        events.append(entry)

    events.sort(
        key=lambda e: (
            e["type"] != "Warning",
            -(e["count"] if type(e["count"]) is int else 0),
            str(e["reason"]),
        )
    )
    truncated = len(events) > K8S_EVENT_MAX_ITEMS

    return {
        "namespace": arguments.namespace,
        "pod": pod,
        "pod_uid": pod_uid,
        "events": events[:K8S_EVENT_MAX_ITEMS],
        "truncated": truncated,
    }


def get_deployment(arguments) -> dict[str, Any]:
    deployment = apps_v1().read_namespaced_deployment(
        name=arguments.deployment,
        namespace=arguments.namespace,
        _request_timeout=K8S_REQUEST_TIMEOUT,
    )

    return {
        "name": deployment.metadata.name,
        "namespace": deployment.metadata.namespace,
        "desired_replicas": deployment.spec.replicas,
        "ready_replicas": deployment.status.ready_replicas or 0,
        "available_replicas": deployment.status.available_replicas or 0,
        "updated_replicas": deployment.status.updated_replicas or 0,
        "unavailable_replicas": deployment.status.unavailable_replicas or 0,
    }

def describe_workload_config(arguments) -> dict[str, Any]:
    """Safe configuration summary for the Deployment that owns a pod.

    Deliberately separate from `get_deployment`, which is unchanged. Reads the
    Pod, its ReplicaSet and Deployment (verified by owner reference + UID) and
    returns names/source types only: no env values, no command text, no
    annotations. See app/tools/workload_config.py for the policy.
    """
    try:
        pod = core_v1().read_namespaced_pod(
            name=arguments.pod,
            namespace=arguments.namespace,
            _request_timeout=K8S_REQUEST_TIMEOUT,
        )

        if (
            pod.metadata.name != arguments.pod
            or pod.metadata.namespace != arguments.namespace
        ):
            raise WorkloadConfigError("Pod identity could not be verified.")

        rs_name, _ = controller_reference(pod, "ReplicaSet")

        replicaset = apps_v1().read_namespaced_replica_set(
            name=rs_name,
            namespace=arguments.namespace,
            _request_timeout=K8S_REQUEST_TIMEOUT,
        )

        dep_name, _ = controller_reference(replicaset, "Deployment")

        deployment = apps_v1().read_namespaced_deployment(
            name=dep_name,
            namespace=arguments.namespace,
            _request_timeout=K8S_REQUEST_TIMEOUT,
        )

        return build_workload_config(
            namespace=arguments.namespace,
            pod=pod,
            replicaset=replicaset,
            deployment=deployment,
        )
    except ApiException as exc:
        raise KubernetesToolError(
            f"Kubernetes workload request failed with HTTP {exc.status}: "
            f"{exc.reason}"
        ) from exc
    except WorkloadConfigError as exc:
        raise KubernetesToolError(str(exc)) from exc


def get_logs(arguments) -> dict[str, Any]:
    return _read_logs(arguments, previous=False)


def get_previous_logs(arguments) -> dict[str, Any]:
    return _read_logs(arguments, previous=True)


HANDLERS = {
    "k8s.get_pods": get_pods,
    "k8s.describe_pod": describe_pod,
    "k8s.get_events": get_events,
    "k8s.get_deployment": get_deployment,
    "k8s.describe_workload_config": describe_workload_config,
    "k8s.get_logs": get_logs,
    "k8s.get_previous_logs": get_previous_logs,
}
