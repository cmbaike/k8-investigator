"""Kubernetes reads for one health check.

Calls already allowed by the investigator role: get pod, list pods, get
deployment, get replicaset, list events. No logs, Secrets, or writes.
StatefulSet, DaemonSet and Job are not read, because that role cannot get them.
"""

from datetime import datetime

from app.health.types import (
    HealthReadError,
    ObservedContainer,
    ObservedDeployment,
    ObservedPod,
    ObservedReplicaSet,
    valid_uid,
)
from app.tools.handlers import (
    K8S_LIST_PAGE_SIZE,
    K8S_REQUEST_TIMEOUT,
    _age_seconds,
    _container_state,
    _controller,
    _memory_resources,
    apps_v1,
    core_v1,
)
from app.tools.pod_health import MOUNT_EVENT_REASONS


def _fail(exc: Exception) -> HealthReadError:
    status = getattr(exc, "status", None)
    if status == 404:
        return HealthReadError("not_found")
    if status == 403:
        return HealthReadError("permission_denied")
    return HealthReadError("observation_failed")


def _count(value: object, *, absent_is_zero: bool) -> int | None:
    if value is None and absent_is_zero:
        return 0
    if type(value) is int and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _containers(pod) -> tuple[ObservedContainer, ...]:
    memory = _memory_resources(pod)
    observed: list[ObservedContainer] = []
    statuses = getattr(getattr(pod, "status", None), "container_statuses", None) or []

    for status in statuses:
        state = _container_state(status)
        last = state.get("last_termination") or {}
        resources = memory.get(state.get("name"), {})
        observed.append(
            ObservedContainer(
                name=state.get("name"),
                ready=state.get("ready") if type(state.get("ready")) is bool else None,
                restart_count=state.get("restart_count"),
                state=state.get("state"),
                reason=state.get("reason"),
                exit_code=state.get("exit_code"),
                last_reason=last.get("reason") if isinstance(last, dict) else None,
                last_exit_code=last.get("exit_code") if isinstance(last, dict) else None,
                memory_request=resources.get("memory_request"),
                memory_limit=resources.get("memory_limit"),
            )
        )

    if observed:
        return tuple(observed)

    for name, resources in memory.items():
        observed.append(
            ObservedContainer(
                name=name,
                ready=None,
                restart_count=None,
                state=None,
                reason=None,
                exit_code=None,
                last_reason=None,
                last_exit_code=None,
                memory_request=resources.get("memory_request"),
                memory_limit=resources.get("memory_limit"),
            )
        )
    return tuple(observed)


def _scheduled(pod) -> tuple[str | None, str | None]:
    conditions = getattr(getattr(pod, "status", None), "conditions", None) or []
    for condition in conditions:
        if getattr(condition, "type", None) == "PodScheduled":
            status = getattr(condition, "status", None)
            reason = getattr(condition, "reason", None)
            return (
                status if status in {"True", "False"} else None,
                reason if isinstance(reason, str) else None,
            )
    return None, None


def _pod(pod) -> ObservedPod:
    metadata = getattr(pod, "metadata", None)
    status = getattr(pod, "status", None)
    owner = _controller(pod)
    scheduled_status, scheduled_reason = _scheduled(pod)
    created = getattr(metadata, "creation_timestamp", None)
    age = _age_seconds(pod) if isinstance(created, datetime) else None
    return ObservedPod(
        name=getattr(metadata, "name", None),
        namespace=getattr(metadata, "namespace", None),
        uid=valid_uid(getattr(metadata, "uid", None)),
        phase=getattr(status, "phase", None) if status is not None else None,
        scheduled_status=scheduled_status,
        scheduled_reason=scheduled_reason,
        age_seconds=age,
        containers=_containers(pod),
        owner_kind=getattr(owner, "kind", None) if owner is not None else None,
        owner_name=getattr(owner, "name", None) if owner is not None else None,
        owner_uid=valid_uid(getattr(owner, "uid", None)) if owner is not None else None,
        owner_is_controller=owner is not None,
    )


def _deployment_owner(replica) -> tuple[str | None, str | None]:
    owner = _controller(replica, "Deployment")
    if owner is None:
        return None, None
    name = getattr(owner, "name", None)
    return (name if isinstance(name, str) else None, valid_uid(getattr(owner, "uid", None)))


class KubernetesHealthReader:
    """Lazy client. Importing this module does not contact the cluster."""

    def read_pod(self, namespace: str, name: str) -> ObservedPod:
        try:
            pod = core_v1().read_namespaced_pod(
                name=name, namespace=namespace, _request_timeout=K8S_REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise _fail(exc) from None
        return _pod(pod)

    def read_deployment(self, namespace: str, name: str) -> ObservedDeployment:
        try:
            deployment = apps_v1().read_namespaced_deployment(
                name=name, namespace=namespace, _request_timeout=K8S_REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise _fail(exc) from None
        metadata = deployment.metadata
        status = getattr(deployment, "status", None)
        spec = getattr(deployment, "spec", None)
        desired = getattr(spec, "replicas", None) if spec is not None else None
        observed = status is not None
        return ObservedDeployment(
            name=getattr(metadata, "name", None),
            namespace=getattr(metadata, "namespace", None),
            uid=getattr(metadata, "uid", None),
            desired=desired if type(desired) is int and desired >= 0 else None,
            ready=_count(getattr(status, "ready_replicas", None), absent_is_zero=observed) if observed else None,
            available=_count(getattr(status, "available_replicas", None), absent_is_zero=observed) if observed else None,
            updated=_count(getattr(status, "updated_replicas", None), absent_is_zero=observed) if observed else None,
            status_observed=observed,
        )

    def list_pods(self, namespace: str) -> tuple[tuple[ObservedPod, ...], bool]:
        try:
            response = core_v1().list_namespaced_pod(
                namespace=namespace,
                limit=K8S_LIST_PAGE_SIZE,
                _request_timeout=K8S_REQUEST_TIMEOUT,
            )
        except Exception as exc:
            raise _fail(exc) from None
        truncated = bool(getattr(getattr(response, "metadata", None), "_continue", None))
        pods = tuple(
            _pod(item)
            for item in (getattr(response, "items", None) or [])
            if getattr(getattr(item, "metadata", None), "namespace", None) == namespace
        )
        return pods, truncated

    def read_replica_set(self, namespace: str, name: str) -> ObservedReplicaSet:
        try:
            replica = apps_v1().read_namespaced_replica_set(
                name=name, namespace=namespace, _request_timeout=K8S_REQUEST_TIMEOUT
            )
        except Exception as exc:
            raise _fail(exc) from None
        metadata = replica.metadata
        dep_name, dep_uid = _deployment_owner(replica)
        return ObservedReplicaSet(
            name=getattr(metadata, "name", None),
            namespace=getattr(metadata, "namespace", None),
            uid=getattr(metadata, "uid", None),
            deployment_name=dep_name,
            deployment_uid=dep_uid,
        )

    def mount_event_counts(
        self, namespace: str, pod_name: str, pod_uid: str
    ) -> tuple[dict[str, int], bool]:
        try:
            response = core_v1().list_namespaced_event(
                namespace=namespace,
                field_selector=f"involvedObject.kind=Pod,involvedObject.name={pod_name}",
                limit=K8S_LIST_PAGE_SIZE,
                _request_timeout=K8S_REQUEST_TIMEOUT,
            )
        except Exception as exc:
            raise _fail(exc) from None
        truncated = bool(getattr(getattr(response, "metadata", None), "_continue", None))
        counts: dict[str, int] = {}
        for event in getattr(response, "items", None) or []:
            involved = getattr(event, "involved_object", None)
            if involved is None:
                continue
            if getattr(involved, "kind", None) != "Pod" or getattr(involved, "name", None) != pod_name:
                continue
            if getattr(involved, "namespace", None) not in (None, namespace):
                continue
            if valid_uid(getattr(involved, "uid", None)) != pod_uid:
                continue
            reason = getattr(event, "reason", None)
            if reason not in MOUNT_EVENT_REASONS:
                continue
            count = getattr(event, "count", None)
            counts[reason] = counts.get(reason, 0) + (count if type(count) is int and count > 0 else 1)
        return counts, truncated


def kubernetes_reader() -> KubernetesHealthReader:
    return KubernetesHealthReader()
