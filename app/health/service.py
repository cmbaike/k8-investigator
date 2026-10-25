"""On-demand health for one exact Pod or Deployment.

Authorization is the caller's job and must happen before any read. A missing
resource or a denied namespace raises HealthRequestError and does not list
other workloads. Descendant pods are included only when the Pod -> ReplicaSet
-> Deployment owner chain matches this Deployment's UID. Name-only ownership
is not accepted.

One request performs several Kubernetes reads (the resource, one pod page,
a capped number of ReplicaSet reads, and mount events only when a pod is
stuck in ContainerCreating). Those reads are not audited individually. The
caller records one audit row for the request.
"""

import re
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Protocol

from app.health.classify import (
    PodVerdict,
    Signal,
    classify_observed_pod,
    limitation_label,
    needs_mount_events,
)
from app.health.models import (
    ContainerHealth,
    HealthCoverage,
    HealthLimitation,
    HealthSignal,
    PodHealth,
    ResourceHealthResponse,
    ResourceIdentity,
    WorkloadCounts,
)
from app.health.types import (
    HEALTH_DEADLINE_SECONDS,
    HEALTH_TTL_SECONDS,
    MAX_EVENT_READS,
    MAX_PODS_EXAMINED,
    MAX_REPLICA_SET_READS,
    SUPPORTED_KINDS,
    HealthAuditRecord,
    HealthReadError,
    HealthRequestError,
    ObservedDeployment,
    ObservedPod,
    ObservedReplicaSet,
    valid_name,
    valid_uid,
)
from app.security.api_keys import APIKeyPrincipal, NamespaceAuthorizationError, authorize_namespace

_PRINCIPAL = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_AUDIT_KINDS = SUPPORTED_KINDS | {"StatefulSet", "DaemonSet", "Job", "ReplicaSet"}


class HealthReader(Protocol):
    def read_pod(self, namespace: str, name: str) -> ObservedPod: ...

    def read_deployment(self, namespace: str, name: str) -> ObservedDeployment: ...

    def list_pods(self, namespace: str) -> tuple[tuple[ObservedPod, ...], bool]: ...

    def read_replica_set(self, namespace: str, name: str) -> ObservedReplicaSet: ...

    def mount_event_counts(
        self, namespace: str, pod_name: str, pod_uid: str
    ) -> tuple[dict[str, int], bool]: ...


def _coverage_summary(discovered: int, examined: int, limitations: list[str]) -> str:
    if "pod_list_truncated" in limitations:
        return (
            f"Inspected {examined} of at least {discovered} matching pods. "
            "The listing was truncated."
        )
    if "pod_list_failed" in limitations:
        return "Pod listing failed, so no pod was inspected."
    return f"Inspected {examined} of {discovered} pods."


def _coverage(discovered: int, examined: int, limitations: list[str]) -> HealthCoverage:
    # A truncated listing or a cap means the check cannot claim completeness.
    complete = not limitations
    return HealthCoverage(
        discovered=discovered,
        examined=examined,
        complete=complete,
        summary=_coverage_summary(discovered, examined, limitations),
        limitations=[
            HealthLimitation(code=code, label=limitation_label(code)) for code in limitations
        ],
    )


def _signals(items: list[Signal]) -> list[HealthSignal]:
    ordered = sorted(items, key=lambda item: (not item.critical, item.code))
    return [HealthSignal(code=item.code, label=item.label) for item in ordered[:6]]


def _pod_model(verdict: PodVerdict) -> PodHealth:
    return PodHealth(
        name=verdict.name,
        uid=verdict.uid,
        phase=verdict.phase,
        ready=verdict.ready,
        category=verdict.category,  # type: ignore[arg-type]
        signals=_signals(list(verdict.signals)),
        containers=[
            ContainerHealth(
                name=item.name,
                ready=item.ready,
                state=item.state,  # type: ignore[arg-type]
                waiting_reason=item.waiting_reason,
                last_termination_reason=item.last_termination_reason,
                last_exit_code=item.last_exit_code,
                restart_count=item.restart_count,
                configured_memory_request=item.configured_memory_request,
                configured_memory_limit=item.configured_memory_limit,
            )
            for item in verdict.containers
        ],
    )


def _unknown(
    *,
    namespace: str,
    kind: str,
    name: str,
    limitation: str,
    now: datetime,
) -> ResourceHealthResponse:
    return ResourceHealthResponse(
        resource=ResourceIdentity(namespace=namespace, kind=kind, name=name, uid=None),  # type: ignore[arg-type]
        category="unknown",
        signals=[],
        workload=None,
        pods=[],
        coverage=_coverage(0, 0, [limitation]),
        observed_at=now,
        ttl_seconds=HEALTH_TTL_SECONDS,
    )


def _combine(
    categories: list[str],
    *,
    desired: int | None,
    ready: int | None,
    coverage_complete: bool,
) -> tuple[str, list[str]]:
    extra: list[str] = []
    if not categories:
        if desired == 0:
            return "healthy", ["scaled_to_zero"]
        if not coverage_complete:
            if desired is not None and ready is not None and desired > 0 and ready < desired:
                return "degraded", ["replicas_not_ready"]
            return "unknown", []
        if desired is not None and ready is not None and desired > 0 and ready < desired:
            return "degraded", ["replicas_not_ready"]
        return "unknown", []

    if "unhealthy" in categories and any(item in {"healthy", "degraded"} for item in categories):
        category = "degraded"
        extra.append("partial_failure")
    elif "unhealthy" in categories:
        category = "unhealthy"
    elif "degraded" in categories:
        category = "degraded"
    elif "unknown" in categories:
        category = "unknown"
    else:
        category = "healthy"

    if category == "healthy" and not coverage_complete:
        category = "unknown"
    if desired == 0 and category == "healthy":
        extra.append("scaled_to_zero")
    if (
        category == "healthy"
        and desired is not None
        and ready is not None
        and desired > 0
        and ready < desired
    ):
        category = "degraded"
        extra.append("replicas_not_ready")
    return category, extra


def _events_for(
    reader: HealthReader,
    pod: ObservedPod,
    *,
    namespace: str,
    deadline: float,
    budget: list[int],
    limitations: list[str],
) -> tuple[dict[str, int], bool]:
    if not needs_mount_events(pod) or pod.uid is None:
        return {}, False
    if budget[0] <= 0:
        _note(limitations, "events_unavailable")
        return {}, True
    if time.monotonic() >= deadline:
        _note(limitations, "deadline_exceeded")
        return {}, True
    budget[0] -= 1
    try:
        counts, truncated = reader.mount_event_counts(namespace, pod.name, pod.uid)
    except HealthReadError:
        _note(limitations, "events_unavailable")
        return {}, True
    if truncated:
        _note(limitations, "events_truncated")
    return counts, truncated


def _note(limitations: list[str], code: str) -> None:
    if code not in limitations:
        limitations.append(code)


def _matches(pod: ObservedPod, deployment: ObservedDeployment, replica: ObservedReplicaSet) -> bool:
    if not pod.owner_is_controller or pod.owner_kind != "ReplicaSet":
        return False
    if not pod.owner_uid or not pod.owner_name:
        return False
    return (
        replica.name == pod.owner_name
        and replica.namespace == deployment.namespace
        and replica.uid == pod.owner_uid
        and replica.deployment_name == deployment.name
        and replica.deployment_uid == deployment.uid
    )


def _inspect_pods(
    pods: list[ObservedPod],
    reader: HealthReader,
    *,
    namespace: str,
    deadline: float,
    limitations: list[str],
) -> list[PodVerdict]:
    budget = [MAX_EVENT_READS]
    examined = pods[:MAX_PODS_EXAMINED]
    if len(pods) > MAX_PODS_EXAMINED:
        _note(limitations, "pod_cap")
    verdicts: list[PodVerdict] = []
    for pod in examined:
        if time.monotonic() >= deadline:
            _note(limitations, "deadline_exceeded")
            break
        counts, inconclusive = _events_for(
            reader, pod, namespace=namespace, deadline=deadline, budget=budget, limitations=limitations
        )
        verdicts.append(
            classify_observed_pod(pod, counts, events_inconclusive=inconclusive)
        )
    return verdicts


def _deployment(
    reader: HealthReader,
    *,
    namespace: str,
    name: str,
    now: datetime,
    deadline: float,
) -> ResourceHealthResponse:
    try:
        deployment = reader.read_deployment(namespace, name)
    except HealthReadError as exc:
        if exc.code == "not_found":
            raise HealthRequestError(404, "not_found") from None
        if exc.code == "permission_denied":
            raise HealthRequestError(403, "permission_denied") from None
        return _unknown(
            namespace=namespace, kind="Deployment", name=name, limitation="observation_failed", now=now
        )

    if (
        deployment.name != name
        or deployment.namespace != namespace
        or valid_uid(deployment.uid) is None
    ):
        raise HealthRequestError(404, "not_found")

    limitations: list[str] = []
    if not deployment.status_observed:
        _note(limitations, "replica_status_missing")

    listed: tuple[ObservedPod, ...] = ()
    truncated = False
    if time.monotonic() >= deadline:
        _note(limitations, "deadline_exceeded")
        list_failed = True
    else:
        try:
            listed, truncated = reader.list_pods(namespace)
        except HealthReadError:
            _note(limitations, "pod_list_failed")
            list_failed = True
            listed = ()
        else:
            list_failed = False
            if truncated:
                _note(limitations, "pod_list_truncated")

    verified: list[ObservedPod] = []
    if not list_failed:
        cache: dict[str, ObservedReplicaSet | None] = {}
        reads = 0
        # Prefer ReplicaSets named for this Deployment so unrelated owners cannot
        # consume the read cap. Inclusion still requires the UID chain; the
        # prefix only chooses which reads to spend. Other ReplicaSet names are
        # not treated as children of this Deployment.
        prefix = f"{deployment.name}-"

        def _preferred(pod: ObservedPod) -> bool:
            return pod.owner_name == deployment.name or (
                isinstance(pod.owner_name, str) and pod.owner_name.startswith(prefix)
            )

        ordered = sorted(
            listed,
            key=lambda pod: (not _preferred(pod), pod.name),
        )
        for pod in ordered:
            if (
                pod.owner_is_controller
                and pod.owner_kind == "Deployment"
                and pod.owner_uid == deployment.uid
                and pod.owner_name == deployment.name
            ):
                verified.append(pod)
                continue
            if not pod.owner_is_controller or pod.owner_kind != "ReplicaSet" or not pod.owner_name:
                continue
            if not _preferred(pod):
                continue
            if pod.owner_name not in cache:
                if reads >= MAX_REPLICA_SET_READS or time.monotonic() >= deadline:
                    _note(limitations, "owner_lookup_cap" if reads >= MAX_REPLICA_SET_READS else "deadline_exceeded")
                    break
                reads += 1
                try:
                    replica = reader.read_replica_set(namespace, pod.owner_name)
                except HealthReadError:
                    cache[pod.owner_name] = None
                    _note(limitations, "owner_unverified")
                    continue
                if (
                    replica.name != pod.owner_name
                    or replica.namespace != namespace
                    or valid_uid(replica.uid) is None
                ):
                    cache[pod.owner_name] = None
                    _note(limitations, "owner_unverified")
                    continue
                cache[pod.owner_name] = replica
            replica = cache[pod.owner_name]
            if replica is not None and _matches(pod, deployment, replica):
                verified.append(pod)

    verdicts = _inspect_pods(
        verified, reader, namespace=namespace, deadline=deadline, limitations=limitations
    )
    discovered = len(verified)
    # Pods skipped because the deadline fired during inspection are not examined.
    examined = len(verdicts)
    if examined < min(discovered, MAX_PODS_EXAMINED) and "deadline_exceeded" not in limitations:
        _note(limitations, "deadline_exceeded")

    coverage = _coverage(discovered, examined, limitations)
    category, extra_codes = _combine(
        [item.category for item in verdicts],
        desired=deployment.desired,
        ready=deployment.ready,
        coverage_complete=coverage.complete,
    )
    signals = [Signal(code, critical=False) for code in extra_codes]
    for verdict in verdicts:
        for signal in verdict.signals:
            if all(item.code != signal.code for item in signals):
                signals.append(signal)

    return ResourceHealthResponse(
        resource=ResourceIdentity(
            namespace=namespace, kind="Deployment", name=name, uid=valid_uid(deployment.uid)
        ),
        category=category,  # type: ignore[arg-type]
        signals=_signals(signals),
        workload=WorkloadCounts(
            desired=deployment.desired,
            ready=deployment.ready,
            available=deployment.available,
            updated=deployment.updated,
        ),
        pods=[_pod_model(item) for item in verdicts],
        coverage=coverage,
        observed_at=now,
        ttl_seconds=HEALTH_TTL_SECONDS,
    )


def _pod(
    reader: HealthReader,
    *,
    namespace: str,
    name: str,
    now: datetime,
    deadline: float,
) -> ResourceHealthResponse:
    try:
        pod = reader.read_pod(namespace, name)
    except HealthReadError as exc:
        if exc.code == "not_found":
            raise HealthRequestError(404, "not_found") from None
        if exc.code == "permission_denied":
            raise HealthRequestError(403, "permission_denied") from None
        return _unknown(
            namespace=namespace, kind="Pod", name=name, limitation="observation_failed", now=now
        )

    if pod.name != name or pod.namespace != namespace or valid_name(pod.name) is None:
        raise HealthRequestError(404, "not_found")

    limitations: list[str] = []
    counts, inconclusive = _events_for(
        reader,
        pod,
        namespace=namespace,
        deadline=deadline,
        budget=[MAX_EVENT_READS],
        limitations=limitations,
    )
    verdict = classify_observed_pod(pod, counts, events_inconclusive=inconclusive)
    if verdict.events_unmet:
        _note(limitations, "events_unavailable")
    category = verdict.category
    if category == "healthy" and limitations:
        category = "unknown"
    return ResourceHealthResponse(
        resource=ResourceIdentity(
            namespace=namespace, kind="Pod", name=name, uid=valid_uid(pod.uid)
        ),
        category=category,  # type: ignore[arg-type]
        signals=_signals(list(verdict.signals)),
        workload=None,
        pods=[_pod_model(verdict)],
        coverage=_coverage(1, 1, limitations),
        observed_at=now,
        ttl_seconds=HEALTH_TTL_SECONDS,
    )


def inspect_resource(
    *,
    namespace: str,
    kind: str,
    name: str,
    reader: HealthReader,
    now: datetime | None = None,
    deadline_seconds: float = HEALTH_DEADLINE_SECONDS,
) -> ResourceHealthResponse:
    """Read and classify one resource. Does not authorize and does not audit."""
    if kind not in SUPPORTED_KINDS:
        raise HealthRequestError(422, "unsupported_kind")
    if valid_name(namespace) is None or valid_name(name) is None:
        raise HealthRequestError(422, "invalid_name")

    moment = now or datetime.now(timezone.utc)
    deadline = time.monotonic() + deadline_seconds
    if kind == "Pod":
        return _pod(reader, namespace=namespace, name=name, now=moment, deadline=deadline)
    return _deployment(reader, namespace=namespace, name=name, now=moment, deadline=deadline)


def _principal_ref(principal_id: str) -> str:
    return principal_id if _PRINCIPAL.fullmatch(principal_id) else "redacted"


def run_health_check(
    *,
    principal: APIKeyPrincipal,
    namespace: str,
    kind: str,
    name: str,
    reader: HealthReader,
    audit: Callable[[HealthAuditRecord], None],
    now: datetime | None = None,
) -> ResourceHealthResponse:
    """Authorize, inspect, and write exactly one audit row.

    The audit row describes the request, not each internal Kubernetes read.
    """
    recorded = False

    def record(**kwargs: object) -> None:
        nonlocal recorded
        recorded = True
        audit(
            HealthAuditRecord(
                principal_id=_principal_ref(principal.principal_id),
                namespace=namespace if valid_name(namespace) else "invalid",
                kind=kind if kind in _AUDIT_KINDS else "unsupported",
                name=name if valid_name(name) else "invalid",
                resource_uid=kwargs.get("resource_uid") if valid_uid(kwargs.get("resource_uid")) else None,  # type: ignore[arg-type]
                category=kwargs.get("category"),  # type: ignore[arg-type]
                status=str(kwargs.get("status")),
                error_code=kwargs.get("error_code"),  # type: ignore[arg-type]
                discovered=kwargs.get("discovered"),  # type: ignore[arg-type]
                examined=kwargs.get("examined"),  # type: ignore[arg-type]
                coverage_complete=kwargs.get("coverage_complete"),  # type: ignore[arg-type]
            )
        )

    try:
        authorize_namespace(principal, namespace)
    except NamespaceAuthorizationError:
        record(status="namespace_denied", error_code="namespace_denied")
        raise HealthRequestError(403, "namespace_denied") from None

    try:
        result = inspect_resource(namespace=namespace, kind=kind, name=name, reader=reader, now=now)
    except HealthRequestError as exc:
        record(status=exc.code, error_code=exc.code)
        raise
    except Exception:
        if not recorded:
            record(status="observation_failed", error_code="observation_failed")
        raise

    error = None
    if any(item.code == "observation_failed" for item in result.coverage.limitations):
        error = "observation_failed"
    record(
        status="recorded",
        category=result.category,
        error_code=error,
        resource_uid=result.resource.uid,
        discovered=result.coverage.discovered,
        examined=result.coverage.examined,
        coverage_complete=result.coverage.complete,
    )
    return result
