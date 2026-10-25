"""Values the health check is allowed to carry.

These are structured observations, not Kubernetes messages. A field that is not
declared here is not part of a health result.
"""

import re
from dataclasses import dataclass

SUPPORTED_KINDS = frozenset({"Pod", "Deployment"})

MAX_PODS_EXAMINED = 20
MAX_CONTAINERS = 8
MAX_REPLICA_SET_READS = 8
MAX_EVENT_READS = 8
HEALTH_DEADLINE_SECONDS = 12.0
HEALTH_TTL_SECONDS = 30

_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
_UID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_QUANTITY = re.compile(
    r"^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,6})?(?:Ki|Mi|Gi|Ti|Pi|Ei|[kMGTPE]|m)?$"
)
_CONTAINER = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")


class HealthRequestError(Exception):
    """A health check that must not return a health category."""

    def __init__(self, status: int, code: str) -> None:
        self.status = status
        self.code = code
        super().__init__(code)


class HealthReadError(Exception):
    """A Kubernetes read failed. `code` is a fixed token, never a message."""

    def __init__(self, code: str) -> None:
        if code not in {"not_found", "permission_denied", "observation_failed"}:
            code = "observation_failed"
        self.code = code
        super().__init__(code)


def valid_name(value: object) -> str | None:
    return value if isinstance(value, str) and _NAME.fullmatch(value) else None


def valid_uid(value: object) -> str | None:
    return value if isinstance(value, str) and _UID.fullmatch(value) else None


def valid_quantity(value: object) -> str | None:
    return value if isinstance(value, str) and _QUANTITY.fullmatch(value) else None


def valid_container_name(value: object) -> str | None:
    return value if isinstance(value, str) and _CONTAINER.fullmatch(value) else None


@dataclass(frozen=True)
class ObservedContainer:
    name: str
    ready: bool | None
    restart_count: int | None
    state: str | None
    reason: str | None
    exit_code: int | None
    last_reason: str | None
    last_exit_code: int | None
    memory_request: str | None
    memory_limit: str | None


@dataclass(frozen=True)
class ObservedPod:
    name: str
    namespace: str
    uid: str | None
    phase: str | None
    scheduled_status: str | None
    scheduled_reason: str | None
    age_seconds: int | None
    containers: tuple[ObservedContainer, ...]
    owner_kind: str | None
    owner_name: str | None
    owner_uid: str | None
    owner_is_controller: bool


@dataclass(frozen=True)
class ObservedReplicaSet:
    name: str
    namespace: str
    uid: str
    deployment_name: str | None
    deployment_uid: str | None


@dataclass(frozen=True)
class ObservedDeployment:
    name: str
    namespace: str
    uid: str
    desired: int | None
    ready: int | None
    available: int | None
    updated: int | None
    status_observed: bool


@dataclass(frozen=True)
class HealthAuditRecord:
    principal_id: str
    namespace: str
    kind: str
    name: str
    resource_uid: str | None
    category: str | None
    status: str
    error_code: str | None
    discovered: int | None
    examined: int | None
    coverage_complete: bool | None
