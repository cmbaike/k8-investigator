"""Browser response for one on-demand health check. No free-text diagnosis."""

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field

from app.web.models import WebModel

HealthCategoryName = Literal["healthy", "degraded", "unhealthy", "unknown"]


class HealthSignal(WebModel):
    code: str
    label: str


class HealthLimitation(WebModel):
    code: str
    label: str


class ContainerHealth(WebModel):
    name: str
    ready: bool | None = None
    state: Literal["waiting", "running", "terminated"] | None = None
    waiting_reason: str | None = None
    last_termination_reason: str | None = None
    last_exit_code: int | None = None
    restart_count: int | None = None
    configured_memory_request: str | None = None
    configured_memory_limit: str | None = None


class PodHealth(WebModel):
    name: str
    uid: str | None = None
    phase: Literal["Pending", "Running", "Succeeded", "Failed", "Unknown"] | None = None
    ready: bool | None = None
    category: HealthCategoryName
    signals: list[HealthSignal] = Field(default_factory=list)
    containers: list[ContainerHealth] = Field(default_factory=list)


class WorkloadCounts(WebModel):
    desired: int | None = None
    ready: int | None = None
    available: int | None = None
    updated: int | None = None


class HealthCoverage(WebModel):
    discovered: int
    examined: int
    complete: bool
    summary: str
    limitations: list[HealthLimitation] = Field(default_factory=list)


class ResourceIdentity(WebModel):
    namespace: str
    kind: Literal["Pod", "Deployment"]
    name: str
    uid: str | None = None


class ResourceHealthResponse(WebModel):
    """One point-in-time read. Not a monitor and not an availability SLO."""

    model_config = ConfigDict(extra="forbid")

    resource: ResourceIdentity
    category: HealthCategoryName
    signals: list[HealthSignal] = Field(default_factory=list)
    workload: WorkloadCounts | None = None
    pods: list[PodHealth] = Field(default_factory=list)
    coverage: HealthCoverage
    observed_at: datetime
    ttl_seconds: int
    snapshot: Literal["point_in_time"] = "point_in_time"
