"""Deterministic pod-level health classification from structured Kubernetes state.

`container_health` classifies a container from its own status. Two failures
leave no container status to classify, or only a transitional one, so they are
classified here from the pod's structured state:

  UNSCHEDULABLE         the scheduler placed the pod nowhere. The pod is Pending
                        and Kubernetes' own pod condition PodScheduled is False
                        with reason Unschedulable. No container exists yet, so
                        nothing ran: there are no logs, restarts or probes.
  VOLUME_MOUNT_FAILURE  the pod WAS scheduled but its containers cannot be
                        created: the pod is Pending, PodScheduled is True, a
                        container is waiting in ContainerCreating, and
                        Kubernetes recorded a FailedMount or FailedAttachVolume
                        event for the pod (identity-checked by the caller). The
                        waiting state alone is NOT enough: ContainerCreating is
                        normal and brief, so without the event it stays
                        unclassified.

Both are statements of what Kubernetes reports. Neither asserts why: that a
scheduler constraint or a volume problem exists is established, what caused it
is not. No application names, event messages or model output are involved.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum


class PodCategory(StrEnum):
    UNSCHEDULABLE = "unschedulable"
    VOLUME_MOUNT_FAILURE = "volume_mount_failure"


MOUNT_EVENT_REASONS = frozenset({"FailedMount", "FailedAttachVolume"})
CREATING = "ContainerCreating"
# ContainerCreating is a normal, brief state. A pod still in it after this long
# is not "merely being created", and its events are worth reading. An unknown
# age never triggers anything (the prior behavior).
CREATING_GRACE_SECONDS = 30


@dataclass(frozen=True)
class PodAssessment:
    category: PodCategory
    severity: str  # "critical": no container of the pod can run

    @property
    def meaning(self) -> str:
        if self.category is PodCategory.UNSCHEDULABLE:
            return (
                "Kubernetes reports that the scheduler could not place the pod "
                "on any node, so no container has been created"
            )

        return (
            "Kubernetes reports that the pod was scheduled to a node but its "
            "containers cannot be created while Kubernetes records volume "
            "mount or attach failures for it"
        )


def _creating(states: Iterable[tuple[object, object]]) -> bool:
    return any(state == "waiting" and reason == CREATING for state, reason in states)


def needs_events(
    *,
    phase: object,
    scheduled: tuple[object, object] | None,
    container_states: Iterable[tuple[object, object]],
    age_seconds: object = None,
) -> bool:
    """True when the pod is stuck before its containers run and Kubernetes'
    events are the record that explains where: unschedulable, or Pending in
    ContainerCreating for longer than the grace period. Structural only; it
    asserts nothing about cause."""
    if phase != "Pending":
        return False

    if scheduled == ("False", "Unschedulable"):
        return True

    return (
        type(age_seconds) is int
        and age_seconds >= CREATING_GRACE_SECONDS
        and _creating(container_states)
    )


def classify_pod(
    *,
    phase: object,
    scheduled: tuple[object, object] | None,
    container_states: Iterable[tuple[object, object]],
    event_counts: Mapping[str, int],
) -> PodAssessment | None:
    """Pod-level assessment, or None when neither failure is established.

    `scheduled` is (status, reason) of the PodScheduled condition.
    `container_states` is (state, reason) per observed container.
    `event_counts` maps event reason -> count for identity-checked events.
    """
    if phase != "Pending" or scheduled is None:
        return None

    if scheduled == ("False", "Unschedulable"):
        return PodAssessment(PodCategory.UNSCHEDULABLE, "critical")

    states = tuple(container_states)

    if (
        scheduled[0] == "True"
        and _creating(states)
        and any(event_counts.get(reason, 0) >= 1 for reason in MOUNT_EVENT_REASONS)
    ):
        return PodAssessment(PodCategory.VOLUME_MOUNT_FAILURE, "critical")

    return None
