"""Deterministic container-health classification from structured Kubernetes state.

Pure functions over values the application already minted as trusted
observations (readiness, restart count, state, waiting/termination reasons,
exit codes). No application names, namespaces, images, logs, event messages or
model output are involved, and nothing is inferred beyond what the Kubernetes
reason itself means.

Categories:
  HEALTHY            running and ready, or completed successfully.
  RUNTIME_FAILURE    the container started and then failed: a crash loop, a
                     non-zero or error termination, an OOM kill.
  PRE_START_FAILURE  the container has not (successfully) started because
                     Kubernetes could not pull its image or create/run it.
                     Application logs may not exist for such a container.
  NOT_READY          the container IS running but Kubernetes reports it not
                     ready (for example a failing readiness probe). It started,
                     so logs can exist; it is an operational concern even with
                     zero restarts. Kubernetes does not say why.
  RESTARTED_RUNNING  the container is running and ready NOW but Kubernetes
                     records that it was restarted (whatever its previous
                     termination looked like).
                     Current health and history are separate facts: this is
                     not a current failure (it is not `is_failure`), but the
                     restarts are real and are reported, never hidden because
                     the container happens to be ready at the moment it was
                     inspected.
  UNKNOWN            not enough was observed to classify (for example a
                     container that is still being created, or fields missing).

A classification states what Kubernetes reports. It never asserts why: the
meaning texts below restate the Kubernetes reason, and the cause of a pull or
configuration failure stays unestablished until further evidence supports it.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class HealthCategory(StrEnum):
    HEALTHY = "healthy"
    RUNTIME_FAILURE = "runtime_failure"
    PRE_START_FAILURE = "pre_start_failure"
    NOT_READY = "running_not_ready"
    RESTARTED_RUNNING = "restarted_running"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReasonInfo:
    meaning: str
    severity: str  # "warning" | "critical"


# Waiting reasons that mean the container could not be started. Meanings
# restate the reason; they do not claim why it happened.
PRE_START_REASONS: dict[str, ReasonInfo] = {
    "ImagePullBackOff": ReasonInfo(
        "Kubernetes reports that pulling the container image failed and the "
        "kubelet is backing off before it retries",
        "critical",
    ),
    "ErrImagePull": ReasonInfo(
        "Kubernetes reports that pulling the container image failed", "warning"
    ),
    "ErrImageNeverPull": ReasonInfo(
        "Kubernetes reports that the image is not present on the node and the "
        "pull policy does not allow pulling it",
        "critical",
    ),
    "InvalidImageName": ReasonInfo(
        "Kubernetes reports that the container image reference is not valid",
        "critical",
    ),
    "ImageInspectError": ReasonInfo(
        "Kubernetes reports that the container image could not be inspected",
        "critical",
    ),
    "RegistryUnavailable": ReasonInfo(
        "Kubernetes reports that the image registry could not be reached",
        "warning",
    ),
    "CreateContainerConfigError": ReasonInfo(
        "Kubernetes reports that the container could not be created from its "
        "configuration",
        "critical",
    ),
    "CreateContainerError": ReasonInfo(
        "Kubernetes reports that creating the container failed", "critical"
    ),
    "RunContainerError": ReasonInfo(
        "Kubernetes reports that starting the container failed", "critical"
    ),
}

# Reasons that mean the container ran and then failed.
RUNTIME_FAILURE_REASONS = frozenset(
    {"Error", "OOMKilled", "ContainerCannotRun", "CrashLoopBackOff", "StartError"}
)

# Terminations that mean the container exited abnormally (not a clean exit).
FAILED_TERMINATION_REASONS = frozenset({"Error", "OOMKilled", "ContainerCannotRun"})

# Transitional states that are normal and are NOT failures.
TRANSITIONAL_REASONS = frozenset({"ContainerCreating", "PodInitializing"})

CRASH_LOOP = "CrashLoopBackOff"


@dataclass(frozen=True)
class ContainerAssessment:
    category: HealthCategory
    # The Kubernetes reason the classification rests on (a known catalog value
    # or None). Never free text.
    reason: str | None
    # True when there is evidence the container ran before (a restart or a
    # recorded previous termination); only then can logs exist.
    ran_before: bool
    severity: str | None  # None for healthy/unknown
    signals: tuple[str, ...] = ()

    @property
    def is_failure(self) -> bool:
        return self.category in {
            HealthCategory.RUNTIME_FAILURE,
            HealthCategory.PRE_START_FAILURE,
            HealthCategory.NOT_READY,
        }

    @property
    def has_restart_history(self) -> bool:
        """The container was restarted after a failed termination, whether or
        not it is healthy now."""
        return "restarted_before" in self.signals

    @property
    def meaning(self) -> str | None:
        info = PRE_START_REASONS.get(self.reason or "")
        return info.meaning if info else None


def _int(value: Any) -> int | None:
    return value if type(value) is int else None


def classify_container(fields: Mapping[str, Any]) -> ContainerAssessment:
    """Classify one container from its observed fields.

    Keys: ready, restart_count, state, reason, last_termination.exit_code,
    last_termination.reason. Missing keys are simply unobserved.
    """
    ready = fields.get("ready")
    state = fields.get("state")
    reason = fields.get("reason") if isinstance(fields.get("reason"), str) else None
    restarts = _int(fields.get("restart_count"))
    exit_code = _int(fields.get("last_termination.exit_code"))
    last_reason = fields.get("last_termination.reason")
    last_reason = last_reason if isinstance(last_reason, str) else None

    ran_before = (
        (restarts is not None and restarts >= 1)
        or exit_code is not None
        or last_reason is not None
    )

    # Pre-start: the container is waiting for a start that Kubernetes could not
    # complete. Readiness is necessarily False; it is not required as a signal.
    if reason in PRE_START_REASONS and state in (None, "waiting"):
        return ContainerAssessment(
            HealthCategory.PRE_START_FAILURE,
            reason,
            ran_before,
            PRE_START_REASONS[reason].severity,
            ("pre_start_failure",),
        )

    if ready is True and state == "running":
        # Ready NOW. Any recorded restart is history, reported separately from
        # current readiness (never folded into it, and never hidden by it). The
        # previous termination need not look like a failure: a container that
        # Kubernetes kills (for example after probe failures) can exit with
        # code 0 and reason "Completed". The restart count alone is a fact; it
        # is not a cause.
        if restarts is not None and restarts >= 1:
            return ContainerAssessment(
                HealthCategory.RESTARTED_RUNNING,
                last_reason,
                ran_before,
                "warning",
                ("restarted_before",),
            )

        return ContainerAssessment(HealthCategory.HEALTHY, None, ran_before, None)

    if state == "terminated" and reason == "Completed" and exit_code in (None, 0):
        return ContainerAssessment(HealthCategory.HEALTHY, None, ran_before, None)

    # Running now but not ready: that is the current fact, whatever the history.
    # Past restarts are recorded as history and do not turn a container that is
    # running into one that "failed at runtime".
    if ready is False and state == "running":
        history = restarts is not None and restarts >= 1

        return ContainerAssessment(
            HealthCategory.NOT_READY,
            None,
            True,
            "warning",
            ("running_not_ready", "restarted_before") if history else ("running_not_ready",),
        )

    # Runtime failure: not ready AND demonstrably ran and failed.
    if ready is False:
        signals: list[str] = []

        if restarts is not None and restarts >= 1:
            signals.append("restarted")

        if exit_code is not None and exit_code != 0:
            signals.append("nonzero_exit")

        if last_reason in RUNTIME_FAILURE_REASONS:
            signals.append("terminated_with_error")

        if reason in RUNTIME_FAILURE_REASONS:
            signals.append("failure_reason")

        if signals:
            looping = (
                state == "waiting"
                and reason == CRASH_LOOP
                and restarts is not None
                and restarts >= 1
            )
            return ContainerAssessment(
                HealthCategory.RUNTIME_FAILURE,
                reason if reason in RUNTIME_FAILURE_REASONS else last_reason,
                ran_before,
                "critical" if looping else "warning",
                tuple(signals),
            )

    # Running but not ready: it started, Kubernetes does not route to it, and
    # no failure reason or termination explains it. A concern, not a cause.
    if ready is False and state == "running":
        return ContainerAssessment(
            HealthCategory.NOT_READY,
            None,
            True,
            "warning",
            ("running_not_ready",),
        )

    return ContainerAssessment(HealthCategory.UNKNOWN, None, ran_before, None)
