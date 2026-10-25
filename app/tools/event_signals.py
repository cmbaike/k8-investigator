"""Fixed-vocabulary classification of Kubernetes scheduler/kubelet messages.

Event and condition MESSAGES are untrusted free text. They are never stored,
displayed or cited. What this module produces from one is a small set of
fixed-vocabulary signals, derived by anchored patterns that match the wording
Kubernetes' own components emit (scheduler, kubelet, attach/detach
controller). A signal therefore says "Kubernetes' message was classified as X",
never "X is the cause": it narrows what Kubernetes reported, and the underlying
cause stays a hypothesis.

Bounds: the message is cut to MAX_MESSAGE_CHARS before matching (so matching is
linear and bounded), at most MAX_SIGNALS signals are returned per message, a
signal is only meaningful for the event reason it is registered under, and
signals are only accepted from the Kubernetes component that emits that reason.
Volume names are never taken from the message alone: the caller must confirm a
name against the pod's own declared volumes (see `volume_names`).
"""

import re
from collections.abc import Iterable

MAX_MESSAGE_CHARS = 2_048
MAX_SIGNALS = 4
MAX_VOLUME_NAMES = 4

SCHEDULING_REASON = "FailedScheduling"
MOUNT_REASONS = frozenset({"FailedMount", "FailedAttachVolume"})
PROBE_REASON = "Unhealthy"
KILLING_REASON = "Killing"

SCHEDULING_CONSTRAINTS: dict[str, re.Pattern[str]] = {
    "insufficient_cpu": re.compile(r"\binsufficient cpu\b", re.IGNORECASE),
    "insufficient_memory": re.compile(r"\binsufficient memory\b", re.IGNORECASE),
    "insufficient_ephemeral_storage": re.compile(
        r"\binsufficient ephemeral-storage\b", re.IGNORECASE
    ),
    "too_many_pods": re.compile(r"\btoo many pods\b", re.IGNORECASE),
    "untolerated_taint": re.compile(r"\buntolerated taint\b", re.IGNORECASE),
    "node_selector_mismatch": re.compile(
        r"didn't match pod's node (?:affinity|selector)", re.IGNORECASE
    ),
    "pod_affinity_mismatch": re.compile(
        r"didn't match pod (?:anti-)?affinity|topology spread constraints",
        re.IGNORECASE,
    ),
    "node_unschedulable": re.compile(
        r"\bnode\(s\) (?:were|was) unschedulable\b", re.IGNORECASE
    ),
    "unbound_volume_claim": re.compile(
        r"unbound immediate persistentvolumeclaims"
        r"|persistentvolumeclaim \"[^\"]{1,253}\" not found"
        r"|didn't find available persistent volumes to bind",
        re.IGNORECASE,
    ),
    "volume_node_conflict": re.compile(
        r"volume node affinity conflict", re.IGNORECASE
    ),
}

MOUNT_PROBLEMS: dict[str, re.Pattern[str]] = {
    "config_map_not_found": re.compile(r"\bconfigmap \"[^\"]{1,253}\" not found", re.IGNORECASE),
    "secret_not_found": re.compile(r"\bsecret \"[^\"]{1,253}\" not found", re.IGNORECASE),
    "claim_not_found": re.compile(
        r"persistentvolumeclaim \"[^\"]{1,253}\" not found", re.IGNORECASE
    ),
    "mount_timeout": re.compile(r"timed out waiting for the condition", re.IGNORECASE),
    "attach_failed": re.compile(r"\bAttachVolume\.Attach failed\b"),
    "mount_device_failed": re.compile(r"\bMountVolume\.MountDevice failed\b"),
    "mount_setup_failed": re.compile(r"\bMountVolume\.SetUp failed\b"),
}

# Anchored at the start: kubelet formats "<Kind> probe failed: <detail>".
PROBE_FAILURES: dict[str, re.Pattern[str]] = {
    "liveness_probe_failed": re.compile(r"^\s*Liveness probe failed\b"),
    "readiness_probe_failed": re.compile(r"^\s*Readiness probe failed\b"),
    "startup_probe_failed": re.compile(r"^\s*Startup probe failed\b"),
}

# Kubelet's "Killing" event: "Container <name> failed <kind> probe, will be
# restarted". Only the probe kind is read; the container name is not.
KILLING_RESTARTS: dict[str, re.Pattern[str]] = {
    "liveness_restart": re.compile(r"\bfailed liveness probe, will be restarted\b"),
    "startup_restart": re.compile(r"\bfailed startup probe, will be restarted\b"),
}

# Kubelet image-pull events. Reason "Failed" and "BackOff" are used for several
# different things, so the reason alone says nothing about image pulls: only
# these classified messages do. "Back-off restarting failed container" is the
# crash-loop back-off, which is NOT an image-pull signal.
IMAGE_FAILURES: dict[str, re.Pattern[str]] = {
    "image_pull_failed": re.compile(
        r"^\s*Failed to pull image\b|^\s*Error: (?:ErrImagePull|ImagePullBackOff)\b"
    ),
}
BACKOFFS: dict[str, re.Pattern[str]] = {
    "image_pull_backoff": re.compile(r"^\s*Back-off pulling image\b"),
    "container_restart_backoff": re.compile(
        r"^\s*Back-off restarting failed container\b"
    ),
}

IMAGE_PULL_SIGNALS = frozenset({"image_pull_failed", "image_pull_backoff"})
# Classified messages of the same reasons that are positively NOT about pulling.
NOT_PULL_SIGNALS = frozenset({"container_restart_backoff"})

_SIGNALS_BY_REASON: dict[str, dict[str, re.Pattern[str]]] = {
    "Failed": IMAGE_FAILURES,
    "BackOff": BACKOFFS,
    SCHEDULING_REASON: SCHEDULING_CONSTRAINTS,
    "FailedMount": MOUNT_PROBLEMS,
    "FailedAttachVolume": MOUNT_PROBLEMS,
    PROBE_REASON: PROBE_FAILURES,
    KILLING_REASON: KILLING_RESTARTS,
}

# The components that emit each reason. A matching reason from any other source
# is still counted (reason/type/count), but never classified.
_SCHEDULER = re.compile(r"^(?:[a-z0-9][-a-z0-9.]{0,50}-)?scheduler$")
_SOURCES: dict[str, re.Pattern[str]] = {
    SCHEDULING_REASON: _SCHEDULER,
    "FailedMount": re.compile(r"^kubelet$"),
    "FailedAttachVolume": re.compile(r"^attachdetach-controller$|^kubelet$"),
    PROBE_REASON: re.compile(r"^kubelet$"),
    KILLING_REASON: re.compile(r"^kubelet$"),
    "Failed": re.compile(r"^kubelet$"),
    "BackOff": re.compile(r"^kubelet$"),
}

ALL_SIGNALS: frozenset[str] = frozenset(
    name for table in _SIGNALS_BY_REASON.values() for name in table
)

_VOLUME_NAME = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
VOLUME_NAME = re.compile(rf"^{_VOLUME_NAME}$")
_FOR_VOLUME = re.compile(rf"\bfor volume \"({_VOLUME_NAME})\"")
_UNMOUNTED = re.compile(r"\bunmounted volumes=\[([^\]]{1,512})\]")

SIGNAL_NAME = re.compile(r"^[a-z][a-z_]{2,40}$")


def _bounded(message: object) -> str | None:
    if not isinstance(message, str):
        return None

    return message[:MAX_MESSAGE_CHARS]


def signals_allowed(reason: str, signal: str) -> bool:
    """True when `signal` is in the fixed vocabulary registered for `reason`."""
    return signal in _SIGNALS_BY_REASON.get(reason, {})


def source_allowed(reason: str, source: object) -> bool:
    """True when `source` is the Kubernetes component that emits `reason`."""
    pattern = _SOURCES.get(reason)

    return bool(
        pattern is not None
        and isinstance(source, str)
        and len(source) <= 63
        and pattern.fullmatch(source)
    )


def classify_scheduling_message(message: object) -> tuple[str, ...]:
    """Constraint signals in a scheduler status message (event or condition)."""
    text = _bounded(message)

    if text is None:
        return ()

    return tuple(
        name for name, pattern in SCHEDULING_CONSTRAINTS.items() if pattern.search(text)
    )[:MAX_SIGNALS]


def classify_event(reason: object, message: object, source: object) -> tuple[str, ...]:
    """Fixed-vocabulary signals for one event, or () when it is not a
    recognised message from the component that emits its reason."""
    if not isinstance(reason, str) or not source_allowed(reason, source):
        return ()

    table = _SIGNALS_BY_REASON.get(reason)
    text = _bounded(message)

    if table is None or text is None:
        return ()

    return tuple(name for name, pattern in table.items() if pattern.search(text))[
        :MAX_SIGNALS
    ]


def volume_names(message: object, declared: Iterable[str]) -> tuple[str, ...]:
    """Volume names a mount message mentions that the pod ACTUALLY declares.

    A name is taken from the message only to be confirmed against the pod's own
    declared volumes: a name the spec does not declare is dropped, so a
    message can never introduce an identifier of its own.
    """
    text = _bounded(message)

    if text is None:
        return ()

    known = {name for name in declared if isinstance(name, str) and VOLUME_NAME.fullmatch(name)}
    mentioned: list[str] = []

    for match in _FOR_VOLUME.finditer(text):
        mentioned.append(match.group(1))

    for match in _UNMOUNTED.finditer(text):
        mentioned.extend(part.strip() for part in match.group(1).split(","))

    found = dict.fromkeys(name for name in mentioned if name in known)

    return tuple(found)[:MAX_VOLUME_NAMES]
