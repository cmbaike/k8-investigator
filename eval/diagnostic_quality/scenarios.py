"""Controlled Kubernetes scenarios for the diagnostic-quality benchmark.

Each scenario is a fake cluster whose objects have the shape the real Kubernetes
API returns for that failure. The REAL handlers, observation extraction,
controller, coverage policy, evidence snapshot and report builder run on them
(see `tests.pod_scenarios`); only the Kubernetes client is faked. The exact
objects are therefore reproducible, and the same inputs can be given to any
model or prompt for a fair comparison.

Scenario ids, builders and the grading definitions are fixed (see `rubric`).
"""

from eval.diagnostic_quality.rubric import (
    FAILURE_NOW,
    HEALTHY_WORDS,
    IMAGE_PULL_WORDS,
    PROBE_WORDS,
    RAN_WORDS,
    START_FAILURE,
    Scenario,
    _re,
)
from tests.pod_scenarios import (
    NS,
    Cluster,
    container_spec,
    container_status,
    event,
    http_probe,
    ns,
    pod,
    volume,
)

PREEMPTION = (
    "preemption: 0/1 nodes are available: 1 Preemption is not helpful for scheduling."
)
MESSAGES = {
    "cpu": f"0/1 nodes are available: 1 Insufficient cpu. {PREEMPTION}",
    "memory": f"0/1 nodes are available: 1 Insufficient memory. {PREEMPTION}",
    "taint": (
        "0/1 nodes are available: 1 node(s) had untolerated taint {dedicated: gpu}. "
        + PREEMPTION
    ),
    "selector": (
        "0/1 nodes are available: 1 node(s) didn't match Pod's node affinity/selector. "
        + PREEMPTION
    ),
    "mixed": (
        "0/3 nodes are available: 1 Insufficient cpu, 1 Insufficient memory, "
        "1 node(s) had untolerated taint {node-role.kubernetes.io/control-plane: }. "
        "preemption: 0/3 nodes are available: 3 Preemption is not helpful for scheduling."
    ),
    "pvc": (
        '0/1 nodes are available: persistentvolumeclaim "data" not found. '
        + PREEMPTION
    ),
}
KUBELET = "kubelet"
SCHEDULER = "default-scheduler"
PULL_MESSAGE = 'Failed to pull image "registry.example.invalid/app:9.9": not found'
BACKOFF_MESSAGE = "Back-off restarting failed container app in pod {name}"
READINESS_MESSAGE = "Readiness probe failed: HTTP probe failed with statuscode: 503"
LIVENESS_MESSAGE = "Liveness probe failed: HTTP probe failed with statuscode: 404"
MOUNT_MESSAGE = (
    'MountVolume.SetUp failed for volume "cfg" : configmap "app-settings" not found'
)


def _container(*, memory_request=None, memory_limit=None, liveness=None, readiness=None):
    spec = container_spec(
        memory_request=memory_request, memory_limit=memory_limit, liveness=liveness
    )
    spec.readiness_probe = readiness

    return spec


def _unschedulable(name, kind, *, containers=None, node_selector=None, volumes=None):
    message = MESSAGES[kind]

    return Cluster(
        [
            pod(
                name,
                scheduler_message=message,
                containers=containers or [_container()],
                node_selector=node_selector,
                volumes=volumes,
            )
        ],
        {
            name: [
                event(
                    pod_name=name,
                    reason="FailedScheduling",
                    message=message,
                    component=SCHEDULER,
                )
            ]
        },
    )


def _running(name, *, ready, restarts=0, last_exit=None, last_reason=None, containers,
             events=()):
    return Cluster(
        [
            pod(
                name,
                phase="Running",
                scheduled=("True", None),
                statuses=[
                    container_status(
                        ready=ready,
                        restarts=restarts,
                        state="running",
                        reason=None,
                        last_exit=last_exit,
                        last_reason=last_reason,
                    )
                ],
                containers=containers,
                age=900,
            )
        ],
        {name: list(events)},
    )


def build_cluster(scenario_id: str) -> Cluster:
    if scenario_id == "sched_cpu":
        return _unschedulable("cpu-hog", "cpu")

    if scenario_id == "sched_memory":
        return _unschedulable(
            "mem-hog", "memory", containers=[_container(memory_request="900Gi")]
        )

    if scenario_id == "sched_taint":
        return _unschedulable("gpu-job", "taint")

    if scenario_id == "sched_selector":
        return _unschedulable("pinned", "selector", node_selector={"disktype": "ssd"})

    if scenario_id == "sched_multiple":
        return _unschedulable(
            "greedy", "mixed", containers=[_container(memory_request="900Gi")]
        )

    if scenario_id == "sched_missing_pvc":
        return _unschedulable(
            "needs-data", "pvc", volumes=[volume("data", "persistent_volume_claim")]
        )

    if scenario_id == "image_pull":
        name = "pull"

        return Cluster(
            [
                pod(
                    name,
                    scheduled=("True", None),
                    statuses=[
                        container_status(reason="ImagePullBackOff", restarts=0)
                    ],
                    age=600,
                )
            ],
            {
                name: [
                    event(
                        pod_name=name,
                        reason="Failed",
                        message=PULL_MESSAGE,
                        component=KUBELET,
                    )
                ]
            },
        )

    if scenario_id == "oom_killed":
        name = "oom"

        return Cluster(
            [
                pod(
                    name,
                    phase="Running",
                    scheduled=("True", None),
                    statuses=[
                        container_status(
                            ready=False,
                            restarts=4,
                            state="waiting",
                            reason="CrashLoopBackOff",
                            last_exit=137,
                            last_reason="OOMKilled",
                        )
                    ],
                    containers=[
                        _container(memory_request="64Mi", memory_limit="128Mi")
                    ],
                    age=900,
                )
            ],
            {
                name: [
                    event(
                        pod_name=name,
                        reason="BackOff",
                        message=BACKOFF_MESSAGE.format(name=name),
                        component=KUBELET,
                    )
                ]
            },
        )

    if scenario_id == "running_not_ready":
        name = "slow"

        return _running(
            name,
            ready=False,
            containers=[_container(readiness=http_probe("/ready", 8080))],
            events=[
                event(
                    pod_name=name,
                    reason="Unhealthy",
                    message=READINESS_MESSAGE,
                    component=KUBELET,
                )
            ],
        )

    if scenario_id == "liveness_failure":
        name = "live"

        return _running(
            name,
            ready=True,
            restarts=3,
            last_exit=137,
            last_reason="Error",
            containers=[_container(liveness=http_probe("/healthz", 8080))],
            events=[
                event(
                    pod_name=name,
                    reason="Unhealthy",
                    message=LIVENESS_MESSAGE,
                    component=KUBELET,
                ),
                event(
                    pod_name=name,
                    reason="Killing",
                    message="Container app failed liveness probe, will be restarted",
                    component=KUBELET,
                ),
            ],
        )

    if scenario_id == "mount_failure":
        name = "vol"

        return Cluster(
            [
                pod(
                    name,
                    scheduled=("True", None),
                    statuses=[container_status()],
                    volumes=[volume("cfg", "config_map")],
                    age=300,
                )
            ],
            {
                name: [
                    event(
                        pod_name=name,
                        reason="FailedMount",
                        message=MOUNT_MESSAGE,
                        component=KUBELET,
                    )
                ]
            },
        )

    if scenario_id == "crash_loop":
        name = "loop"

        return Cluster(
            [
                pod(
                    name,
                    phase="Running",
                    scheduled=("True", None),
                    statuses=[
                        container_status(
                            ready=False,
                            restarts=6,
                            state="waiting",
                            reason="CrashLoopBackOff",
                            last_exit=1,
                            last_reason="Error",
                        )
                    ],
                    containers=[_container()],
                    age=900,
                )
            ],
            {
                name: [
                    event(
                        pod_name=name,
                        reason="BackOff",
                        message=BACKOFF_MESSAGE.format(name=name),
                        component=KUBELET,
                    )
                ]
            },
        )

    if scenario_id == "restart_history":
        # Ready now; restarted twice before (clean exit); nothing else recorded.
        return _running(
            "steady",
            ready=True,
            restarts=2,
            last_exit=0,
            last_reason="Completed",
            containers=[_container()],
        )

    if scenario_id == "oom_recovered":
        # Ready now; one earlier OOMKilled termination (limit 128Mi).
        return _running(
            "recovered",
            ready=True,
            restarts=1,
            last_exit=137,
            last_reason="OOMKilled",
            containers=[_container(memory_request="64Mi", memory_limit="128Mi")],
        )

    if scenario_id == "healthy":
        return _running("fine", ready=True, containers=[_container()])

    raise KeyError(scenario_id)


_SCHEDULING = _re(r"\b(?:schedul\w*|pending|node|nodes|capacity|allocat\w*|requests?)\b")
_RESOURCE = _re(r"\b(?:cpu|memory|resources?|requests?|capacity|allocatable)\b")
_PLACEMENT_CHECK = _re(
    r"\b(?:taints?|tolerations?|requests?|allocatable|capacity|selector|labels?|"
    r"affinity|nodes?|persistentvolumeclaim|pvc|volume|storage|events?)\b"
)

# Contradictions with state that is established for pods that never ran.
_NEVER_RAN = (RAN_WORDS, IMAGE_PULL_WORDS, PROBE_WORDS)
_RUNNING = (START_FAILURE, IMAGE_PULL_WORDS)

_EVENTS = frozenset({"k8s.get_events"})
_CORE = frozenset({"k8s.get_pods", "k8s.describe_pod"})

SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "sched_cpu", "Unschedulable: insufficient CPU",
        "Pending; scheduler reports Insufficient cpu",
        _SCHEDULING, (_re(r"\bcpu\b"),), _NEVER_RAN,
        check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="cpu-hog",
    ),
    Scenario(
        "sched_memory", "Unschedulable: insufficient memory",
        "Pending; scheduler reports Insufficient memory",
        _SCHEDULING, (_re(r"\bmemory\b"),), _NEVER_RAN,
        check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="mem-hog",
    ),
    Scenario(
        "sched_taint", "Unschedulable: untolerated node taint",
        "Pending; scheduler reports an untolerated taint",
        _SCHEDULING, (_re(r"\b(?:taints?|tolerat\w*)\b"),), _NEVER_RAN,
        check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="gpu-job",
    ),
    Scenario(
        "sched_selector", "Unschedulable: node selector mismatch",
        "Pending; scheduler reports the node selector/affinity matched no node",
        _SCHEDULING, (_re(r"\b(?:selectors?|affinity|labels?)\b"),), _NEVER_RAN,
        check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="pinned",
    ),
    Scenario(
        "sched_multiple", "Unschedulable: several independent constraints",
        "Pending; scheduler reports insufficient CPU, insufficient memory and an untolerated taint",
        _SCHEDULING,
        (_re(r"\bcpu\b"), _re(r"\bmemory\b"), _re(r"\b(?:taints?|tolerat\w*)\b")),
        _NEVER_RAN, multiple_constraints=True,
        check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="greedy",
    ),
    Scenario(
        "sched_missing_pvc", "Unschedulable: missing PersistentVolumeClaim",
        "Pending; scheduler reports a PersistentVolumeClaim was not found",
        _SCHEDULING, (_re(r"\b(?:persistentvolumeclaim|pvc|claims?|volumes?|storage)\b"),),
        _NEVER_RAN, check_relevant=_PLACEMENT_CHECK, expected_tools=_CORE | _EVENTS,
        limit_as_basis_is_error=True, pod="needs-data",
    ),
    Scenario(
        "image_pull", "ImagePullBackOff",
        "Container waiting with ImagePullBackOff; kubelet reports a failed pull",
        _re(r"\b(?:image|registry|tag|pull\w*|credentials?|secret)\b"),
        (_re(r"\b(?:image|registry|tag|pull\w*|credentials?)\b"),),
        (RAN_WORDS, PROBE_WORDS),
        check_relevant=_re(r"\b(?:image|registry|tag|pull\w*|credentials?|secrets?|events?)\b"),
        expected_tools=_CORE | _EVENTS, pod="pull",
    ),
    Scenario(
        "oom_killed", "OOMKilled crash loop",
        "Container restarted after OOMKilled (exit 137); now CrashLoopBackOff",
        _re(r"\b(?:memory|oom\w*|limit\w*|exit|terminat\w*|killed|restart\w*)\b"),
        (_re(r"\b(?:memory|oom\w*|limits?)\b"),), (IMAGE_PULL_WORDS,),
        check_relevant=_re(r"\b(?:memory|limits?|requests?|usage|oom\w*|exit|terminat\w*|events?|logs?)\b"),
        expected_tools=_CORE | _EVENTS, pod="oom",
        undeclared_probes=("readiness", "liveness"),
    ),
    Scenario(
        "running_not_ready", "Running but not ready",
        "Container running, readiness false; kubelet reports readiness probe failures",
        _re(r"\b(?:readiness|ready|probe|traffic|initiali[sz]\w*|port|path)\b"),
        (_re(r"\b(?:readiness|ready|probe)\b"),),
        (*_RUNNING, HEALTHY_WORDS),
        check_relevant=_re(r"\b(?:readiness|probe|port|path|events?|ready)\b"),
        expected_tools=_CORE | _EVENTS, pod="slow",
        undeclared_probes=("liveness",),
    ),
    Scenario(
        "liveness_failure", "Liveness probe failures (restarted, ready now)",
        "Container restarted after failed termination; kubelet reports liveness failures",
        _re(r"\b(?:liveness|probe|restart\w*|killed|health\w*)\b"),
        (_re(r"\b(?:liveness|probe)\b"),), _RUNNING,
        check_relevant=_re(r"\b(?:liveness|probe|restarts?|events?|port|path)\b"),
        expected_tools=_CORE | _EVENTS, pod="live",
        undeclared_probes=("readiness",),
    ),
    Scenario(
        "mount_failure", "FailedMount",
        "Container creating; kubelet reports a volume mount failure",
        _re(r"\b(?:volumes?|mount\w*|configmaps?|secrets?|persistentvolumeclaims?|pvc)\b"),
        (_re(r"\b(?:volumes?|mount\w*|configmaps?|secrets?|persistentvolumeclaims?|pvc)\b"),),
        _NEVER_RAN,
        check_relevant=_re(r"\b(?:volumes?|mount\w*|configmaps?|secrets?|persistentvolumeclaims?|pvc|events?)\b"),
        expected_tools=_CORE | _EVENTS, pod="vol",
    ),
    Scenario(
        "crash_loop", "CrashLoopBackOff (non-OOM)",
        "Container restarted after an error exit (exit 1); now CrashLoopBackOff",
        _re(r"\b(?:crash\w*|exit\w*|terminat\w*|restart\w*|start\w*|command|entrypoint|"
            r"configuration|config|dependency|dependencies|application)\b"),
        (_re(r"\b(?:crash\w*|exit\w*|terminat\w*|restart\w*|start\w*|error)\b"),),
        (IMAGE_PULL_WORDS,),
        check_relevant=_re(r"\b(?:logs?|exit|terminat\w*|restarts?|events?|command|entrypoint|configuration|config)\b"),
        expected_tools=_CORE | _EVENTS, pod="loop",
        undeclared_probes=("readiness", "liveness"),
    ),
    Scenario(
        "healthy", "Healthy workload",
        "Running and ready, no restarts, no events",
        _re(r"\b(?:healthy|ready|running)\b"), (), (START_FAILURE, IMAGE_PULL_WORDS),
        healthy=True, expected_tools=_CORE, pod="fine",
        undeclared_probes=("readiness", "liveness"),
    ),
)

# Added by the correctness-gaps increment (historical restarts of a container
# that is ready now). Kept apart so the original thirteen stay comparable.
EXTRA_SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        "restart_history", "Restarted before, ready now (clean exit)",
        "Running and ready; restart count 2; last termination exit 0 (Completed)",
        _re(r"\b(?:restart\w*|terminat\w*|exit\w*|history|previous\w*|earlier)\b"),
        (_re(r"\b(?:restart\w*|terminat\w*|exit\w*)\b"),),
        (*_RUNNING, FAILURE_NOW),
        check_relevant=_re(r"\b(?:restarts?|terminat\w*|events?|logs?|previous\w*|exit)\b"),
        expected_tools=_CORE | _EVENTS, pod="steady",
        undeclared_probes=("readiness", "liveness"),
    ),
    Scenario(
        "oom_recovered", "OOMKilled before, ready now",
        "Running and ready; restart count 1; last termination OOMKilled (exit 137)",
        _re(r"\b(?:memory|oom\w*|limits?|restart\w*|terminat\w*|killed|exit\w*)\b"),
        (_re(r"\b(?:memory|oom\w*|limits?)\b"),),
        (*_RUNNING, FAILURE_NOW),
        check_relevant=_re(r"\b(?:memory|limits?|requests?|usage|oom\w*|terminat\w*|restarts?|events?|logs?)\b"),
        expected_tools=_CORE, pod="recovered",
        undeclared_probes=("readiness", "liveness"),
    ),
)

ALL_SCENARIOS: tuple[Scenario, ...] = (*SCENARIOS, *EXTRA_SCENARIOS)
BY_ID = {s.id: s for s in ALL_SCENARIOS}
