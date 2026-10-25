"""Deterministic evidence-coverage policy for investigations.

The proposal model decides what to look at, but it must not be the only thing
guaranteeing that a failing container's logs and configuration are examined:
the same input can make it `finish` early. This module adds a narrow,
workload-agnostic follow-up rule on top of the unchanged execution boundary:

  TRIGGER (general Kubernetes failure observations, no application names):
    app.tools.container_health classifies each described container.
      * RUNTIME failure: not ready AND demonstrably ran and failed (restarted,
        non-zero exit, error termination, failure reason such as OOMKilled or
        CrashLoopBackOff).
      * PRE-START failure: Kubernetes could not start it (ImagePullBackOff,
        ErrImagePull, CreateContainerConfigError, ...). It need not have run.
      * NOT READY: the container runs but Kubernetes reports it not ready
        (even with zero restarts): logs, pod-bound events and configuration.
    A container that is merely being created (ContainerCreating) or is healthy
    triggers nothing.

  TARGET: in a targeted investigation (the question names a workload) every
    call here is confined to the pods of the resolved target. See
    app.tools.workload_target.

  ACTION: when the proposal model finishes (or when the remaining budget is
    needed to guarantee it), propose, each at most once per target,
      * k8s.get_logs for a container that ran before (runtime failures, or a
        pre-start failure with a restart or previous termination). A
        container that never started has no logs: none are requested;
      * k8s.get_events bound to the failing pod, for pre-start failures and
        running-but-not-ready containers (Kubernetes' own record of failed
        pulls, create attempts and probes); and
      * k8s.describe_workload_config for its pod.

Follow-ups are ordinary proposals. They go through
`execute_investigation_step`, so namespace scoping, argument grounding from
trusted observations, read-only policy, step budget and audit are unchanged.

A second, earlier rule guarantees the evidence those triggers depend on exists
at all. Container health (phase, readiness, restarts, last termination) comes
only from k8s.describe_pod, and nothing else obliges the model to call it:

  HEALTH INSPECTION: in an application-bound workload investigation, every
    in-scope pod that get_pods discovered is inspected with k8s.describe_pod
    when no inspection of it was attempted yet. At most
    `health_inspection_allowance(max_steps)` inspections are made, so the step
    budget keeps room for the model and for the log/config follow-ups. Pods are
    ordered deterministically (unhealthy signals first, then name) and the
    report discloses every discovered pod that was not inspected.

This module never executes anything and never authorizes anything.
"""

import re
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from app.tools.investigation import InvestigationContext
from app.tools.investigation_authority import InvestigationKind
from app.tools.investigation_controller import (
    InvestigationStep,
    InvestigationStopReason,
    is_credential_failure,
)
from app.tools.orchestrator import execute_investigation_step
from app.tools.container_health import HealthCategory, classify_container
from app.tools.pod_health import needs_events
from app.tools.models import ToolCall, ToolExecutionStatus
from app.tools.workload_target import call_outside_target
from app.tools.workload_config import WORKLOAD_CONFIG_TOOL

LOGS_TOOL = "k8s.get_logs"
DESCRIBE_POD_TOOL = "k8s.describe_pod"
EVENTS_TOOL = "k8s.get_events"

# Evidence-gathering tools whose FAILURE must not fail the whole investigation:
# the deterministic report is still valuable, and the gap is disclosed.
# A failed health inspection of one pod likewise must not discard everything
# gathered about the others; the pod stays "not inspected" in the report and
# is never reported healthy. (Credential failures are always fatal: see the
# controller.)
SUPPLEMENTARY_TOOLS = frozenset(
    {LOGS_TOOL, WORKLOAD_CONFIG_TOOL, DESCRIBE_POD_TOOL, EVENTS_TOOL}
)

MAX_FOLLOW_UP_CONTAINERS = 3

POD_DISCOVERY_TOOL = "k8s.get_pods"
POD_DISCOVERY_FIELD = "pods[].name"

# Hard ceiling on automatic health inspections that spend the analysis step
# budget. A namespace-wide run does not use this for basic health: that pass
# has its own cap below and does not consume analysis steps. The live
# "3 of 10" result was this ceiling combined with the default 6-step budget
# (allowance = min(4, max_steps // 2) = 3).
MAX_HEALTH_INSPECTIONS = 4
# Basic health descriptions in a namespace-wide investigation. One list page
# can name more pods than this; the rest stay unknown, not healthy.
MAX_NAMESPACE_HEALTH_INSPECTIONS = 20
# Wall-clock bound for that pass. A slow API stops the pass; remaining pods
# stay unknown.
HEALTH_DISCOVERY_DEADLINE_SECONDS = 12.0

_POD_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")
_UNHEALTHY_PHASES = frozenset({"Pending", "Failed", "Unknown"})

_FIELD_PREFIX = "containers["


@dataclass(frozen=True)
class FailingContainer:
    namespace: str
    pod: str
    container: str
    signals: tuple[str, ...]
    # HealthCategory value: runtime_failure | pre_start_failure | running_not_ready
    category: str = HealthCategory.RUNTIME_FAILURE.value
    reason: str | None = None
    # Evidence the container ran before: only then can logs exist.
    ran_before: bool = True
    # The spec declares a liveness probe for this container (None: unknown).
    liveness_declared: bool | None = None

    @property
    def pre_start(self) -> bool:
        return self.category == HealthCategory.PRE_START_FAILURE.value

    @property
    def wants_events(self) -> bool:
        """Kubernetes' own event record is relevant for a container that
        could not start, one that runs but is not ready, and one that failed
        at runtime while declaring a liveness probe (probe failures and the
        kills that follow them are recorded as events)."""
        return (
            self.pre_start
            or self.category == "running_not_ready"
            # A container that failed at runtime AND declares a liveness probe:
            # the probe's failures, and the restarts they trigger, are recorded
            # as events. Without a declared probe there is nothing to look for.
            or (
                self.category == HealthCategory.RUNTIME_FAILURE.value
                and self.liveness_declared is True
            )
        )

    @property
    def may_have_logs(self) -> bool:
        return not self.pre_start or self.ran_before


def _split_field(field: str) -> tuple[str, str] | None:
    """`containers[name].attr` -> (name, attr). Env fields etc. are ignored."""
    if not field.startswith(_FIELD_PREFIX):
        return None

    end = field.find("].")

    # `containers[].name` (empty index) is the container listing, not a value.
    if end <= len(_FIELD_PREFIX):
        return None

    return field[len(_FIELD_PREFIX) : end], field[end + 2 :]


def failing_containers(observations: Iterable[Any]) -> list[FailingContainer]:
    """Containers Kubernetes reports as failing, runtime or pre-start.

    Accepts trusted observations or report evidence (anything exposing tool,
    field, value, namespace, pod). Latest value wins per field. Classification
    is app.tools.container_health: deterministic, from structured state only.
    """
    latest: dict[tuple[str, str, str, str], Any] = {}

    for item in observations:
        if getattr(item, "tool", None) != DESCRIBE_POD_TOOL:
            continue

        namespace, pod = getattr(item, "namespace", None), getattr(item, "pod", None)
        split = _split_field(getattr(item, "field", ""))

        if not namespace or not pod or split is None:
            continue

        container, attribute = split
        latest[(namespace, pod, container, attribute)] = item.value

    containers = sorted({key[:3] for key in latest})
    result: list[FailingContainer] = []

    for namespace, pod, container in containers:
        fields = {
            attribute: value
            for (n, p, c, attribute), value in latest.items()
            if (n, p, c) == (namespace, pod, container)
        }
        assessment = classify_container(fields)

        if assessment.is_failure:
            result.append(
                FailingContainer(
                    namespace,
                    pod,
                    container,
                    assessment.signals,
                    assessment.category.value,
                    assessment.reason,
                    assessment.ran_before,
                    (
                        fields.get("liveness_probe.declared")
                        if type(fields.get("liveness_probe.declared")) is bool
                        else None
                    ),
                )
            )

    return result


def pods_wanting_events(observations: Iterable[Any]) -> list[tuple[str, str]]:
    """Pods whose Kubernetes events are the record that explains them, though
    no container of theirs is "failing":

      * a pod stuck before its containers run: Pending and unschedulable, or
        Pending with a container in ContainerCreating (scheduler and kubelet
        events say where it is stuck);
      * a container running and ready now that was restarted after a failed
        termination (probe and kill events record why Kubernetes restarted it).

    Structural, from describe_pod observations only; it asserts no cause.
    """
    latest: dict[tuple[str, str, str], Any] = {}

    for item in observations:
        if getattr(item, "tool", None) != DESCRIBE_POD_TOOL:
            continue

        namespace, pod = getattr(item, "namespace", None), getattr(item, "pod", None)

        if namespace and pod:
            latest[(namespace, pod, getattr(item, "field", ""))] = item.value

    pods = sorted({key[:2] for key in latest})
    wanted: list[tuple[str, str]] = []

    for namespace, pod in pods:
        def value(field: str) -> Any:
            return latest.get((namespace, pod, field))

        states, containers = [], {}

        for (n, p, field), v in latest.items():
            split = _split_field(field) if (n, p) == (namespace, pod) else None

            if split is not None:
                containers.setdefault(split[0], {})[split[1]] = v

        for fields in containers.values():
            states.append((fields.get("state"), fields.get("reason")))

        scheduled = (value("conditions[PodScheduled].status"), value("conditions[PodScheduled].reason"))
        stuck = needs_events(
            phase=value("pod.phase"),
            scheduled=scheduled if scheduled[0] is not None else None,
            container_states=states,
            age_seconds=value("pod.age_seconds"),
        )
        restarted = any(
            classify_container(fields).category is HealthCategory.RESTARTED_RUNNING
            and fields.get("last_termination.reason") != "OOMKilled"
            for fields in containers.values()
        )

        if stuck or restarted:
            wanted.append((namespace, pod))

    return wanted


def _attempted(steps: Sequence[InvestigationStep], tool: str) -> list[dict[str, Any]]:
    return [
        dict(step.proposed_call.arguments)
        for step in steps
        if step.proposed_call.name == tool
    ]


def pending_follow_ups(
    context: InvestigationContext, steps: Sequence[InvestigationStep]
) -> list[ToolCall]:
    """Follow-up proposals still owed, in priority order (logs, events, config).

    Attempts are read from the controller's own step list, so a follow-up that
    FAILED is never proposed again.
    """
    targets = _ranked_failures(context.observations)
    namespace = context.require_authorized_namespace()
    log_attempts = _attempted(steps, LOGS_TOOL)
    config_attempts = _attempted(steps, WORKLOAD_CONFIG_TOOL)
    event_attempts = _attempted(steps, EVENTS_TOOL)
    failing_per_pod: dict[str, int] = {}

    for target in targets:
        failing_per_pod[target.pod] = failing_per_pod.get(target.pod, 0) + 1

    pending_logs: list[ToolCall] = []
    pending_events: list[ToolCall] = []
    pending_config: list[ToolCall] = []
    event_pods: set[str] = set()
    config_pods: set[str] = set()

    for target in targets:
        if target.namespace != namespace:
            continue

        def covers_logs(arguments: dict[str, Any]) -> bool:
            if arguments.get("pod") != target.pod:
                return False

            container = arguments.get("container")

            # A call without a container reads the default container, which
            # is only unambiguous when one container is failing in that pod.
            return container == target.container or (
                container is None and failing_per_pod[target.pod] == 1
            )

        # A container that never started has no logs to read.
        if target.may_have_logs and not any(covers_logs(a) for a in log_attempts):
            pending_logs.append(
                ToolCall(
                    name=LOGS_TOOL,
                    arguments={
                        "namespace": namespace,
                        "pod": target.pod,
                        "container": target.container,
                    },
                )
            )

        if target.wants_events and target.pod not in event_pods:
            event_pods.add(target.pod)

            if not any(a.get("pod") == target.pod for a in event_attempts):
                pending_events.append(
                    ToolCall(
                        name=EVENTS_TOOL,
                        arguments={"namespace": namespace, "pod": target.pod},
                    )
                )

        if target.pod not in config_pods:
            config_pods.add(target.pod)

            if not any(a.get("pod") == target.pod for a in config_attempts):
                pending_config.append(
                    ToolCall(
                        name=WORKLOAD_CONFIG_TOOL,
                        arguments={"namespace": namespace, "pod": target.pod},
                    )
                )

    # Pods that are stuck before their containers run, or restarted and now
    # running, have no failing container but need their events.
    for namespace_, pod_ in pods_wanting_events(context.observations)[
        :MAX_FOLLOW_UP_CONTAINERS
    ]:
        if (
            namespace_ == namespace
            and pod_ not in event_pods
            and not any(a.get("pod") == pod_ for a in event_attempts)
        ):
            event_pods.add(pod_)
            pending_events.append(
                ToolCall(
                    name=EVENTS_TOOL,
                    arguments={"namespace": namespace, "pod": pod_},
                )
            )

    return [*pending_logs, *pending_events, *pending_config]


# --------------------------------------------------------------- health coverage


def _ranked_failures(observations: Iterable[Any]) -> list[FailingContainer]:
    """Failing containers in operational severity order, then name.

    Pre-start and runtime failures outrank a container that is running but
    not ready. The analysis step budget still follows at most
    MAX_FOLLOW_UP_CONTAINERS of them. A restarted container that is ready now
    is not in this list: that history is not a current failure.
    """
    rank = {"pre_start_failure": 0, "runtime_failure": 0, "running_not_ready": 1}

    return sorted(
        failing_containers(observations),
        key=lambda item: (
            rank.get(item.category, 9),
            item.namespace,
            item.pod,
            item.container,
        ),
    )[:MAX_FOLLOW_UP_CONTAINERS]


def health_inspection_allowance(max_steps: int) -> int:
    """Automatic describe_pod calls permitted for a step budget.

    At most half the budget (and never more than MAX_HEALTH_INSPECTIONS, never
    fewer than one), so discovery, the model's own choices and the log/config
    follow-ups for failing containers keep room.
    """
    return min(MAX_HEALTH_INSPECTIONS, max(1, max_steps // 2))


def discovered_pods(context: InvestigationContext) -> list[str]:
    """In-scope pod names minted from successful get_pods executions.

    Only trusted observations count (never model text), only the authorized
    namespace, and only names that are valid Kubernetes pod names.
    """
    namespace = context.require_authorized_namespace()
    names: dict[str, None] = {}

    for observation in context.observations:
        if (
            observation.tool == POD_DISCOVERY_TOOL
            and observation.field == POD_DISCOVERY_FIELD
            and observation.namespace == namespace
            and isinstance(observation.value, str)
            and _POD_NAME.fullmatch(observation.value)
        ):
            names[observation.value] = None

    # A targeted investigation inspects only its resolved workload's pods.
    in_scope = getattr(context, "in_target_scope", lambda _pod: True)

    return [name for name in names if in_scope(name)]


def _discovery_hints(steps: Sequence[InvestigationStep], namespace: str) -> dict[str, dict]:
    """Advisory per-pod hints from get_pods results, used ONLY for ordering.

    Never evidence, never authority: a pod must still be a trusted observation
    to be inspected, and a wrong or missing hint only changes the order.
    """
    hints: dict[str, dict] = {}

    for step in steps:
        if (
            step.proposed_call.name != POD_DISCOVERY_TOOL
            or step.result.status != ToolExecutionStatus.SUCCESS
        ):
            continue

        output = step.result.output

        if not isinstance(output, dict) or output.get("namespace") != namespace:
            continue

        for pod in output.get("pods") or []:
            if isinstance(pod, dict) and isinstance(pod.get("name"), str):
                hints[pod["name"]] = pod

    return hints


def _priority(name: str, hint: dict | None) -> tuple[int, int, str]:
    """Deterministic inspection order. Groups, most urgent first:

      0  not ready, or Pending/Failed/Unknown   (acute: not serving or stuck)
      1  ready but has restarted                 (recovered or intermittent)
      2  no unhealthy signal, or no hint         (health unknown/normal)
      3  Succeeded                               (completed; least urgent)

    Within a group: most restarts first, then name. The hints are advisory
    list-time counts; a missing or wrong hint can only change the order.
    """
    hint = hint or {}
    phase = hint.get("phase")
    total, ready = hint.get("containers_total"), hint.get("containers_ready")
    restarts = hint.get("restart_count")
    restarts = restarts if type(restarts) is int and restarts >= 0 else 0

    not_ready = (
        type(total) is int and type(ready) is int and total > 0 and ready < total
    )

    if phase == "Succeeded":
        group = 3
    elif phase in _UNHEALTHY_PHASES or not_ready:
        group = 0
    elif restarts > 0:
        group = 1
    else:
        group = 2

    return (group, -restarts, name)


def _inspection_blocked(steps: Sequence[InvestigationStep]) -> bool:
    """Stop inspecting once Kubernetes has refused this identity.

    A forbidden/unauthorized describe will not succeed for another pod, and
    retrying would only spend budget. (401 is fatal for the whole run in the
    controller; this also covers 403.)
    """
    return any(
        step.proposed_call.name == DESCRIBE_POD_TOOL
        and step.result.status != ToolExecutionStatus.SUCCESS
        and (step.result.error or "").startswith(
            ("ForbiddenException", "UnauthorizedException")
        )
        for step in steps
    )


def pending_health_inspections(
    context: InvestigationContext, steps: Sequence[InvestigationStep]
) -> list[ToolCall]:
    """describe_pod proposals still owed, in priority order.

    Applies only to application-bound workload investigations: contexts that
    keep text-derived authority may have been narrowed to a single operation
    by the user and are never widened here. Each pod is inspected at most
    once per investigation, whether the model or this policy asked first, and
    a FAILED inspection is never retried.
    """
    if context.investigation_kind != InvestigationKind.K8S_WORKLOAD:
        return []

    # Namespace-wide basic health is the discovery pass, not this step budget.
    if getattr(context, "namespace_health_discovery", False):
        return []

    if _inspection_blocked(steps):
        return []

    namespace = context.require_authorized_namespace()
    attempted = {
        a.get("pod")
        for a in _attempted(steps, DESCRIBE_POD_TOOL)
        if a.get("namespace") in (None, namespace)
    }
    attempted |= {
        o.pod
        for o in context.observations
        if o.tool == DESCRIBE_POD_TOOL and o.namespace == namespace
    }
    room = health_inspection_allowance(context.max_steps) - len(attempted)

    if room <= 0:
        return []

    hints = _discovery_hints(steps, namespace)
    owed = sorted(
        (name for name in discovered_pods(context) if name not in attempted),
        key=lambda name: _priority(name, hints.get(name)),
    )

    return [
        ToolCall(
            name=DESCRIBE_POD_TOOL,
            arguments={"namespace": namespace, "pod": name},
        )
        for name in owed[:room]
    ]


def discover_namespace_health(
    context: InvestigationContext,
    *,
    audit,
    executor,
    request_id_factory: Callable[[], str],
    clock: Callable[[], float] = time.monotonic,
) -> tuple[list[InvestigationStep], InvestigationStopReason | None]:
    """List the namespace and describe pods through the audited tool boundary.

    Does not ask the model which pods to inspect, and does not consume the
    analysis step budget. Stops at the inspection cap, the deadline, a
    forbidden response, or a credential failure. A failed inspection of one
    pod does not stop the others and is not recorded as healthy.
    """
    steps: list[InvestigationStep] = []
    started = clock()
    issued = 0

    def run(call: ToolCall) -> InvestigationStep:
        nonlocal issued
        issued += 1
        request_id = f"{request_id_factory()}-health-{issued}"
        result = execute_investigation_step(
            context=context,
            request_id=request_id,
            proposed_call=call,
            audit=audit,
            executor=executor,
            consume_step=False,
        )
        step = InvestigationStep(request_id, call, result)
        steps.append(step)
        return step

    namespace = context.require_authorized_namespace()
    listed = run(
        ToolCall(name=POD_DISCOVERY_TOOL, arguments={"namespace": namespace})
    )

    if listed.result.status != ToolExecutionStatus.SUCCESS or is_credential_failure(
        listed.result
    ):
        return steps, InvestigationStopReason.TOOL_FAILED

    hints = _discovery_hints(steps, namespace)
    owed = sorted(
        discovered_pods(context),
        key=lambda name: _priority(name, hints.get(name)),
    )
    described = 0

    for name in owed:
        if described >= MAX_NAMESPACE_HEALTH_INSPECTIONS:
            break

        if clock() - started >= HEALTH_DISCOVERY_DEADLINE_SECONDS:
            break

        if _inspection_blocked(steps):
            break

        step = run(
            ToolCall(
                name=DESCRIBE_POD_TOOL,
                arguments={"namespace": namespace, "pod": name},
            )
        )
        described += 1

        if is_credential_failure(step.result):
            return steps, InvestigationStopReason.TOOL_FAILED

    return steps, None


class CoverageProvider:
    """Wraps a proposal provider with the deterministic follow-up rule.

    Satisfies the controller's ProposalProvider protocol. It only ever returns
    a proposal (a ToolCall) or None: the controller still executes through
    `execute_investigation_step`.
    """

    def __init__(
        self,
        inner: Callable[
            [InvestigationContext, tuple[InvestigationStep, ...]], ToolCall | None
        ],
    ) -> None:
        self._inner = inner

    def __call__(
        self,
        context: InvestigationContext,
        steps: tuple[InvestigationStep, ...],
    ) -> ToolCall | None:
        # Baseline health evidence first: without describe_pod there is no
        # phase, readiness, restart or termination evidence for any pod, and
        # the model is not obliged to ask for it. Ordinary proposal: the
        # controller still authorizes, executes and audits it.
        # A targeted question needs the namespace listing first: it is how the
        # target is resolved (from verified owner references). The model is
        # not obliged to ask for it.
        if context.target is not None and not any(
            step.proposed_call.name == POD_DISCOVERY_TOOL for step in steps
        ):
            return ToolCall(
                name=POD_DISCOVERY_TOOL,
                arguments={"namespace": context.require_authorized_namespace()},
            )

        health = pending_health_inspections(context, steps)

        if health:
            return health[0]

        pending = pending_follow_ups(context, steps)
        remaining = context.max_steps - context.completed_steps

        # Reserve budget: if every remaining step is owed to a follow-up,
        # the model cannot spend them elsewhere.
        if pending and remaining <= len(pending):
            return pending[0]

        # A model that has already had MAX_REJECTED_PROPOSALS proposals refused
        # is not consulted again: only the deterministic follow-ups remain.
        proposed = (
            None if context.rejection_limit_reached else self._inner(context, steps)
        )

        # The model may not widen a targeted investigation to another
        # workload. The execution boundary would reject such a call and the
        # controller would audit it; here the call is withheld so that the
        # deterministic follow-ups still run, but it is RECORDED, not dropped
        # silently: the controller writes its proposed/rejected audit events
        # and the report discloses the count. It is never executed.
        reason = _target_rejection(proposed, context)

        if proposed is not None and reason is not None:
            context.note_rejected_proposal(proposed, reason, audited=False)
            proposed = None

        # The model is not a second inspection path. A pod already described
        # (or already attempted) is never described again through this wrapper.
        if proposed is not None and _already_inspected(proposed, steps):
            proposed = None

        # Health discovery already listed the namespace. Ask the model for its
        # next proposal instead of spending an analysis step on a second list
        # or ending the run.
        if proposed is not None and _duplicate_listing(proposed, steps):
            proposed = self._inner(context, steps)
            reason = _target_rejection(proposed, context)

            if proposed is not None and reason is not None:
                context.note_rejected_proposal(proposed, reason, audited=False)
                proposed = None

            if proposed is not None and (
                _already_inspected(proposed, steps)
                or _duplicate_listing(proposed, steps)
            ):
                proposed = None

        # A targeted run already listed the namespace to resolve its target;
        # listing it again would only spend a step.
        if (
            proposed is not None
            and context.target is not None
            and proposed.name == POD_DISCOVERY_TOOL
        ):
            proposed = None

        if proposed is None and pending:
            return pending[0]

        return proposed


def _target_rejection(
    proposed: ToolCall | None, context: InvestigationContext
) -> str | None:
    """The fixed reason a proposal falls outside the bound target, else None."""
    resolution = context.target_resolution

    if proposed is None or resolution is None:
        return None

    return call_outside_target(proposed.name, proposed.arguments, resolution)


def _duplicate_listing(
    proposed: ToolCall, steps: Sequence[InvestigationStep]
) -> bool:
    """True when the namespace was already listed successfully."""
    if proposed.name != POD_DISCOVERY_TOOL:
        return False

    return any(
        step.proposed_call.name == POD_DISCOVERY_TOOL
        and step.result.status == ToolExecutionStatus.SUCCESS
        for step in steps
    )


def _already_inspected(proposed: ToolCall, steps: Sequence[InvestigationStep]) -> bool:
    """True when the model re-proposes a read that was already attempted.

    Covers pod descriptions and pod-bound event listings (same namespace and
    pod). A namespace-wide events call is a different read and is not
    suppressed here.
    """
    if proposed.name not in {DESCRIBE_POD_TOOL, EVENTS_TOOL}:
        return False

    pod = proposed.arguments.get("pod")
    namespace = proposed.arguments.get("namespace")

    if proposed.name == EVENTS_TOOL and pod is None:
        return False

    return any(
        step.proposed_call.name == proposed.name
        and step.proposed_call.arguments.get("pod") == pod
        and step.proposed_call.arguments.get("namespace") == namespace
        for step in steps
    )
