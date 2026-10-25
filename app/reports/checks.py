"""Evidence-aware coverage gaps and recommended read-only checks.

Everything is derived from the trusted evidence snapshot. Suggestions address
UNRESOLVED questions, not steps the investigation already performed, and never
mention values, commands or credentials (none exist in the evidence).
"""

from app.reports.config_grounding import (
    collect_configuration,
    configuration_context_for,
)
from typing import NamedTuple

from app.reports.pod_health_grounding import (
    pod_health_check_items,
    restart_history,
    build_pod_health_uncertainties,
)
from app.reports.probe_declarations import readiness_declared
from app.reports.scope_grounding import scope_checks
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.tools.coverage import (
    EVENTS_TOOL,
    LOGS_TOOL,
    MAX_FOLLOW_UP_CONTAINERS,
    failing_containers,
)
from app.tools.workload_config import WORKLOAD_CONFIG_TOOL, safe_image

MAX_CHECKS = 20

_LOG_TOOLS = frozenset({LOGS_TOOL, "k8s.get_previous_logs"})

LEGACY_CHECKS = [
    "Inspect pod status and readiness using authorized read-only tools.",
    "Review structured container restart information.",
]


def _pods_with_logs(snapshot: InvestigationEvidenceSnapshot) -> set[tuple[str, str]]:
    return {
        (item.namespace, item.pod)
        for item in snapshot.evidence
        if item.tool in _LOG_TOOLS
        and item.field == "logs.retrieved"
        and item.value is True
        and item.namespace
        and item.pod
    }


def _pods_with_config(snapshot: InvestigationEvidenceSnapshot) -> set[tuple[str, str]]:
    return {
        (item.namespace, item.pod)
        for item in snapshot.evidence
        if item.tool == WORKLOAD_CONFIG_TOOL and item.namespace and item.pod
    }


def _pods_with_events(snapshot: InvestigationEvidenceSnapshot) -> set[tuple[str, str]]:
    return {
        (item.namespace, item.pod)
        for item in snapshot.evidence
        if item.tool == EVENTS_TOOL and item.namespace and item.pod
    }


IMAGE_REASONS = frozenset(
    {
        "ImagePullBackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "ImageInspectError",
        "RegistryUnavailable",
    }
)


def _pre_start_checks(
    target, where: str, image: str | None, has_events: bool
) -> list[str]:
    """Read-only checks that target a container that could not start."""
    checks: list[str] = []

    if not has_events:
        checks.append(
            f"Retrieve the bounded Kubernetes events for pod {target.pod!r} "
            "with the read-only events tool: Kubernetes records each failed "
            "attempt there."
        )
    else:
        checks.append(
            f"Read the event messages Kubernetes recorded for pod "
            f"{target.pod!r} (for example with kubectl describe pod): they "
            "name the specific error. They are not retained in this report."
        )

    if target.reason in IMAGE_REASONS:
        reference = f"image reference {image!r}" if image else "configured image reference"
        checks.append(
            f"Confirm that the {reference} for {where} names an image and "
            "tag that exist in the registry it points to. Compare it with "
            "the registry's published tags (read-only)."
        )
        checks.append(
            f"Check that the registry host for {where} is reachable from the "
            "cluster's nodes, and whether the pod spec lists image pull "
            "secret names. Names only: never read Secret contents."
        )
    else:
        checks.append(
            f"Compare the configuration sources declared for {where} (names "
            "only, never values) with the ConfigMaps and Secrets that exist "
            "in the namespace, and confirm each referenced key is present."
        )

    return checks


def _not_ready_checks(
    where: str, pod: str, probe: str | None, declared: bool | None, has_events: bool
) -> list[str]:
    """Read-only checks for a container that runs but is not ready."""
    checks: list[str] = []

    if not has_events:
        checks.append(
            f"Retrieve the bounded Kubernetes events for pod {pod!r} with the "
            "read-only events tool: probe failures are recorded there."
        )
    else:
        checks.append(
            f"Read the event messages Kubernetes recorded for pod {pod!r} "
            "(for example with kubectl describe pod): they say which probe "
            "failed and why. They are not retained in this report."
        )

    if declared is True:
        checks.append(
            f"Confirm that the readiness probe declared for {where} targets "
            "the port and path the application actually serves, and that the "
            "application is listening on that port (read-only checks)."
        )
    elif declared is False:
        checks.append(
            f"No readiness probe is declared for {where}, so review the pod's "
            "readiness conditions and events to see what else keeps it not "
            "ready."
        )

    return checks


def _failing(snapshot: InvestigationEvidenceSnapshot):
    return failing_containers(snapshot.evidence)[:MAX_FOLLOW_UP_CONTAINERS]


def build_coverage_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    """Disclose evidence that should exist for a failing container but doesn't."""
    with_logs = _pods_with_logs(snapshot)
    with_config = _pods_with_config(snapshot)
    with_events = _pods_with_events(snapshot)
    notes: list[str] = list(build_pod_health_uncertainties(snapshot))

    for target in _failing(snapshot):
        where = f"Pod {target.pod!r}, container {target.container!r}"
        key = (target.namespace, target.pod)

        if target.wants_events and key not in with_events:
            notes.append(
                f"{where}: "
                + (
                    "the container has not started"
                    if target.pre_start
                    else "the container is running but not ready"
                )
                + ", but the Kubernetes events for the pod were not "
                "retrieved, so the events Kubernetes recorded have not been "
                "examined."
            )

        if target.pre_start:
            if not target.may_have_logs:
                notes.append(
                    f"{where}: application logs were not requested because "
                    "Kubernetes reports the container has not started; there "
                    "is no application-level evidence about it."
                )

        elif key not in with_logs:
            notes.append(
                f"{where}: the container is failing, but no container logs "
                "were retrieved, so errors reported by the application have "
                "not been examined."
            )

        if key not in with_config:
            notes.append(
                f"{where}: the container is failing, but the workload "
                "configuration was not inspected, so environment variable "
                "names and startup behavior have not been established."
            )

    return notes


class AttributedCheck(NamedTuple):
    """A suggested check and the resource it was written for, if it has one."""

    text: str
    namespace: str | None
    pod: str | None
    container: str | None


def _keep(items: list[AttributedCheck]) -> list[AttributedCheck]:
    """First text wins, then the report's check cap. Same order as before."""
    chosen: list[AttributedCheck] = []
    seen: set[str] = set()

    for item in items:
        if item.text in seen:
            continue

        seen.add(item.text)
        chosen.append(item)

        if len(chosen) == MAX_CHECKS:
            break

    return chosen


def _bare(texts: list[str]) -> list[AttributedCheck]:
    return [AttributedCheck(text, None, None, None) for text in texts]


def attributed_checks(snapshot: InvestigationEvidenceSnapshot) -> list[AttributedCheck]:
    """Suggested checks, each carrying the resource it was generated for.

    A check written for several resources at once, or for the investigation
    as a whole, has no pod. Callers must not recover a pod from the wording.
    """
    unresolved = scope_checks(snapshot.scope)

    if unresolved:
        return _keep(_bare(unresolved))

    has_pod_state = any(
        item.tool == "k8s.describe_pod" for item in snapshot.evidence
    )

    if not has_pod_state:
        return _keep(_bare(list(LEGACY_CHECKS)))

    failing = _failing(snapshot)
    pod_items = [
        AttributedCheck(text, namespace, pod, container)
        for text, namespace, pod, container in pod_health_check_items(snapshot)
    ]

    if not failing:
        if pod_items:
            return _keep(pod_items)

        history = restart_history(snapshot)

        if history:
            namespace, pod, container, restarts = history[0]
            more = len(history) - 1
            text = (
                "No container is failing at the moment it was inspected, but "
                f"Kubernetes records {restarts} earlier restart"
                f"{'' if restarts == 1 else 's'} of container {container!r} "
                f"in pod {pod!r}"
                + (
                    f" (and {more} other restarted container"
                    f"{'s' if more > 1 else ''})"
                    if more
                    else ""
                )
                + ". That history is not a current failure and does not show "
                "its cause: review the container's previous termination and "
                "the pod's recorded events with read-only tools."
            )
            # One sentence that names further containers is not one resource's check.
            if more:
                return _keep([AttributedCheck(text, None, None, None)])

            return _keep([AttributedCheck(text, namespace, pod, container)])

        return _keep(_bare([
            "No failing container was established from the observed pod "
            "state. Confirm the reported symptom with read-only "
            "application-level checks, such as service health or recent "
            "namespace events."
        ]))

    pods, exit_codes = collect_configuration(snapshot)
    with_logs = _pods_with_logs(snapshot)
    with_config = _pods_with_config(snapshot)
    with_events = _pods_with_events(snapshot)
    checks: list[AttributedCheck] = []

    for target in failing:
        name, pod = target.container, target.pod
        key = (target.namespace, pod)
        where = f"container {name!r} in pod {pod!r}"

        def add(text: str, *, container: str | None = name) -> None:
            checks.append(AttributedCheck(text, target.namespace, pod, container))

        if target.pre_start:
            config = pods.get(key)
            container = config.containers.get(name) if config else None
            for text in _pre_start_checks(
                target,
                where,
                safe_image(container.attrs.get("image")) if container else None,
                key in with_events,
            ):
                add(text)
        elif target.category == "running_not_ready":
            config = pods.get(key)
            container = config.containers.get(name) if config else None
            for text in _not_ready_checks(
                where,
                pod,
                None,
                readiness_declared(snapshot, key, name, container),
                key in with_events,
            ):
                add(text)

        if target.may_have_logs and key not in with_logs:
            add(
                f"Retrieve the bounded application logs of {where} with the "
                "read-only log tool to see what the application itself "
                "reports at failure."
            )

        if key not in with_config:
            add(
                f"Inspect the owning Deployment's configuration for {where} "
                "(environment variable names and source types, startup "
                "behavior only, values are never collected)."
            )
        else:
            config = pods.get(key)
            container = config.containers.get(name) if config else None
            attrs = container.attrs if container else {}
            # Startup-command analysis concerns a container that ran; it is
            # not relevant to one that could not be started.
            static = (
                attrs.get("startup.static_analysis")
                if target.category == "runtime_failure"
                else None
            )
            static_code = attrs.get("startup.static_exit_code")
            observed = exit_codes.get((target.namespace, pod, name))

            if static == "unconditional_exit":
                if observed is not None and observed[0] == static_code:
                    add(
                        f"The startup command of {where} exits unconditionally "
                        f"with code {static_code}, independent of environment "
                        "values. Ask the workload owner to review how that "
                        "startup command is defined in the Deployment "
                        "manifest (command text is intentionally not "
                        "collected). Changing environment variables alone "
                        "would not be expected to help."
                    )
                else:
                    add(
                        f"Static analysis found an unconditional exit with "
                        f"code {static_code} for {where}, which differs from "
                        "the exit code Kubernetes last reported. Re-inspect "
                        "the most recent termination before drawing "
                        "conclusions."
                    )
            elif static == "not_established":
                add(
                    f"Startup behavior of {where} could not be established by "
                    "static analysis. Ask the workload owner to review its "
                    "entrypoint and the image's default command."
                )

            context = configuration_context_for(
                snapshot, target.namespace, pod, name
            )

            if (
                context is not None
                and context.none_declared
                and target.category == "runtime_failure"
            ):
                add(
                    f"If the application reports a required setting for "
                    f"{where}, confirm with the workload owner how it is "
                    "meant to be supplied (the Deployment manifest or "
                    "deployment tooling, image defaults or an init step). "
                    "The inspected spec declares no environment sources, "
                    "which does not establish the complete runtime "
                    "environment."
                )

            if attrs.get("env.names_complete") is False:
                add(
                    f"Review which ConfigMap or Secret references supply "
                    f"environment variables to {where}. Confirm names only, "
                    "never values."
                )

        if key in with_logs and key in with_config:
            add(
                f"Compare what the application logs report for {where} "
                "(untrusted, not retained) with the declared environment "
                "variable names, and confirm any claimed missing setting in "
                "the Deployment definition before changing anything."
            )

        if not target.wants_events:
            add(
                f"Review recent namespace events for pod {pod!r} (probe "
                "failures, back-off, image pulls). Events are not part of "
                "this report's evidence."
            )

    return _keep([*checks, *pod_items])


def build_suggested_checks(snapshot: InvestigationEvidenceSnapshot) -> list[str]:
    """Recommended read-only checks for questions the evidence leaves open."""
    return [item.text for item in attributed_checks(snapshot)]
