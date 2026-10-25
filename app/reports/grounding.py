"""Deterministic construction of verified investigation findings."""

import re
from app.reports.scope_grounding import scope_uncertainties
from app.reports.models import (
    EvidenceReference,
    InvestigationFinding,
    InvestigationReport,
)
from app.reports.config_grounding import (
    build_configuration_findings,
    build_configuration_uncertainties,
)
from app.reports.checks import build_coverage_uncertainties, build_suggested_checks
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.health_grounding import (
    build_container_health_findings,
    build_health_inspection_uncertainties,
)
from app.reports.pod_health_grounding import (
    build_pod_health_findings,
    unschedulable_pods,
)
from app.reports.summary import build_summary
from app.tools.observations import MEMORY_QUANTITY


POD_DISCOVERY_TOOL = "k8s.get_pods"
POD_DISCOVERY_FIELD = "pods[].name"

CONTAINER_FIELD_PATTERN = re.compile(
    r"^containers\[([a-z0-9](?:[-a-z0-9]*[a-z0-9])?)\]"
    r"\.(ready|restart_count|state|reason|last_termination\.(?:exit_code|reason)"
    r"|resources\.memory_(?:request|limit))$"
)

CONTAINER_FIELD_LABELS = {
    "ready": "readiness",
    "restart_count": "restart count",
    "state": "state",
    "reason": "state reason",
}


def build_grounded_report(
    snapshot: InvestigationEvidenceSnapshot,
) -> InvestigationReport:
    """Build verified findings without using model-generated claims."""

    findings: list[InvestigationFinding] = []

    for item in snapshot.evidence:
        if item.tool in {"k8s.describe_pod", "k8s.get_logs", "k8s.get_previous_logs",}:
           if not item.namespace or not item.pod:
               continue 
        observation = describe_verified_observation(item)
        if observation is None:
            continue
        
        # title, description = observation
        # resource = evidence_resource_label(item)
        # if resource is not None:
        #     description = f"{description} Resource: {resource}."
        
        title, description = observation
        resource = evidence_resource_label(item)
        if resource is not None:
            description = f"{description} Resource: {resource}."
            
        description = (
           f"{description} "
           f"Observed during tool execution {item.request_id!r}."
        )
           
        findings.append(
            InvestigationFinding(
                title=title,
                description=description,
                severity="info",
                evidence=[
                    EvidenceReference(evidence_id=item.evidence_id)
                ],
            )
        )

    findings.extend(build_configuration_findings(snapshot))
    findings.extend(build_container_health_findings(snapshot))
    findings.extend(build_pod_health_findings(snapshot))

    uncertainties = bound_uncertainties(build_report_uncertainties(snapshot))

    return InvestigationReport(
        investigation_id=snapshot.investigation_id,
        summary=build_summary(findings, snapshot, uncertainties),
        findings=findings,
        uncertainties=uncertainties,
        suggested_checks=build_suggested_checks(snapshot),
    )
    
    
MAX_UNCERTAINTIES = 20


def bound_uncertainties(uncertainties: list[str]) -> list[str]:
    """Fit the report's uncertainty limit without dropping the standing
    caveat (always last) and while disclosing that entries were omitted."""
    if len(uncertainties) <= MAX_UNCERTAINTIES:
        return uncertainties

    keep = MAX_UNCERTAINTIES - 2
    omitted = len(uncertainties) - keep - 1

    return [
        *uncertainties[:keep],
        f"{omitted} additional uncertainty entries were omitted to bound "
        "the report; coverage may be less complete than shown.",
        uncertainties[-1],
    ]


def describe_verified_observation(item):
    """Return a verified finding description for supported evidence."""

    if (
        item.tool == "k8s.get_pods"
        and item.field == "pods[].name"
        and isinstance(item.value, str)
        and item.value
    ):
        return (
            "Pod discovered",
            f"Pod {item.value!r} appeared in a successful Kubernetes pod listing.",
        )
        
    if (item.tool in {"k8s.get_logs", "k8s.get_previous_logs"} and item.field == "logs.retrieved"):
       if item.value is True and item.namespace and item.pod:
          return (
            "Container logs retrieved",
            "Container logs were retrieved successfully. "
            "Log contents have not been established as verified "
            "root-cause evidence."
          )
       return None       

    if item.tool != "k8s.describe_pod":
        return None

    if item.field == "pod.name":
        if isinstance(item.value, str) and item.value:
            return (
                "Pod identified",
                f"Kubernetes returned pod {item.value!r} in a pod description.",
            )
        return None

    if item.field == "pod.phase":
        if item.value in {
            "Pending",
            "Running",
            "Succeeded",
            "Failed",
            "Unknown",
        }:
            return (
                "Pod phase observed",
                f"Kubernetes reported pod phase {item.value!r}.",
            )
        return None

    match = CONTAINER_FIELD_PATTERN.fullmatch(item.field)

    if match is None:
        return None

    container_name, attribute = match.groups()
    
    if attribute == "last_termination.exit_code":
        if (
            type(item.value) is not int
            or not 0 <= item.value <= 255
        ):
            return None

        return (
            "Previous container exit code observed",
            (
                f"Kubernetes reported that container "
                f"{container_name!r} previously terminated "
                f"with exit code {item.value}."
            ),
        )

    if attribute == "last_termination.reason":
        if item.value not in {
            "Completed",
            "Error",
            "OOMKilled",
            "ContainerCannotRun",
        }:
            return None

        return (
            "Previous container termination reason observed",
            (
                f"Kubernetes reported that container "
                f"{container_name!r} previously terminated "
                f"with reason {item.value!r}."
            ),
        )

    if attribute.startswith("resources.memory_"):
        if (
            not isinstance(item.value, str)
            or MEMORY_QUANTITY.fullmatch(item.value) is None
        ):
            return None

        kind = "limit" if attribute.endswith("limit") else "request"

        return (
            f"Container memory {kind} declared",
            (
                f"The pod spec declares a memory {kind} of {item.value} for "
                f"container {container_name!r}. This is a configured value, "
                "not observed memory usage."
            ),
        )

    if attribute == "ready":
        if type(item.value) is not bool:
            return None

    elif attribute == "restart_count":
        if (
            type(item.value) is not int
            or not 0 <= item.value <= 1_000_000
        ):
            return None

    elif attribute == "state":
        if item.value not in {
            "waiting",
            "running",
            "terminated",
        }:
            return None

    elif attribute == "reason":
        if (
            not isinstance(item.value, str)
            or not item.value
            or len(item.value) > 100
        ):
            return None

    label = CONTAINER_FIELD_LABELS[attribute]

    return (
        f"Container {label} observed",
        (
            f"Kubernetes reported container {container_name!r} "
            f"{label} as {item.value!r}."
        ),
    )    


def evidence_resource_label(item) -> str | None:
    if not item.namespace or not item.pod:
        return None

    return (
        f"namespace {item.namespace!r}, "
        f"pod {item.pod!r}"
    )
    
def build_report_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    """Scope limitations first, then missing pod and container evidence."""
    return [
        *scope_uncertainties(snapshot.scope),
        *_build_evidence_uncertainties(snapshot),
    ]


def _build_evidence_uncertainties(
    snapshot: InvestigationEvidenceSnapshot,
) -> list[str]:
    """Track missing pod and container evidence independently."""

    pod_coverage: dict[tuple[str, str], set[str]] = {}

    # Key: (namespace, pod, request_id)
    # Value: container name -> observed health fields
    execution_containers: dict[
        tuple[str, str, str],
        dict[str, set[str]],
    ] = {}
    
    declared_containers: dict[
        tuple[str, str, str],
        set[str],
    ] = {}
    
    latest_describe_execution: dict[
        tuple[str, str],
        tuple[str, str, str],
        ] = {}

    for item in snapshot.evidence:
        if not item.namespace or not item.pod:
            continue

        resource = (item.namespace, item.pod)
        pod_fields = pod_coverage.setdefault(resource, set())

        if item.tool != "k8s.describe_pod":
            continue

        execution = (
            item.namespace,
            item.pod,
            item.request_id,
        )
        latest_describe_execution[resource] = execution
        containers = execution_containers.setdefault(
            execution,
            {},
        )

        if (
            item.field == "containers[].name"
            and isinstance(item.value, str)
            and re.fullmatch(
                r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?",
                item.value,
            )
        ):  
            declared_containers.setdefault(
                     execution,
                     set(),
            ).add(item.value)
            containers.setdefault(item.value, set())
            continue
        
        # Evidence is projected in execution-recording order.
        # Track the most recently observed describe execution for each pod.


        # Reject malformed or unsupported health evidence.
        if describe_verified_observation(item) is None:
            continue

        if item.field == "pod.phase":
            pod_fields.add(item.request_id)
            continue

        match = CONTAINER_FIELD_PATTERN.fullmatch(item.field)

        if match is None:
            continue

        container_name, attribute = match.groups()

        if attribute not in {"ready", "restart_count"}:
            continue

        # Coverage is established only for a container whose
        # identity was observed in the same tool execution.
        #
        # The field may precede the name observation in the
        # snapshot, so record it first and validate later.
        container_fields = containers.setdefault(
            container_name,
            set(),
        )

        container_fields.add(attribute)

    # First, so the report's uncertainty bound can never drop it in favour of
    # the per-pod entries below: which pods were never inspected is the most
    # important coverage statement a broad investigation makes.
    uncertainties: list[str] = list(build_health_inspection_uncertainties(snapshot))

    if not pod_coverage:
        uncertainties.extend(
            [
                "Pod phase has not been established by trusted report evidence.",
                "Container readiness has not been established by trusted report evidence.",
                "Container restart counts have not been established by trusted report evidence.",
            ]
        )

    unscheduled = unschedulable_pods(snapshot)

    for (namespace, pod), fields in sorted(pod_coverage.items()):
        resource = f"Pod {pod!r} in namespace {namespace!r}"
        latest_execution = latest_describe_execution.get(
            (namespace, pod)
        )
        
        latest_request_id = (
            latest_execution[2]
            if latest_execution is not None
            else None
        )
        
        if latest_request_id not in fields:
            uncertainties.append(
                f"{resource}: phase has not been established."
            )

        if (namespace, pod) not in latest_describe_execution:
            uncertainties.append(
                f"{resource}: container readiness has not been established."
            )
            uncertainties.append(
                f"{resource}: container restart counts have not been established."
            )
            continue

        # Aggregate observations only after validating container
        # identity within each individual execution.
        #
        # A future enhancement can retain execution-level
        # timestamps to distinguish historical from current state.
        container_coverage: dict[str, set[str]] = {}
        
        if latest_execution is not None:
           containers = execution_containers.get(
               latest_execution,
               {},
         )

           declared = declared_containers.get(
                latest_execution,
                set(),
         )

           for container_name in declared:
               container_coverage[container_name] = set(
                   containers.get(container_name, set())
              )
        if (namespace, pod) in unscheduled:
            # The pod was never scheduled, so Kubernetes has created no
            # container: there is no readiness or restart count to establish.
            uncertainties.append(
                f"{resource}: no container exists yet because the pod was "
                "never scheduled, so container readiness, restart counts and "
                "logs do not exist."
            )
            continue

        if not container_coverage:
            uncertainties.append(
                f"{resource}: container readiness has not been established."
            )
            uncertainties.append(
                f"{resource}: container restart counts have not been established."
            )
            continue

        for container_name, observed_fields in sorted(
            container_coverage.items()
        ):
            container_resource = (
                f"{resource}, container {container_name!r}"
            )

            if "ready" not in observed_fields:
                uncertainties.append(
                    f"{container_resource}: readiness has not been established."
                )

            if "restart_count" not in observed_fields:
                uncertainties.append(
                    f"{container_resource}: restart count has not been established."
                )
    
    bounded_log_executions = {
        (
            item.request_id,
            item.tool,
            item.namespace,
            item.pod,
        )
        for item in snapshot.evidence
        if item.tool in {
            "k8s.get_logs",
            "k8s.get_previous_logs",
        }
        and item.field == "logs.completeness"
        and item.value == "bounded_unknown"
        and item.namespace
        and item.pod
    }

    for request_id, tool, namespace, pod in sorted(
        bounded_log_executions
    ):
        uncertainties.append(
            f"Log retrieval for pod {pod!r} in namespace "
            f"{namespace!r} during execution {request_id!r} "
            f"({tool}) was bounded. The retrieved excerpt may "
            "omit relevant log entries."
        )
    
    
    if snapshot.truncated:
        uncertainties.append(
         "Report evidence was truncated at 100 observations. "
         "Additional trusted observations were omitted; "
         "findings and coverage may be incomplete."
       )
        uncertainties.append(
          "Latest-execution health coverage cannot be established "
         "from a truncated evidence snapshot."
       ) 
    uncertainties.extend(build_configuration_uncertainties(snapshot))
    uncertainties.extend(build_coverage_uncertainties(snapshot))

    uncertainties.append(
        "Underlying failure causes and log-derived failures have not "
        "been established by trusted report evidence."
    )

    return uncertainties  