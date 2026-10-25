"""Group a namespace-wide report by verified resource identity.

Associations come from evidence records (namespace and pod), from owner
observations the application minted, and from the resource already stored on
each hypothesis. Display order and the wording of a finding are not used.
"""

import re
from dataclasses import dataclass, field

from app.reports.checks import attributed_checks
from app.reports.models import (
    DiagnosticCheck,
    DiagnosticFinding,
    DiagnosticResource,
    InvestigationReport,
    NamespaceDiagnostic,
)
from app.reports.snapshot import InvestigationEvidenceSnapshot


_OWNER_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet")
_OWNER_VALUE = re.compile(
    r"^(Deployment|StatefulSet|DaemonSet|Job|ReplicaSet)/"
    r"([a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)$"
)
_NAME = re.compile(
    r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
)
_SEVERITY = {"critical": 0, "warning": 1, "unknown": 2}
_DEEP_TOOLS = {
    "k8s.get_logs",
    "k8s.get_previous_logs",
    "k8s.get_events",
    "k8s.describe_workload_config",
}


@dataclass
class _Group:
    namespace: str
    kind: str
    name: str
    ownership: str
    pods: set[str] = field(default_factory=set)
    findings: list[DiagnosticFinding] = field(default_factory=list)
    hypothesis_indexes: list[int] = field(default_factory=list)
    checks: list[DiagnosticCheck] = field(default_factory=list)

    def affected(self, report: InvestigationReport) -> bool:
        if self.hypothesis_indexes or self.checks:
            return True

        return any(
            report.findings[item.index].severity in _SEVERITY
            for item in self.findings
        )


def _owners(snapshot: InvestigationEvidenceSnapshot) -> dict[tuple[str, str], str]:
    """Pod -> 'Kind/name', 'pod', or 'unverified'. Conflicting records lose."""
    values: dict[tuple[str, str], set[str]] = {}
    config: dict[tuple[str, str], dict[str, set[str]]] = {}

    def remember(key: tuple[str, str], value: str) -> None:
        values.setdefault(key, set()).add(value)

    for item in snapshot.evidence:
        if not item.namespace or not item.pod:
            continue

        key = (item.namespace, item.pod)

        if item.field == "workload.owner" and isinstance(item.value, str):
            if item.value in {"pod", "unverified"} or _OWNER_VALUE.fullmatch(item.value):
                remember(key, item.value)
            continue

        slot = config.setdefault(key, {})

        if item.field == "workload.kind" and item.value in _OWNER_KINDS:
            slot.setdefault("kinds", set()).add(item.value)
        elif (
            item.field == "workload.name"
            and isinstance(item.value, str)
            and len(item.value) <= 253
            and _NAME.fullmatch(item.value)
        ):
            slot.setdefault("names", set()).add(item.value)
        elif item.field == "workload.ownership_verified" and item.value is True:
            slot.setdefault("verified", set()).add("yes")

    for key, slot in config.items():
        if "yes" not in slot.get("verified", set()):
            continue

        kinds, names = slot.get("kinds", set()), slot.get("names", set())

        if len(kinds) == 1 and len(names) == 1:
            remember(key, f"{next(iter(kinds))}/{next(iter(names))}")
        elif kinds or names:
            remember(key, "unverified")

    return {
        key: next(iter(found)) if len(found) == 1 else "unverified"
        for key, found in values.items()
    }


def _namespace_for(snapshot: InvestigationEvidenceSnapshot, pod: str) -> str | None:
    """Namespace recorded for this pod, or the snapshot's only namespace."""
    for item in snapshot.evidence:
        if item.namespace and (item.pod == pod or item.value == pod):
            return item.namespace

    namespaces = {item.namespace for item in snapshot.evidence if item.namespace}

    if len(namespaces) == 1:
        return next(iter(namespaces))

    return None


def _identity(
    namespace: str, pod: str, owners: dict[tuple[str, str], str]
) -> tuple[tuple, str, str, str, str]:
    """Return the group key and the kind, name and ownership to display."""
    owner = owners.get((namespace, pod))
    match = _OWNER_VALUE.fullmatch(owner) if isinstance(owner, str) else None

    if match is not None:
        kind, name = match.group(1), match.group(2)
        return ("workload", namespace, kind, name), kind, name, "verified"

    if owner == "pod":
        return ("pod", namespace, pod, "verified"), "Pod", pod, "verified"

    return ("pod", namespace, pod, "unresolved"), "Pod", pod, "unresolved"


def _cited_pods(finding, by_id) -> set[tuple[str, str]] | None:
    """Pods cited by a finding, or None when any citation has no pod identity."""
    pods: set[tuple[str, str]] = set()

    for reference in finding.evidence:
        item = by_id.get(reference.evidence_id)

        if item is None or not item.namespace or not item.pod:
            return None

        pods.add((item.namespace, item.pod))

    return pods


def attach_namespace_diagnostic(
    report: InvestigationReport,
    snapshot: InvestigationEvidenceSnapshot,
) -> InvestigationReport:
    """Store resource groups for a namespace-wide report. Workload reports are unchanged."""
    scope = snapshot.scope

    if scope is None or scope.mode != "namespace":
        return report

    return report.model_copy(
        update={"namespace_diagnostic": _build(report, snapshot)}
    )


def _build(
    report: InvestigationReport,
    snapshot: InvestigationEvidenceSnapshot,
) -> NamespaceDiagnostic:
    owners = _owners(snapshot)
    by_id = {item.evidence_id: item for item in snapshot.evidence}
    groups: dict[tuple, _Group] = {}
    shared_findings: list[DiagnosticFinding] = []
    shared_hypotheses: list[int] = []
    shared_checks: list[DiagnosticCheck] = []

    def group_for(namespace: str, pod: str) -> _Group:
        key, kind, name, ownership = _identity(namespace, pod, owners)
        group = groups.get(key)

        if group is None:
            group = _Group(
                namespace=namespace, kind=kind, name=name, ownership=ownership
            )
            groups[key] = group

        group.pods.add(pod)
        return group

    for index, finding in enumerate(report.findings):
        pods = _cited_pods(finding, by_id)

        if not pods:
            shared_findings.append(DiagnosticFinding(index=index))
            continue

        keys = {_identity(namespace, pod, owners)[0] for namespace, pod in pods}

        if len(keys) != 1:
            shared_findings.append(DiagnosticFinding(index=index))
            continue

        namespace, pod = next(iter(pods))
        group_for(namespace, pod).findings.append(
            DiagnosticFinding(index=index, pod=pod if len(pods) == 1 else None)
        )

        if len(pods) > 1:
            for namespace, pod in pods:
                group_for(namespace, pod)

    claimed: set[str] = set()

    for index, hypothesis in enumerate(report.ai_hypotheses):
        resource = hypothesis.resource
        check = None

        if hypothesis.verification_check:
            claimed.add(hypothesis.verification_check)
            check = DiagnosticCheck(
                text=hypothesis.verification_check,
                source="hypothesis",
                hypothesis_index=index,
                pod=resource.pod,
                container=resource.container,
            )

        if not resource.pod:
            shared_hypotheses.append(index)

            if check is not None:
                shared_checks.append(check)

            continue

        group = group_for(resource.namespace, resource.pod)
        group.hypothesis_indexes.append(index)

        if check is not None:
            group.checks.append(check)

    produced = attributed_checks(snapshot)
    aligned = [item.text for item in produced] == list(report.suggested_checks)

    for index, text in enumerate(report.suggested_checks):
        if text in claimed:
            continue

        item = produced[index] if aligned else None

        if (
            item is None
            or item.namespace is None
            or item.pod is None
        ):
            shared_checks.append(DiagnosticCheck(text=text, source="report"))
            continue

        group_for(item.namespace, item.pod).checks.append(
            DiagnosticCheck(
                text=text,
                source="report",
                pod=item.pod,
                container=item.container,
            )
        )

    kept = [group for group in groups.values() if group.affected(report)]
    kept.sort(
        key=lambda group: (
            min(
                (
                    _SEVERITY[report.findings[item.index].severity]
                    for item in group.findings
                    if report.findings[item.index].severity in _SEVERITY
                ),
                default=len(_SEVERITY),
            ),
            group.kind,
            group.name,
        )
    )

    scope = snapshot.scope
    listed = scope.listed if scope is not None else 0
    inspected = scope.inspected if scope is not None else 0
    described = {
        item.pod
        for item in snapshot.evidence
        if item.tool == "k8s.describe_pod" and item.pod
    }
    deep = {
        item.pod
        for item in snapshot.evidence
        if item.tool in _DEEP_TOOLS and item.pod
    }
    failed = set(scope.unsuccessful_pods) if scope is not None else set()

    def resource_of(group: _Group) -> DiagnosticResource:
        established = any(pod in described for pod in group.pods)
        attempted = any(pod in failed for pod in group.pods)
        coverage = (
            "established" if established
            else "failed" if attempted
            else "unknown"
        )

        return DiagnosticResource(
            namespace=group.namespace,
            kind=group.kind,  # type: ignore[arg-type]
            name=group.name,
            ownership=group.ownership,  # type: ignore[arg-type]
            pods=sorted(group.pods),
            findings=group.findings,
            hypothesis_indexes=group.hypothesis_indexes,
            checks=group.checks,
            coverage=coverage,
            deeply_investigated=any(pod in deep for pod in group.pods),
        )

    resources = [resource_of(group) for group in kept]

    # Pods the inspection record left out. Evidence truncation can omit a
    # describe that did happen; those pods are not shown as unknown.
    placed = {pod for resource in resources for pod in resource.pods}

    def add_uncovered(names: tuple[str, ...], coverage: str) -> None:
        for pod in names:
            if pod in placed or len(resources) >= 100:
                continue

            namespace = _namespace_for(snapshot, pod)

            if namespace is None:
                continue

            owner = owners.get((namespace, pod))
            match = _OWNER_VALUE.fullmatch(owner) if isinstance(owner, str) else None
            taken = match is not None and any(
                resource.namespace == namespace
                and resource.kind == match.group(1)
                and resource.name == match.group(2)
                for resource in resources
            )

            if match is not None and not taken:
                kind, name, ownership = match.group(1), match.group(2), "verified"
            else:
                kind, name = "Pod", pod
                ownership = "unresolved" if owner == "unverified" else "verified"

            resources.append(
                DiagnosticResource(
                    namespace=namespace,
                    kind=kind,  # type: ignore[arg-type]
                    name=name,
                    ownership=ownership,  # type: ignore[arg-type]
                    pods=[pod],
                    coverage=coverage,  # type: ignore[arg-type]
                )
            )
            placed.add(pod)

    if scope is not None:
        add_uncovered(scope.unsuccessful_pods, "failed")
        add_uncovered(scope.uninspected_pods, "unknown")

    return NamespaceDiagnostic(
        listed_pods=listed,
        inspected_pods=inspected,
        uninspected_pods=scope.uninspected if scope is not None else 0,
        unsuccessful_pods=scope.unsuccessful if scope is not None else 0,
        listing_truncated=scope.listing_truncated if scope is not None else False,
        assessment_complete=(
            scope is not None
            and scope.uninspected == 0
            and scope.unsuccessful == 0
            and not scope.listing_truncated
            and scope.inspected >= scope.listed
        ),
        resources=resources,
        shared_findings=shared_findings,
        shared_hypothesis_indexes=shared_hypotheses,
        shared_checks=shared_checks,
    )
