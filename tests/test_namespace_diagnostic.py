"""Namespace-wide reports group by evidence identity, not by wording."""

from app.reports.checks import attributed_checks
from app.reports.evidence import ReportEvidence
from app.reports.models import (
    AIHypothesis,
    EvidenceReference,
    HypothesisResource,
    InvestigationFinding,
    InvestigationReport,
)
from app.reports.resource_groups import attach_namespace_diagnostic
from app.reports.snapshot import InvestigationEvidenceSnapshot, SnapshotScope


NS = "demo"


def evidence(evidence_id, pod, field, value, tool="k8s.describe_pod"):
    return ReportEvidence(
        evidence_id=evidence_id,
        request_id="request-1",
        tool=tool,
        field=field,
        value=value,
        namespace=NS,
        pod=pod,
    )


def finding(title, evidence_id, severity="critical", description="Observed state."):
    return InvestigationFinding(
        title=title,
        description=description,
        severity=severity,
        evidence=[EvidenceReference(evidence_id=evidence_id)],
    )


def hypothesis(pod, check):
    return AIHypothesis(
        explanation="Possible explanation, unverified.",
        possible_explanation="Memory pressure may have led to the earlier termination.",
        not_yet_verified="Measured memory usage has not been established.",
        evidence_refs=["ev-0102"],
        resource=HypothesisResource(namespace=NS, pod=pod, container="app"),
        verification_check=check,
    )


def snapshot(items, *, mode="namespace"):
    return InvestigationEvidenceSnapshot(
        investigation_id="investigation-1",
        evidence=tuple(items),
        scope=SnapshotScope(
            mode=mode,
            listed=5,
            inspected=4,
            broad_explicit=True,
        ),
    )


def names(report):
    diagnostic = report.namespace_diagnostic
    assert diagnostic is not None
    return {(item.kind, item.name, item.ownership): item for item in diagnostic.resources}


def test_namespace_report_keeps_each_workload_with_its_own_evidence():
    items = [
        evidence("ev-0101", "ceb-pod", "containers[app].state", "waiting"),
        evidence("ev-0102", "ceb-pod", "containers[app].reason", "ImagePullBackOff"),
        evidence("ev-0103", "ceb-pod", "workload.owner", "Deployment/ceb", tool="k8s.get_pods"),
        evidence("ev-0201", "hog-pod", "containers[app].state", "waiting"),
        evidence("ev-0202", "hog-pod", "containers[app].reason", "CrashLoopBackOff"),
        evidence("ev-0203", "hog-pod", "containers[app].last_termination.reason", "OOMKilled"),
        evidence("ev-0205", "hog-pod", "containers[app].ready", False),
        evidence("ev-0206", "hog-pod", "containers[app].restart_count", 12),
        evidence("ev-0204", "hog-pod", "workload.owner", "Deployment/hog", tool="k8s.get_pods"),
        evidence("ev-0301", "quiet-pod", "containers[app].ready", True),
        evidence("ev-0302", "quiet-pod", "containers[app].state", "running"),
        evidence("ev-0303", "quiet-pod", "containers[app].restart_count", 4),
        evidence("ev-0304", "quiet-pod", "containers[app].last_termination.reason", "Completed"),
        evidence("ev-0305", "quiet-pod", "workload.owner", "Deployment/quiet", tool="k8s.get_pods"),
        evidence("ev-0401", "orphan-pod", "containers[app].state", "waiting"),
        evidence("ev-0402", "orphan-pod", "containers[app].reason", "CrashLoopBackOff"),
        evidence("ev-0407", "orphan-pod", "containers[app].ready", False),
        evidence("ev-0408", "orphan-pod", "containers[app].restart_count", 2),
        evidence("ev-0403", "orphan-pod", "workload.owner", "unverified", tool="k8s.get_pods"),
        evidence("ev-0404", "orphan-pod", "workload.kind", "Deployment", tool="k8s.get_workload_config"),
        evidence("ev-0405", "orphan-pod", "workload.name", "hog", tool="k8s.get_workload_config"),
        evidence("ev-0406", "orphan-pod", "workload.ownership_verified", True, tool="k8s.get_workload_config"),
        evidence("ev-0501", "calm-pod", "pod.phase", "Running"),
        evidence("ev-0502", "calm-pod", "workload.owner", "Deployment/calm", tool="k8s.get_pods"),
    ]
    built = snapshot(items)
    checks = [item.text for item in attributed_checks(built)]
    report = InvestigationReport(
        investigation_id="investigation-1",
        summary="Namespace investigation.",
        findings=[
            finding(
                "Image pull is backing off",
                "ev-0102",
                description=(
                    "ImagePullBackOff on ceb-pod. The wording also mentions "
                    "hog and OOMKilled, which is not this finding's evidence."
                ),
            ),
            finding("Container was OOMKilled", "ev-0203"),
            finding(
                "Container restarted earlier and is running now",
                "ev-0303",
                severity="warning",
            ),
            finding(
                "Container is crash-looping",
                "ev-0402",
                severity="warning",
                description="Some text claims this pod belongs to Deployment hog.",
            ),
            InvestigationFinding(
                title="Events were read",
                description="One event list covered ceb-pod and hog-pod.",
                severity="warning",
                evidence=[
                    EvidenceReference(evidence_id="ev-0102"),
                    EvidenceReference(evidence_id="ev-0202"),
                ],
            ),
            finding("Pod phase observed", "ev-0501", severity="info"),
        ],
        suggested_checks=checks,
        ai_hypotheses=[
            hypothesis(
                "hog-pod",
                "Review the memory configuration of container 'app' in pod 'hog-pod'.",
            )
        ],
    )

    grouped = attach_namespace_diagnostic(report, built)
    by_name = names(grouped)
    diagnostic = grouped.namespace_diagnostic
    assert diagnostic is not None
    assert (diagnostic.listed_pods, diagnostic.inspected_pods) == (5, 4)

    ceb = by_name[("Deployment", "ceb", "verified")]
    hog = by_name[("Deployment", "hog", "verified")]
    quiet = by_name[("Deployment", "quiet", "verified")]
    orphan = by_name[("Pod", "orphan-pod", "unresolved")]

    assert [item.index for item in ceb.findings] == [0]
    assert ceb.hypothesis_indexes == []
    assert ceb.checks
    assert all(check.pod == "ceb-pod" for check in ceb.checks)
    assert "hog-pod" not in ceb.pods

    assert [item.index for item in hog.findings] == [1]
    assert hog.hypothesis_indexes == [0]
    assert any(
        check.source == "hypothesis" and "memory configuration" in check.text
        for check in hog.checks
    )
    assert all(check.pod == "hog-pod" for check in hog.checks)

    assert [item.index for item in quiet.findings] == [2]
    assert quiet.hypothesis_indexes == []
    assert quiet.pods == ["quiet-pod"]

    assert orphan.kind == "Pod"
    assert orphan.ownership == "unresolved"
    assert [item.index for item in orphan.findings] == [3]
    assert orphan.hypothesis_indexes == []
    assert orphan.checks
    assert all(check.pod == "orphan-pod" for check in orphan.checks)

    assert ("Deployment", "calm", "verified") not in by_name
    assert [item.index for item in diagnostic.shared_findings] == [4]
    assert 5 not in {item.index for item in diagnostic.shared_findings}
    assert not any(check.pod == "ceb-pod" for check in diagnostic.shared_checks)


def test_workload_report_keeps_the_single_resource_layout_data():
    built = snapshot(
        [evidence("ev-0101", "ceb-pod", "containers[app].reason", "ImagePullBackOff")],
        mode="workload",
    )
    report = InvestigationReport(
        investigation_id="investigation-1",
        summary="One workload.",
        findings=[finding("Image pull is backing off", "ev-0101")],
        ai_hypotheses=[hypothesis("ceb-pod", "Read the image reference.")],
    )

    assert attach_namespace_diagnostic(report, built).namespace_diagnostic is None
