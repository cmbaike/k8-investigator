"""Namespace-wide health discovery is deterministic and does not spend analysis steps.

The live "3 of 10" result came from the analysis-step allowance
(min(4, max_steps // 2) with the default budget of 6), not from the model
choosing three pods. Basic health now runs before that budget, through the
same authorized and audited tool path.
"""

from types import SimpleNamespace

from app.reports.resource_groups import attach_namespace_diagnostic
from app.tools import handlers
from app.tools.coverage import (
    MAX_NAMESPACE_HEALTH_INSPECTIONS,
    discover_namespace_health,
)
from app.tools.investigation_controller import InvestigationStopReason
from app.tools.models import ToolExecutionResult, ToolExecutionStatus
from tests.pod_scenarios import container_status
from tests.pod_scenarios import event as k8s_event
from tests.pod_scenarios import investigate
from tests.pod_scenarios import pod as k8s_pod
from tests.pod_scenarios import volume
from tests.test_pod_health_coverage import (
    NS,
    POD,
    Cluster,
    bound,
    container,
    healthy,
    model,
    report_of,
    run,
)

MOUNT_MESSAGE = (
    'MountVolume.SetUp failed for volume "cfg" : configmap "app-config" not found'
)


def _described(cluster):
    return [call.arguments["pod"] for call in cluster.calls if call.name == "k8s.describe_pod"]


def _pods_for(tool, cluster):
    return [
        call.arguments.get("pod")
        for call in cluster.calls
        if call.name == tool
    ]


def test_several_failing_deployments_are_health_inspected_without_the_model():
    names = {
        f"deploy-{i}": {
            "phase": "Pending",
            "containers_total": 1,
            "containers_ready": 0,
            "restart_count": 0,
        }
        for i in range(4)
    }
    cluster = Cluster(
        pods=names,
        containers={
            name: [container(ready=False, restarts=0, reason="ImagePullBackOff", exit_code=None)]
            for name in names
        },
    )
    ctx = bound()

    result = run(ctx, model(), cluster)

    assert result.stop_reason == InvestigationStopReason.STEP_BUDGET_EXHAUSTED
    assert _described(cluster) == [f"deploy-{i}" for i in range(4)]
    assert ctx.namespace_health_discovery is True


def test_healthy_unhealthy_and_historical_restarts_are_all_inspected():
    pods = {
        "pull": {"phase": "Pending", "containers_total": 1, "containers_ready": 0, "restart_count": 0},
        "oom": {"phase": "Running", "containers_total": 1, "containers_ready": 0, "restart_count": 12},
        "quiet": {"phase": "Running", "containers_total": 1, "containers_ready": 1, "restart_count": 4},
        "ok": {"phase": "Running", "containers_total": 1, "containers_ready": 1, "restart_count": 0},
    }
    cluster = Cluster(
        pods=pods,
        containers={
            "pull": [container(ready=False, restarts=0, reason="ImagePullBackOff", exit_code=None)],
            "oom": [container()],
            "quiet": [container(
                ready=True, restarts=4, state="running", reason=None,
                exit_code=0, term_reason="Completed",
            )],
            "ok": [healthy()],
        },
    )
    ctx = bound()
    run(ctx, model(), cluster)
    _, report = report_of(ctx)

    assert _described(cluster) == ["oom", "pull", "quiet", "ok"]
    assert "quiet" not in _pods_for("k8s.get_logs", cluster)
    assert "ok" not in _pods_for("k8s.get_logs", cluster)
    assert "oom" in _pods_for("k8s.get_logs", cluster)
    assert "pull" in _pods_for("k8s.get_events", cluster)
    titles = {finding.title for finding in report.findings}
    assert any("OOMKilled" in title for title in titles)
    assert "Container could not be started" in titles
    assert not any(
        finding.severity == "critical" and "quiet" in finding.description
        for finding in report.findings
    )


def test_unschedulable_image_pull_and_volume_mount_are_established_from_kubernetes():
    stuck = k8s_pod("stuck", uid="11111111-1111-4111-8111-111111111111")
    pull = k8s_pod(
        "pull",
        uid="22222222-2222-4222-8222-222222222222",
        scheduled=("True", None),
        statuses=[container_status(reason="ImagePullBackOff")],
    )
    vol_uid = "33333333-3333-4333-8333-333333333333"
    mounted = k8s_pod(
        "vol",
        uid=vol_uid,
        scheduled=("True", None),
        statuses=[container_status(reason="ContainerCreating")],
        volumes=[volume("cfg")],
    )
    okay = k8s_pod(
        "ok",
        uid="44444444-4444-4444-8444-444444444444",
        phase="Running",
        scheduled=("True", None),
        statuses=[container_status(ready=True, state="running", reason=None)],
    )
    events = {
        "vol": [k8s_event(
            pod_name="vol", reason="FailedMount", message=MOUNT_MESSAGE,
            component="kubelet", uid=vol_uid,
        )],
    }
    from tests.pod_scenarios import Cluster as LiveCluster

    cluster = LiveCluster([stuck, pull, mounted, okay], events)
    ctx, snapshot, report, _audit = investigate(cluster, max_steps=10)
    described = _described(cluster)
    titles = {finding.title for finding in report.findings}

    assert set(described) == {"stuck", "pull", "vol", "ok"}
    assert "Pod could not be scheduled" in titles
    assert "Container could not be started" in titles
    assert "Pod containers cannot be created: volume mount failure" in titles
    assert ctx.completed_steps <= 10
    assert snapshot.scope.uninspected == 0
    assert snapshot.scope.unsuccessful == 0


def test_inspection_cap_leaves_the_remainder_unknown():
    assert MAX_NAMESPACE_HEALTH_INSPECTIONS == 20
    pods = {f"pod-{i:02d}": {"phase": "Running"} for i in range(21)}
    cluster = Cluster(pods=pods, containers={name: [healthy()] for name in pods})
    ctx = bound()

    run(ctx, model(), cluster)
    snapshot, report = report_of(ctx)
    grouped = attach_namespace_diagnostic(report, snapshot)
    diagnostic = grouped.namespace_diagnostic

    assert snapshot.scope.inspected == 20
    assert snapshot.scope.uninspected == 1
    assert snapshot.scope.unsuccessful == 0
    assert snapshot.scope.uninspected_pods == ("pod-20",)
    assert diagnostic is not None
    assert diagnostic.assessment_complete is False
    unknown = next(item for item in diagnostic.resources if item.coverage == "unknown")
    assert unknown.pods == ["pod-20"]
    assert any("unknown and must not be read as healthy" in note for note in report.uncertainties)


def test_deadline_stops_the_pass_and_leaves_pods_unknown():
    pods = {f"pod-{i}": {"phase": "Running"} for i in range(3)}
    cluster = Cluster(pods=pods, containers={name: [healthy()] for name in pods})
    ctx = bound()
    clock = iter((0.0, 30.0))

    steps, fatal = discover_namespace_health(
        ctx,
        audit=lambda _event: None,
        executor=cluster,
        request_id_factory=lambda: "health",
        clock=lambda: next(clock),
    )

    assert fatal is None
    assert [step.proposed_call.name for step in steps] == ["k8s.get_pods"]
    assert ctx.completed_steps == 0
    snapshot, _report = report_of(ctx)
    assert snapshot.scope.inspected == 0
    assert snapshot.scope.uninspected == 3


def test_one_describe_failure_does_not_stop_the_others_or_count_as_healthy():
    pods = {"a-pod": {"phase": "Running"}, "b-pod": {"phase": "Running"}}
    cluster = Cluster(
        pods=pods,
        containers={"b-pod": [healthy()]},
        errors={("k8s.describe_pod", "a-pod"): "ApiException: (500) internal"},
    )
    ctx = bound()

    result = run(ctx, model(), cluster)
    snapshot, report = report_of(ctx)

    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert _described(cluster) == ["a-pod", "b-pod"]
    assert ctx.health_outcomes == {"a-pod": "failed", "b-pod": "inspected"}
    assert snapshot.scope.unsuccessful == 1
    assert snapshot.scope.unsuccessful_pods == ("a-pod",)
    assert snapshot.scope.uninspected == 0
    assert any("did not succeed" in note for note in report.uncertainties)
    assert not any(
        finding.title.lower().startswith("pod phase") and "a-pod" in finding.description
        for finding in report.findings
    )


def test_a_truncated_listing_is_used_and_disclosed():
    class Truncated(Cluster):
        def __call__(self, call):
            result = super().__call__(call)

            if call.name != "k8s.get_pods":
                return result

            output = dict(result.output)
            output["listing_truncated"] = True

            return result.model_copy(update={"output": output})

    cluster = Truncated(pods={"only": {"phase": "Running"}}, containers={"only": [healthy()]})
    ctx = bound()
    run(ctx, model(), cluster)
    snapshot, report = report_of(ctx)

    assert _described(cluster) == ["only"]
    assert snapshot.scope.listing_truncated is True
    assert any("longer than one API page" in note for note in report.uncertainties)
    grouped = attach_namespace_diagnostic(report, snapshot)
    assert grouped.namespace_diagnostic.assessment_complete is False


def test_get_pods_keeps_one_page_when_the_api_list_continues(monkeypatch):
    pod = SimpleNamespace(
        metadata=SimpleNamespace(name="kept", namespace=NS),
        status=SimpleNamespace(
            phase="Running",
            pod_ip=None,
            container_statuses=[],
            conditions=[],
        ),
        spec=SimpleNamespace(node_name="node-a"),
    )
    response = SimpleNamespace(metadata=SimpleNamespace(_continue="next-page"), items=[pod])
    monkeypatch.setattr(
        handlers, "core_v1", lambda: SimpleNamespace(list_namespaced_pod=lambda **_: response)
    )
    monkeypatch.setattr(handlers, "_pod_workloads", lambda *_args: {})

    output = handlers.get_pods(SimpleNamespace(namespace=NS))

    assert output["listing_truncated"] is True
    assert [item["name"] for item in output["pods"]] == ["kept"]


class _LoggingCluster(Cluster):
    def __call__(self, call):
        if call.name != "k8s.get_logs":
            return super().__call__(call)

        self.calls.append(call)
        pod = call.arguments["pod"]

        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.SUCCESS,
            output={
                "namespace": NS,
                "pod": pod,
                "container": call.arguments.get("container"),
                "previous": False,
                "logs": "terminated",
                "completeness": "bounded_unknown",
            },
        )


def test_health_inspected_workloads_are_disclosed_when_analysis_does_not_reach_them():
    pods = {
        "pod-a": {"phase": "Running", "containers_total": 1, "containers_ready": 0, "restart_count": 3},
        "pod-b": {"phase": "Running", "containers_total": 1, "containers_ready": 0, "restart_count": 1},
    }
    cluster = _LoggingCluster(pods=pods, containers={name: [container()] for name in pods})
    ctx = bound(max_steps=1)

    run(ctx, model(), cluster)
    snapshot, report = report_of(ctx)
    grouped = attach_namespace_diagnostic(report, snapshot)
    by_pod = {
        resource.pods[0]: resource
        for resource in grouped.namespace_diagnostic.resources
    }

    assert set(_described(cluster)) == {"pod-a", "pod-b"}
    assert ctx.completed_steps == 1
    assert by_pod["pod-a"].coverage == "established"
    assert by_pod["pod-b"].coverage == "established"
    assert by_pod["pod-a"].deeply_investigated is True
    assert by_pod["pod-b"].deeply_investigated is False


def test_discovery_uses_the_audited_execution_path():
    cluster = Cluster(containers={POD: [healthy()]})
    events = []
    ctx = bound()

    run(ctx, model(), cluster, events)

    describe_events = [event for event in events if event.tool == "k8s.describe_pod"]
    assert [event.phase for event in describe_events] == [
        "proposed", "authorized", "execution_started", "completed",
    ]
    assert all("-health-" in event.request_id for event in describe_events)
    assert ctx.completed_steps == 0
