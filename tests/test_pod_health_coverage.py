"""Minimum container-health coverage for workload investigations.

Regression for a live investigation that never called k8s.describe_pod, so an
OOMKilled container (exit code 137, 81 restarts, CrashLoopBackOff) produced no
phase, readiness, restart or termination evidence.

The real controller, binder grounding, scope checks, step budget, observation
extraction and report builder run. Only the Kubernetes executor and the
proposal model are stubbed.
"""

from types import SimpleNamespace

import pytest

from app.reports.grounding import build_grounded_report
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.tools import handlers
from app.tools.coverage import (
    MAX_HEALTH_INSPECTIONS,
    SUPPLEMENTARY_TOOLS,
    CoverageProvider,
    health_inspection_allowance,
    pending_health_inspections,
)
from app.tools.investigation import InvestigationContext
from app.tools.investigation_controller import (
    InvestigationStopReason,
    is_credential_failure,
    run_investigation,
)
from app.tools.investigation_scope import create_bound_investigation_context
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.observations import MEMORY_QUANTITY, observations_from_execution

NS = "ai-ops-demo"
POD = "memory-hog-5f46c8f8d6-mxq6x"
QUESTION = "Investigate the health of the platform"

GET_PODS = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})


def describe(pod):
    return ToolCall(name="k8s.describe_pod", arguments={"namespace": NS, "pod": pod})


def bound(max_steps=6):
    return create_bound_investigation_context(QUESTION, namespace=NS, max_steps=max_steps)


def container(
    name="app", *, ready=False, restarts=81, state="waiting", reason="CrashLoopBackOff",
    exit_code=137, term_reason="OOMKilled", memory_limit="32Mi", memory_request="16Mi",
):
    data = {
        "name": name,
        "ready": ready,
        "restart_count": restarts,
        "state": state,
        "reason": reason,
        "last_termination": (
            None if exit_code is None else {"exit_code": exit_code, "reason": term_reason}
        ),
        "resources": {"memory_request": memory_request, "memory_limit": memory_limit},
    }
    return {k: v for k, v in data.items() if v is not None}


def healthy():
    return container(ready=True, restarts=0, state="running", reason=None, exit_code=None,
                     term_reason=None)


class Cluster:
    """Stub executor recording every call it is actually asked to run."""

    def __init__(self, pods=None, containers=None, errors=None):
        # name -> advisory list-time hints (phase, counts)
        self.pods = pods if pods is not None else {POD: {"phase": "Running"}}
        self.containers = containers or {}
        self.errors = errors or {}
        self.calls: list[ToolCall] = []

    @property
    def names(self):
        return [c.name for c in self.calls]

    def described(self):
        return [c.arguments["pod"] for c in self.calls if c.name == "k8s.describe_pod"]

    def __call__(self, call):
        self.calls.append(call)
        error = self.errors.get((call.name, call.arguments.get("pod"))) or self.errors.get(call.name)

        if error:
            return ToolExecutionResult(
                tool=call.name, status=ToolExecutionStatus.ERROR, error=error
            )

        if call.name == "k8s.get_pods":
            output = {
                "namespace": NS,
                "pods": [{"name": n, "namespace": NS, **h} for n, h in self.pods.items()],
            }
        elif call.name == "k8s.describe_pod":
            pod = call.arguments["pod"]
            output = {
                "namespace": NS,
                "name": pod,
                "phase": self.pods.get(pod, {}).get("phase", "Running"),
                "containers": self.containers.get(pod, [container()]),
            }
        else:
            output = {}

        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.SUCCESS, output=output
        )


def model(*calls):
    queue = list(calls)

    def provider(context, steps):
        return queue.pop(0) if queue else None

    return provider


def run(ctx, proposals, cluster, events=None):
    return run_investigation(
        context=ctx,
        provider=CoverageProvider(proposals),
        audit=(events if events is not None else []).append,
        executor=cluster,
        tolerated_failure_tools=SUPPLEMENTARY_TOOLS,
    )


def report_of(ctx):
    snapshot = build_investigation_evidence_snapshot(ctx)
    return snapshot, build_grounded_report(snapshot)


def observed(ctx, field):
    return [o.value for o in ctx.observations if o.tool == "k8s.describe_pod" and o.field == field]


# ======================================================== the original failure


def test_model_finishing_right_after_discovery_still_gets_pod_health_inspected():
    ctx, cluster = bound(), Cluster()

    result = run(ctx, model(GET_PODS), cluster)  # the model then proposes finish

    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert cluster.described() == [POD]
    assert observed(ctx, "pod.phase") == ["Running"]


def test_model_proposing_nothing_still_gets_deterministic_health_discovery():
    ctx, cluster = bound(), Cluster(containers={POD: [healthy()]})

    run(ctx, model(), cluster)

    # Basic health does not wait for the model and does not spend analysis steps.
    assert cluster.names == ["k8s.get_pods", "k8s.describe_pod"]
    assert ctx.completed_steps == 0


def test_health_inspection_runs_before_model_chosen_follow_on_calls():
    ctx, cluster = bound(), Cluster()
    events_call = ToolCall(name="k8s.get_events", arguments={"namespace": NS})

    run(ctx, model(GET_PODS, events_call), cluster)

    assert cluster.names[:3] == ["k8s.get_pods", "k8s.describe_pod", "k8s.get_events"]


# =================================================== OOMKilled / exit code 137


def test_oomkilled_with_exit_137_reaches_trusted_observations_without_any_logs():
    ctx, cluster = bound(), Cluster()

    run(ctx, model(GET_PODS), cluster)

    assert observed(ctx, "containers[app].last_termination.reason") == ["OOMKilled"]
    assert observed(ctx, "containers[app].last_termination.exit_code") == [137]
    assert observed(ctx, "containers[app].restart_count") == [81]
    assert observed(ctx, "containers[app].reason") == ["CrashLoopBackOff"]
    assert observed(ctx, "containers[app].state") == ["waiting"]
    assert observed(ctx, "containers[app].ready") == [False]


def test_oomkilled_crash_loop_is_a_critical_finding_with_all_the_evidence_cited():
    ctx, cluster = bound(), Cluster()
    run(ctx, model(GET_PODS), cluster)

    snapshot, report = report_of(ctx)
    oom = [f for f in report.findings if "OOMKilled" in f.title]

    assert len(oom) == 1 and oom[0].severity == "critical"
    text = oom[0].description
    assert "'OOMKilled'" in text and "exit code 137" in text
    assert "restarted 81 times" in text and "CrashLoopBackOff" in text
    assert "memory limit of 32Mi" in text and "memory request of 16Mi" in text
    assert f"pod '{POD}'" in text

    by_id = {e.evidence_id: e for e in snapshot.evidence}
    cited = {by_id[r.evidence_id].field for r in oom[0].evidence}
    assert {
        "containers[app].last_termination.reason",
        "containers[app].last_termination.exit_code",
        "containers[app].restart_count",
        "containers[app].reason",
        "containers[app].resources.memory_limit",
    } <= cited
    assert "k8s.get_logs" not in {e.tool for e in snapshot.evidence}  # no log text needed


def test_oomkilled_container_that_recovered_is_a_warning_not_critical():
    ctx = bound()
    cluster = Cluster(containers={POD: [container(
        ready=True, restarts=1, state="running", reason=None,
    )]})
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)
    oom = [f for f in report.findings if "OOMKilled" in f.title]

    assert [f.severity for f in oom] == ["warning"]
    assert "restarted 1 time." in oom[0].description  # singular


def test_oomkilled_is_ranked_ahead_of_informational_findings_in_the_summary():
    ctx, cluster = bound(), Cluster()
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)

    assert "1 critical" in report.summary
    assert "1. [critical] Container previously terminated as OOMKilled" in report.summary


def test_memory_limit_is_never_described_as_observed_usage():
    ctx, cluster = bound(), Cluster()
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)
    declared = [f for f in report.findings if f.title.startswith("Container memory")]

    assert {f.title for f in declared} == {
        "Container memory limit declared",
        "Container memory request declared",
    }
    for finding in declared:
        assert "configured value, not observed memory usage" in finding.description

    oom = next(f for f in report.findings if "OOMKilled" in f.title)
    assert "not measured memory usage" in oom.description
    assert "peak" not in oom.description.lower()


def test_oomkilled_without_declared_memory_resources_still_reports_cleanly():
    ctx = bound()
    cluster = Cluster(containers={POD: [container(memory_limit=None, memory_request=None)]})
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)
    oom = next(f for f in report.findings if "OOMKilled" in f.title)

    assert "memory limit" not in oom.description and "declares" not in oom.description
    assert not [f for f in report.findings if f.title.startswith("Container memory")]


def test_non_oom_termination_gets_no_oom_finding():
    ctx = bound()
    cluster = Cluster(containers={POD: [container(exit_code=1, term_reason="Error")]})
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)

    assert not [f for f in report.findings if "OOMKilled" in f.title]


# ===================================== CrashLoopBackOff with repeated restarts


def test_crashloop_with_repeated_restarts_is_inspected_and_followed_up():
    ctx = bound()
    cluster = Cluster(containers={POD: [container(restarts=12, exit_code=1, term_reason="Error")]})

    run(ctx, model(GET_PODS), cluster)

    assert observed(ctx, "containers[app].restart_count") == [12]
    assert observed(ctx, "containers[app].reason") == ["CrashLoopBackOff"]
    # The existing failing-container follow-up now has the evidence it needs.
    assert cluster.names == [
        "k8s.get_pods", "k8s.describe_pod", "k8s.get_logs", "k8s.describe_workload_config",
    ]
    _, report = report_of(ctx)
    assert any(f.title == "Container restart count observed" for f in report.findings)


def test_healthy_pod_is_inspected_and_reports_no_failure():
    ctx = bound()
    cluster = Cluster(containers={POD: [healthy()]})

    run(ctx, model(GET_PODS), cluster)

    assert cluster.names == ["k8s.get_pods", "k8s.describe_pod"]
    _, report = report_of(ctx)
    assert not [f for f in report.findings if f.severity in {"warning", "critical"}]


# ================================================ discovered but not described


def analysis_only(max_steps=6):
    """The in-loop allowance, used when namespace health discovery is off."""
    ctx = bound(max_steps)
    object.__setattr__(ctx, "namespace_health_discovery", False)
    return ctx


def discover_only(ctx, pods=None):
    """Record a successful get_pods execution, with no inspection yet."""
    pods = pods if pods is not None else {POD: {"phase": "Running"}}
    ctx.record_execution(
        request_id="discover",
        call=GET_PODS,
        result=ToolExecutionResult(
            tool=GET_PODS.name,
            status=ToolExecutionStatus.SUCCESS,
            output={"namespace": NS, "pods": [{"name": n, **h} for n, h in pods.items()]},
        ),
    )


def test_discovered_pod_with_no_inspection_is_owed_a_describe_call():
    ctx = analysis_only()
    discover_only(ctx)

    assert pending_health_inspections(ctx, ()) == [describe(POD)]


def test_pending_inspection_is_an_ordinary_toolcall_for_the_authorized_namespace_only():
    ctx = analysis_only()
    discover_only(ctx)

    calls = pending_health_inspections(ctx, ())

    assert calls and all(isinstance(c, ToolCall) for c in calls)
    assert all(c.name == "k8s.describe_pod" for c in calls)
    assert all(c.arguments == {"namespace": NS, "pod": POD} for c in calls)


def test_nothing_is_owed_before_any_pod_is_discovered():
    assert pending_health_inspections(analysis_only(), ()) == []


def test_namespace_discovery_does_not_spend_the_analysis_allowance():
    ctx = bound()
    discover_only(ctx)

    assert pending_health_inspections(ctx, ()) == []


# ====================================================== step budget and caps


@pytest.mark.parametrize(
    "max_steps, allowance",
    [(1, 1), (2, 1), (3, 1), (4, 2), (6, 3), (8, 4), (10, 4)],
)
def test_allowance_is_at_most_half_the_budget_and_hard_capped(max_steps, allowance):
    assert health_inspection_allowance(max_steps) == allowance
    assert allowance <= MAX_HEALTH_INSPECTIONS


def test_two_step_budget_still_limits_analysis_after_every_pod_is_inspected():
    ctx = bound(max_steps=2)
    names = {f"pod-{i}": {"phase": "Running"} for i in range(5)}
    cluster = Cluster(pods=names, containers={name: [healthy()] for name in names})

    result = run(ctx, model(GET_PODS), cluster)

    assert cluster.described() == [f"pod-{i}" for i in range(5)]
    assert ctx.completed_steps == 0
    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED


def test_automatic_inspection_does_not_spend_the_analysis_step_budget():
    ctx = bound(max_steps=6)
    names = {f"pod-{i}": {"phase": "Running"} for i in range(9)}
    cluster = Cluster(pods=names, containers={name: [healthy()] for name in names})

    run(ctx, model(GET_PODS), cluster)

    assert ctx.completed_steps <= 6
    assert len(cluster.described()) == 9
    assert len(cluster.described()) > health_inspection_allowance(6)


def test_budget_keeps_room_for_failing_container_follow_ups():
    ctx = bound(max_steps=6)
    cluster = Cluster(
        pods={f"pod-{i}": {"phase": "Running"} for i in range(5)},
        containers={f"pod-{i}": [container(restarts=5, exit_code=1, term_reason="Error")]
                    for i in range(5)},
    )

    run(ctx, model(GET_PODS), cluster)

    assert "k8s.get_logs" in cluster.names  # follow-up budget was not starved


# ============================================================== multiple pods


def multi_pods():
    return {
        "f-healthy": {"phase": "Running", "containers_total": 1, "containers_ready": 1, "restart_count": 0},
        "a-healthy": {"phase": "Running", "containers_total": 1, "containers_ready": 1, "restart_count": 0},
        "d-done": {"phase": "Succeeded", "containers_total": 1, "containers_ready": 0, "restart_count": 0},
        "e-restarted": {"phase": "Running", "containers_total": 1, "containers_ready": 1, "restart_count": 2},
        "c-pending": {"phase": "Pending", "containers_total": 1, "containers_ready": 0, "restart_count": 0},
        "b-crashing": {"phase": "Running", "containers_total": 1, "containers_ready": 0, "restart_count": 80},
    }


def test_multiple_pods_are_prioritized_deterministically_most_unhealthy_first():
    ctx = bound(max_steps=10)
    cluster = Cluster(pods=multi_pods(), containers={
        n: [healthy()] for n in multi_pods()
    })

    run(ctx, model(GET_PODS), cluster)

    assert cluster.described() == [
        "b-crashing", "c-pending", "e-restarted", "a-healthy", "f-healthy", "d-done",
    ]


def test_prioritization_does_not_depend_on_the_order_pods_were_listed():
    orders = []

    for names in (list(multi_pods()), list(reversed(list(multi_pods())))):
        pods = {n: multi_pods()[n] for n in names}
        ctx = bound(max_steps=10)
        cluster = Cluster(pods=pods, containers={n: [healthy()] for n in pods})
        run(ctx, model(GET_PODS), cluster)
        orders.append(cluster.described())

    assert orders[0] == orders[1]


def test_pods_not_inspected_are_disclosed_by_name_and_never_called_healthy():
    ctx = bound(max_steps=10)
    pods = {f"pod-{i:02d}": {"phase": "Running"} for i in range(25)}
    cluster = Cluster(pods=pods, containers={n: [healthy()] for n in pods})
    run(ctx, model(GET_PODS), cluster)

    _, report = report_of(ctx)
    note = next(u for u in report.uncertainties if "not health-inspected" in u)

    assert "5 of 25 pod(s)" in note
    assert "'pod-20'" in note and "'pod-24'" in note
    assert "unknown and must not be read as healthy" in note
    assert "'pod-00'" not in note  # inspected ones are not listed


def test_full_coverage_has_no_not_inspected_disclosure():
    ctx = bound()
    run(ctx, model(GET_PODS), Cluster())

    _, report = report_of(ctx)

    assert not [u for u in report.uncertainties if "not health-inspected" in u]


def test_long_lists_of_uninspected_pods_are_summarized():
    ctx = bound(max_steps=10)
    pods = {f"pod-{i:02d}": {"phase": "Running"} for i in range(30)}
    run(ctx, model(GET_PODS), Cluster(pods=pods, containers={n: [healthy()] for n in pods}))

    _, report = report_of(ctx)
    note = next(u for u in report.uncertainties if "not health-inspected" in u)

    assert "10 of 30 pod(s)" in note and "and 5 more" in note


# ================================================ duplicate inspection prevention


def test_model_inspecting_a_pod_first_is_not_duplicated_by_the_policy():
    ctx, cluster = bound(), Cluster()

    run(ctx, model(GET_PODS, describe(POD)), cluster)

    assert cluster.described() == [POD]


def test_a_failed_inspection_is_never_retried():
    ctx = bound()
    cluster = Cluster(errors={("k8s.describe_pod", POD): "NotFoundException: pod gone"})

    result = run(ctx, model(GET_PODS), cluster)

    assert cluster.described() == [POD]  # exactly one attempt
    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED


def test_every_pod_is_inspected_at_most_once_across_the_whole_run():
    ctx = bound(max_steps=10)
    cluster = Cluster(pods=multi_pods(), containers={n: [healthy()] for n in multi_pods()})

    run(ctx, model(GET_PODS, describe("a-healthy"), describe("a-healthy")), cluster)

    described = cluster.described()
    assert len(described) == len(set(described))
    assert described.count("b-crashing") == 1 and described.count("a-healthy") == 1


# ============================================ failures: no fabricated evidence


def test_failed_inspection_mints_no_observations_and_the_pod_is_not_called_healthy():
    ctx = bound()
    cluster = Cluster(errors={"k8s.describe_pod": "NotFoundException: (404) not found"})

    run(ctx, model(GET_PODS), cluster)

    assert [o for o in ctx.observations if o.tool == "k8s.describe_pod"] == []
    snapshot, report = report_of(ctx)
    assert not [e for e in snapshot.evidence if e.tool == "k8s.describe_pod"]
    assert not [f for f in report.findings if "phase" in f.title.lower()
                or "readiness" in f.title.lower() or "restart" in f.title.lower()]
    assert any(f"Pod '{POD}'" in u and "phase has not been established" in u
               for u in report.uncertainties)
    assert any("not health-inspected" in u for u in report.uncertainties)


def test_a_failed_pod_does_not_discard_evidence_about_the_other_pods():
    ctx = bound(max_steps=10)
    pods = {"a-pod": {"phase": "Running"}, "b-pod": {"phase": "Running"}}
    cluster = Cluster(
        pods=pods,
        containers={"b-pod": [container()]},
        errors={("k8s.describe_pod", "a-pod"): "NotFoundException: (404)"},
    )

    result = run(ctx, model(GET_PODS), cluster)

    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert cluster.described() == ["a-pod", "b-pod"]
    _, report = report_of(ctx)
    assert any("OOMKilled" in f.title for f in report.findings)
    note = next(u for u in report.uncertainties if "not health-inspected" in u)
    assert "'a-pod'" in note and "'b-pod'" not in note


def test_unauthorized_401_fails_the_whole_run_and_mints_nothing():
    ctx = bound(max_steps=10)
    cluster = Cluster(
        pods={"a": {"phase": "Running"}, "b": {"phase": "Running"}},
        errors={"k8s.describe_pod": "UnauthorizedException: (401)\nReason: Unauthorized"},
    )

    result = run(ctx, model(GET_PODS), cluster)

    assert result.stop_reason == InvestigationStopReason.TOOL_FAILED
    assert cluster.described() == ["a"]  # no second pod, no retry
    assert [o for o in ctx.observations if o.tool == "k8s.describe_pod"] == []


def test_a_401_is_fatal_even_for_a_tolerated_supplementary_tool():
    ctx = bound()
    cluster = Cluster(
        containers={POD: [container(restarts=3, exit_code=1, term_reason="Error")]},
        errors={"k8s.get_logs": "UnauthorizedException: (401)"},
    )

    result = run(ctx, model(GET_PODS), cluster)

    assert result.stop_reason == InvestigationStopReason.TOOL_FAILED
    assert "k8s.describe_workload_config" not in cluster.names


def test_forbidden_403_stops_further_automatic_inspection_but_does_not_fail_the_run():
    ctx = bound(max_steps=10)
    cluster = Cluster(
        pods={"a": {"phase": "Running"}, "b": {"phase": "Running"}, "c": {"phase": "Running"}},
        errors={"k8s.describe_pod": 'ForbiddenException: (403) pods "a" is forbidden'},
    )

    result = run(ctx, model(GET_PODS), cluster)

    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert cluster.described() == ["a"]  # denied once; the budget is not burned on the rest
    _, report = report_of(ctx)
    note = next(u for u in report.uncertainties if "not health-inspected" in u)
    assert "3 of 3 pod(s)" in note


def test_credential_failure_classifier():
    def result(error, status=ToolExecutionStatus.ERROR):
        return ToolExecutionResult(tool="k8s.get_pods", status=status, error=error)

    assert is_credential_failure(result("UnauthorizedException: (401)"))
    assert not is_credential_failure(result("ForbiddenException: (403)"))
    assert not is_credential_failure(result("NotFoundException: (404)"))
    assert not is_credential_failure(result(None))
    assert not is_credential_failure(
        ToolExecutionResult(tool="k8s.get_pods", status=ToolExecutionStatus.SUCCESS, output={})
    )


# ====================================================== boundaries unchanged


def test_policy_proposals_flow_through_the_full_audit_pipeline():
    ctx, cluster, events = bound(), Cluster(), []

    run(ctx, model(GET_PODS), cluster, events)

    describe_events = [e for e in events if e.tool == "k8s.describe_pod"]
    assert [e.phase for e in describe_events] == [
        "proposed", "authorized", "execution_started", "completed",
    ]
    assert all(e.arguments["namespace"] == NS for e in describe_events)


def test_pods_observed_in_another_namespace_are_never_considered():
    from app.tools.coverage import discovered_pods
    from app.tools.observations import TrustedToolObservation

    def obs(namespace, pod):
        return TrustedToolObservation(
            request_id="r", tool="k8s.get_pods", field="pods[].name",
            value=pod, namespace=namespace, pod=pod,
        )

    # The public recording path cannot even mint such an observation (the
    # execution scope check rejects it), so this probes the policy directly.
    stub = SimpleNamespace(
        observations=[obs(NS, "mine"), obs("production", "theirs"), obs(None, "nowhere")],
        require_authorized_namespace=lambda: NS,
    )

    assert discovered_pods(stub) == ["mine"]


def test_other_tools_observations_never_count_as_discovered_pods():
    from app.tools.coverage import discovered_pods
    from app.tools.observations import TrustedToolObservation

    stub = SimpleNamespace(
        observations=[
            TrustedToolObservation(request_id="r", tool="k8s.describe_pod",
                                   field="pods[].name", value="x", namespace=NS, pod="x"),
            TrustedToolObservation(request_id="r", tool="k8s.get_pods",
                                   field="pod.phase", value="y", namespace=NS, pod="y"),
        ],
        require_authorized_namespace=lambda: NS,
    )

    assert discovered_pods(stub) == []


def test_malformed_pod_names_are_never_proposed():
    ctx = bound()
    cluster = Cluster(pods={"Bad_Name": {}, "../etc": {}, "ok-pod": {"phase": "Running"}})

    run(ctx, model(GET_PODS), cluster)

    assert cluster.described() == ["ok-pod"]


def test_contexts_without_an_application_bound_kind_are_never_widened():
    # Text-derived authority may have been narrowed to one operation by the
    # user; the coverage policy must not add calls to such a context.
    legacy = InvestigationContext(
        investigation_id="legacy",
        user_text=f"Investigate the failing workload in namespace {NS}.",
        authorized_namespace=NS,
        max_steps=6,
    )
    cluster = Cluster()

    run(legacy, model(GET_PODS), cluster)

    assert cluster.names == ["k8s.get_pods"]


def test_policy_cannot_reach_other_tools_or_namespaces():
    ctx, cluster = bound(max_steps=10), Cluster(pods=multi_pods(),
        containers={n: [healthy()] for n in multi_pods()})

    run(ctx, model(GET_PODS), cluster)

    allowed = {"k8s.get_pods", "k8s.describe_pod", "k8s.get_logs", "k8s.describe_workload_config"}
    assert set(cluster.names) <= allowed
    assert all(c.arguments["namespace"] == NS for c in cluster.calls)


def test_every_finding_cites_evidence_that_exists_in_the_snapshot():
    ctx, cluster = bound(), Cluster()
    run(ctx, model(GET_PODS), cluster)

    snapshot, report = report_of(ctx)
    ids = {e.evidence_id for e in snapshot.evidence}

    assert report.findings
    for finding in report.findings:
        assert finding.evidence
        assert {r.evidence_id for r in finding.evidence} <= ids


def test_model_proposing_a_describe_in_another_namespace_is_still_rejected():
    from app.tools.investigation import InvestigationScopeError

    ctx, cluster = bound(), Cluster()
    hostile = ToolCall(name="k8s.describe_pod", arguments={"namespace": "production", "pod": POD})

    with pytest.raises(InvestigationScopeError):
        run(ctx, model(GET_PODS, hostile), cluster)

    assert "production" not in {c.arguments.get("namespace") for c in cluster.calls}


# ============================================ resource metadata and the handler


@pytest.mark.parametrize("value", ["16Mi", "32Mi", "1Gi", "128974848", "0.5Gi", "129e6", "512M", "1500m"])
def test_valid_memory_quantities_are_accepted(value):
    assert MEMORY_QUANTITY.fullmatch(value)


@pytest.mark.parametrize(
    "value",
    ["", "abc", "32 Mi", "32Mi; rm -rf /", "$(id)", "-1Mi", "32MiB", "1e", "9" * 40,
     "<script>", "32Mi\n", "32mi"],
)
def test_malformed_memory_quantities_never_become_evidence(value):
    call = describe(POD)
    result = ToolExecutionResult(
        tool=call.name, status=ToolExecutionStatus.SUCCESS,
        output={
            "namespace": NS, "name": POD, "phase": "Running",
            "containers": [{"name": "app", "ready": True, "restart_count": 0,
                            "resources": {"memory_limit": value, "memory_request": value}}],
        },
    )

    minted = observations_from_execution(request_id="r", call=call, result=result)

    assert not [o for o in minted if "resources" in o.field]


def test_non_string_memory_values_never_become_evidence():
    call = describe(POD)
    result = ToolExecutionResult(
        tool=call.name, status=ToolExecutionStatus.SUCCESS,
        output={"namespace": NS, "name": POD, "containers": [
            {"name": "app", "resources": {"memory_limit": 33554432, "memory_request": {"x": 1}}},
        ]},
    )

    assert not [o for o in observations_from_execution(request_id="r", call=call, result=result)
                if "resources" in o.field]


def fake_pod(*, env=True):
    spec = SimpleNamespace(
        name="app",
        resources=SimpleNamespace(requests={"memory": "16Mi", "cpu": "50m"},
                                  limits={"memory": "32Mi"}),
        env=[SimpleNamespace(name="TOKEN", value="super-secret-value")] if env else None,
        command=["sh", "-c", "echo secret-command"],
    )
    status = SimpleNamespace(
        name="app", ready=False, restart_count=81,
        state=SimpleNamespace(waiting=SimpleNamespace(reason="CrashLoopBackOff", message="back-off"),
                              running=None, terminated=None),
        last_state=SimpleNamespace(terminated=SimpleNamespace(
            reason="OOMKilled", message=None, exit_code=137)),
    )
    return SimpleNamespace(
        metadata=SimpleNamespace(name=POD, namespace=NS),
        spec=SimpleNamespace(node_name="node-1", containers=[spec]),
        status=SimpleNamespace(phase="Running", pod_ip="10.0.0.1",
                               container_statuses=[status], conditions=[]),
    )


def test_describe_pod_handler_returns_state_termination_and_declared_memory(monkeypatch):
    pod = fake_pod()
    monkeypatch.setattr(handlers, "core_v1", lambda: SimpleNamespace(
        read_namespaced_pod=lambda **_: pod))

    output = handlers.describe_pod(SimpleNamespace(pod=POD, namespace=NS))
    only = output["containers"][0]

    assert only["state"] == "waiting" and only["reason"] == "CrashLoopBackOff"
    assert only["restart_count"] == 81
    assert only["last_termination"]["reason"] == "OOMKilled"
    assert only["last_termination"]["exit_code"] == 137
    assert only["resources"] == {"memory_request": "16Mi", "memory_limit": "32Mi"}


def test_describe_pod_handler_exposes_no_environment_values_commands_or_cpu(monkeypatch):
    monkeypatch.setattr(handlers, "core_v1", lambda: SimpleNamespace(
        read_namespaced_pod=lambda **_: fake_pod()))

    output = handlers.describe_pod(SimpleNamespace(pod=POD, namespace=NS))
    blob = repr(output)

    assert "super-secret-value" not in blob and "echo secret-command" not in blob
    assert "TOKEN" not in blob and "50m" not in blob
    assert set(output["containers"][0]["resources"]) == {"memory_request", "memory_limit"}


def test_describe_pod_handler_tolerates_containers_without_resources(monkeypatch):
    pod = fake_pod()
    pod.spec.containers[0].resources = None
    monkeypatch.setattr(handlers, "core_v1", lambda: SimpleNamespace(
        read_namespaced_pod=lambda **_: pod))

    output = handlers.describe_pod(SimpleNamespace(pod=POD, namespace=NS))

    assert output["containers"][0]["resources"] == {"memory_request": None, "memory_limit": None}


def test_get_pods_handler_adds_ordering_counts_without_changing_its_identity_fields(monkeypatch):
    pod = fake_pod()
    pod.status.container_statuses.append(SimpleNamespace(name="side", ready=True, restart_count=2))
    response = SimpleNamespace(metadata=SimpleNamespace(_continue=None), items=[pod])
    monkeypatch.setattr(handlers, "core_v1", lambda: SimpleNamespace(
        list_namespaced_pod=lambda **_: response))

    entry = handlers.get_pods(SimpleNamespace(namespace=NS))["pods"][0]

    assert entry["name"] == POD and entry["phase"] == "Running"
    assert (entry["containers_total"], entry["containers_ready"], entry["restart_count"]) == (2, 1, 83)


def test_get_pods_counts_are_ordering_hints_not_evidence():
    call = GET_PODS
    result = ToolExecutionResult(
        tool=call.name, status=ToolExecutionStatus.SUCCESS,
        output={"namespace": NS, "pods": [
            {"name": POD, "phase": "Running", "containers_total": 1,
             "containers_ready": 0, "restart_count": 81}]},
    )

    fields = {o.field for o in observations_from_execution(request_id="r", call=call, result=result)}

    assert fields == {"pods[].name"}
