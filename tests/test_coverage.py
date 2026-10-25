"""Deterministic coverage policy: log/config follow-up for failing containers.

No cluster, database or model. The real controller, binder grounding, scope
checks and step budget run; only the executor and proposal model are stubbed.
"""

import pytest

from app.tools.coverage import (
    SUPPLEMENTARY_TOOLS,
    CoverageProvider,
    failing_containers,
)
from app.tools.investigation import InvestigationContext
from app.tools.investigation_controller import (
    InvestigationStopReason,
    run_investigation,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus

NS = "ai-ops-demo"


def make_context(max_steps=6):
    return InvestigationContext(
        investigation_id="inv-coverage",
        user_text=f"Investigate the failing workload in namespace {NS}.",
        authorized_namespace=NS,
        max_steps=max_steps,
    )


def container(name="app", *, ready=False, restarts=3, state="waiting",
              reason="CrashLoopBackOff", exit_code=1, term_reason="Error"):
    data = {
        "name": name,
        "ready": ready,
        "restart_count": restarts,
        "state": state,
        "reason": reason,
        "last_termination": (
            None if exit_code is None
            else {"exit_code": exit_code, "reason": term_reason}
        ),
    }
    return {k: v for k, v in data.items() if v is not None}


class Cluster:
    """Stub executor that records every call it is actually asked to run."""

    def __init__(self, containers, fail=()):
        self.containers = containers
        self.fail = set(fail)
        self.calls: list[ToolCall] = []

    def __call__(self, call: ToolCall) -> ToolExecutionResult:
        self.calls.append(call)

        if call.name in self.fail:
            return ToolExecutionResult(
                tool=call.name, status=ToolExecutionStatus.ERROR,
                output=None, error="boom",
            )

        if call.name == "k8s.get_pods":
            output = {"namespace": NS, "pods": [{"name": "web-1"}]}
        elif call.name == "k8s.describe_pod":
            output = {
                "namespace": NS, "name": "web-1", "phase": "Running",
                "containers": self.containers,
            }
        elif call.name == "k8s.get_logs":
            output = {"namespace": NS, "pod": "web-1", "logs": "x\n"}
        else:
            output = {}

        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.SUCCESS, output=output
        )

    @property
    def names(self):
        return [c.name for c in self.calls]


def model(*calls):
    """Scripted proposal model: replays calls in order, then finishes."""
    queue = list(calls)

    def provider(_context, _history):
        return queue.pop(0) if queue else None

    return provider


GET_PODS = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})
DESCRIBE = ToolCall(
    name="k8s.describe_pod", arguments={"namespace": NS, "pod": "web-1"}
)


def run(context, provider, executor, *, tolerated=SUPPLEMENTARY_TOOLS):
    ids = iter(f"req-{i:03d}" for i in range(100))
    return run_investigation(
        context=context,
        provider=CoverageProvider(provider),
        executor=executor,
        audit=lambda _event: None,
        request_id_factory=lambda: next(ids),
        tolerated_failure_tools=tolerated,
    )


def test_failing_container_gets_logs_and_config_when_model_finishes_early():
    cluster = Cluster([container()])
    ctx = make_context()

    result = run(ctx, model(GET_PODS, DESCRIBE), cluster)

    assert cluster.names == [
        "k8s.get_pods", "k8s.describe_pod",
        "k8s.get_logs", "k8s.describe_workload_config",
    ]
    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    logs_call = cluster.calls[2]
    # `container` was grounded against the observed container name; `tail`
    # is the application's own bounded default, not a model-supplied value.
    assert {k: logs_call.arguments[k] for k in ("namespace", "pod", "container")} == {
        "namespace": NS, "pod": "web-1", "container": "app",
    }
    assert 0 < logs_call.arguments["tail"] <= 1000


def test_followups_go_through_the_normal_step_budget_and_scope():
    cluster = Cluster([container()])
    ctx = make_context(max_steps=3)

    result = run(ctx, model(GET_PODS, DESCRIBE), cluster)

    # Budget is a hard ceiling: follow-ups cannot exceed it.
    assert result.stop_reason == InvestigationStopReason.STEP_BUDGET_EXHAUSTED
    assert len(cluster.calls) == 3
    assert all(c.arguments["namespace"] == NS for c in cluster.calls)


def test_budget_is_reserved_so_model_cannot_spend_it_elsewhere():
    cluster = Cluster([container()])
    ctx = make_context(max_steps=4)
    chatty = model(GET_PODS, DESCRIBE, GET_PODS, GET_PODS, GET_PODS)

    run(ctx, chatty, cluster)

    assert cluster.names[-2:] == ["k8s.get_logs", "k8s.describe_workload_config"]
    assert len(cluster.calls) == 4


@pytest.mark.parametrize(
    "spec",
    [
        # healthy
        dict(ready=True, restarts=0, state="running", reason=None, exit_code=None),
        # still being created: a normal transition, not a failure.
        # (A pre-start FAILURE such as ImagePullBackOff is diagnosed by the
        # events + configuration follow-up: tests/test_k8s_failure_classification.py)
        dict(ready=False, restarts=0, state="waiting", reason="ContainerCreating",
             exit_code=None),
    ],
)
def test_no_followup_without_failure_observations(spec):
    cluster = Cluster([container(**spec)])
    ctx = make_context()

    run(ctx, model(GET_PODS, DESCRIBE), cluster)

    assert cluster.names == ["k8s.get_pods", "k8s.describe_pod"]


def test_no_duplicate_when_model_already_retrieved_logs_and_config():
    cluster = Cluster([container()])
    ctx = make_context()
    logs = ToolCall(
        name="k8s.get_logs",
        arguments={"namespace": NS, "pod": "web-1", "container": "app"},
    )
    config = ToolCall(
        name="k8s.describe_workload_config",
        arguments={"namespace": NS, "pod": "web-1"},
    )

    run(ctx, model(GET_PODS, DESCRIBE, logs, config), cluster)

    assert cluster.names.count("k8s.get_logs") == 1
    assert cluster.names.count("k8s.describe_workload_config") == 1


def test_failed_followup_is_not_retried_and_does_not_fail_the_run():
    cluster = Cluster([container()], fail={"k8s.get_logs"})
    ctx = make_context()

    result = run(ctx, model(GET_PODS, DESCRIBE), cluster)

    assert result.stop_reason == InvestigationStopReason.PROVIDER_FINISHED
    assert cluster.names.count("k8s.get_logs") == 1
    # The run continued to the configuration inspection after the log failure.
    assert cluster.names[-1] == "k8s.describe_workload_config"
    # A failed tool minted no observations.
    assert not ctx.find_observations(field="logs.retrieved")


def test_failure_of_core_tools_still_stops_the_investigation():
    # Discovery is the core tool: without it there is nothing to inspect.
    # (A failed describe_pod is tolerated and disclosed; see
    # tests/test_pod_health_coverage.py.)
    cluster = Cluster([container()], fail={"k8s.get_pods"})
    ctx = make_context()

    result = run(ctx, model(GET_PODS, DESCRIBE), cluster)

    assert result.stop_reason == InvestigationStopReason.TOOL_FAILED
    assert cluster.names == ["k8s.get_pods"]


def test_tolerance_is_opt_in_so_default_controller_behavior_is_unchanged():
    cluster = Cluster([container()], fail={"k8s.get_logs"})
    ctx = make_context()

    result = run(ctx, model(GET_PODS, DESCRIBE), cluster, tolerated=frozenset())

    assert result.stop_reason == InvestigationStopReason.TOOL_FAILED


def test_multi_container_pod_targets_only_the_failing_container():
    cluster = Cluster([
        container("sidecar", ready=True, restarts=0, state="running",
                  reason=None, exit_code=None),
        container("app"),
    ])
    ctx = make_context()

    run(ctx, model(GET_PODS, DESCRIBE), cluster)

    logs = [c for c in cluster.calls if c.name == "k8s.get_logs"]
    assert [c.arguments["container"] for c in logs] == ["app"]


def test_model_log_call_without_container_does_not_hide_ambiguous_coverage():
    cluster = Cluster([container("app"), container("worker")])
    ctx = make_context()
    default_logs = ToolCall(
        name="k8s.get_logs", arguments={"namespace": NS, "pod": "web-1"}
    )

    run(ctx, model(GET_PODS, DESCRIBE, default_logs), cluster)

    covered = {
        c.arguments.get("container")
        for c in cluster.calls if c.name == "k8s.get_logs"
    }
    assert {"app", "worker"} <= covered


def test_failing_containers_is_workload_agnostic_and_uses_latest_values():
    from app.tools.observations import TrustedToolObservation as Obs

    def obs(field, value):
        return Obs(request_id="r", tool="k8s.describe_pod", field=field,
                   value=value, namespace=NS, pod="p")

    items = [
        obs("containers[].name", "zzz"),
        obs("containers[zzz].ready", False),
        obs("containers[zzz].restart_count", 0),
        obs("containers[zzz].last_termination.exit_code", 137),
    ]

    found = failing_containers(items)

    assert [(f.pod, f.container, f.signals) for f in found] == [
        ("p", "zzz", ("nonzero_exit",))
    ]


def test_followup_arguments_carry_no_free_text():
    cluster = Cluster([container()])
    ctx = make_context()

    run(ctx, model(GET_PODS, DESCRIBE), cluster)

    for call in cluster.calls:
        assert set(call.arguments) <= {"namespace", "pod", "container", "tail"}
        assert all(
            isinstance(v, (str, int)) and len(str(v)) <= 100
            for v in call.arguments.values()
        )
