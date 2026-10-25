"""Fake Kubernetes objects and a cluster stub for pod-level health scenarios.

The REAL handlers (`describe_pod`, `get_events`), observation extraction,
controller, coverage policy and report builder run. Only the Kubernetes client
is faked, so what the application derives is exactly what it would derive from
objects of this shape.
"""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

from app.reports.grounding import build_grounded_report
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.tools import handlers
from app.tools.coverage import SUPPLEMENTARY_TOOLS, CoverageProvider
from app.tools.investigation_controller import run_investigation
from app.tools.investigation_scope import create_bound_investigation_context
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus

NS = "ai-ops-demo"
QUESTION = "Investigate the health of the platform"
UID = "5b0f3c1e-8a2d-4f6b-9c1d-0a1b2c3d4e5f"
OTHER_UID = "9d8c7b6a-1f2e-4d3c-8b7a-6f5e4d3c2b1a"

GET_PODS = ToolCall(name="k8s.get_pods", arguments={"namespace": NS})


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def container_spec(name="app", *, memory_request=None, memory_limit=None, liveness=None):
    requests = {"memory": memory_request} if memory_request else None
    limits = {"memory": memory_limit} if memory_limit else None

    return ns(
        name=name,
        resources=ns(requests=requests, limits=limits),
        liveness_probe=liveness,
    )


def http_probe(path="/nonexistent", port=80, period=2):
    return ns(
        http_get=ns(path=path, port=port),
        tcp_socket=None,
        grpc=None,
        period_seconds=period,
        timeout_seconds=1,
        failure_threshold=3,
        initial_delay_seconds=0,
    )


def volume(name, source="config_map"):
    return ns(name=name, **{source: ns()})


def container_status(
    name="app", *, ready=False, restarts=0, state="waiting", reason="ContainerCreating",
    last_exit=None, last_reason=None,
):
    waiting = ns(reason=reason, message="free text") if state == "waiting" else None
    running = ns(started_at=None) if state == "running" else None

    return ns(
        name=name,
        ready=ready,
        restart_count=restarts,
        state=ns(waiting=waiting, running=running, terminated=None),
        last_state=ns(
            terminated=(
                None
                if last_exit is None
                else ns(reason=last_reason, message=None, exit_code=last_exit)
            )
        ),
    )


def pod(
    name,
    *,
    phase="Pending",
    uid=UID,
    age=300,
    scheduled=("False", "Unschedulable"),
    scheduler_message=None,
    containers=None,
    statuses=None,
    volumes=None,
    node_selector=None,
):
    conditions = []

    if scheduled is not None:
        conditions.append(
            ns(
                type="PodScheduled",
                status=scheduled[0],
                reason=scheduled[1],
                message=scheduler_message,
            )
        )

    return ns(
        metadata=ns(
            name=name,
            namespace=NS,
            uid=uid,
            creation_timestamp=datetime.now(timezone.utc) - timedelta(seconds=age),
        ),
        spec=ns(
            node_name=None,
            containers=containers if containers is not None else [container_spec()],
            volumes=volumes or [],
            node_selector=node_selector,
            affinity=None,
        ),
        status=ns(
            phase=phase,
            pod_ip=None,
            container_statuses=statuses,
            conditions=conditions,
        ),
    )


def event(
    *, pod_name, reason, message, component, uid=UID, type_="Warning", count=3,
    kind="Pod",
):
    return ns(
        type=type_,
        reason=reason,
        message=message,
        count=count,
        involved_object=ns(kind=kind, name=pod_name, namespace=NS, uid=uid),
        source=ns(component=component),
        reporting_component=None,
    )


class FakeApi:
    def __init__(self, pods, events=None, event_continue=None):
        self.pods = {p.metadata.name: p for p in pods}
        self.events = events or {}
        self.event_continue = event_continue

    def read_namespaced_pod(self, *, name, namespace, **_):
        return self.pods[name]

    def list_namespaced_event(self, *, field_selector=None, **_):
        pod_name = field_selector.split("involvedObject.name=")[1] if field_selector else None

        return ns(
            items=self.events.get(pod_name, []),
            metadata=ns(_continue=self.event_continue),
        )


@contextmanager
def fake_cluster_api(api):
    with patch.object(handlers, "core_v1", return_value=api):
        yield


class Cluster:
    """Executor that runs the real handlers against a fake client."""

    def __init__(self, pods, events=None):
        self.api = FakeApi(pods, events)
        self.calls: list[ToolCall] = []

    @property
    def names(self):
        return [c.name for c in self.calls]

    def __call__(self, call):
        self.calls.append(call)
        arguments = SimpleNamespace(**call.arguments)

        with fake_cluster_api(self.api):
            if call.name == "k8s.get_pods":
                output = {
                    "namespace": NS,
                    "pods": [
                        {"name": n, "namespace": NS, "phase": p.status.phase}
                        for n, p in self.api.pods.items()
                    ],
                }
            elif call.name == "k8s.describe_pod":
                output = handlers.describe_pod(arguments)
            elif call.name == "k8s.get_events":
                output = handlers.get_events(arguments)
            else:
                output = {}

        return ToolExecutionResult(
            tool=call.name, status=ToolExecutionStatus.SUCCESS, output=output
        )


def investigate(cluster, *, max_steps=8):
    """Run the real controller, then build the evidence snapshot and report."""
    ctx = create_bound_investigation_context(QUESTION, namespace=NS, max_steps=max_steps)
    audit: list = []

    run_investigation(
        context=ctx,
        provider=CoverageProvider(_once(GET_PODS)),
        audit=audit.append,
        executor=cluster,
        tolerated_failure_tools=SUPPLEMENTARY_TOOLS,
    )
    snapshot = build_investigation_evidence_snapshot(ctx)

    return ctx, snapshot, build_grounded_report(snapshot), audit


def _once(call):
    queue = [call]

    def provider(context, steps):
        return queue.pop(0) if queue else None

    return provider


def fields(ctx, tool=None):
    return {
        o.field: o.value
        for o in ctx.observations
        if tool is None or o.tool == tool
    }
