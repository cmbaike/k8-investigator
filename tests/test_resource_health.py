"""On-demand resource health: exact identity, existing classifiers, one audit row."""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.health.kubernetes import KubernetesHealthReader
from app.health.service import inspect_resource, run_health_check
from app.health.types import (
    MAX_PODS_EXAMINED,
    HealthReadError,
    HealthRequestError,
    ObservedContainer,
    ObservedDeployment,
    ObservedPod,
    ObservedReplicaSet,
)
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import get_demo_principal
from app.web.routes import get_health_audit, get_health_reader

NS = "ai-ops-demo"
OTHER = "other-namespace"
UID_DEP = "11111111-1111-1111-1111-111111111111"
UID_DEP_OLD = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
UID_RS = "22222222-2222-2222-2222-222222222222"
UID_RS_OTHER = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
UID_POD = "33333333-3333-3333-3333-333333333333"
NOW = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)


def container(**overrides) -> ObservedContainer:
    values = dict(
        name="app",
        ready=True,
        restart_count=0,
        state="running",
        reason=None,
        exit_code=None,
        last_reason=None,
        last_exit_code=None,
        memory_request="16Mi",
        memory_limit="32Mi",
    )
    values.update(overrides)
    return ObservedContainer(**values)


def make_pod(name="payments-api-5d6b7c8d9-k7m2p", uid=UID_POD, containers=(container(),), **overrides) -> ObservedPod:
    values = dict(
        name=name,
        namespace=NS,
        uid=uid,
        phase="Running",
        scheduled_status="True",
        scheduled_reason=None,
        age_seconds=120,
        containers=tuple(containers),
        owner_kind="ReplicaSet",
        owner_name="payments-api-7d9f8c",
        owner_uid=UID_RS,
        owner_is_controller=True,
    )
    values.update(overrides)
    return ObservedPod(**values)


def make_deployment(**overrides) -> ObservedDeployment:
    values = dict(
        name="payments-api",
        namespace=NS,
        uid=UID_DEP,
        desired=1,
        ready=1,
        available=1,
        updated=1,
        status_observed=True,
    )
    values.update(overrides)
    return ObservedDeployment(**values)


def make_rs(**overrides) -> ObservedReplicaSet:
    values = dict(
        name="payments-api-7d9f8c",
        namespace=NS,
        uid=UID_RS,
        deployment_name="payments-api",
        deployment_uid=UID_DEP,
    )
    values.update(overrides)
    return ObservedReplicaSet(**values)


class FakeReader:
    def __init__(self) -> None:
        self.deployment = make_deployment()
        self.pod = make_pod()
        self.pods = [self.pod]
        self.replica_sets = {"payments-api-7d9f8c": make_rs()}
        self.events: dict[tuple[str, str], dict[str, int]] = {}
        self.truncated = False
        self.event_truncated = False
        self.fail: dict[str, str] = {}
        self.calls: list[tuple] = []

    def read_pod(self, namespace: str, name: str) -> ObservedPod:
        self.calls.append(("pod", namespace, name))
        if "pod" in self.fail:
            raise HealthReadError(self.fail["pod"])
        if self.pod is None or self.pod.name != name or self.pod.namespace != namespace:
            raise HealthReadError("not_found")
        return self.pod

    def read_deployment(self, namespace: str, name: str) -> ObservedDeployment:
        self.calls.append(("deployment", namespace, name))
        if "deployment" in self.fail:
            raise HealthReadError(self.fail["deployment"])
        if (
            self.deployment is None
            or self.deployment.name != name
            or self.deployment.namespace != namespace
        ):
            raise HealthReadError("not_found")
        return self.deployment

    def list_pods(self, namespace: str):
        self.calls.append(("list", namespace))
        if "list" in self.fail:
            raise HealthReadError(self.fail["list"])
        return tuple(self.pods), self.truncated

    def read_replica_set(self, namespace: str, name: str) -> ObservedReplicaSet:
        self.calls.append(("rs", namespace, name))
        if "rs" in self.fail:
            raise HealthReadError(self.fail["rs"])
        replica = self.replica_sets.get(name)
        if replica is None or replica.namespace != namespace:
            raise HealthReadError("not_found")
        return replica

    def mount_event_counts(self, namespace: str, pod_name: str, pod_uid: str):
        self.calls.append(("events", namespace, pod_name, pod_uid))
        return self.events.get((pod_name, pod_uid), {}), self.event_truncated


def principal(namespaces=(NS,)) -> APIKeyPrincipal:
    return APIKeyPrincipal(principal_id="demo", allowed_namespaces=frozenset(namespaces))


def check(reader: FakeReader, kind="Deployment", name="payments-api", namespace=NS, who=None):
    audits = []
    result = run_health_check(
        principal=who or principal(),
        namespace=namespace,
        kind=kind,
        name=name,
        reader=reader,
        audit=audits.append,
        now=NOW,
    )
    return result, audits


def test_authorized_deployment_is_a_point_in_time_snapshot():
    result, audits = check(FakeReader())

    assert result.category == "healthy"
    assert result.snapshot == "point_in_time"
    assert result.resource.uid == UID_DEP
    assert result.resource.kind == "Deployment"
    assert result.workload is not None and result.workload.ready == 1
    assert result.coverage.complete is True
    assert result.coverage.summary == "Inspected 1 of 1 pods."
    assert result.pods[0].name == "payments-api-5d6b7c8d9-k7m2p"
    assert result.pods[0].containers[0].configured_memory_limit == "32Mi"
    assert audits[0].status == "recorded"
    assert audits[0].category == "healthy"
    assert len(audits) == 1


def test_unauthorized_namespace_does_not_read():
    reader = FakeReader()
    with pytest.raises(HealthRequestError) as caught:
        check(reader, namespace=OTHER, who=principal())
    assert caught.value.status == 403
    assert caught.value.code == "namespace_denied"
    assert reader.calls == []


def test_unsupported_kind_does_not_read():
    reader = FakeReader()
    with pytest.raises(HealthRequestError) as caught:
        check(reader, kind="StatefulSet")
    assert caught.value.code == "unsupported_kind"
    assert reader.calls == []


def test_not_found_does_not_list_other_workloads():
    reader = FakeReader()
    reader.deployment = None
    with pytest.raises(HealthRequestError) as caught:
        check(reader, name="missing-api")
    assert caught.value.code == "not_found"
    assert [call[0] for call in reader.calls] == ["deployment"]


def test_unrelated_pod_and_uid_mismatch_are_excluded():
    reader = FakeReader()
    foreign = make_pod(
        name="other-app-aaa",
        uid="55555555-5555-5555-5555-555555555555",
        owner_name="other-rs",
        owner_uid=UID_RS_OTHER,
    )
    mismatched = make_pod(
        name="payments-api-old",
        uid="66666666-6666-6666-6666-666666666666",
        owner_uid=UID_RS_OTHER,
    )
    reader.pods = [reader.pod, foreign, mismatched]
    reader.replica_sets["other-rs"] = make_rs(
        name="other-rs", uid=UID_RS_OTHER, deployment_name="other-app", deployment_uid=UID_DEP_OLD
    )
    result, _audits = check(reader)

    assert [pod.name for pod in result.pods] == ["payments-api-5d6b7c8d9-k7m2p"]
    assert result.coverage.discovered == 1


def test_replaced_deployment_uid_does_not_claim_old_pods():
    reader = FakeReader()
    reader.replica_sets["payments-api-7d9f8c"] = make_rs(deployment_uid=UID_DEP_OLD)
    result, _audits = check(reader)

    assert result.pods == []
    assert result.category == "unknown"


def test_multiple_descendants_and_the_examination_cap():
    reader = FakeReader()
    reader.pods = []
    for index in range(MAX_PODS_EXAMINED + 1):
        reader.pods.append(
            make_pod(
                name=f"payments-api-{index:02d}",
                uid=f"33333333-3333-3333-3333-{index:012d}",
            )
        )
    reader.deployment = make_deployment(desired=MAX_PODS_EXAMINED + 1, ready=MAX_PODS_EXAMINED + 1)
    result, _audits = check(reader)

    assert result.coverage.discovered == MAX_PODS_EXAMINED + 1
    assert result.coverage.examined == MAX_PODS_EXAMINED
    assert result.coverage.complete is False
    assert result.category == "unknown"
    assert any(item.code == "pod_cap" for item in result.coverage.limitations)


def test_unrelated_replica_sets_do_not_crowd_out_the_target():
    reader = FakeReader()
    reader.pods = []
    for index in range(12):
        rs_name = f"other-{index:02d}"
        rs_uid = f"44444444-4444-4444-4444-{index:012d}"
        pod_uid = f"55555555-5555-5555-5555-{index:012d}"
        reader.replica_sets[rs_name] = make_rs(
            name=rs_name,
            uid=rs_uid,
            deployment_name=rs_name,
            deployment_uid=UID_DEP_OLD,
        )
        reader.pods.append(
            make_pod(
                name=f"other-{index:02d}-pod",
                uid=pod_uid,
                owner_name=rs_name,
                owner_uid=rs_uid,
                containers=(container(ready=False, state="waiting", reason="ImagePullBackOff"),),
            )
        )
    reader.pods.append(
        make_pod(
            name="payments-api-zzz",
            uid="66666666-6666-6666-6666-666666666666",
            containers=(
                container(
                    ready=False,
                    state="waiting",
                    reason="CrashLoopBackOff",
                    restart_count=4,
                    last_reason="OOMKilled",
                    last_exit_code=137,
                ),
            ),
        )
    )
    reader.deployment = make_deployment(ready=0, available=0)
    result, _audits = check(reader)

    assert [pod.name for pod in result.pods] == ["payments-api-zzz"]
    assert result.category == "unhealthy"
    assert "oom_killed" in {item.code for item in result.signals}
    assert [call for call in reader.calls if call[0] == "rs"] == [("rs", NS, "payments-api-7d9f8c")]


def test_primary_read_failure_is_unknown_and_does_not_scan():
    reader = FakeReader()
    reader.fail["deployment"] = "observation_failed"
    result, audits = check(reader)

    assert result.category == "unknown"
    assert result.coverage.limitations[0].code == "observation_failed"
    assert [call[0] for call in reader.calls] == ["deployment"]
    assert audits[0].error_code == "observation_failed"
    assert audits[0].status == "recorded"


def test_listing_failure_does_not_report_healthy():
    reader = FakeReader()
    reader.fail["list"] = "observation_failed"
    result, _audits = check(reader)

    assert result.category == "unknown"
    assert "list" in [call[0] for call in reader.calls]
    assert result.pods == []


def test_mixed_replicas_are_degraded_not_a_single_cause():
    reader = FakeReader()
    failing = make_pod(
        name="payments-api-bbb",
        uid="77777777-7777-7777-7777-777777777777",
        containers=(container(ready=False, state="waiting", reason="CrashLoopBackOff", restart_count=3, last_reason="Error", last_exit_code=1),),
    )
    reader.pods = [reader.pod, failing]
    reader.deployment = make_deployment(desired=2, ready=1, available=1)
    result, _audits = check(reader)

    assert result.category == "degraded"
    assert {item.code for item in result.signals} >= {"partial_failure", "crash_loop_backoff"}


def test_scale_to_zero_is_not_unhealthy():
    reader = FakeReader()
    reader.pods = []
    reader.deployment = make_deployment(desired=0, ready=0, available=0, updated=0)
    result, _audits = check(reader)

    assert result.category == "healthy"
    assert result.signals[0].code == "scaled_to_zero"
    assert result.pods == []


def test_oom_history_running_ready_is_degraded_and_does_not_claim_the_limit():
    reader = FakeReader()
    reader.pod = make_pod(
        containers=(container(restart_count=2, last_reason="OOMKilled", last_exit_code=137),)
    )
    reader.pods = [reader.pod]
    result, _audits = check(reader)
    text = result.model_dump_json()

    assert result.category == "degraded"
    assert "oom_killed" in {item.code for item in result.signals}
    assert "restarted_before" in {item.code for item in result.signals}
    assert "exceeded" not in text
    assert "32Mi" in text


def test_image_pull_crash_unschedulable_and_not_ready_use_existing_semantics():
    pull = FakeReader()
    pull.pod = make_pod(
        phase="Pending",
        containers=(container(ready=False, state="waiting", reason="ImagePullBackOff", restart_count=0),),
    )
    pull.pods = [pull.pod]
    pull.deployment = make_deployment(ready=0, available=0)
    pulled, _audits = check(pull)
    assert pulled.category == "unhealthy"
    assert pulled.signals[0].code == "image_pull_backoff"

    unschedulable = FakeReader()
    unschedulable.pod = make_pod(
        phase="Pending",
        scheduled_status="False",
        scheduled_reason="Unschedulable",
        containers=(),
    )
    unschedulable.pods = [unschedulable.pod]
    unschedulable.deployment = make_deployment(ready=0, available=0)
    pending, _audits = check(unschedulable)
    assert pending.category == "unhealthy"
    assert pending.signals[0].code == "unschedulable"
    assert not any(call[0] == "events" for call in unschedulable.calls)

    not_ready = FakeReader()
    not_ready.pod = make_pod(containers=(container(ready=False, state="running"),))
    not_ready.pods = [not_ready.pod]
    waiting, _audits = check(not_ready)
    assert waiting.category == "degraded"
    assert {item.code for item in waiting.signals} == {"running_not_ready"}


def test_volume_failure_needs_a_uid_matched_event_and_incomplete_events_stay_unknown():
    reader = FakeReader()
    creating = container(ready=False, state="waiting", reason="ContainerCreating", restart_count=0)
    reader.pod = make_pod(phase="Pending", containers=(creating,), age_seconds=90)
    reader.pods = [reader.pod]
    reader.events[(reader.pod.name, reader.pod.uid)] = {"FailedMount": 2}
    reader.deployment = make_deployment(ready=0, available=0)
    mounted, _audits = check(reader)
    assert mounted.category == "unhealthy"
    assert mounted.signals[0].code == "volume_mount_failure"

    unread = FakeReader()
    unread.pod = make_pod(phase="Pending", containers=(creating,), age_seconds=90)
    unread.pods = [unread.pod]
    unread.fail["events"] = "observation_failed"
    unread.deployment = make_deployment(ready=0, available=0)
    unknown, _audits = check(unread)
    assert unknown.category == "unknown"
    assert "volume_mount_failure" not in {item.code for item in unknown.signals}


def test_truncated_listing_is_not_reported_healthy():
    reader = FakeReader()
    reader.truncated = True
    result, _audits = check(reader)

    assert result.coverage.complete is False
    assert result.category == "unknown"
    assert "truncated" in result.coverage.summary


def test_sensitive_fields_are_not_in_the_response_or_the_audit_row():
    reader = FakeReader()
    reader.pod = make_pod(
        containers=(container(memory_limit="secret=hunter2", memory_request="PASSWORD=hunter2"),)
    )
    reader.pods = [reader.pod]
    result, audits = check(reader)
    payload = result.model_dump()

    def keys(value):
        if isinstance(value, dict):
            found = set(value)
            for item in value.values():
                found |= keys(item)
            return found
        if isinstance(value, list):
            found = set()
            for item in value:
                found |= keys(item)
            return found
        return set()

    assert keys(payload).isdisjoint(
        {"message", "logs", "log", "env", "command", "args", "secret", "password", "token"}
    )
    assert "hunter2" not in result.model_dump_json()
    assert audits[0].error_code is None
    assert not hasattr(audits[0], "message")


def test_permission_denied_is_not_unhealthy():
    reader = FakeReader()
    reader.fail["deployment"] = "permission_denied"
    with pytest.raises(HealthRequestError) as caught:
        check(reader)
    assert caught.value.status == 403
    assert [call[0] for call in reader.calls] == ["deployment"]


def test_health_package_does_not_call_the_model_or_logs():
    from pathlib import Path

    text = "\n".join(path.read_text() for path in Path("app/health").glob("*.py")).lower()
    for banned in ("qwen", "openai", "get_logs", "read_namespaced_pod_log", "execute_tool_call"):
        assert banned not in text


def test_event_adapter_drops_a_different_pod_uid_and_keeps_no_message(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import Mock

    event = SimpleNamespace(
        reason="FailedMount",
        count=4,
        message="secret token should-not-leak",
        involved_object=SimpleNamespace(
            kind="Pod", name="payments", namespace=NS, uid="99999999-9999-9999-9999-999999999999"
        ),
    )
    core = Mock()
    core.list_namespaced_event.return_value = SimpleNamespace(
        items=[event], metadata=SimpleNamespace(_continue=None)
    )
    monkeypatch.setattr("app.health.kubernetes.core_v1", lambda: core)

    counts, truncated = KubernetesHealthReader().mount_event_counts(NS, "payments", UID_POD)

    assert counts == {}
    assert truncated is False
    assert "should-not-leak" not in repr(counts)


def test_direct_inspect_rejects_a_bad_name_before_reading():
    reader = FakeReader()
    with pytest.raises(HealthRequestError) as caught:
        inspect_resource(namespace=NS, kind="Pod", name="Bad_Name", reader=reader, now=NOW)
    assert caught.value.code == "invalid_name"
    assert reader.calls == []


@pytest.fixture
def client():
    app.dependency_overrides[get_demo_principal] = lambda: APIKeyPrincipal(
        principal_id="demo", allowed_namespaces=frozenset({NS})
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_demo_principal, None)


def test_http_health_check_is_session_scoped_and_audited_once(client):
    reader = FakeReader()
    audits = []
    app.dependency_overrides[get_health_reader] = lambda: reader
    app.dependency_overrides[get_health_audit] = lambda: audits.append
    try:
        denied = client.get(
            "/api/resources/health",
            params={"namespace": OTHER, "kind": "Deployment", "name": "payments-api"},
        )
        assert denied.status_code == 403

        response = client.get(
            "/api/resources/health",
            params={"namespace": NS, "kind": "Deployment", "name": "payments-api"},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["category"] == "healthy"
        assert body["resource"]["name"] == "payments-api"
        assert response.headers["cache-control"] == "no-store"
        assert len(audits) == 2

        missing = client.get(
            "/api/resources/health",
            params={"namespace": NS, "kind": "Job", "name": "payments-api"},
        )
        assert missing.status_code == 422
        assert missing.json()["detail"] == "unsupported_kind"
        assert len(audits) == 3
    finally:
        app.dependency_overrides.pop(get_health_reader, None)
        app.dependency_overrides.pop(get_health_audit, None)
