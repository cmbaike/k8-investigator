from types import SimpleNamespace
from unittest.mock import patch

import pytest

from app.tools.handlers import (
    KubernetesToolError,
    _container_state,
    _read_logs,
)


def ns(**kwargs):
    return SimpleNamespace(**kwargs)


def test_waiting_container_state_exposes_reason():
    status = ns(
        name="payments-api",
        ready=False,
        restart_count=8,
        state=ns(
            waiting=ns(
                reason="CrashLoopBackOff",
                message="back-off restarting failed container",
            ),
            running=None,
            terminated=None,
        ),
        last_state=ns(
            terminated=ns(
                reason="Error",
                message=None,
                exit_code=1,
            )
        ),
    )

    result = _container_state(status)

    assert result["state"] == "waiting"
    assert result["reason"] == "CrashLoopBackOff"
    assert result["restart_count"] == 8
    assert result["last_termination"]["reason"] == "Error"
    assert result["last_termination"]["exit_code"] == 1


def test_log_bytes_are_decoded():
    arguments = ns(
        namespace="ai-ops-demo",
        pod="payments-api-123",
        container="payments-api",
        tail=20,
    )

    api = ns(
        read_namespaced_pod_log=lambda **kwargs: (
            b"ERROR: PAYMENTS_DB_HOST is not set"
        )
    )

    with patch("app.tools.handlers.core_v1", return_value=api):
        result = _read_logs(arguments, previous=True)

    assert result["previous"] is True
    assert result["logs"] == "ERROR: PAYMENTS_DB_HOST is not set"


def test_runtime_log_error_is_not_successful_observation():
    arguments = ns(
        namespace="ai-ops-demo",
        pod="payments-api-123",
        container="payments-api",
        tail=20,
    )

    api = ns(
        read_namespaced_pod_log=lambda **kwargs: (
            b"unable to retrieve container logs for containerd://abc"
        )
    )

    with patch("app.tools.handlers.core_v1", return_value=api):
        with pytest.raises(KubernetesToolError):
            _read_logs(arguments, previous=True)

import pytest

from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.tools.observations import observations_from_execution


@pytest.mark.parametrize(
    ("status", "namespace", "pod", "expected_count"),
    [
        (ToolExecutionStatus.SUCCESS, "ai-ops-demo", "payments-api", 1),
        (ToolExecutionStatus.SUCCESS, "wrong-namespace", "payments-api", 0),
        (ToolExecutionStatus.SUCCESS, "ai-ops-demo", "wrong-pod", 0),
        (ToolExecutionStatus.ERROR, "ai-ops-demo", "payments-api", 0),
    ],
)
def test_get_logs_trusted_observation_requires_success_and_resource_match(
    status,
    namespace,
    pod,
    expected_count,
):
    call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api",
            "container": "payments-api",
            "tail": 100,
        },
    )

    result = ToolExecutionResult(
        tool="k8s.get_logs",
        status=status,
        output={
            "namespace": namespace,
            "pod": pod,
            "container": "payments-api",
            "tail": 100,
            "previous": False,
            "logs": "SECRET_LOG_CONTENT",
        },
    )

    observations = observations_from_execution(
        request_id="req-investigation-step-3",
        call=call,
        result=result,
    )

    assert len(observations) == expected_count

    if expected_count == 1:
        observation = observations[0]

        assert observation.request_id == "req-investigation-step-3"
        assert observation.tool == "k8s.get_logs"
        assert observation.field == "logs.retrieved"
        assert observation.value is True
        assert observation.namespace == "ai-ops-demo"
        assert observation.pod == "payments-api"

        # Raw logs must never become trusted report evidence.
        assert "SECRET_LOG_CONTENT" not in observation.model_dump_json()