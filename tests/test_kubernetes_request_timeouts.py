from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from app.tools import handlers


def _args(**overrides):
    values = {
        "namespace": "ai-ops-demo",
        "pod": "example-pod",
        "deployment": "example-deployment",
        "container": "app",
        "tail": 50,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


@pytest.mark.parametrize(
    ("handler_name", "client_method"),
    [
        ("get_pods", "list_namespaced_pod"),
        ("describe_pod", "read_namespaced_pod"),
        ("get_events", "list_namespaced_event"),
        ("get_deployment", "read_namespaced_deployment"),
        ("get_logs", "read_namespaced_pod_log"),
        ("get_previous_logs", "read_namespaced_pod_log"),
    ],
)
def test_kubernetes_requests_have_explicit_timeouts(
    handler_name,
    client_method,
):
    client = Mock()

    if handler_name == "get_pods":
        client.list_namespaced_pod.return_value = SimpleNamespace(metadata=SimpleNamespace(_continue=None),items=[])

    elif handler_name == "get_events":
        client.list_namespaced_event.return_value = SimpleNamespace(metadata=SimpleNamespace(_continue=None),items=[])

    elif handler_name == "describe_pod":
        client.read_namespaced_pod.return_value = SimpleNamespace(
            metadata=SimpleNamespace(
                name="example-pod",
                namespace="ai-ops-demo",
            ),
            status=SimpleNamespace(
                phase="Running",
                pod_ip="10.0.0.1",
                container_statuses=[],
                conditions=[],
            ),
            spec=SimpleNamespace(node_name="node-1"),
        )

    elif handler_name == "get_deployment":
        client.read_namespaced_deployment.return_value = SimpleNamespace(
            metadata=SimpleNamespace(
                name="example-deployment",
                namespace="ai-ops-demo",
            ),
            spec=SimpleNamespace(replicas=2),
            status=SimpleNamespace(
                ready_replicas=2,
                available_replicas=2,
                updated_replicas=2,
                unavailable_replicas=0,
            ),
        )

    else:
        client.read_namespaced_pod_log.return_value = "example log"

    client_factory = (
        "app.tools.handlers.apps_v1"
        if handler_name == "get_deployment"
        else "app.tools.handlers.core_v1"
    )

    with patch(client_factory, return_value=client):
        getattr(handlers, handler_name)(_args())

    kwargs = getattr(client, client_method).call_args.kwargs

    assert kwargs["_request_timeout"] == handlers.K8S_REQUEST_TIMEOUT

    if handler_name in ("get_logs", "get_previous_logs"):
        assert kwargs["follow"] is False
        assert kwargs["previous"] is (
            handler_name == "get_previous_logs"
        )
