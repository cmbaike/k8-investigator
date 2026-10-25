from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from app.tools import handlers
from app.tools.limits import (
    K8S_LIST_PAGE_SIZE,
    K8S_LOG_LIMIT_BYTES,
)


def _args():
    return SimpleNamespace(
        namespace="ai-ops-demo",
        pod="example-pod",
        container="app",
        tail=50,
    )


@pytest.mark.parametrize(
    ("handler_name", "client_method"),
    [
        ("get_pods", "list_namespaced_pod"),
        ("get_events", "list_namespaced_event"),
    ],
)
def test_list_requests_have_page_limits(
    handler_name,
    client_method,
):
    client = Mock()

    getattr(client, client_method).return_value = SimpleNamespace(
        metadata=SimpleNamespace(_continue=None),
        items=[],
    )

    with patch("app.tools.handlers.core_v1", return_value=client):
        getattr(handlers, handler_name)(_args())

    kwargs = getattr(client, client_method).call_args.kwargs

    assert kwargs["limit"] == K8S_LIST_PAGE_SIZE


def test_get_pods_keeps_an_incomplete_page_and_marks_it_truncated():
    client = Mock()
    client.list_namespaced_pod.return_value = SimpleNamespace(
        metadata=SimpleNamespace(_continue="next-page-token"),
        items=[],
    )

    with patch("app.tools.handlers.core_v1", return_value=client):
        output = handlers.get_pods(_args())

    assert output["listing_truncated"] is True
    assert output["pods"] == []


@pytest.mark.parametrize(
    ("handler_name", "client_method"),
    [
        ("get_events", "list_namespaced_event"),
    ],
)
def test_list_handlers_reject_incomplete_pages(
    handler_name,
    client_method,
):
    client = Mock()

    getattr(client, client_method).return_value = SimpleNamespace(
        metadata=SimpleNamespace(_continue="next-page-token"),
        items=[],
    )

    with patch("app.tools.handlers.core_v1", return_value=client):
        with pytest.raises(
            handlers.KubernetesToolError,
            match="results are incomplete",
        ):
            getattr(handlers, handler_name)(_args())


@pytest.mark.parametrize(
    ("handler_name", "previous"),
    [
        ("get_logs", False),
        ("get_previous_logs", True),
    ],
)
def test_log_requests_have_byte_limits(
    handler_name,
    previous,
):
    client = Mock()
    client.read_namespaced_pod_log.return_value = "example log"

    with patch("app.tools.handlers.core_v1", return_value=client):
        result = getattr(handlers, handler_name)(_args())

    kwargs = client.read_namespaced_pod_log.call_args.kwargs

    assert kwargs["limit_bytes"] == K8S_LOG_LIMIT_BYTES
    assert kwargs["follow"] is False
    assert kwargs["previous"] is previous

    assert result["retrieval_limits"]["limit_bytes"] == K8S_LOG_LIMIT_BYTES
    assert result["completeness"] == "bounded_unknown"