import pytest

from app.tools.models import ToolCall
from app.tools.operation_intent import (
    ToolOperationIntentError,
    infer_explicit_read_only_operation,
    validate_proposed_operation,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "List pods in namespace demo.",
            "k8s.get_pods",
        ),
        (
            "Show pods in namespace demo.",
            "k8s.get_pods",
        ),
        (
            "Inspect pod api-123 in namespace demo.",
            "k8s.describe_pod",
        ),
        (
            "Show me the deployment in namespace demo.",
            "k8s.get_deployment",
        ),
        (
            "Show Kubernetes events in namespace demo.",
            "k8s.get_events",
        ),
        (
            "Inspect deployment api in namespace demo.",
            "k8s.get_deployment",
        ),
        (
            "Read logs for pod api-123 in namespace demo.",
            "k8s.get_logs",
        ),
        (
            "Fetch the last 75 log lines from pod api-123 "
            "in namespace demo.",
            "k8s.get_logs",
        ),
        (
            "Retrieve previous logs for pod api-123 "
            "in namespace demo.",
            "k8s.get_previous_logs",
        ),
    ],
)
def test_infers_explicit_operation(text, expected):
    assert infer_explicit_read_only_operation(text) == expected


def test_rejects_logs_to_previous_logs_substitution():
    call = ToolCall(
        name="k8s.get_previous_logs",
        arguments={
            "namespace": "search-test",
            "pod": "search-api-84d2b",
            "tail": 75,
        },
    )

    with pytest.raises(
        ToolOperationIntentError,
        match="does not match",
    ):
        validate_proposed_operation(
            call,
            "Fetch the last 75 log lines from pod "
            "search-api-84d2b in namespace search-test.",
        )


def test_rejects_logs_to_get_pods_substitution():
    call = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "orders-prod",
        },
    )

    with pytest.raises(
        ToolOperationIntentError,
        match="does not match",
    ):
        validate_proposed_operation(
            call,
            "Get logs from namespace orders-prod. "
            "Guess which pod belongs to the orders API.",
        )


def test_rejects_ambiguous_request():
    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "demo"},
    )

    with pytest.raises(
        ToolOperationIntentError,
        match="does not authorize exactly one",
    ):
        validate_proposed_operation(
            call,
            "Investigate the application in namespace demo.",
        )
        
def test_operation_authorization_does_not_validate_required_arguments():
    call = ToolCall(
        name="k8s.get_deployment",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    validate_proposed_operation(
        call,
        "Show me the deployment in namespace ai-ops-demo.",
    )
    
def test_previous_logs_with_pod_does_not_collide_with_get_pods():
    text = (
        "Show previous logs for pod "
        "payments-api-8557447b4-4bm8n "
        "in namespace ai-ops-demo."
    )

    assert (
        infer_explicit_read_only_operation(text)
        == "k8s.get_previous_logs"
    )


def test_show_logs_with_pod_does_not_collide_with_get_pods():
    text = (
        "Show logs for pod "
        "payments-api-8557447b4-4bm8n "
        "in namespace ai-ops-demo."
    )

    assert (
        infer_explicit_read_only_operation(text)
        == "k8s.get_logs"
    )


def test_explicit_pod_listing_forms():
    cases = [
        "List pods in namespace demo.",
        "List the pods in namespace demo.",
        "Show pods in namespace demo.",
        "Show the pods in namespace demo.",
        "Show me pods in namespace demo.",
        "Show me the pods in namespace demo.",
    ]

    for text in cases:
        assert (
            infer_explicit_read_only_operation(text)
            == "k8s.get_pods"
        )          
