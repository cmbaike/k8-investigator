import pytest

from app.tools.intent import (
    ToolIntentError,
    validate_proposed_tool_intent,
)
from app.tools.models import ToolCall


def test_read_only_logs_intent_is_allowed():
    call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    validate_proposed_tool_intent(
        call,
        (
            "Show logs for pod payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )


def test_kubectl_exec_cannot_be_substituted_with_logs():
    call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    with pytest.raises(
        ToolIntentError,
        match="not eligible",
    ):
        validate_proposed_tool_intent(
            call,
            (
                "Run kubectl exec in pod payments-api-abc123 "
                "in namespace ai-ops-demo and execute env."
            ),
        )


@pytest.mark.parametrize(
    "question",
    [
        "kubectl apply the manifest",
        "kubectl patch deployment payments-api",
        "kubectl delete pod payments-api-abc123",
        "kubectl scale deployment payments-api",
        "rollout restart payments-api",
    ],
)
def test_state_changing_intent_cannot_be_substituted(
    question,
):
    call = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    with pytest.raises(ToolIntentError):
        validate_proposed_tool_intent(call, question)