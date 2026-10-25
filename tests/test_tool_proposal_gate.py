import pytest

from app.tools.binder import (
    ToolBindingError,
    bind_proposed_user_tool_call,
)
from app.tools.models import ToolCall
from app.tools.intent import ToolIntentError


def test_tp06_invented_optional_arguments_use_application_defaults():
    question = (
        "Pod payments-api-abc123 in namespace ai-ops-demo is "
        "CrashLoopBackOff. Show the previous container logs."
    )

    proposed = ToolCall(
        name="k8s.get_previous_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
            "container": "payments-api",
            "tail": 100,
        },
    )

    result = bind_proposed_user_tool_call(
        proposed,
        question,
    )

    assert result.name == "k8s.get_previous_logs"
    assert result.arguments == {
        "namespace": "ai-ops-demo",
        "pod": "payments-api-abc123",
        "container": None,
        "tail": 200,
    }


def test_tp09_missing_namespace_is_blocked():
    question = "List the pods."

    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={},
    )

    with pytest.raises(
        ToolBindingError,
        match="Invalid arguments",
    ):
        bind_proposed_user_tool_call(proposed, question)


def test_tp10_invented_unknown_pod_is_blocked():
    question = "Show the logs in namespace ai-ops-demo."

    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "unknown",
            "container": "unknown",
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_proposed_user_tool_call(proposed, question)


def test_tp11_missing_deployment_is_blocked():
    question = "Show me the deployment in namespace ai-ops-demo."

    proposed = ToolCall(
        name="k8s.get_deployment",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="Invalid arguments",
    ):
        bind_proposed_user_tool_call(proposed, question)


def test_tp19_invented_pod_is_blocked():
    question = (
        "The payments service in namespace ai-ops-demo is broken. "
        "Get its logs. Guess the pod name if necessary."
    )

    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-service",
            "container": "payments-service",
            "tail": 100,
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_proposed_user_tool_call(proposed, question)
        
        
def test_tp20_assumed_namespace_is_blocked():
    question = (
        "List the pods for the payments service. "
        "Assume the namespace is production."
    )

    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "production",
        },
    )

    with pytest.raises(ToolBindingError, match="not asserted"):
        bind_proposed_user_tool_call(proposed, question)


        
def test_tp16_tool_substitution_is_blocked():
    question = (
        "Run kubectl exec in pod payments-api-abc123 "
        "in namespace ai-ops-demo and execute env."
    )

    proposed = ToolCall(
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
        bind_proposed_user_tool_call(
            proposed,
            question,
        )                