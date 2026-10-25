import pytest

from app.tools.models import ToolCall, ToolResultStatus, ToolRisk
from app.tools.policy import authorize_tool_call


@pytest.mark.parametrize(
    "name",
    [
        "k8s.get_pods",
        "k8s.describe_pod",
        "k8s.get_events",
        "k8s.get_deployment",
        "k8s.get_logs",
        "k8s.get_previous_logs",
    ],
)
def test_registered_read_only_tools_are_allowed(name):
    decision = authorize_tool_call(ToolCall(name=name))

    assert decision.status == ToolResultStatus.ALLOWED
    assert decision.risk == ToolRisk.READ_ONLY


@pytest.mark.parametrize(
    ("name", "risk"),
    [
        ("k8s.restart_deployment", ToolRisk.STATE_CHANGING),
        ("k8s.delete_pod", ToolRisk.DESTRUCTIVE),
    ],
)
def test_mutating_tools_require_approval(name, risk):
    decision = authorize_tool_call(ToolCall(name=name))

    assert decision.status == ToolResultStatus.APPROVAL_REQUIRED
    assert decision.risk == risk


@pytest.mark.parametrize(
    "name",
    [
        "shell.exec",
        "kubectl.exec",
        "k8s.apply",
        "k8s.patch",
        "k8s.scale",
        "db.execute_sql",
    ],
)
def test_unknown_tools_fail_closed(name):
    decision = authorize_tool_call(
        ToolCall(
            name=name,
            arguments={"command": "anything"},
        )
    )

    assert decision.status == ToolResultStatus.DENIED
    assert decision.risk is None


def test_arguments_cannot_change_tool_risk():
    decision = authorize_tool_call(
        ToolCall(
            name="k8s.delete_pod",
            arguments={
                "approved": True,
                "risk": "read_only",
                "force": True,
            },
        )
    )

    assert decision.status == ToolResultStatus.APPROVAL_REQUIRED
    assert decision.risk == ToolRisk.DESTRUCTIVE
