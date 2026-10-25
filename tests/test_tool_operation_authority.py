import pytest

from app.tools.models import ToolCall
from app.tools.operation_authority import (
    OperationAuthorityError,
    OperationAuthorityMode,
    authorize_proposed_operation,
)


def _call(name: str) -> ToolCall:
    return ToolCall(
        name=name,
        arguments={},
    )


def test_explicit_operation_remains_authorized():
    result = authorize_proposed_operation(
        _call("k8s.describe_pod"),
        "Describe pod in namespace ai-ops-demo.",
    )

    assert result.mode == OperationAuthorityMode.EXPLICIT
    assert result.investigation_kind is None


def test_investigation_authorizes_supported_read_only_operation():
    result = authorize_proposed_operation(
        _call("k8s.get_pods"),
        "Investigate the failing workload in namespace ai-ops-demo.",
    )

    assert result.mode == OperationAuthorityMode.INVESTIGATION
    assert result.investigation_kind == "k8s_workload"


@pytest.mark.parametrize(
    "tool_name",
    [
        "k8s.get_pods",
        "k8s.describe_pod",
        "k8s.get_logs",
        "k8s.get_previous_logs",
        "k8s.get_events",
        "k8s.get_deployment",
    ],
)
def test_investigation_authorizes_only_registered_read_only_tools(
    tool_name,
):
    result = authorize_proposed_operation(
        _call(tool_name),
        "Investigate the failing workload in namespace ai-ops-demo.",
    )

    assert result.mode == OperationAuthorityMode.INVESTIGATION


@pytest.mark.parametrize(
    "tool_name",
    [
        "k8s.rollout_restart",
        "k8s.delete_pod",
        "k8s.exec",
        "shell.exec",
    ],
)
def test_investigation_does_not_authorize_mutating_or_unknown_tools(
    tool_name,
):
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call(tool_name),
            "Investigate the failing workload in namespace ai-ops-demo.",
        )


def test_generic_investigation_does_not_grant_operation_authority():
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call("k8s.get_pods"),
            "Investigate this problem.",
        )


def test_workload_mention_without_investigation_does_not_grant_authority():
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call("k8s.get_pods"),
            "Tell me about the workload.",
        )


def test_explicit_operation_cannot_be_substituted():
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call("k8s.get_pods"),
            "Describe pod payments-api-abc123 "
            "in namespace ai-ops-demo.",
        )
        
@pytest.mark.parametrize(
    ("text", "proposed_tool"),
    [
        (
            "Investigate the failing workload, "
            "but do not restart anything.",
            "k8s.rollout_restart",
        ),
        (
            "Diagnose the failing pod without deleting it.",
            "k8s.delete_pod",
        ),
        (
            "Troubleshoot the service without executing commands.",
            "k8s.exec",
        ),
    ],
)
def test_investigation_language_never_authorizes_mutation(
    text,
    proposed_tool,
):
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call(proposed_tool),
            text,
        )
        
def test_model_cannot_turn_generic_request_into_investigation():
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call("k8s.get_pods"),
            "Help me with ai-ops-demo.",
        ) 
        
def test_explicit_operation_overrides_investigation_authority():
    with pytest.raises(OperationAuthorityError):
        authorize_proposed_operation(
            _call("k8s.get_pods"),
            (
                "Investigate the workload, but first "
                "describe pod payments-api-abc123 "
                "in namespace ai-ops-demo."
            ),
        )                      
