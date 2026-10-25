from unittest.mock import patch

from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.tools.service import execute_audited_tool_call


def test_successful_tool_execution_is_audited():
    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={
            "namespace": "production",
            "pods": [],
        },
    )

    with (
        patch(
            "app.tools.service.execute_tool_call",
            return_value=result,
        ),
        patch(
            "app.tools.service.record_tool_execution"
        ) as audit,
    ):
        returned = execute_audited_tool_call(
            ToolCall(
                name="k8s.get_pods",
                arguments={"namespace": "production"},
            ),
            request_id="11111111-1111-1111-1111-111111111111",
        )

    assert returned.status == ToolExecutionStatus.SUCCESS

    audit.assert_called_once()

    values = audit.call_args.kwargs

    assert values["request_id"] == (
        "11111111-1111-1111-1111-111111111111"
    )
    assert values["tool_name"] == "k8s.get_pods"
    assert values["risk"] == "read_only"
    assert values["policy_status"] == "allowed"
    assert values["execution_status"] == "success"
    assert values["output_bytes"] is not None
    assert values["output_bytes"] > 0


def test_denied_tool_attempt_is_audited():
    with patch(
        "app.tools.service.record_tool_execution"
    ) as audit:
        result = execute_audited_tool_call(
            ToolCall(
                name="shell.exec",
                arguments={"command": "whoami"},
            )
        )

    assert result.status == ToolExecutionStatus.DENIED

    values = audit.call_args.kwargs

    assert values["tool_name"] == "shell.exec"
    assert values["risk"] is None
    assert values["policy_status"] == "denied"
    assert values["execution_status"] == "denied"
    assert values["output_bytes"] is None


def test_approval_required_attempt_is_audited():
    with patch(
        "app.tools.service.record_tool_execution"
    ) as audit:
        result = execute_audited_tool_call(
            ToolCall(
                name="k8s.delete_pod",
                arguments={
                    "namespace": "production",
                    "pod": "payments-123",
                },
            )
        )

    assert result.status == ToolExecutionStatus.APPROVAL_REQUIRED

    values = audit.call_args.kwargs

    assert values["risk"] == "destructive"
    assert values["policy_status"] == "approval_required"
    assert values["execution_status"] == "approval_required"


def test_tool_output_is_not_written_to_audit():
    secret = "SECRET-DATA-THAT-MUST-NOT-BE-AUDITED"

    result = ToolExecutionResult(
        tool="k8s.get_logs",
        status=ToolExecutionStatus.SUCCESS,
        output={"logs": secret},
    )

    with (
        patch(
            "app.tools.service.execute_tool_call",
            return_value=result,
        ),
        patch(
            "app.tools.service.record_tool_execution"
        ) as audit,
    ):
        execute_audited_tool_call(
            ToolCall(
                name="k8s.get_logs",
                arguments={
                    "namespace": "production",
                    "pod": "payments",
                },
            )
        )

    values = audit.call_args.kwargs

    assert "output" not in values
    assert secret not in str(values)
    assert values["output_bytes"] is not None
