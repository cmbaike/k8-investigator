import time

from app.tools.executor import execute_tool_call
from app.tools.models import ToolCall, ToolExecutionStatus
from unittest.mock import patch


def test_read_only_tool_executes():
    def fake_handler(arguments):
        return {
            "namespace": arguments.namespace,
            "pods": [],
        }

    with patch.dict(
        "app.tools.executor.HANDLERS",
        {"k8s.get_pods": fake_handler},
        clear=False,
    ):
        result = execute_tool_call(
            ToolCall(
                name="k8s.get_pods",
                arguments={"namespace": "production"},
            )
        )

    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.output["namespace"] == "production"


def test_missing_required_argument_is_rejected():
    result = execute_tool_call(
        ToolCall(
            name="k8s.describe_pod",
            arguments={"namespace": "production"},
        )
    )

    assert result.status == ToolExecutionStatus.INVALID_ARGUMENTS
    
def test_oversized_output_is_rejected():
    def huge_handler(arguments):
        return {"data": "x" * (128 * 1024)}

    with patch.dict(
        "app.tools.executor.HANDLERS",
        {"k8s.get_pods": huge_handler},
        clear=False,
    ):
        result = execute_tool_call(
            ToolCall(
                name="k8s.get_pods",
                arguments={"namespace": "production"},
            )
        )

    assert result.status == ToolExecutionStatus.ERROR
    assert result.output is None
    assert "maximum size" in result.error


def test_tool_timeout_is_reported():
    def slow_handler(arguments):
        time.sleep(0.1)
        return {"ok": True}

    with (
        patch.dict(
            "app.tools.executor.HANDLERS",
            {"k8s.get_pods": slow_handler},
            clear=False,
        ),
        patch(
            "app.tools.executor.TOOL_TIMEOUT_SECONDS",
            0.01,
        ),
    ):
        result = execute_tool_call(
            ToolCall(
                name="k8s.get_pods",
                arguments={"namespace": "production"},
            )
        )

    assert result.status == ToolExecutionStatus.TIMEOUT
    assert result.output is None  


def test_unknown_argument_is_rejected():
    result = execute_tool_call(
        ToolCall(
            name="k8s.get_pods",
            arguments={
                "namespace": "production",
                "command": "whoami",
            },
        )
    )

    assert result.status == ToolExecutionStatus.INVALID_ARGUMENTS


def test_invalid_tail_is_rejected():
    result = execute_tool_call(
        ToolCall(
            name="k8s.get_logs",
            arguments={
                "namespace": "production",
                "pod": "payments-123",
                "tail": 1000000,
            },
        )
    )

    assert result.status == ToolExecutionStatus.INVALID_ARGUMENTS


def test_default_log_tail_is_applied():
    def fake_handler(arguments):
        return {
            "namespace": arguments.namespace,
            "pod": arguments.pod,
            "tail": arguments.tail,
        }

    with patch.dict(
        "app.tools.executor.HANDLERS",
        {"k8s.get_logs": fake_handler},
        clear=False,
    ):
        result = execute_tool_call(
            ToolCall(
                name="k8s.get_logs",
                arguments={
                    "namespace": "production",
                    "pod": "payments-123",
                },
            )
        )

    assert result.status == ToolExecutionStatus.SUCCESS
    assert result.output["tail"] == 200


def test_state_changing_tool_never_reaches_handler():
    result = execute_tool_call(
        ToolCall(
            name="k8s.restart_deployment",
            arguments={
                "namespace": "production",
                "deployment": "payments",
                "approved": True,
            },
        )
    )

    assert result.status == ToolExecutionStatus.APPROVAL_REQUIRED
    assert result.output is None


def test_destructive_tool_never_reaches_handler():
    result = execute_tool_call(
        ToolCall(
            name="k8s.delete_pod",
            arguments={
                "namespace": "production",
                "pod": "payments-123",
            },
        )
    )

    assert result.status == ToolExecutionStatus.APPROVAL_REQUIRED
    assert result.output is None


def test_unknown_tool_is_denied():
    result = execute_tool_call(
        ToolCall(
            name="shell.exec",
            arguments={"command": "whoami"},
        )
    )

    assert result.status == ToolExecutionStatus.DENIED
