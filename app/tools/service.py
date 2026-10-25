import json
from time import perf_counter
from uuid import uuid4

from app.tool_audit import record_tool_execution
from app.tools.executor import execute_tool_call
from app.tools.models import ToolCall, ToolExecutionResult
from app.tools.policy import authorize_tool_call


def _output_size(output) -> int | None:
    if output is None:
        return None

    return len(
        json.dumps(
            output,
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    )


def execute_audited_tool_call(
    call: ToolCall,
    *,
    request_id: str | None = None,
) -> ToolExecutionResult:
    tool_call_id = str(uuid4())

    # Capture the deterministic policy decision independently for audit.
    decision = authorize_tool_call(call)

    started = perf_counter()

    try:
        result = execute_tool_call(call)
    except Exception as exc:
        duration_ms = (perf_counter() - started) * 1000

        record_tool_execution(
            tool_call_id=tool_call_id,
            request_id=request_id,
            tool_name=call.name,
            arguments=call.arguments,
            risk=decision.risk.value if decision.risk else None,
            policy_status=decision.status.value,
            execution_status="error",
            duration_ms=duration_ms,
            output_bytes=None,
            error_type=type(exc).__name__,
            error_message=str(exc),
        )

        raise

    duration_ms = (perf_counter() - started) * 1000

    error_type = None
    if result.error:
        error_type = result.status.value

    record_tool_execution(
        tool_call_id=tool_call_id,
        request_id=request_id,
        tool_name=call.name,
        arguments=call.arguments,
        risk=decision.risk.value if decision.risk else None,
        policy_status=decision.status.value,
        execution_status=result.status.value,
        duration_ms=duration_ms,
        output_bytes=_output_size(result.output),
        error_type=error_type,
        error_message=result.error,
    )

    return result
