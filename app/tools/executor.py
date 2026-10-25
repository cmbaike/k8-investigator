import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError

from pydantic import ValidationError

from app.tools.arguments import validate_tool_arguments
from app.tools.handlers import HANDLERS
from app.tools.limits import MAX_TOOL_OUTPUT_BYTES, TOOL_TIMEOUT_SECONDS
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
    ToolResultStatus,
)
from app.tools.policy import authorize_tool_call


def _output_size(output) -> int:
    encoded = json.dumps(
        output,
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")

    return len(encoded)


def execute_tool_call(call: ToolCall) -> ToolExecutionResult:
    decision = authorize_tool_call(call)

    if decision.status == ToolResultStatus.DENIED:
        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.DENIED,
            error=decision.reason,
        )

    if decision.status == ToolResultStatus.APPROVAL_REQUIRED:
        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.APPROVAL_REQUIRED,
            error=decision.reason,
        )

    try:
        validated_arguments = validate_tool_arguments(
            call.name,
            call.arguments,
        )
    except ValidationError as exc:
        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.INVALID_ARGUMENTS,
            error=str(exc),
        )

    handler = HANDLERS.get(call.name)

    if validated_arguments is None or handler is None:
        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.DENIED,
            error="Tool has no executable handler or argument schema.",
        )

    executor = ThreadPoolExecutor(max_workers=1)

    try:
        future = executor.submit(handler, validated_arguments)

        try:
            output = future.result(timeout=TOOL_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            future.cancel()

            return ToolExecutionResult(
                tool=call.name,
                status=ToolExecutionStatus.TIMEOUT,
                error=(
                    f"Tool execution exceeded "
                    f"{TOOL_TIMEOUT_SECONDS:.1f} seconds."
                ),
            )
        except Exception as exc:
            return ToolExecutionResult(
                tool=call.name,
                status=ToolExecutionStatus.ERROR,
                error=f"{type(exc).__name__}: {exc}",
            )

        size = _output_size(output)

        if size > MAX_TOOL_OUTPUT_BYTES:
            return ToolExecutionResult(
                tool=call.name,
                status=ToolExecutionStatus.ERROR,
                error=(
                    f"Tool output exceeded maximum size "
                    f"of {MAX_TOOL_OUTPUT_BYTES} bytes."
                ),
            )

        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.SUCCESS,
            output=output,
        )

    finally:
        executor.shutdown(wait=False, cancel_futures=True)
