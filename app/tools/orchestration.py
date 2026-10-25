from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.tools.models import ToolCall, ToolExecutionResult
from app.tools.proposal import propose_tool
from app.tools.proposal_gate import gate_tool_proposal
from app.tools.service import execute_audited_tool_call
from app.security.api_keys import (
    APIKeyPrincipal,
    authorize_namespace,
)


class ToolOrchestrationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "none",
        "blocked",
        "executed",
    ]

    call: ToolCall | None = None
    execution: ToolExecutionResult | None = None
    reason: str | None = None


def run_read_only_tool_request(
    *,
    request_id: UUID,
    user_text: str,
    principal: APIKeyPrincipal,
) -> ToolOrchestrationResult:
    proposal = propose_tool(user_text)

    gate = gate_tool_proposal(
        proposal,
        user_text,
    )

    if gate.status == "none":
        return ToolOrchestrationResult(
            status="none",
            call=None,
            execution=None,
            reason=None,
        )

    if gate.status == "blocked":
        return ToolOrchestrationResult(
            status="blocked",
            call=None,
            execution=None,
            reason=gate.reason,
        )

    # Defensive fail-closed invariant.
    if gate.status != "bound" or gate.call is None:
        return ToolOrchestrationResult(
            status="blocked",
            call=None,
            execution=None,
            reason=(
                "Tool proposal did not produce "
                "an executable bound call."
            ),
        )
        
    # Authenticated HTTP callers must be authorized for the
    # exact namespace in the deterministic bound ToolCall.   
    namespace = gate.call.arguments.get("namespace")
    if not isinstance(namespace, str) or not namespace:
       return ToolOrchestrationResult(
        status="blocked",
        call=None,
        execution=None,
        reason="Tool call has no authorized namespace.",
    )
    authorize_namespace(principal, namespace)
    # SECURITY BOUNDARY:
    # Only the ToolCall returned by the deterministic gate
    # may cross into audited execution.
    execution = execute_audited_tool_call(
        gate.call,
        request_id=str(request_id),
    )

    return ToolOrchestrationResult(
        status="executed",
        call=gate.call,
        execution=execution,
        reason=None,
    )