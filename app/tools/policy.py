from app.tools.models import (
    PolicyDecision,
    ToolCall,
    ToolResultStatus,
    ToolRisk,
)
from app.tools.registry import get_tool


def authorize_tool_call(call: ToolCall) -> PolicyDecision:
    tool = get_tool(call.name)

    if tool is None:
        return PolicyDecision(
            status=ToolResultStatus.DENIED,
            tool=call.name,
            risk=None,
            reason="Tool is not registered in the application allow-list.",
        )

    if tool.risk == ToolRisk.READ_ONLY:
        return PolicyDecision(
            status=ToolResultStatus.ALLOWED,
            tool=tool.name,
            risk=tool.risk,
            reason="Registered read-only tool.",
        )

    if tool.risk in {
        ToolRisk.STATE_CHANGING,
        ToolRisk.DESTRUCTIVE,
    }:
        return PolicyDecision(
            status=ToolResultStatus.APPROVAL_REQUIRED,
            tool=tool.name,
            risk=tool.risk,
            reason="State-changing or destructive operations require explicit human approval.",
        )

    # Defensive fail-closed branch.
    return PolicyDecision(
        status=ToolResultStatus.DENIED,
        tool=tool.name,
        risk=tool.risk,
        reason="Tool risk classification is not permitted.",
    )
