from pydantic import BaseModel, ConfigDict
from typing import Literal

from app.tools.binder import (
    ToolBindingError,
    bind_proposed_user_tool_call,
)
from app.tools.intent import ToolIntentError
from app.tools.models import ToolCall
from app.tools.proposal import ToolProposal


class ProposalGateResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["bound", "none", "blocked"]
    call: ToolCall | None = None
    reason: str | None = None


def gate_tool_proposal(
    proposal: ToolProposal,
    user_text: str,
) -> ProposalGateResult:
    if proposal.action == "none":
        return ProposalGateResult(
            status="none",
            call=None,
            reason=None,
        )

    if proposal.tool is None:
        return ProposalGateResult(
            status="blocked",
            call=None,
            reason="Tool proposal did not contain a tool call.",
        )

    try:
        bound = bind_proposed_user_tool_call(
            proposal.tool,
            user_text,
        )
    except (ToolBindingError, ToolIntentError, ValueError) as exc:
        return ProposalGateResult(
            status="blocked",
            call=None,
            reason=str(exc),
        )

    return ProposalGateResult(
        status="bound",
        call=bound,
        reason=None,
    )