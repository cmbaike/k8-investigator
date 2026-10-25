from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

TIMEOUT = "timeout"


class ToolExecutionStatus(StrEnum):
    SUCCESS = "success"
    INVALID_ARGUMENTS = "invalid_arguments"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"
    
class ToolRisk(StrEnum):
    READ_ONLY = "read_only"
    STATE_CHANGING = "state_changing"
    DESTRUCTIVE = "destructive"


class ToolDefinition(BaseModel):
    name: str
    description: str
    risk: ToolRisk


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ToolResultStatus(StrEnum):
    ALLOWED = "allowed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"


class PolicyDecision(BaseModel):
    status: ToolResultStatus
    tool: str
    risk: ToolRisk | None = None
    reason: str

class ToolExecutionResult(BaseModel):
    tool: str
    status: ToolExecutionStatus
    output: Any | None = None
    error: str | None = None
