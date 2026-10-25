from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class InvestigationStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class InvestigationRecord(BaseModel):
    """Durable metadata for a single investigation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    investigation_id: str = Field(min_length=1)
    authorized_namespace: str = Field(min_length=1)

    status: InvestigationStatus

    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None

    stop_reason: str | None = None
    
    user_text: str | None = Field(
        default=None,
        min_length=1,
        max_length=4000,
    )

    max_steps: int | None = Field(
       default=None,
       ge=1,
       le=10,
    )