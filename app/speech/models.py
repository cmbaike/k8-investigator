from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class TranscriptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transcript: str = Field(max_length=4_000)


class SpeechProposalRequest(BaseModel):
    """Untrusted transcript plus the namespace already selected in the form."""

    model_config = ConfigDict(extra="forbid")

    transcript: str = Field(min_length=1, max_length=3_800)
    namespace: str = Field(min_length=1, max_length=63)


class SpeechProposalResponse(BaseModel):
    """A scope the existing classifier would accept. Never an investigation."""

    model_config = ConfigDict(extra="forbid")

    outcome: Literal["workload", "namespace", "clarify"]
    name: str | None = None
    kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Pod"] | None = None
    code: str | None = None


class SpokenBriefingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=2_000)
    speech_available: bool
