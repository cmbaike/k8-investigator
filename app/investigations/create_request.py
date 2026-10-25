"""Request body for creating an investigation."""

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.tools.explicit_target import ExplicitTarget


class InvestigationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The diagnostic question, in natural language. It may be broad and need
    # not name a namespace or any resource.
    question: str = Field(min_length=1, max_length=4000)
    # The Kubernetes namespace to investigate. Authoritative, authenticated
    # against the API key's allowed namespaces, and bound before any model
    # runs. When omitted (older clients), the single namespace stated in the
    # question is used instead.
    namespace: str | None = Field(default=None, min_length=1, max_length=63)
    max_steps: int = Field(default=6, ge=1, le=10)
    # Optional structured scope (clients that predate these send only the
    # question, whose text then decides the scope as before). At most one may
    # be given. Both are bound by the same rules as a question: see
    # app.tools.explicit_target. Neither can widen to the namespace.
    target: ExplicitTarget | None = None
    namespace_wide: bool = False

    @model_validator(mode="after")
    def _one_scope(self):
        if self.target is not None and self.namespace_wide:
            raise ValueError("Send either a target or namespace_wide, not both.")

        return self
