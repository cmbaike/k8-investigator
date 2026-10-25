from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from app.tools.investigation_authority import (
    InvestigationAuthority,
    InvestigationAuthorityError,
    InvestigationKind,
    infer_investigation_authority,
    validate_investigation_operation,
)
from app.tools.models import ToolCall
from app.tools.operation_intent import (
    ToolOperationIntentError,
    validate_proposed_operation,
)
from app.tools.operation_intent import (
    infer_explicit_read_only_operation,
)


class OperationAuthorityError(ValueError):
    pass


class OperationAuthorityMode(StrEnum):
    EXPLICIT = "explicit"
    INVESTIGATION = "investigation"


class AuthorizedOperation(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    mode: OperationAuthorityMode
    investigation_kind: InvestigationKind | None = None


def authorize_proposed_operation(
    proposed_call: ToolCall,
    user_text: str,
    *,
    bound_kind: InvestigationKind | None = None,
) -> AuthorizedOperation:
    """
    Deterministic operation authorization.

    When the application has bound an investigation kind (from the
    authenticated request), that binding is the authority: the tool must be in
    the kind's read-only allowlist and the question text is not consulted.
    Otherwise explicit operation authority takes precedence over text-inferred
    investigation authority.
    """

    if bound_kind is not None:
        try:
            validate_investigation_operation(
                proposed_call,
                InvestigationAuthority(kind=bound_kind),
            )
        except InvestigationAuthorityError as exc:
            raise OperationAuthorityError(str(exc)) from exc

        return AuthorizedOperation(
            mode=OperationAuthorityMode.INVESTIGATION,
            investigation_kind=bound_kind,
        )

    explicit_operation = infer_explicit_read_only_operation(
        user_text
    )

    if explicit_operation is not None:
        if proposed_call.name != explicit_operation:
            raise OperationAuthorityError(
                "Proposed operation does not match the "
                "explicitly authorized user operation."
            )

        return AuthorizedOperation(
            mode=OperationAuthorityMode.EXPLICIT,
        )

    authority = infer_investigation_authority(user_text)

    if authority is None:
        raise OperationAuthorityError(
            "User input does not authorize the proposed operation."
        )

    try:
        validate_investigation_operation(
            proposed_call,
            authority,
        )
    except InvestigationAuthorityError as exc:
        raise OperationAuthorityError(str(exc)) from exc

    return AuthorizedOperation(
        mode=OperationAuthorityMode.INVESTIGATION,
        investigation_kind=authority.kind,
    )
