from app.tools.investigation import (
    InvestigationContext,
    InvestigationScopeError,
)
from app.tools.models import ToolCall


def validate_investigation_scope(
    call: ToolCall,
    context: InvestigationContext,
) -> None:
    """
    Require a proposed tool call to remain within the
    investigation's authorized Kubernetes namespace.
    """

    authorized_namespace = (
        context.require_authorized_namespace()
    )

    proposed_namespace = call.arguments.get("namespace")

    if not isinstance(proposed_namespace, str):
        raise InvestigationScopeError(
            "Tool call requires an explicit namespace."
        )

    if proposed_namespace != authorized_namespace:
        raise InvestigationScopeError(
            "Proposed namespace is outside the "
            "authorized investigation scope."
        )
