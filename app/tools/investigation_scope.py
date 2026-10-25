import re
from uuid import uuid4

import pytest

from app.tools.investigation import InvestigationContext
from app.tools.investigation_authority import (
    InvestigationKind,
    infer_investigation_authority,
)
from app.tools.workload_target import (
    ScopeIntent,
    TargetQuestionError,
    classify_question_target,
)
from app.tools.question_scope import (
    QuestionScopeError,
    is_valid_namespace_name,
    referenced_namespaces,
    validate_question_scope,
)



class InvestigationScopeCreationError(ValueError):
    """The request cannot become an investigation.

    `code` is a fixed vocabulary value; it never echoes the question."""

    def __init__(self, message: str = "Invalid investigation scope.", *, code: str = "invalid_scope") -> None:
        super().__init__(message)
        self.code = code


_NAMESPACE_PATTERN = re.compile(
    r"\bnamespace\s*(?:=|:|\s+)\s*"
    r"(?P<namespace>[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)\b",
    re.IGNORECASE,
)


def extract_authorized_namespace(
    user_text: str,
) -> str:
    """
    Extract exactly one explicitly asserted Kubernetes namespace.

    Never infer a namespace from a model proposal.
    """

    matches = list(_NAMESPACE_PATTERN.finditer(user_text))

    if len(matches) != 1:
        raise InvestigationScopeCreationError(
            "Investigation requires exactly one explicit namespace."
        )

    namespace = matches[0].group("namespace")

    if namespace != namespace.lower():
        raise InvestigationScopeCreationError(
            "Namespace must use lowercase Kubernetes naming."
        )

    return namespace


def create_investigation_context(
    user_text: str,
    *,
    max_steps: int = 6,
) -> InvestigationContext:
    
    if infer_investigation_authority(user_text) is None:
       raise InvestigationScopeCreationError(
        "User request does not authorize a workload investigation."
    )
       
    namespace = extract_authorized_namespace(user_text)

    if not 1 <= max_steps <= 10:
        raise InvestigationScopeCreationError(
            "Investigation step budget must be between 1 and 10."
        )

    return InvestigationContext(
        investigation_id=str(uuid4()),
        user_text=user_text,
        authorized_namespace=namespace,
        max_steps=max_steps,
    )


def resolve_requested_namespace(
    question: str,
    requested_namespace: str | None,
) -> str:
    """Decide WHICH namespace is being requested. Authorization is separate.

    The structured field is authoritative. Only when it is absent does the
    single namespace named in the question text stand in for it (backward
    compatibility for clients that predate the field). The question can never
    contradict an explicit field: see `create_bound_investigation_context`.
    """
    if requested_namespace is not None:
        if not is_valid_namespace_name(requested_namespace):
            raise InvestigationScopeCreationError(
                "Invalid namespace name.", code="namespace_invalid"
            )

        return requested_namespace

    named = referenced_namespaces(question)

    if not named:
        raise InvestigationScopeCreationError(
            "A namespace is required.", code="namespace_required"
        )

    if len(named) > 1:
        raise InvestigationScopeCreationError(
            "The question names more than one namespace.",
            code="namespace_conflict",
        )

    if not is_valid_namespace_name(named[0]):
        # Kubernetes names are lowercase; never lower-case on the caller's behalf.
        raise InvestigationScopeCreationError(
            "Invalid namespace name.", code="namespace_invalid"
        )

    return named[0]


def create_bound_investigation_context(
    question: str,
    *,
    namespace: str,
    max_steps: int = 6,
    investigation_id: str | None = None,
) -> InvestigationContext:
    """Build the context for an investigation of exactly `namespace`.

    `namespace` must already be authenticated and authorized by the caller. The
    question is the diagnostic question only; it may be broad, may omit the
    namespace and any resource names, and needs no fixed verbs. It is checked
    to be fulfillable by a read-only investigation of this one namespace, and
    is rejected, never reinterpreted, when it is not.

    The investigation kind is bound HERE, before any model is invoked, so tool
    authority never depends on re-reading the question.
    """
    if not is_valid_namespace_name(namespace):
        raise InvestigationScopeCreationError(
            "Invalid namespace name.", code="namespace_invalid"
        )

    if not 1 <= max_steps <= 10:
        raise InvestigationScopeCreationError(
            "Investigation step budget must be between 1 and 10.",
            code="invalid_steps",
        )

    try:
        validate_question_scope(question, namespace=namespace)
    except QuestionScopeError as exc:
        raise InvestigationScopeCreationError(str(exc), code=exc.code) from exc

    # A named resource identity becomes a bound target. A question that names
    # none stays a broad, namespace-level investigation (explicitly broad, or
    # unspecified, which the report discloses). A question that names several,
    # names one and also asks about the rest, or names something that cannot
    # be a resource name is REJECTED for clarification, never reinterpreted.
    try:
        intent = classify_question_target(question, namespace=namespace)
    except TargetQuestionError as exc:
        raise InvestigationScopeCreationError(str(exc), code=exc.code) from exc

    # Fail closed: a namespace-wide investigation needs EXPLICIT broad intent.
    # A question that names no recognised resource and does not ask about the
    # namespace as a whole is ambiguous; it is never promoted to a broad run.
    if intent.scope is ScopeIntent.BROAD_UNSPECIFIED:
        raise InvestigationScopeCreationError(
            SCOPE_REJECTION_MESSAGES["scope_unspecified"], code="scope_unspecified"
        )

    return InvestigationContext(
        investigation_id=investigation_id or str(uuid4()),
        user_text=question,
        authorized_namespace=namespace,
        max_steps=max_steps,
        investigation_kind=InvestigationKind.K8S_WORKLOAD,
        target=intent.target,
        broad_scope_explicit=intent.scope is ScopeIntent.BROAD_EXPLICIT,
        # A namespace-wide question has no bound workload. Basic health
        # inspection is then deterministic and does not spend analysis steps.
        namespace_health_discovery=intent.target is None,
    )


# Fixed API responses for a request that cannot become a read-only
# investigation of one authorized namespace. None echoes the question. Shared
# by the API (which sends them) and the CLI (which recognises exactly these).
SCOPE_REJECTION_MESSAGES = {
    "namespace_required": "A namespace is required: send the 'namespace' field.",
    "namespace_invalid": "Invalid namespace name.",
    "namespace_conflict": (
        "The question refers to a namespace other than the one requested."
    ),
    "cluster_wide": (
        "Cluster-wide or cross-namespace investigation is not supported; "
        "investigate one authorized namespace."
    ),
    "broader_access": (
        "The question requests access beyond the authorized namespace."
    ),
    "state_change": (
        "Investigations are read-only; the question requests a change."
    ),
    "question_empty": "The question must not be empty.",
    "multiple_targets": (
        "The question names more than one workload; ask about one workload "
        "at a time, or ask a broad question about the namespace."
    ),
    "ambiguous_scope": (
        "The question names a workload and also asks about the rest of the "
        "namespace; ask about one workload, or ask a broad question about "
        "the namespace."
    ),
    "scope_unspecified": (
        "The question does not say what to investigate: name one workload "
        "(for example 'Why is <name> failing?') or ask about the namespace as "
        "a whole (for example 'Investigate the health of the namespace')."
    ),
    "invalid_target_name": (
        "A name in the question is not a valid Kubernetes resource name "
        "(lowercase letters, digits and hyphens); check the spelling."
    ),
    "target_not_bindable": (
        "That workload name cannot be bound as an explicit target (it may be a "
        "reserved word). Use the exact name of an existing workload."
    ),
    "question_too_long": "The question is too long once the scope is added.",
}
DEFAULT_SCOPE_REJECTION = "Invalid investigation scope."

