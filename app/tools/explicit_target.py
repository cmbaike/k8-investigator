"""Structured investigation targets, bound by the same rules as a question.

A client may send a structured target (`kind` + `name`) or an explicit
namespace-wide scope instead of relying on a name appearing in free text. Both
are turned into a canonical question here and then pass through exactly the
same checks as any other question (`create_bound_investigation_context`), so:

  * the persisted `user_text` IS the canonical question, and execution
    re-validates it unchanged;
  * the application's own classifier must read back exactly the target that was
    requested. If it cannot (a reserved word, an unsupported name) the request
    is refused with a fixed code, never reinterpreted;
  * a free-form question that names another workload, or asks about the rest of
    the namespace, is refused by the existing multiple_targets / ambiguous_scope
    rules; a target is never widened to the namespace;
  * `kind` is a hint, as it is for questions. It is not checked against the
    resource's real kind; resolution is by verified owner identity and name.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.tools.workload_target import (
    NAME_PATTERN,
    ScopeIntent,
    TargetQuestionError,
    classify_question_target,
)

# kind -> the noun the classifier recognises.
SUPPORTED_TARGET_KINDS = {
    "Deployment": "deployment",
    "StatefulSet": "statefulset",
    "DaemonSet": "daemonset",
    "Pod": "pod",
}

TARGET_NOT_BINDABLE = "target_not_bindable"
TARGET_NOT_BINDABLE_MESSAGE = (
    "That workload name cannot be bound as an explicit target (it may be a "
    "reserved word). Use the exact name of an existing workload."
)


class ExplicitTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["Deployment", "StatefulSet", "DaemonSet", "Pod"]
    name: str = Field(min_length=1, max_length=63, pattern=NAME_PATTERN.pattern)


def compose_question(
    question: str,
    *,
    namespace: str,
    target: ExplicitTarget | None,
    namespace_wide: bool,
) -> str:
    """The canonical question for a structured scope; `question` unchanged when
    none was requested (legacy behaviour).

    Raises `TargetQuestionError(TARGET_NOT_BINDABLE)` when the application's
    classifier does not read back the requested target. Other rules (several
    names, widening, namespace conflicts) are enforced by the caller's normal
    question validation on the returned text."""
    if target is not None and namespace_wide:
        raise TargetQuestionError("ambiguous_scope")

    if target is not None:
        canonical = (
            f"Investigate {SUPPORTED_TARGET_KINDS[target.kind]}/{target.name}. "
            f"{question}"
        )

        try:
            intent = classify_question_target(canonical, namespace=namespace)
        except TargetQuestionError:
            # Another name or a widening phrase in the free-form question:
            # let the standard validation report the precise fixed code.
            return canonical

        if (
            intent.scope is not ScopeIntent.TARGETED
            or intent.target is None
            or intent.target.name != target.name
        ):
            raise TargetQuestionError(TARGET_NOT_BINDABLE)

        return canonical

    if namespace_wide:
        canonical = f"Investigate the health of the whole namespace. {question}"

        try:
            intent = classify_question_target(canonical, namespace=namespace)
        except TargetQuestionError:
            return canonical

        if intent.scope is not ScopeIntent.BROAD_EXPLICIT:
            raise TargetQuestionError("ambiguous_scope")

        return canonical

    return question
