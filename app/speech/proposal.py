"""Propose a form scope from a transcript.

The transcript is untrusted user text. This uses the same deterministic
question checks as investigation creation and does not list the cluster,
execute a tool, or start an investigation.
"""

from dataclasses import dataclass
from typing import Literal

from app.tools.explicit_target import SUPPORTED_TARGET_KINDS
from app.tools.investigation_scope import SCOPE_REJECTION_MESSAGES
from app.tools.question_scope import QuestionScopeError, validate_question_scope
from app.tools.workload_target import (
    ScopeIntent,
    TargetQuestionError,
    classify_question_target,
)

Outcome = Literal["workload", "namespace", "clarify"]


@dataclass(frozen=True)
class SpeechScopeProposal:
    outcome: Outcome
    name: str | None = None
    kind: str | None = None
    code: str | None = None


def propose_speech_scope(transcript: str, *, namespace: str) -> SpeechScopeProposal:
    """Classify one transcript against one already-authorized namespace.

    A targeted question proposes that workload. An explicit namespace-wide
    question proposes the namespace as a whole. Anything else asks for
    clarification and proposes no broader scope.
    """
    text = transcript.strip() if isinstance(transcript, str) else ""

    if not text:
        return SpeechScopeProposal("clarify", code="question_empty")

    try:
        validate_question_scope(text, namespace=namespace)
        intent = classify_question_target(text, namespace=namespace)
    except (QuestionScopeError, TargetQuestionError) as exc:
        code = exc.code if exc.code in SCOPE_REJECTION_MESSAGES else "scope_unspecified"

        return SpeechScopeProposal("clarify", code=code)

    if intent.scope is ScopeIntent.BROAD_EXPLICIT:
        return SpeechScopeProposal("namespace")

    if intent.scope is ScopeIntent.TARGETED and intent.target is not None:
        kind = intent.target.kind if intent.target.kind in SUPPORTED_TARGET_KINDS else None

        return SpeechScopeProposal("workload", name=intent.target.name, kind=kind)

    return SpeechScopeProposal("clarify", code="scope_unspecified")
