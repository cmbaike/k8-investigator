import re

from app.tools.models import ToolCall


class ToolIntentError(ValueError):
    pass


_PROHIBITED_INTENT_PATTERNS = (
    re.compile(r"\bkubectl\s+exec\b", re.IGNORECASE),
    re.compile(r"\bexec(?:ute)?\s+(?:into|in)\b", re.IGNORECASE),
    re.compile(
        r"\bkubectl\s+(?:apply|patch|delete|scale)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brollout\s+restart\b", re.IGNORECASE),
)


def validate_proposed_tool_intent(
    proposed_call: ToolCall,
    user_text: str,
) -> None:
    # proposed_call is intentionally accepted here even though this
    # first version only needs the original user request. Keeping it
    # in the interface makes the security boundary explicit.
    _ = proposed_call

    for pattern in _PROHIBITED_INTENT_PATTERNS:
        if pattern.search(user_text):
            raise ToolIntentError(
                "User request contains an operation that is not "
                "eligible for read-only tool substitution."
            )


def has_prohibited_intent(user_text: str) -> bool:
    """True if the text asks for an operation that read-only tools can never do.

    Single source of truth shared by tool binding and investigation creation.
    """
    return any(p.search(user_text) for p in _PROHIBITED_INTENT_PATTERNS)

