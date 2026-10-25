"""Prepare text that may be spoken.

Finding text is application-authored and already validated. Model fields are
still untrusted wording, so assignments, long tokens, evidence ids, and
command-like phrases are removed before synthesis. Nothing here rewrites a
diagnosis.
"""

import re

_EVIDENCE_ID = re.compile(r"\b(?:ev|log)-\d{4}\b", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|password|passwd|secret|token|authorization|bearer|credential)"
    r"\b\s*[:=]\s*\S+"
)
_LONG_TOKEN = re.compile(r"\b(?:[A-Za-z0-9+/]{32,}={0,2}|[A-Fa-f0-9]{32,})\b")
_CONTROL = re.compile(r"[\x00-\x1f<>`]")
_SPACE = re.compile(r"\s+")
# Model-authored checks and explanations only. Finding prose can legitimately
# say a container "cannot be created".
_COMMAND = re.compile(
    r"(?i)\b(?:kubectl|curl|wget|bash|sudo|rm\s+-|sh\s+-c)\b[^.]*"
)
_MUTATION = re.compile(
    r"(?i)\b(?:kubectl|curl|wget|sudo|delete|apply|patch|scale|drain|cordon|exec)\b"
)

_TOOL_SENTENCE = re.compile(r"\s*Observed during tool execution '[^']*'\.?")
_RESOURCE_SENTENCE = re.compile(
    r"\s*Resource: namespace '[^']*'(?:, pod '[^']*')?(?:, container '[^']*')?\.?"
)


def _clean(text: str, *, limit: int, drop_commands: bool) -> str:
    if drop_commands:
        text = _COMMAND.sub(" ", text)

    text = _SECRET_ASSIGNMENT.sub(" ", text)
    text = _LONG_TOKEN.sub(" ", text)
    text = _EVIDENCE_ID.sub(" ", text)
    text = _CONTROL.sub(" ", text)
    text = _SPACE.sub(" ", text).strip(" .;,")

    if len(text) > limit:
        trimmed = text[:limit].rsplit(" ", 1)[0].strip(" .;,")
        text = trimmed or text[:limit].strip()

    return text


def for_finding(text: str, *, limit: int = 240) -> str:
    text = _RESOURCE_SENTENCE.sub(" ", text)
    text = _TOOL_SENTENCE.sub(" ", text)

    return _clean(text, limit=limit, drop_commands=False)


def for_model_text(text: str, *, limit: int = 300) -> str:
    return _clean(text, limit=limit, drop_commands=True)


def model_text_is_speakable(text: str) -> bool:
    """False when a model field tells the listener to change the cluster or
    run a command. The field is then left out of the briefing entirely."""
    return _MUTATION.search(text) is None and _COMMAND.search(text) is None


def first_sentence(text: str) -> str:
    cleaned = " ".join(text.split())

    for mark in (". ", "? ", "! "):
        if mark in cleaned:
            return cleaned.split(mark, 1)[0].strip()

    return cleaned.strip()
