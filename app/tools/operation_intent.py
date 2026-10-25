import re

from app.tools.models import ToolCall


class ToolOperationIntentError(ValueError):
    pass


_EXPLICIT_OPERATION_PATTERNS = (
    (
        "k8s.get_previous_logs",
        re.compile(
            r"\bprevious\s+(?:container\s+)?logs?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "k8s.describe_pod",
        re.compile(
            r"\b(?:describe|inspect)\s+pod\b",
            re.IGNORECASE,
        ),
    ),
    (
        "k8s.get_deployment",
        re.compile(
            r"\b(?:"
            r"get\s+(?:the\s+)?deployment"
            r"|show\s+(?:me\s+)?(?:the\s+)?deployment"
            r"|inspect\s+(?:the\s+)?deployment"
            r")\b",
            re.IGNORECASE,
        ),
    ),
    (
        "k8s.get_events",
        re.compile(
            r"\b(?:kubernetes|cluster)?\s*events?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "k8s.get_logs",
        re.compile(
            r"\b(?:get|show|read|fetch|retrieve)\b.*\blogs?\b",
            re.IGNORECASE,
        ),
    ),
   (
    "k8s.get_pods",
    re.compile(
        r"\b(?:"
        r"list\s+(?:the\s+)?pods?"
        r"|show\s+(?:me\s+)?(?:the\s+)?pods?"
        r")\b",
        re.IGNORECASE,
    ),
   ),
)


def infer_explicit_read_only_operation(
    user_text: str,
) -> str | None:
    previous_logs = re.search(
        r"\bprevious\s+(?:container\s+)?logs?\b",
        user_text,
        re.IGNORECASE,
    )

    matches: list[str] = []

    for tool_name, pattern in _EXPLICIT_OPERATION_PATTERNS:
        if (
            tool_name == "k8s.get_logs"
            and previous_logs is not None
        ):
            continue

        if pattern.search(user_text):
            matches.append(tool_name)

    if len(matches) != 1:
        return None

    return matches[0]


def validate_proposed_operation(
    proposed_call: ToolCall,
    user_text: str,
) -> None:
    authorized_tool = infer_explicit_read_only_operation(
        user_text
    )

    if authorized_tool is None:
        raise ToolOperationIntentError(
            "User input does not authorize exactly one "
            "supported read-only operation."
        )

    if proposed_call.name != authorized_tool:
        raise ToolOperationIntentError(
            "Proposed tool does not match the read-only "
            "operation authorized by the user."
        )
