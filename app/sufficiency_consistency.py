import re

from app.sufficiency import SufficiencyResult


INSUFFICIENCY_PATTERNS = (
    r"\bnot provided\b",
    r"\bnot present\b",
    r"\bnot stated\b",
    r"\bdoes not provide\b",
    r"\bdoes not mention\b",
    r"\bdoes not specify\b",
    r"\binsufficient\b",
)


def apply_consistency_guard(
    result: SufficiencyResult,
) -> SufficiencyResult:
    """
    Fail closed when the classifier returns sufficient=True
    but its own explanation explicitly states that required
    evidence is absent or insufficient.
    """

    if not result.sufficient:
        return result

    reason = result.reason.lower()

    contradiction = any(
        re.search(pattern, reason)
        for pattern in INSUFFICIENCY_PATTERNS
    )

    if not contradiction:
        return result

    return SufficiencyResult(
        sufficient=False,
        reason=(
            "Consistency guard rejected a contradictory "
            f"sufficient=true decision. Classifier reason: {result.reason}"
        ),
    )
