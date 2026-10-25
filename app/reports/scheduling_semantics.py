"""Narrow check for inverted taint/toleration wording in model-authored text.

In Kubernetes a NODE carries taints and a POD declares tolerations. A pod
"tolerates" (or fails to tolerate) a node's taint; a node never tolerates
anything and a pod never carries a taint. A model occasionally reverses this
("the pod contains a taint that no node tolerates", "check the taints on the
pod and the tolerations on the nodes"), which would send an engineer to
inspect the wrong object.

This is deliberately NOT general scheduling-semantics validation. It matches
only a few unambiguous phrasings in which taints are attributed to a pod or
tolerations (or the act of tolerating) are attributed to a node. Anything it
does not recognise passes, and a correct statement ("node taints the pod does
not tolerate", "the tolerations the pod declares") never matches. A match
omits ONE hypothesis with a fixed code; no text is kept, and nothing is
rewritten.
"""

import re
from collections.abc import Iterable

INVERTED_SCHEDULING_TERMS = "inverted_scheduling_terms"

# Determiners that may sit between a preposition/verb and the noun it governs.
_DET = (
    r"(?:(?:the|a|an|each|every|any|all|no|this|that|these|those|available|"
    r"cluster|worker|failing|pending|unschedulable)\s+){0,3}"
)
# Words that may stand between a subject and its verb without changing it.
_MODAL = (
    r"(?:(?:do|does|did|can|could|may|might|will|would|should|must|cannot|"
    r"can't|not|never|also|currently|possibly|perhaps|actually)\s+){0,3}"
)
# "A node never tolerates anything" is the CORRECT statement; "never" is
# therefore not a word that can sit between a node and "tolerates" in a claim.
_MODAL_NO_NEVER = _MODAL.replace("not|never|", "not|")
_APOSTROPHE = r"['\u2019]"

_TOLERATE = r"(?:tolerates?|tolerated|tolerating)"

_INVERTED = (
    # A node as the subject of "tolerate": "no node in the cluster tolerates",
    # "the nodes do not tolerate". ("nodes that the pod does not tolerate" has
    # another word between them and is correct.)
    re.compile(
        r"\bnodes?\b(?:\s+(?:in|of|within|across)\s+the\s+(?:cluster|namespace|pool))?"
        r"\s+" + _MODAL_NO_NEVER + _TOLERATE + r"\b",
        re.IGNORECASE,
    ),
    # "not tolerated by any node".
    re.compile(
        r"\b" + _TOLERATE + r"\s+by\s+" + _DET + r"nodes?\b(?!" + _APOSTROPHE + r")",
        re.IGNORECASE,
    ),
    # "tolerations on the nodes" / "tolerations of each node". A phrase such as
    # "tolerations for the node taints" is about the taints, and is correct.
    re.compile(
        r"\btolerations?\b(?:\s+\w+){0,2}?\s+"
        r"(?:on|of|for|from|in|at|set\s+on|declared\s+on|defined\s+on|"
        r"configured\s+on|applied\s+to)\s+"
        + _DET
        + r"nodes?\b(?!" + _APOSTROPHE + r"|\s+(?:taints?|labels?|capacity|selectors?|pool))",
        re.IGNORECASE,
    ),
    # "node tolerations", "the node's tolerations".
    re.compile(
        r"\bnodes?(?:" + _APOSTROPHE + r"s?)?\s+tolerations?\b", re.IGNORECASE
    ),
    # "the node has sufficient resources and tolerations". (A span that
    # mentions the pod, a taint or a relative clause is about the taints, as
    # in "nodes have taints that the pod has no tolerations for".)
    re.compile(
        r"\bnodes?\s+(?:(?:may|might|could|also|currently)\s+){0,2}"
        r"(?:has|have|declares?|defines?|needs?|requires?)\s+"
        r"(?:(?!\bpods?\b|\btaints?\b|\bthat\b|\bwhich\b)[^.;]){0,40}?"
        r"\btolerations?\b",
        re.IGNORECASE,
    ),
    # "taints on the pod", "taints set on pods". A negation attached to the
    # claim ("no taint is set on the pod", "taints are not set on pods") is the
    # correct statement and does not match.
    re.compile(
        r"(?<!\bno\s)(?<!\bnot\s)\btaints?\b(?:\s+(?!not\b|never\b|no\b)\w+){0,2}?\s+"
        r"(?:on|of|from|set\s+on|declared\s+on|defined\s+on|applied\s+to|"
        r"attached\s+to|carried\s+by)\s+"
        + _DET
        + r"pods?\b(?!" + _APOSTROPHE + r")",
        re.IGNORECASE,
    ),
    # "the pod's taints", "pod taints".
    re.compile(
        r"\bpods?(?:" + _APOSTROPHE + r"s)?\s+taints?\b", re.IGNORECASE
    ),
    # "taints the pod has / carries / declares" (not "taints the pod does not
    # tolerate").
    re.compile(
        r"\btaints?\s+(?:that\s+|which\s+)?the\s+pod\s+"
        r"(?:has|have|carries|carry|contains|contain|declares|declare|defines|"
        r"define|sets|set|specifies|specify)\b"
        # "taints that the pod has no tolerations for" is about tolerations.
        r"(?!\s+(?:\w+\s+){0,2}tolerations?\b)",
        re.IGNORECASE,
    ),
    # "the pod contains / has / carries a taint".
    re.compile(
        r"\bpods?\s+(?:(?:may|might|could|possibly|perhaps|also|itself|currently)\s+){0,2}"
        r"(?:contains?|has|have|carr(?:y|ies)|declares?|defines?|specif(?:y|ies)|sets?)\s+"
        r"(?:(?:a|an|the|any|one|some|several|multiple|these|those|node|its|own)\s+){0,3}"
        r"taints?\b",
        re.IGNORECASE,
    ),
    # "the pod is tainted", "a tainted pod".
    re.compile(
        r"\bpods?\s+(?:(?:may|might|could|possibly|perhaps|also|currently)\s+){0,2}"
        r"(?:is|are|be|being|been)\s+tainted\b|\btainted\s+pods?\b",
        re.IGNORECASE,
    ),
)


_QUOTED = re.compile(
    r"\"[^\"]{0,200}\"|\u201c[^\u201d]{0,200}\u201d|(?<![\w])'[^']{3,160}'(?![\w])"
)


def without_quotations(text: str) -> str:
    """`text` with quoted passages removed. A phrase held up in quotation
    marks is being discussed, not asserted ("Wrong: 'the pod contains a
    taint'"), so claim checks never match inside one. Apostrophes inside words
    are not quotation marks."""
    return _QUOTED.sub(" ", text)


def inverted_taint_toleration(texts: Iterable[str | None]) -> bool:
    """True when any text attributes a taint to a pod or a toleration (or the
    act of tolerating) to a node. Never inspects anything else."""
    for text in texts:
        if not text:
            continue

        normalized = " ".join(without_quotations(text).split())

        if any(pattern.search(normalized) for pattern in _INVERTED):
            return True

    return False
