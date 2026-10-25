"""Deterministic hygiene checks for a natural-language investigation question.

The investigation's authority does NOT come from the question. It comes from
the authenticated request: the namespace is a structured field, checked against
the principal, and bound to the context before any model runs. Tool-level scope
validation, the read-only allowlist, RBAC and audit enforce it independently.

These checks exist so the platform fails HONESTLY instead of silently doing
something other than what was asked. A question that names a different
namespace, asks for cluster-wide or cross-namespace coverage, asks for broader
credentials or a bypass of authorization, or asks for a state change cannot be
fulfilled by a read-only, single-namespace investigation. Each is rejected with
a fixed code. Nothing in this module grants anything.

Matching is intentionally conservative about NOT rejecting ordinary phrasing:
negated mentions ("this is not cluster-wide", "don't restart anything") and
words like "restarting" or "scale-up" are accepted.
"""

import re
from dataclasses import dataclass

from app.tools.intent import has_prohibited_intent

NAMESPACE_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?")
_NAME = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"


class QuestionScopeError(ValueError):
    """The question cannot be fulfilled by a read-only, single-namespace
    investigation. `code` is a fixed value; messages never echo the question."""

    def __init__(self, code: str) -> None:
        super().__init__(f"Question scope rejected: {code}.")
        self.code = code


CODES = frozenset(
    {
        "question_empty",
        "namespace_conflict",
        "cluster_wide",
        "broader_access",
        "state_change",
    }
)


def is_valid_namespace_name(value: object) -> bool:
    """RFC 1123 label, lowercase, at most 63 characters. No normalisation."""
    return (
        isinstance(value, str)
        and len(value) <= 63
        and NAMESPACE_NAME.fullmatch(value) is not None
    )


# ----------------------------------------------------------- namespace mentions

# Words that follow the word "namespace" without naming one.
_NOT_A_NAME_AFTER = frozenset(
    """
    is are was were be been being has have had does do did will would should
    can could may might must the a an it its their my our your this that these
    those why what how when where which who there here too also still only just
    all any each every same other another current given authorized authorised
    requested specified first last next using named called and or but not no
    of for in on at to from with without by as per
    health status state condition resources resource pods pod events event logs
    log issues issue problems problem errors error failures failure workloads
    workload deployments deployment services service overall general looks
    seems appears failing failed broken down up running ready ok fine healthy
    unhealthy slow degraded scope limits limit restrictions restriction quota
    quotas config configuration setup incident outage performance behaviour
    behavior activity metrics usage age name names list view overview summary
    report review check checks audit analysis
    """.split()
)

# Words that precede the word "namespace" without naming one.
_NOT_A_NAME_BEFORE = frozenset(
    """
    this that the a an same current given authorized authorised requested
    specified whole entire each every any all other another one my our your
    its their which cluster single target above kubernetes k8s and or per of in
    on is are
    """.split()
)

_SYSTEM_NAMESPACES = r"kube-system|kube-public|kube-node-lease"

# (pattern, words that the pattern may capture without naming a namespace)
_NAMESPACE_PATTERNS = (
    # namespace=prod, namespace: prod, --namespace=prod
    (
        re.compile(rf"\bnamespaces?\s*[:=]\s*(?P<ns>{_NAME})\b", re.IGNORECASE),
        frozenset(),
    ),
    # namespace prod, namespace is prod, namespace called prod
    (
        re.compile(
            rf"\bnamespace\s+(?:is\s+|called\s+|named\s+)?(?P<ns>{_NAME})\b",
            re.IGNORECASE,
        ),
        _NOT_A_NAME_AFTER,
    ),
    # in the prod namespace. A cue word is required so that "Investigate
    # namespace health" does not read "Investigate" as a namespace name.
    (
        re.compile(
            rf"\b(?:in|on|from|inside|within|under|of|for|to|the|a|my|our)\s+"
            rf"(?:the\s+)?(?P<ns>{_NAME})\s+namespace\b",
            re.IGNORECASE,
        ),
        _NOT_A_NAME_BEFORE,
    ),
    # -n prod
    (
        re.compile(rf"(?<![\w-])-n\s+(?P<ns>{_NAME})\b", re.IGNORECASE),
        frozenset(),
    ),
    # ns/prod
    (
        re.compile(rf"(?<![\w/-])ns/(?P<ns>{_NAME})\b", re.IGNORECASE),
        frozenset(),
    ),
    # Cluster-internal namespaces are never this investigation's scope.
    (
        re.compile(
            rf"(?<![\w.-])(?P<ns>{_SYSTEM_NAMESPACES})(?![\w.-])", re.IGNORECASE
        ),
        frozenset(),
    ),
)


def referenced_namespaces(question: str) -> list[str]:
    """Namespaces the question names, in order of first mention, de-duplicated.

    Names are returned as written: a case difference is a different name and
    will conflict with the (lowercase) authorized namespace.
    """
    found: list[tuple[int, str]] = []

    for pattern, not_a_name in _NAMESPACE_PATTERNS:
        for match in pattern.finditer(question):
            value = match.group("ns")

            if value.lower() in not_a_name:
                continue

            found.append((match.start("ns"), value))

    ordered: list[str] = []

    for _, value in sorted(found):
        if value not in ordered:
            ordered.append(value)

    return ordered


# ------------------------------------------------------------ broader requests

_CLUSTER_WIDE = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\ball[\s-]+(?:the\s+|of\s+the\s+|my\s+|our\s+)?namespaces?\b",
        r"\bevery\s+namespace\b",
        r"\bany\s+namespace\b",
        r"\b(?:other|different|multiple|several|both|various)\s+namespaces\b",
        r"\bacross\s+(?:the\s+|all\s+|multiple\s+|different\s+|other\s+)?"
        r"(?:clusters?|namespaces?)\b",
        r"\bcross[-\s]namespace\b",
        r"\bcluster[-\s]?wide\b",
        r"\b(?:whole|entire|full|complete)\s+cluster\b",
        r"\bcluster[-\s](?:health|status|state|level|overview)\b",
        r"\b(?:health|status|state|condition)\s+of\s+(?:the\s+)?"
        r"(?:[\w-]+\s+)?cluster\b",
        r"--all-namespaces\b",
        r"(?<![\w-])-A(?![\w-])",
    )
)

_BROADER_ACCESS = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\bcluster[-\s]?admin\b",
        r"\badmin(?:istrator)?\s+(?:access|credentials?|rights|privileges?|"
        r"kubeconfig|token|role|permissions?)\b",
        r"\b(?:bypass|circumvent|disable|skip|ignore|override|get\s+around)\s+"
        r"(?:the\s+|any\s+|all\s+)?(?:rbac|authori[sz]ation|authentication|"
        r"permissions?|namespace\s+(?:restrictions?|limits?|scope|isolation))\b",
        r"\b(?:elevate|escalate)\w*\b[^.!?;]{0,30}\b(?:privileges?|permissions?|"
        r"access|rights)\b",
        r"\bimpersonat\w*\b",
        r"\bkubeconfig\b",
        r"\b(?:service\s*account|serviceaccount)\s+tokens?\b",
        r"\b(?:grant|give)\s+(?:me|us|yourself|you)\b[^.!?;]{0,30}\b(?:access|"
        r"permissions?|rights|privileges?)\b",
        r"\bwith\s+(?:full|broader|wider|unrestricted|root|admin(?:istrator)?)\s+"
        r"(?:access|permissions?|privileges?|rights)\b",
        r"\b(?:secret|password|credential|private[-\s]key)s?\s+"
        r"(?:values?|contents?|data|in\s+plain\s*text)\b",
        r"\b(?:print|dump|reveal|decode|expose|leak|exfiltrate)\w*\b"
        r"[^.!?;]{0,30}\b(?:secrets?|passwords?|credentials?)\b",
    )
)

_INTRO = (
    r"(?:^|[.!?;:\n]\s*|\b(?:please|then|and|also|just|now|first|next)\s+"
    r"|\b(?:can|could|would|will)\s+you\s+(?:please\s+)?|go\s+ahead\s+and\s+)"
)
_STATE_VERBS = (
    r"(?:restart|reboot|delete|remove|kill|terminate|scale|resize|patch|edit|"
    r"apply|roll\s*back|redeploy|evict|drain|cordon|uncordon|fix|repair|heal|"
    r"reset|recreate|re-create|rerun|re-run)"
)
_STATE_OBJECT = (
    r"(?:the|this|that|my|our|these|those|all|any|every|a|an|it|them|pods?|"
    r"deployments?|workloads?|services?|containers?|[a-z0-9]+-[a-z0-9-]+)\b"
)
_STATE_CHANGE = re.compile(
    rf"{_INTRO}{_STATE_VERBS}\s+{_STATE_OBJECT}", re.IGNORECASE
)

_NEGATION = re.compile(
    r"\b(?:not|no|never|without|nothing|neither|nor|don'?t|do\s+not|"
    r"doesn'?t|isn'?t|aren'?t|wasn'?t|cannot|can'?t|won'?t|avoid|instead\s+of)\b|n't",
    re.IGNORECASE,
)
_SENTENCE_START = re.compile(r"[.!?;\n]")


def _negated(text: str, start: int) -> bool:
    """A mention negated earlier in its own sentence ("not cluster-wide")."""
    window = text[max(0, start - 40) : start]
    boundary = [m.end() for m in _SENTENCE_START.finditer(window)]
    clause = window[boundary[-1] :] if boundary else window
    return _NEGATION.search(clause) is not None


def _requested(patterns, text: str) -> bool:
    for pattern in patterns:
        for match in pattern.finditer(text):
            if not _negated(text, match.start()):
                return True
    return False


# ----------------------------------------------------------------------- entry


@dataclass(frozen=True)
class QuestionScope:
    question: str
    namespace: str


def validate_question_scope(question: str, *, namespace: str) -> QuestionScope:
    """Reject a question that a read-only investigation of exactly `namespace`
    cannot fulfil. `namespace` is already authenticated and authorized; this
    never decides, widens or narrows it."""
    if not isinstance(question, str) or not question.strip():
        raise QuestionScopeError("question_empty")

    if _requested(_BROADER_ACCESS, question):
        raise QuestionScopeError("broader_access")

    if _requested(_CLUSTER_WIDE, question):
        raise QuestionScopeError("cluster_wide")

    if any(other != namespace for other in referenced_namespaces(question)):
        raise QuestionScopeError("namespace_conflict")

    if has_prohibited_intent(question):
        raise QuestionScopeError("state_change")

    for match in _STATE_CHANGE.finditer(question):
        if not _negated(question, match.start()):
            raise QuestionScopeError("state_change")

    return QuestionScope(question=question, namespace=namespace)
