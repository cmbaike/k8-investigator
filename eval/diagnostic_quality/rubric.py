"""FIXED grading rubric for hypothesis diagnostic quality (version 2).

Version 1 was written before any model output was reviewed. Reading the
BASELINE arm's outputs (the previous release's prompt and validators) then
showed errors version 1 could not see; version 2 adds graders for exactly those
(a missing selector blamed for unschedulability, probes blamed for a pod that
never ran or that declares none, "the logged claim" when no log exists, and
"adjust/configure" checks). It was frozen before the AFTER arm was run, and is
applied identically to both arms. Because the new application checks and these
graders were both prompted by reading the baseline, the improvement they show
on those error types is expected by construction; the AFTER outputs were then
read manually for error types neither anticipated (see the results notes).

Kept
apart from the application's validators on purpose: it imports nothing from
`app.reports`, and its patterns are written independently and more simply, so
that "the validator rejected it" and "it was wrong" stay two separate
measurements. Changing this file invalidates comparison with earlier results;
the runner records its SHA-256 with every result so a change is visible.

A raw model hypothesis is graded on the text of its three model-authored
fields (possible_explanation, not_yet_verified, verification_check) along five
independent axes:

  technical     terminology, contradiction with established state, unsupported
                causal certainty, source attribution, scope
  relevance     does it address the failure Kubernetes reported (`relevant`),
                and does it name the specific constraint reported (`specific`)
  check         is the verification check relevant, read-only and scoped
  validation    (measured by the runner from the application's own decisions)
  operations    (measured by the runner: completion, tool coverage, latency)

The rubric never rewards acceptance: a hypothesis the validator accepted can
still be graded wrong here, and that is reported as an ESCAPE.
"""

import re
from dataclasses import dataclass, field

RUBRIC_VERSION = "2"

_I = re.IGNORECASE


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, _I)


# ------------------------------------------------------------------ technical
# Each grader returns True when the text commits the error.

TECHNICAL_GRADERS: dict[str, re.Pattern[str]] = {
    # A pod holding a taint / a node tolerating or holding tolerations.
    "inverted_taint_toleration": _re(
        r"\bpods?\b[^.]{0,30}\b(?:contains?|has|have|carr(?:y|ies)|declares?)\b[^.]{0,15}\btaints?\b"
        r"|\btaints?\b[^.]{0,20}\b(?:on|of)\s+(?:the\s+|each\s+|a\s+)?pods?\b"
        r"|\bpod(?:'s|s)?\s+taints?\b"
        r"|\bnodes?(?:\s+in\s+the\s+cluster)?\s+(?:(?:do(?:es)?\s+not|cannot|can't|never|will)\s+)?tolerat"
        r"|\btolerations?\s+(?:on|of)\s+(?:the\s+|each\s+|all\s+)?nodes?\b(?!\s+taints)"
        r"|\bnode(?:'s)?\s+tolerations?\b"
    ),
    # Nodes request / pods are allocatable.
    "inverted_resource_roles": _re(
        r"\bnodes?\s+(?:may\s+|might\s+|could\s+)?requests?\b"
        r"|\bnode(?:'s)?\s+(?:cpu\s+|memory\s+)?requests?\b"
        r"|\bpods?(?:'s)?\s+(?:cpu\s+|memory\s+)?allocatable\b"
    ),
    # Nodes and taints do not live in a namespace.
    "cluster_object_in_namespace": _re(
        r"\b(?:nodes?|taints?)\s+(?:in|within)\s+(?:the\s+)?(?:\S+\s+)?namespace\b"
    ),
    # A readiness probe restarts the container / proves it never started.
    "readiness_semantics": _re(
        r"\breadiness\b[^.;]{0,50}?\b(?:restart\w*|kill\w*)\b"
        r"|\b(?:restart\w*|kill\w*)\b[^.;]{0,40}\b(?:because\s+of|due\s+to|caused\s+by)\b[^.;]{0,20}\breadiness\b"
        r"|\breadiness\b[^.;]{0,50}?\b(?:proves?|means|confirms?)\b[^.;]{0,30}\b(?:never\s+started|failed\s+to\s+start|crashed)\b"
    ),
    # A Kubernetes state attributed to application logs.
    "state_attributed_to_logs": _re(
        r"\b(?:logs?|logged)\b[^.;]{0,40}\b(?:show\w*|report\w*|indicat\w*|record\w*|says?|contains?|printed)\b"
        r"[^.;]{0,30}\b(?:OOMKilled|CrashLoopBackOff|ImagePullBackOff|ErrImagePull|FailedScheduling|FailedMount)\b"
        r"|\b(?:logged|printed)\s+(?:an?\s+)?(?:OOMKilled|CrashLoopBackOff|ImagePullBackOff|FailedScheduling|FailedMount)\b"
    ),
    # Flat certainty.
    "unsupported_certainty": _re(
        r"\b(?:definitely|certainly|undoubtedly|conclusively|unquestionably)\b"
        r"|\broot\s+cause\s+(?:is|was)\b"
        r"|\b(?:proves?|confirms?|establishes)\s+that\b"
        r"|\bis\s+(?:caused|due)\s+(?:by|to)\b"
    ),
    # The image is asserted not to exist.
    "image_nonexistence_asserted": _re(
        r"\b(?:image|tag)\b[^.;,]{0,40}?\b(?:does\s+not|doesn't|do\s+not)\s+exist\b"
        r"|\b(?:image|tag)\b[^.;,]{0,30}?\b(?:is|are|was)\s+(?:non-?existent|missing|not\s+found)\b"
    ),
}

# The absence of a node selector or affinity cannot block scheduling (a pod with
# none can run anywhere). v2.
SELECTOR_ABSENCE = _re(
    r"(?:\black\w*|\babsence\b|\bwithout\b|\bnot\s+(?:have|declare[sd]?|defined?)\b|"
    r"\bdoes\s*n[o']t\s+(?:have|declare|define)\b|\bno\b)\s+(?:\w+\s+){0,3}"
    r"(?:node\s+selectors?|affinity|placement\s+\w+)"
)
BLOCKING_CONTEXT = _re(
    r"\b(?:prevent\w*|block\w*|unschedul\w*|not\s+(?:be\s+)?schedul\w*|due\s+to|"
    r"because|caus\w+)\b"
)
RULES_OUT = _re(r"\b(?:not\s+the\s+(?:cause|reason)|unlikely|rules?\s+out)\b")

# "the logged claim" / "the logs say ..." when no log exists. v2.
LOG_CLAIM = _re(
    r"\blogged\s+claims?\b|\b(?:application\s+)?logs?\s+(?:claims?|state|says?|shows?|reports?|indicates?)\b"
)

# Probes only run against a running container. v2.
PROBE_WORDS = _re(r"\b(?:liveness|readiness|startup)\s+(?:probes?|checks?)\b")


def undeclared_probe_blamed(text: str, kinds: tuple[str, ...]) -> bool:
    for kind in kinds:
        blamed = _re(
            rf"\b(?:issues?|problems?|errors?|misconfigur\w*|fail\w*|incorrect|wrong)\b[^.]{{0,30}}\b{kind}\s+probes?\b"
            rf"|\b{kind}\s+probes?\b[^.]{{0,40}}\b(?:fail\w*|misconfigur\w*|issues?|problems?|incorrect|wrong|timing|path|port)\b"
        )

        for match in blamed.finditer(text):
            before = re.split(r"[,;:.]", text[: match.start()])[-1]

            if DENIAL.search(before) is None:
                return True

    return False


# Hedge words: a statement of a cause under one of these is tentative.
HEDGE = _re(r"\b(?:may|might|could|possibly|perhaps|potentially|whether|if|unless|appears?|seems?)\b")
DENIAL = _re(r"\b(?:not|no|never|cannot|without|unable)\b|n't")

# Per-scenario state contradictions (see `Scenario.contradictions`).
START_FAILURE = _re(
    r"\b(?:fail(?:ed|s|ing)?\s+to\s+start|never\s+started|(?:has|have|had)\s+not\s+(?:yet\s+)?started|"
    r"not\s+(?:yet\s+)?started|cannot\s+start|unable\s+to\s+start|not\s+running|"
    r"(?:not|never)\s+(?:yet\s+)?(?:been\s+)?observed\s+to\s+(?:have\s+)?(?:run|started))\b"
)
RAN_WORDS = _re(
    r"\b(?:crash\w*|exit\s+codes?|exited|restart\w*|stack\s*traces?|panic\w*|"
    r"application\s+logs?|logs?\s+(?:show|report|indicate))\b"
)
IMAGE_PULL_WORDS = _re(r"\b(?:image\s+pull\w*|pull(?:ing)?\s+(?:the\s+)?image|registry|image\s+tag)\b")
HEALTHY_WORDS = _re(r"\b(?:is|are|was|remains?)\s+(?:healthy|ready|fine|operating\s+normally)\b")
FAILURE_NOW = _re(
    r"\b(?:container|pod|application|app)\b(?:\s+\w+){0,2}?\s+(?:is|are|be|keeps?|remains?)\s+"
    r"(?:\w+\s+)?(?:crash-?looping|crashing|failing|restarting)\b"
)
LIMIT_AS_SCHEDULING = _re(r"\b(?:memory|cpu)\s+limits?\b")
REQUEST_WORD = _re(r"\brequests?\b")
EXCLUSIVE = _re(
    r"\b(?:the\s+(?:only|sole|single)\s+(?:\w+\s+)?(?:reason|cause|constraint|problem|issue)|"
    r"solely|exclusively|no\s+other\s+(?:reason|cause|constraint))\b"
)


# ------------------------------------------------------------ check (grading)

# An action on the cluster, not an inspection (independent of the validator).
MUTATING_CHECK = _re(
    r"(?:^|[.;:]\s+)(?:please\s+)?(?:increase|decrease|raise|lower|reduce|add|remove|"
    r"delete|restart|scale|set|change|update|apply|patch|edit|create|drain|cordon|"
    r"fix|configure|enable|disable|deploy|roll\s*back|provision|label|taint|install|"
    r"adjust|tune|ensure|assign|relax|grant)\b"
    r"|\b(?:and|then|or)\s+(?:adjust|configure|increase|decrease|raise|lower|reduce|add|remove|"
    r"delete|restart|scale|apply|patch|tune|fix)\s+(?:the|a|an|it|them|its|more|any)\b"
    r"|\bkubectl\b[^\n]*\b(?:delete|apply|patch|edit|scale|rollout|replace|drain|cordon|taint|label|set|create|exec)\b"
    r"|\b(?:consider|should|try)\s+(?:increasing|adding|removing|scaling|restarting|changing|setting)\b"
)
# Other namespaces / other workloads / cluster-wide reach.
OUT_OF_SCOPE_CHECK = _re(
    r"\ball[\s-]namespaces\b|\bevery\s+namespace\b|\bother\s+namespaces\b|--all-namespaces"
)


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    # What Kubernetes reports: used only to describe the case in results.
    abnormality: str
    # An explanation is RELEVANT when it addresses the failure family.
    relevant: re.Pattern[str]
    # ...and SPECIFIC when it names the constraint Kubernetes reported. Each
    # entry is one independent reported constraint (several for a mixed case).
    specific: tuple[re.Pattern[str], ...]
    # Terms that contradict what is established about this case.
    contradictions: tuple[re.Pattern[str], ...] = ()
    # True when several independent constraints were reported.
    multiple_constraints: bool = False
    # A check is relevant when it names the failure's family.
    check_relevant: re.Pattern[str] | None = None
    # Tools a complete investigation of this case calls.
    expected_tools: frozenset[str] = frozenset(
        {"k8s.get_pods", "k8s.describe_pod"}
    )
    # No hypothesis is expected: any accepted hypothesis asserting a failure is
    # an error.
    healthy: bool = False
    # Scheduling cases: a memory/CPU LIMIT as the scheduling basis, and a
    # missing selector as a scheduling blocker, are errors.
    limit_as_basis_is_error: bool = False
    # Probe kinds the workload does NOT declare (v2): blaming one is an error.
    undeclared_probes: tuple[str, ...] = ()
    pod: str = ""
    notes: str = field(default="", compare=False)


def grade_text(text: str, scenario: Scenario) -> list[str]:
    """Technical errors the text commits (names from TECHNICAL_GRADERS plus the
    scenario-specific ones). A statement that merely DENIES the error is not an
    error, and a quoted passage is skipped."""
    plain = re.sub(r"\"[^\"]*\"|\u201c[^\u201d]*\u201d", " ", text)
    plain = " ".join(plain.split())
    errors: list[str] = []

    for name, pattern in TECHNICAL_GRADERS.items():
        for match in pattern.finditer(plain):
            before = re.split(r"[,;:.]", plain[: match.start()])[-1]
            window = before + " " + match.group(0)

            if name in {"unsupported_certainty", "image_nonexistence_asserted"}:
                # Flat assertion: only a hedge (or denial) BEFORE it excuses.
                if HEDGE.search(before) or DENIAL.search(before):
                    continue
            elif name == "state_attributed_to_logs":
                if DENIAL.search(window):
                    continue
            elif name == "readiness_semantics":
                if DENIAL.search(window):
                    continue
            elif name == "inverted_taint_toleration":
                # "pods do not carry taints" is the correct statement.
                if re.search(r"\b(?:not|never|no)\b", plain[max(0, match.start() - 12): match.end()]) and not re.search(
                    r"\bnodes?\b", match.group(0), _I
                ):
                    continue

            errors.append(name)
            break

    for pattern in scenario.contradictions:
        for match in pattern.finditer(plain):
            before = re.split(r"[,;:.]", plain[: match.start()])[-1]

            if DENIAL.search(before) is None:
                errors.append(f"contradiction:{pattern.pattern[:24]}")
                break

    if scenario.limit_as_basis_is_error:
        for sentence in re.split(r"(?<=[.!?])\s+", plain):
            if (
                LIMIT_AS_SCHEDULING.search(sentence)
                and not REQUEST_WORD.search(sentence)
                and not DENIAL.search(sentence)
            ):
                errors.append("limit_as_scheduling_basis")
                break

    if scenario.limit_as_basis_is_error:
        for sentence in re.split(r"(?<=[.!?])\s+", plain):
            if (
                SELECTOR_ABSENCE.search(sentence)
                and BLOCKING_CONTEXT.search(sentence)
                and not RULES_OUT.search(sentence)
            ):
                errors.append("selector_absence_blamed_for_unschedulable")
                break

    if scenario.undeclared_probes and undeclared_probe_blamed(plain, scenario.undeclared_probes):
        errors.append("undeclared_probe_blamed")

    for match in LOG_CLAIM.finditer(plain):
        # "has not been verified whether the logged claim..." is still a claim
        # about a log; only "no logs show ..." / "without logs" excuses it.
        if re.search(r"\b(?:no|without|none)\b", re.split(r"[,;:.]", plain[: match.start()])[-1], _I) is None:
            errors.append("log_claim_without_logs")
            break

    if scenario.multiple_constraints and EXCLUSIVE.search(plain):
        errors.append("exclusive_cause_with_multiple_constraints")

    if scenario.healthy and FAILURE_NOW.search(plain):
        errors.append("failure_asserted_for_healthy_workload")

    return errors


def grade_check(check: str, scenario: Scenario) -> dict[str, bool]:
    """Verification-check axes: relevant, read_only, scoped, technically_clean."""
    plain = " ".join(re.sub(r"\"[^\"]*\"", " ", check).split())
    relevant = bool(
        scenario.check_relevant is not None and scenario.check_relevant.search(plain)
    )

    return {
        "relevant": relevant,
        "read_only": MUTATING_CHECK.search(plain) is None,
        "scoped": OUT_OF_SCOPE_CHECK.search(plain) is None
        and TECHNICAL_GRADERS["cluster_object_in_namespace"].search(plain) is None,
        "technically_clean": not grade_text(check, scenario),
    }


def grade_relevance(text: str, scenario: Scenario) -> dict[str, object]:
    plain = " ".join(text.split())
    specific = [bool(p.search(plain)) for p in scenario.specific]

    return {
        "relevant": bool(scenario.relevant.search(plain)),
        "specific": any(specific),
        "specific_families": [i for i, hit in enumerate(specific) if hit],
    }


def distinct(texts: list[str], threshold: float = 0.6) -> int:
    """The number of hypotheses in `texts` that are not near-duplicates of an
    earlier one (word-set Jaccard similarity below `threshold`)."""
    kept: list[set[str]] = []

    for text in texts:
        words = set(re.findall(r"[a-z]{3,}", text.lower()))

        if all(
            not words or not other or len(words & other) / len(words | other) < threshold
            for other in kept
        ):
            kept.append(words)

    return len(kept)
