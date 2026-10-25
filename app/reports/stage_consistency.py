"""Narrow contradictions between an explanation and a completed lifecycle stage.

Kubernetes establishes, from the pod's own status, that some stages of a pod's
life COMPLETED: a pod whose PodScheduled condition is True was scheduled; a
container that restarted exactly once was terminated exactly once, with the
reason Kubernetes recorded. An explanation that claims a failure in such a
stage contradicts what the application established, however plausible the
problem is in general. Two claim types are enforced, each from a fixed phrase
shape and one established fact:

  scheduled pod "cannot be scheduled"
      Contradiction when the pod was scheduled and no scheduling failure is
      recorded for it (no FailedScheduling event, no scheduler constraint).
      Qualified HISTORICAL statements ("was briefly unschedulable earlier")
      and a recorded scheduling history pass.

  the only restart attributed to a non-memory mechanism
      Contradiction when the container restarted exactly once and Kubernetes
      recorded that termination as OOMKilled, and the explanation blames a
      probe, the startup command, the image or an application crash WITHOUT
      any link to memory. (A cause that works through memory, "a memory leak
      in the application", passes.) With several restarts only the latest
      termination is visible, so earlier ones remain open and nothing is
      rejected.

Deliberately not done: judging whether an explanation is a GOOD one. Category
agreement, citation counts and topical wording are not evidence that a
hypothesis explains the failure; they only order hypotheses (see
`hypothesis_ranking`). A generic explanation that contradicts nothing passes
validation and is reported as such. A match omits ONE hypothesis with the
fixed code CONTRADICTS_EVIDENCE; nothing is rewritten or retained.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.reports.scheduling_semantics import without_quotations
from app.reports.state_consistency import CONTRADICTS_EVIDENCE, _sentences

_I = re.IGNORECASE
_CLAUSE_BREAK = re.compile(r"[,;:]")


@dataclass(frozen=True)
class StageFacts:
    """What the application established about completed stages."""

    # PodScheduled is True (or a container is observed to have started).
    scheduled: bool = False
    # A scheduling failure is part of the record: a FailedScheduling event or a
    # classified scheduler constraint exists for the pod.
    scheduling_history: bool = False
    # Every restarted container restarted exactly once and Kubernetes recorded
    # that termination as OOMKilled.
    sole_restart_was_oom: bool = False


# --- scheduled pod "cannot be scheduled" -----------------------------------

SCHEDULING_FAILURE = re.compile(
    r"\b(?:unable|fail\w*|cannot|can't|couldn't|could\s+not|not\s+(?:be\s+)?able)\s+"
    r"(?:to\s+)?(?:be\s+)?schedul\w+"
    r"|\b(?:not|never)\s+(?:be\s+)?(?:schedulable|scheduled)\b"
    r"|\bunschedulable\b|\bunscheduled\b"
    r"|\bscheduling\s+(?:(?:or|and)\s+(?:\w+\s+){1,2}?)?(?:failures?|constraints?|problems?|issues?|conflicts?)\b"
    r"|\b(?:failed|failing|failure\s+of)\s+scheduling\b"
    # "failed to place the pod on any node", "no suitable nodes"
    r"|\b(?:unable|fail\w*|cannot|can't|couldn't|could\s+not|not\s+(?:be\s+)?able)\s+"
    r"(?:to\s+)?(?:be\s+)?(?:place[ds]?|assign\w*|fit)\b[^.;]{0,40}\bnodes?\b"
    r"|\b(?:unable|fail\w*|cannot|can't|couldn't|could\s+not|not\s+(?:be\s+)?able)\s+"
    r"(?:to\s+)?(?:place|assign)\s+(?:the\s+|this\s+)?pod\b"
    r"|\bno\s+(?:suitable|available|eligible|matching|schedulable)\s+nodes?\b",
    _I,
)
# Wording that places the statement in the past, or says the pod was scheduled.
_SCHEDULING_EXCUSE = re.compile(
    r"\b(?:earlier|previous(?:ly)?|before|initially|originally|formerly|briefly|"
    r"once|at\s+(?:one|some)\s+point|had\s+been|was\s+(?:once|initially))\b"
    r"|\b(?:was|were|has\s+been|had\s+been|already|successfully|been)\s+scheduled\b"
    r"|\brules?\s+out\b|\bruled\s+out\b|\bunrelated\b|\birrelevant\b|\bunlikely\b"
    r"|\b(?:is|was|has\s+been|been)\s+placed\b"
    r"|\bnot\s+(?:be\s+)?(?:a|the)\s+(?:cause|reason)\b|\b(?:does|do)\s+not\s+explain\b"
    r"|\bcannot\s+explain\b",
    _I,
)
_DENIAL = re.compile(r"\b(?:no|never|neither|nor|without)\b|n't", _I)


def _scheduled_pod_unschedulable(texts: Iterable[str]) -> bool:
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if _SCHEDULING_EXCUSE.search(sentence):
                continue

            for match in SCHEDULING_FAILURE.finditer(sentence):
                clause = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]

                # "not" inside the match IS the claim ("may not be schedulable");
                # only a denial before it ("no scheduling issue") excuses it.
                if _DENIAL.search(clause) is None and not re.search(
                    r"\bnot\s+$", clause, _I
                ):
                    return True

    return False


# --- the only restart attributed to a non-memory mechanism -----------------

NON_MEMORY_MECHANISM = re.compile(
    r"\b(?:liveness|readiness|startup|health)\s+(?:probes?|checks?)\b"
    r"|\b(?:entrypoint|(?:startup|start-up)\s+(?:command|process|script|"
    r"configuration|behaviou?r|issues?|failures?)|container\s+command|"
    r"misconfigured\s+(?:command|entry\s*point|startup))\b"
    r"|\bimage\s+(?:compatib\w*|incompatib\w*|suitab\w*|corrupt\w*|architecture|"
    r"mismatch\w*|issues?|problems?)\b"
    r"|\b(?:incompatible|unsuitable|corrupt\w*)\s+(?:container\s+)?image\b"
    r"|\bimage\b[^.;]{0,40}\b(?:unsuitable|incompatible|corrupt\w*|"
    r"not\s+(?:suitable|compatible))\b"
    r"|\b(?:unhandled|uncaught)\s+exceptions?\b|\bsegmentation\s+fault\b|\bsegfault\b"
    r"|\bapplication\s+(?:crash\w*|errors?|bugs?)\b",
    _I,
)
_MEMORY_LINK = re.compile(
    r"\b(?:memory|oom\w*|out[\s-]of[\s-]memory|heap|allocat\w*|leak\w*|rss|"
    r"working\s+set)\b",
    _I,
)
# Only wording that rules the mechanism out excuses it. A bare "not" does not:
# "the startup command is not correct" blames the command.
_MECHANISM_EXCUSE = re.compile(
    r"\b(?:unrelated|irrelevant|unlikely|rules?\s+out|ruled\s+out|rather\s+than|"
    r"instead\s+of|whether)\b"
    r"|\bnot\s+(?:be\s+)?(?:caused|due|the\s+(?:cause|reason))\b"
    r"|\bno\s+(?:\w+\s+){1,2}(?:is|are)\s+declared\b|\bnot\s+declared\b",
    _I,
)


def _non_memory_cause(texts: Iterable[str]) -> bool:
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if (
                NON_MEMORY_MECHANISM.search(sentence)
                and _MEMORY_LINK.search(sentence) is None
                and _MECHANISM_EXCUSE.search(sentence) is None
            ):
                return True

    return False


def stage_violation(texts: Iterable[str], facts: StageFacts) -> str | None:
    """CONTRADICTS_EVIDENCE when the explanation claims a failure in a stage the
    application established as completed, else None."""
    texts = tuple(t for t in texts if t)

    if facts.scheduled and not facts.scheduling_history and _scheduled_pod_unschedulable(
        texts
    ):
        return CONTRADICTS_EVIDENCE

    if facts.sole_restart_was_oom and _non_memory_cause(texts):
        return CONTRADICTS_EVIDENCE

    return None
