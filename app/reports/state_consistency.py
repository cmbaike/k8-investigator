"""Deterministic checks of hypothesis wording against structured state.

A hypothesis is an unverified interpretation, but it may not contradict what
the application established from Kubernetes itself. Each rule below applies
only when a specific structured fact is established, and only to a narrow,
specific claim. They are NOT general wording heuristics: hedged, ordinary
uncertainty ("the registry may be unreachable") is untouched unless it
contradicts an established fact. Hedging does not excuse a contradiction.

Established fact                           Contradicted claim
-----------------------------------------  ------------------------------------
container state is 'running'               the container has not started /
                                           failed to start / is not running
container is running and no image-pull     image-pull or registry explanations
event was recorded                         (the image was pulled to start it)
readiness is False                         the container is healthy / ready
spec declares no environment sources,      an environment variable is missing
no log is cited
no readiness probe is declared             the readiness probe failed or is
                                           misconfigured

pod is unschedulable, or its volumes    image-pull or registry explanations
cannot be mounted (no container ran)      (nothing was pulled: the scheduler or
                                           kubelet stopped it first)
no liveness probe is declared              the liveness probe failed or is
                                           misconfigured

A sentence that DENIES the claim ("this does not mean it failed to start") is
the correct wording and is accepted: a negation earlier in the same clause
excuses the match. Results are fixed codes; no text is retained.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

CONTRADICTS_STATE = "contradicts_container_state"
CONTRADICTS_EVIDENCE = "contradicts_established_evidence"
OVERSTATED_ABSENCE = "overstated_absence"

# Event reasons that relate to pulling or creating from an image. Pulling /
# Pulled are routine for any started container and are not evidence of a
# pull problem.
IMAGE_PULL_EVENT_REASONS = frozenset(
    {
        "Failed",
        "BackOff",
        "ErrImagePull",
        "ErrImageNeverPull",
        "InvalidImageName",
        "InspectFailed",
        "FailedToRetrieveImagePullSecret",
    }
)


class ProbeState(StrEnum):
    """What the application established about one kind of probe.

    ABSENT means the pod spec was inspected and declares no such probe. UNKNOWN
    means the probe configuration was not collected (or not observable): that
    is never evidence of absence, and no rule treats it as such."""

    DECLARED = "declared"
    ABSENT = "verified_absent"
    UNKNOWN = "unknown"


def probe_state(declared: object) -> ProbeState:
    """Tri-state from an observed `declared` flag. Only a real boolean counts."""
    if declared is True:
        return ProbeState.DECLARED

    if declared is False:
        return ProbeState.ABSENT

    return ProbeState.UNKNOWN


def _blame_probe(kind: str) -> re.Pattern[str]:
    """A claim that a `kind` probe is failing, misconfigured or at fault. Built
    per kind so the same claim shapes apply to readiness and liveness: an
    issue WITH the probe (however the owner is described), the probe followed
    by a fault word, or a fault word followed by the probe."""
    noun = rf"{kind}\s+(?:probes?|checks?)"
    fault = (
        r"fail\w*|not\s+pass\w*|unsuccessful|time[sd]?\s*out|misconfigur\w*|"
        r"incorrect|wrong|invalid|faulty|broken|"
        # the probe named as the ACTOR: "the probe may be killing the container"
        r"kill\w*|restart\w*|terminat\w*|trigger\w*|caus\w+"
    )

    # A span that never crosses a negation: "the probe is NOT failing" is not
    # the claim that it is failing.
    span = r"(?:(?!\b(?:not|no|never)\b|n't)[^.;]){0,60}"

    return re.compile(
        rf"\b(?:issues?|problems?|errors?|failures?)\s+(?:with|in|on|of)\b[^.;]{{0,60}}?\b{noun}\b"
        rf"|\b{noun}\b{span}\b(?:{fault})\b"
        rf"|\b(?:{fault})\b[^.;]{{0,40}}\b{noun}\b",
        re.IGNORECASE,
    )


@dataclass(frozen=True)
class ContainerFacts:
    """What the application established about one container."""

    running: bool
    not_ready: bool
    event_reasons: frozenset[str]
    readiness_probe_declared: bool | None  # None: configuration not inspected
    env_none_declared: bool
    # The container has run at some point (it is running, or Kubernetes records
    # a previous termination or restarts) and is not currently stuck before
    # start. Its image was therefore pulled.
    ran_before: bool = False
    pre_start: bool = False

    @property
    def readiness_probe(self) -> ProbeState:
        return probe_state(self.readiness_probe_declared)

    @property
    def image_pulled(self) -> bool:
        return self.running or (self.ran_before and not self.pre_start)


_DENIAL = re.compile(
    r"\b(?:not|no|never|cannot|without|unable|neither|nor|whether|if|unless|"
    r"rather\s+than|instead\s+of|rule[sd]?\s+out)\b|n't",
    re.IGNORECASE,
)

_NOT_STARTED = re.compile(
    r"\b(?:not|never)\s+(?:\w+\s+){0,2}(?:start(?:ed|ing)?|launch(?:ed)?)\b"
    r"|\b(?:fail(?:s|ed|ing)?|unable)\s+to\s+(?:start|launch|run)\b"
    r"|\b(?:cannot|can't|couldn't|won't|doesn't|didn't)\s+(?:be\s+)?"
    r"(?:start(?:ed)?|launch(?:ed)?)\b"
    r"|\b(?:not|never)\s+(?:be\s+|currently\s+|yet\s+)*running\b",
    re.IGNORECASE,
)

# More ways to say a container that is running now never began.
_NOT_STARTED_MORE = re.compile(
    r"\b(?:fail(?:s|ed|ing)?|unable)\s+to\s+(?:initiali[sz]e|boot|come\s+up|begin)\b"
    r"|\b(?:did\s+not|didn't)\s+(?:start|launch|begin|boot)\b"
    r"|\bnever\s+(?:began|booted|ran)\b",
    re.IGNORECASE,
)

# A container Kubernetes records as restarted, or as previously terminated,
# started at least once. ("Never started" is false for it. The idiom "failing
# to start" for a crash at startup is NOT matched: only the explicit claim.)
_NEVER_RAN = re.compile(
    r"\bnever\s+(?:start(?:ed)?|launch(?:ed)?|ran|run)\b"
    r"|\b(?:has|have|had)\s+not\s+(?:ever\s+|yet\s+)?(?:started|run)\b"
    r"|\bnot\s+started\s+at\s+all\b",
    re.IGNORECASE,
)

_IMAGE_PULL = re.compile(
    r"\bimage[\s-]?pull\w*"
    r"|\bpull(?:s|ed|ing)?\b[^.]{0,20}\bimage\b"
    r"|\bErr(?:Image|ImageNeverPull)\w*"
    r"|\bregistry\b",
    re.IGNORECASE,
)

# For a pod that never ran, hedged wording such as "the image may not be
# pullable" is still a claim about pulling, so these also match phrasings whose
# own words carry the negation.
_POD_IMAGE_PULL = re.compile(
    _IMAGE_PULL.pattern
    + r"|\bimages?\b[^.]{0,40}\b(?:not\s+(?:\w+\s+)?(?:pull\w*|found|available|"
    r"accessible|download\w*)|unpullable|unavailable|missing)\b"
    r"|\b(?:unable|fail\w*|cannot|can't|couldn't)\s+(?:to\s+)?(?:pull|fetch|download)\b",
    re.IGNORECASE,
)

_HEALTHY_CLAIM = re.compile(
    r"\b(?:is|are|was|were|be|been|remains?|appears?|seems?)\s+(?:to\s+be\s+)?"
    r"(?!not\b|never\b|no\b)(?:\w+\s+)?(?:healthy|ready|operational|fine|normal)\b"
    r"|\b(?:working|functioning|operating|running)\s+"
    r"(?:correctly|properly|normally|fine)\b"
    r"|\bno\s+(?:issues?|problems?)\b",
    re.IGNORECASE,
)

_MISSING_ENV = re.compile(
    r"\b(?:missing|absent|unset|undefined|lacks?|lacking|not\s+"
    r"(?:set|defined|provided|supplied))\b[^.]{0,40}"
    r"\b(?:env(?:ironment)?(?:\s+var\w*)?|variables?|required\s+setting)\b"
    r"|\b(?:env(?:ironment)?\s+variables?|variables?)\b[^.]{0,40}"
    r"\b(?:missing|absent|unset|undefined|not\s+(?:set|defined|provided))\b",
    re.IGNORECASE,
)

_PROBE_FAILURE = _blame_probe("readiness")
_LIVENESS_FAILURE = _blame_probe("liveness")

_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")


def _sentences(text: str) -> list[str]:
    return [s for s in _SENTENCE.split(text) if s.strip()]


_STATED_CONDITION = re.compile(
    r"\b(?:not|never)\s+(?:(?:be|become|yet|currently|always)\s+)*"
    r"(?:ready|running|healthy|available|serving)\b"
    r"|\b(?:isn't|aren't|wasn't)\s+(?:yet\s+)?(?:ready|running|healthy|available)\b",
    re.IGNORECASE,
)


# Words that make "running properly" a described FAILURE ("prevents it from
# running properly"), not a claim that the container is healthy.
_PREVENTS = re.compile(
    r"\b(?:prevent\w*|stop\w*|keep\w*|hinder\w*|block\w*|inhibit\w*|impair\w*|"
    r"disrupt\w*|interfer\w*|unable|fail\w*)\b(?:\s+\w+){0,3}?\s+(?:from\s+)?$",
    re.IGNORECASE,
)


# "checking the endpoint before the application is ready", "once it is ready":
# a condition in time, not a claim that the container is ready now.
_TEMPORAL = re.compile(
    r"\b(?:before|until|till|once|when|whenever|after|unless|if|waiting\s+for)\b"
    r"(?:\s+\w+){0,4}\s*$",
    re.IGNORECASE,
)


def _claims(pattern: re.Pattern[str], texts: Iterable[str]) -> bool:
    """True when some sentence makes the claim without denying it first."""
    for text in texts:
        for sentence in _sentences(text):
            for match in pattern.finditer(sentence):
                clause = re.split(r"[,;:]", sentence[: match.start()])[-1]
                # "not ready" / "not running" states a condition; it does not
                # deny the claim that follows ("... not ready because the
                # probe is failing").
                clause = _STATED_CONDITION.sub(" ", clause)

                if pattern is _HEALTHY_CLAIM and (
                    _PREVENTS.search(clause) or _TEMPORAL.search(clause)
                ):
                    continue

                if _DENIAL.search(clause) is None:
                    return True

    return False


@dataclass(frozen=True)
class PodState:
    """What the application established about the pod itself."""

    # The pod is unschedulable, or its volumes cannot be mounted: nothing was
    # pulled and no container ran.
    blocked_before_start: bool
    # None: container probe configuration was not inspected.
    liveness_probe_declared: bool | None

    @property
    def liveness_probe(self) -> ProbeState:
        return probe_state(self.liveness_probe_declared)


def pod_state_violation(texts: Iterable[str], state: PodState | None) -> str | None:
    """A fixed omission code when the wording contradicts the pod's
    established state, else None."""
    texts = tuple(texts)

    if state is None:
        return None

    if state.blocked_before_start and _claims(_POD_IMAGE_PULL, texts):
        return CONTRADICTS_STATE

    if state.liveness_probe is ProbeState.ABSENT and _claims(_LIVENESS_FAILURE, texts):
        return CONTRADICTS_EVIDENCE

    return None


def state_violation(
    texts: Iterable[str],
    facts: Iterable[ContainerFacts],
    *,
    cites_logs: bool,
    inspection_only: bool = False,
) -> str | None:
    """A fixed omission code when the wording contradicts established state,
    else None. `facts` covers every container the hypothesis concerns; a rule
    applies only when the fact holds for ALL of them.

    `inspection_only` is for a recommended CHECK: it states no fact about the
    container, so only the rules that catch a check pointed at something the
    established state excludes (an image pull for a container that was
    started) apply, never the rules about what a statement claims."""
    texts, facts = tuple(texts), tuple(facts)

    if not facts:
        return None

    if (
        not inspection_only
        and all(f.running for f in facts)
        and (_claims(_NOT_STARTED, texts) or _claims(_NOT_STARTED_MORE, texts))
    ):
        return CONTRADICTS_STATE

    # Not running now, but Kubernetes records that it ran (a restart or a
    # previous termination): "never started" is contradicted.
    if (
        not inspection_only
        and all(f.image_pulled for f in facts)
        and _claims(_NEVER_RAN, texts)
    ):
        return CONTRADICTS_STATE

    # The image was pulled to start the container, now or earlier. A pull
    # explanation for a container that ran needs pull-specific event evidence
    # (history) to stand; a container that never started, or is stuck pulling,
    # is not affected.
    if (
        all(f.image_pulled for f in facts)
        and not any(f.event_reasons & IMAGE_PULL_EVENT_REASONS for f in facts)
        and _claims(_POD_IMAGE_PULL, texts)
    ):
        return CONTRADICTS_STATE

    if inspection_only:
        return None

    if all(f.not_ready for f in facts) and _claims(_HEALTHY_CLAIM, texts):
        return CONTRADICTS_EVIDENCE

    if (
        all(f.env_none_declared for f in facts)
        and not cites_logs
        and _claims(_MISSING_ENV, texts)
    ):
        return OVERSTATED_ABSENCE

    if all(f.readiness_probe is ProbeState.ABSENT for f in facts) and _claims(
        _PROBE_FAILURE, texts
    ):
        return CONTRADICTS_EVIDENCE

    return None
