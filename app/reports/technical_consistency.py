"""Technical consistency of model-authored text with Kubernetes semantics.

The model proposes possible explanations and read-only checks; it is not an
authority on how Kubernetes works. This module rejects a small set of
HIGH-CONFIDENCE technical errors. It is organised by CLAIM TYPE, not by
keyword: each claim type has one anchored extractor (a fixed phrase shape that
is only ever an error) and one rule that decides, from facts the application
established itself, whether the claim is a contradiction.

    claim type                     rule
    -----------------------------  ------------------------------------------
    taint held by a pod, or a      always an error (nodes carry taints, pods
      toleration held by a node    declare tolerations): scheduling_semantics
    node requests / pod            always an error (pods REQUEST, nodes have
      allocatable                  ALLOCATABLE capacity)
    memory/CPU limit as the        an error for an unschedulable pod (the
      scheduling basis             scheduler compares REQUESTS, not limits)
    cluster-scoped object in a     always an error (nodes and their taints
      namespace                    belong to no namespace)
    readiness failure restarts     always an error (readiness gates traffic;
      the container                only a liveness/startup probe restarts)
    readiness failure proves the   always an error (a readiness probe does not
      process never started        establish that the process failed to start)
    absence of a selector/affinity an error for an unschedulable pod (a pod
      as a scheduling blocker      with no selector can run on any node)
    selector/affinity blamed       an error when the pod declares neither
                                   (an established fact, not a guess)
    a node holding tolerations     see the taint row
    one constraint as THE cause    an error when several independent scheduler
                                   constraints were reported
    "the image does not exist"     an error when asserted (an image-pull
      stated flatly                failure names the operation, not the cause)
    container "is failing now"     an error when every observed container is
                                   running and ready now (history is not
                                   current health)
    a Kubernetes state reported    an error: the logs never carry Kubernetes
      by the application's logs    states; they belong to Kubernetes
    "the logs say ..." with no     an error: there is no log to refer to
      log cited

Design limits, deliberately kept:
  * anything an extractor does not recognise passes: this is not a general
    semantic validator and it grades nothing as correct;
  * quoted passages are being discussed, not asserted, and are never matched;
  * a clause that DENIES or hedges the claim ("does not restart the
    container", "may indicate") is accepted for the claim types where that
    changes the meaning, and is not for the ones where it cannot;
  * a match omits ONE hypothesis with a fixed code. No text is kept and no
    content is rewritten into a different statement.

A recommended CHECK is held to the same semantics, and in addition to being:
  * read-only: remediation verbs are refused (`remediation_in_check`);
  * scoped: it may name only the investigated namespace, pod and container
    (`check_out_of_scope`).
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass

from app.reports.scheduling_semantics import (
    INVERTED_SCHEDULING_TERMS,
    inverted_taint_toleration,
    without_quotations,
)
from app.reports.source_claims import _STATE_NAMES
from app.reports.state_consistency import (
    CONTRADICTS_EVIDENCE,
    CONTRADICTS_STATE,
    _sentences,
)

REPORTED_WITHOUT_LOG = "reported_without_log_evidence"
INCORRECT_SEMANTICS = "incorrect_kubernetes_semantics"
UNSUPPORTED_CERTAINTY = "unsupported_causal_certainty"
REMEDIATION_IN_CHECK = "remediation_in_check"
CHECK_OUT_OF_SCOPE = "check_out_of_scope"
MISATTRIBUTED_SOURCE = "misattributed_source"

TECHNICAL_CODES = frozenset(
    {
        INCORRECT_SEMANTICS,
        UNSUPPORTED_CERTAINTY,
        REMEDIATION_IN_CHECK,
        CHECK_OUT_OF_SCOPE,
    }
)

_DENIAL = re.compile(
    r"\b(?:not|no|never|cannot|without|unable|neither|nor|rather\s+than|"
    r"instead\s+of|rule[sd]?\s+out)\b|n't",
    re.IGNORECASE,
)
_HEDGE_OR_DENIAL = re.compile(
    r"\b(?:may|might|could|can|possibly|possible|perhaps|potentially|whether|if|"
    r"unless|appears?|seems?|suggests?|likely|plausibly|not|no|never|cannot|"
    r"without|unable|neither|nor)\b|n't",
    re.IGNORECASE,
)
_CLAUSE_BREAK = re.compile(r"[,;:]")


@dataclass(frozen=True)
class TechnicalFacts:
    """What the application established that the rules below depend on."""

    # The pod is Pending and was never scheduled.
    unschedulable: bool = False
    # The pod declares neither a node selector nor affinity rules (both were
    # observed and both are absent).
    placement_undeclared: bool = False
    # Fixed scheduler-constraint signal names reported for the pod.
    scheduling_signals: frozenset[str] = frozenset()
    # At least one container was observed, and every observed container is
    # running and ready now.
    running_and_ready: bool = False
    authorized_namespace: str = ""
    # The only pod and container names a check about this resource may name.
    scope_names: frozenset[str] = frozenset()
    # A container of the pod declares a memory request (an observed value of
    # the pod spec).
    requests_declared: bool = False
    # The observed memory request / limit quantities of the pod's containers,
    # normalised (see `normalize_quantity`). Used to catch a request quoted as
    # the limit and the reverse.
    # Some container of the pod is recorded as restarted at least once.
    restart_history: bool = False
    memory_requests: frozenset[str] = frozenset()
    memory_limits: frozenset[str] = frozenset()
    # Kubernetes recorded an OOMKilled termination (or state reason) for a
    # container of the pod.
    oom_recorded: bool = False


def _asserted(
    pattern: re.Pattern[str],
    texts: Iterable[str],
    *,
    excuse: re.Pattern[str] = _DENIAL,
    excuse_inside: bool = False,
) -> bool:
    """True when some sentence makes the claim and no excusing word (a denial,
    or a hedge too, depending on the claim type) qualifies it first in the same
    clause. `excuse_inside` also looks at the matched words themselves."""
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            for match in pattern.finditer(sentence):
                clause = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]
                # With a named group "lead", only the words up to the verb
                # that makes the claim are searched, so a negation that IS the
                # claim ("never started") cannot excuse it.
                inside = match.groupdict().get("lead") or match.group(0)
                window = clause + (" " + inside if excuse_inside else "")

                if excuse.search(window) is None:
                    return True

    return False


# --- claim extractors ------------------------------------------------------

# A span inside one sentence that does not cross to a contrasting clause: "a
# readiness failure removes the pod from service whereas a liveness failure
# restarts the container" attributes the restart to liveness.
_SPAN = (
    r"(?:(?!\bliveness\b|\bstartup\b|\bwhereas\b|\bwhile\b|\bbut\b|\bunlike\b|"
    r"\brather\b|\binstead\b|\band\b)[^.;]){0,60}?"
)
_READINESS = r"readiness\s+(?:probes?|checks?|failures?|probe\s+failures?)"
_RESTART = r"(?:restart\w*|kill\w*|terminat\w*|recreat\w*|evict\w*)"

READINESS_CAUSES_RESTART = re.compile(
    r"\b(?P<lead>" + _READINESS + r"\b" + _SPAN + r")\b" + _RESTART + r"\b"
    r"|\b" + _RESTART + r"\b" + _SPAN
    + r"\b(?:because\s+of|due\s+to|caused\s+by|after|from)\s+(?:\w+\s+){0,3}?"
    + _READINESS,
    re.IGNORECASE,
)

READINESS_PROVES_START_FAILURE = re.compile(
    r"\b(?P<lead>" + _READINESS + r"\b" + _SPAN
    + r"\b(?:means?|indicates?|proves?|shows?|confirms?|demonstrates?|implies?))\b"
    r"[^.;]{0,40}?\b(?:(?:not|never)\s+(?:\w+\s+)?start\w*|failed\s+to\s+start|"
    r"crash\w*|exit(?:ed)?\b|not\s+running)",
    re.IGNORECASE,
)

_APOS = r"['\u2019]"

# Pods REQUEST resources; nodes have ALLOCATABLE capacity.
NODE_REQUESTS_OR_POD_ALLOCATABLE = re.compile(
    r"\bnodes?(?:" + _APOS + r"s)?\s+(?:(?:may|might|could|can|also)\s+)?"
    r"(?:(?:cpu|memory|resource|resources)\s+)?request(?:s|ed)?\b"
    r"|\brequests?\s+of\s+(?:the\s+|each\s+|any\s+)?nodes?\b(?!" + _APOS
    + r"|\s+(?:selector|taint|label|pool))"
    r"|\bpods?(?:" + _APOS + r"s)?\s+(?:(?:cpu|memory|resource)\s+)?allocatable\b"
    r"|\ballocatable\s+(?:cpu|memory|resources?|capacity)\s+(?:of|on|for|in)\s+"
    r"(?:the\s+|each\s+|a\s+)?pods?\b(?!\s+(?:count|slots?))",
    re.IGNORECASE,
)

# The scheduler compares a pod's REQUESTS with node capacity. A sentence that
# puts a memory/CPU LIMIT in that role and never mentions requests is wrong.
RESOURCE_LIMIT = re.compile(r"\b(?:memory|cpu|resource)\s+limits?\b", re.IGNORECASE)
_REQUEST_WORD = re.compile(r"\brequests?\b|\brequested\b", re.IGNORECASE)

# Nodes and their taints belong to no namespace.
CLUSTER_OBJECT_IN_NAMESPACE = re.compile(
    r"\b(?:nodes?|taints?|persistent\s*volumes?|storage\s*classes?)\s+"
    r"(?:in|within)\s+(?:the\s+)?(?:\S+\s+)?namespace\b",
    re.IGNORECASE,
)

EXCLUSIVE_CAUSE = re.compile(
    r"\b(?:the|an?)\s+(?:only|sole|single|exclusive|one\s+and\s+only)\s+"
    r"(?:\w+\s+){0,2}(?:reason|cause|constraint|problem|issue|factor|"
    r"explanation|blocker)\b"
    r"|\b(?:solely|exclusively|entirely|purely|only)\s+(?:due\s+to|because|"
    r"caused\s+by|a\s+result\s+of|the\s+result\s+of|explained\s+by)\b"
    r"|\bno\s+other\s+(?:reason|cause|constraint|problem|issue|factor|"
    r"explanation)\b",
    re.IGNORECASE,
)

ASSERTS_MISSING_IMAGE = re.compile(
    r"\b(?:image|tag|image\s+tag|image\s+reference)\b[^.;,]{0,40}?\b"
    r"(?:does\s+not|doesn't|do\s+not|don't|did\s+not|didn't)\s+exist\b"
    r"|\b(?:image|tag)\b[^.;,]{0,30}?\b(?:is|are|was|were)\s+"
    r"(?:non-?existent|missing|not\s+found|invalid|incorrect|wrong)\b"
    r"|\bno\s+such\s+(?:image|tag)\b",
    re.IGNORECASE,
)

_FAILING = (
    r"crash-?looping|crashing|failing|restarting|erroring|"
    r"in\s+a\s+crash[\s-]?loop|stuck\s+in\s+a\s+crash[\s-]?loop"
)
def _currently_failing(failing: str) -> re.Pattern[str]:
    return re.compile(
        r"\b(?:container|pod|application|app|process|workload|service)\b"
        r"(?:\s+\w+){0,2}?\s+(?:is|are|be|keeps?|continues?\s+to|remains?|currently|"
        r"still)\s+(?:(?:repeatedly|continuously|constantly|currently|still|now|"
        r"actively)\s+)?(?:" + failing + r")\b",
        re.IGNORECASE,
    )


CURRENTLY_FAILING = _currently_failing(_FAILING)
# A container Kubernetes records as restarted before may well keep restarting
# (a liveness probe that keeps killing it): "restarting" is then consistent with
# the evidence, while "crash-looping" / "failing" now is still contradicted by a
# container that is ready.
CURRENTLY_FAILING_WITH_RESTART_HISTORY = _currently_failing(
    r"crash-?looping|crashing|failing|erroring|in\s+a\s+crash[\s-]?loop|"
    r"stuck\s+in\s+a\s+crash[\s-]?loop"
)

# --- memory requests, limits and OOM kills ---------------------------------
# A container is OOM-killed when it exceeds its memory LIMIT (or the node runs
# short of memory, where requests only influence which pod goes first). A
# memory REQUEST is what the scheduler reserves; it is not what kills.
_OOM = r"(?:oom\w*|out[\s-]of[\s-]memory|killed\s+for\s+(?:running\s+out\s+of\s+)?memory)"
OOM_WORDS = re.compile(r"\b" + _OOM + r"\b", re.IGNORECASE)
MEMORY_REQUEST = re.compile(
    r"\b(?:memory|resource)\s+requests?\b|\brequests?\s+(?:for|of)\s+memory\b",
    re.IGNORECASE,
)
_CAUSAL_LINK = re.compile(
    r"\b(?:due\s+to|because|caused?|causing|results?\s+in|resulting\s+in|"
    r"lead(?:s|ing)?\s+to|led\s+to|from|trigger\w*|explain\w*|insufficient|"
    r"too\s+(?:low|small)|under-?provision\w*)\b",
    re.IGNORECASE,
)
# Context in which a request IS legitimately part of an OOM story.
_REQUEST_OOM_CONTEXT = re.compile(
    r"\blimits?\b|\bpressure\b|\bevict\w*|\bqos\b|quality\s+of\s+service|"
    r"\bnode\s+(?:memory|capacity|is\s+(?:short|out))",
    re.IGNORECASE,
)
_SENTENCE_DENIAL = re.compile(
    r"\b(?:not|never|cannot|can't|whether|rather\s+than|instead\s+of|unrelated)\b|n't",
    re.IGNORECASE,
)

# For the request-blamed-for-OOM rule: a "not" that says the request was too
# SMALL ("may not have been sufficient") accuses the request; it does not deny
# that the request is the cause.
_INSUFFICIENCY = r"(?:\s+(?:\w+\s+){0,2}?(?:sufficient|enough|adequate|large|big|high)\b)"
_REQUEST_SENTENCE_DENIAL = re.compile(
    r"\b(?:not|never|cannot|can't|whether|rather\s+than|instead\s+of|unrelated)\b"
    r"(?!" + _INSUFFICIENCY + r")|n't(?!" + _INSUFFICIENCY + r")",
    re.IGNORECASE,
)

# Role confusions between requests and limits that do not involve OOM wording.
_REQ = r"(?:memory\s+|resource\s+)?requests?"
RESOURCE_ROLE_CONFUSION = re.compile(
    # the request described as the ceiling
    r"\b(?:memory|resource)\s+requests?\b[^.;]{0,40}\b(?:maximum|max|caps?|ceiling|"
    r"upper\s+bound|hard\s+limit)\b"
    # exceeding the REQUEST described as what kills
    r"|\bexceed\w*\s+(?:its|the|their|a)\s+" + _REQ + r"\b[^.;]{0,60}\b(?:kill\w*|oom\w*|terminat\w*)\b"
    r"|\b(?:kill\w*|oom\w*|terminat\w*)\b[^.;]{0,60}\bexceed\w*\s+(?:its|the|their|a)\s+" + _REQ + r"\b"
    # the LIMIT described as the reservation the scheduler honours
    r"|\b(?:memory|resource)\s+limits?\b[^.;]{0,40}\b(?:guarantee\w*|reserv\w*|schedul\w*)\b",
    re.IGNORECASE,
)

# A container Kubernetes reports READY now is not "not ready". Earlier
# not-readiness is history and stays sayable.
NOT_READY_CLAIM = re.compile(
    r"\b(?P<lead>(?:is|are|be|being|been|was|were|marked|reported|remains?|stays?|"
    r"currently|but|yet)\s+(?:\w+\s+)?)not\s+(?:yet\s+|currently\s+)?ready\b"
    r"|\bunready\b|\bfail\w*\s+(?:its\s+|the\s+)?readiness\b"
    # "is not responding to readiness probes", "not passing the readiness check"
    r"|\b(?:not|fail\w*\s+to|unable\s+to)\s+(?:currently\s+)?(?:respond\w*|pass\w*|"
    r"satisf\w+|meet\w*|answer\w*)\s+(?:to\s+)?(?:the\s+|its\s+)?readiness\b",
    re.IGNORECASE,
)
_HISTORY_WORDS = re.compile(
    r"\b(?:earlier|previous\w*|before|history|historical\w*|formerly|originally|"
    r"briefly|initially|at\s+(?:one|some)\s+point|had\s+been)\b",
    re.IGNORECASE,
)

_QUANTITY = r"\d+(?:\.\d+)?\s?[KMGT]i?B?"
_NOT_ROLE = r"(?:(?!\b(?:limits?|requests?|requested|not|never|no)\b|n't)[^.;\d])"
_ROLE_THEN_VALUE = re.compile(
    r"\b(?P<role>limits?|requests?)\b" + _NOT_ROLE + r"{0,25}?(?P<value>" + _QUANTITY + r")\b",
    re.IGNORECASE,
)
_VALUE_THEN_ROLE = re.compile(
    r"(?<![\w.])(?P<value>" + _QUANTITY + r")\s+(?:memory\s+|resource\s+)?(?P<role>limits?|requests?)\b",
    re.IGNORECASE,
)


def normalize_quantity(text: str) -> str | None:
    """'64Mi', '64 MiB' and '64mi' -> '64mi'; None when not a quantity."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s?([KMGT]i?)B?", text.strip(), re.IGNORECASE)

    return f"{match.group(1)}{match.group(2).lower()}" if match else None


def _quantity_in_wrong_role(texts: Iterable[str], facts: "TechnicalFacts") -> bool:
    """A sentence gives a quantity as the memory LIMIT that the application
    observed as the REQUEST (and not as a limit), or the reverse."""
    if not facts.memory_requests and not facts.memory_limits:
        return False

    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            for pattern in (_ROLE_THEN_VALUE, _VALUE_THEN_ROLE):
                for match in pattern.finditer(sentence):
                    value = normalize_quantity(match.group("value"))
                    limit = match.group("role").lower().startswith("limit")
                    own, other = (
                        (facts.memory_limits, facts.memory_requests)
                        if limit
                        else (facts.memory_requests, facts.memory_limits)
                    )
                    clause = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]

                    if (
                        value in other
                        and value not in own
                        and _DENIAL.search(clause) is None
                    ):
                        return True

    return False


# --- restart history ---------------------------------------------------------
_RESTART = re.compile(r"\b(?:restarts?|restart\s+count|restarted)\b", re.IGNORECASE)
RESTARTS_PROVE = re.compile(
    r"\b(?:restarts?|restart\s+count|restarted)\b[^.;]{0,50}?\b(?:prove[sd]?|confirm\w*|"
    r"demonstrat\w*|establish\w*|conclusive\w*|definitiv\w*)\b",
    re.IGNORECASE,
)
_CAUSE_NAMES = (
    r"(?:liveness|readiness|probe|oom\w*|out[\s-]of[\s-]memory|memory|crash\w*|"
    r"application\s+(?:crash|bug|error))"
)
RESTARTS_SHOW_CAUSE = re.compile(
    r"\b(?P<lead>(?:restarts?|restart\s+count)\b[^.;]{0,40}?\b(?:show\w*|indicat\w*|"
    r"mean\w*|impl\w*|point\w*\s+to))\b[^.;]{0,30}?\b" + _CAUSE_NAMES + r"\b",
    re.IGNORECASE,
)
RESTARTS_SHOW_CURRENT_FAILURE = re.compile(
    r"\b(?:restarts?|restart\s+count)\b[^.;]{0,40}?\b(?:show\w*|indicat\w*|mean\w*|"
    r"impl\w*|prove\w*|suggest\w*)\b[^.;]{0,20}?\b(?:it|container|pod|application)\s+"
    r"(?:is|are|keeps?|remains?)\s+(?:still\s+|currently\s+|now\s+)?"
    r"(?:failing|crash\w*|restarting|unhealthy|unstable|broken)\b",
    re.IGNORECASE,
)

# What an application prints never includes a Kubernetes state: attributing
# one to "the logs" relabels a Kubernetes observation as application output.
LOGS_REPORT_KUBERNETES_STATE = re.compile(
    r"\b(?:logs?|logged|log\s+(?:entries|lines?|messages?)|application|app)\b"
    r"[^.;]{0,50}?\b(?:show\w*|report\w*|indicat\w*|record\w*|state[sd]?|says?|"
    r"said|contains?|printed|prints?|log(?:s|ged)|mention\w*|reveal\w*)\b"
    r"[^.;]{0,40}?\b(?:" + _STATE_NAMES + r")\b"
    r"|\b(?:logged|printed)\s+(?:an?\s+)?(?:" + _STATE_NAMES + r")\b",
    re.IGNORECASE,
)


# A node selector or affinity only NARROWS where a pod may run: a pod that
# declares none can run on any node, so the absence of one never blocks
# scheduling ("the pod lacks a node selector, which prevents scheduling").
SELECTOR_ABSENCE_AS_BLOCKER = re.compile(
    r"(?:\blacks?|\blacking|\babsence\s+of|\bmissing|\bwithout|\bhas\s+no|\bhave\s+no|\bno|"
    r"\bdeclares?\s+no|\bnot\s+(?:have|declare|define|specify|set)\w*|"
    r"\bdoes\s*n[o']t\s+(?:have|declare|define|specify)|"
    r"\b(?:lack|absence)\s+of\s+(?:declared\s+)?)\s+"
    r"(?:an?\s+|any\s+|the\s+|declared\s+)?(?:\w+\s+){0,2}?"
    r"(?:node\s+selectors?|nodeselectors?|affinity|placement\s+(?:rules?|requirements?|constraints?))",
    re.IGNORECASE,
)
_BLOCKING_CONTEXT = re.compile(
    r"\b(?:prevent\w*|block\w*|cause[sd]?|explain\w*|why|due\s+to|because|"
    r"unschedul\w*|not\s+(?:be\s+)?schedul\w*|cannot\s+be\s+schedul\w*|"
    r"fail\w*\s+to\s+schedul\w*|unable\s+to\s+schedul\w*)\b",
    re.IGNORECASE,
)
_RULES_OUT = re.compile(
    r"\b(?:not\s+(?:the|a)\s+(?:cause|reason)|unlikely|rules?\s+out|"
    r"cannot\s+explain|does\s+not\s+explain|is\s+not\s+(?:the\s+)?(?:cause|reason))\b",
    re.IGNORECASE,
)

# A selector/affinity named as what mismatches or blocks, e.g. "the pod may
# have affinity rules that prevent scheduling".
PLACEMENT_RULE_BLAMED = re.compile(
    r"\b(?:node\s+selectors?|nodeselectors?|(?:pod\s+|node\s+)?(?:anti-)?affinity"
    r"(?:\s+(?:rules?|constraints?|requirements?))?|placement\s+(?:rules?|"
    r"requirements?|constraints?))\b[^.;]{0,60}?\b(?:mismatch\w*|prevent\w*|"
    r"block\w*|restrict\w*|conflict\w*|(?:does|do|did)\s*n[o']t\s+match|"
    r"not\s+match\w*|match(?:es)?\s+(?:no|none|any)|unsatisf\w*)",
    re.IGNORECASE,
)
# The same blame worded as a cause: "not schedulable due to a node selector".
# Only wording that rules the rule out excuses it: the "not" of "not schedulable"
# is the claim itself, not a denial of the selector.
PLACEMENT_RULE_AS_CAUSE = re.compile(
    r"\b(?:due\s+to|because\s+of|caused\s+by|owing\s+to|as\s+a\s+result\s+of)\s+"
    r"(?:an?\s+|the\s+|any\s+)?(?:\w+\s+){0,2}?"
    r"(?:node\s+selectors?|nodeselectors?|(?:pod\s+|node\s+)?(?:anti-)?affinity|"
    r"placement\s+(?:rules?|requirements?|constraints?))\b",
    re.IGNORECASE,
)

# "has not declared any resource requests", "no memory requests": a claim of
# absence, contradicted when the pod spec was observed declaring one.
NO_REQUESTS_CLAIM = re.compile(
    r"(?:\blacks?|\blacking|\babsence\s+of|\bmissing|\bwithout|\bhas\s+no|"
    r"\bhave\s+no|\bno|\bundeclared|"
    r"\bnot\s+(?:have|declare|define|specify|set)\w*|"
    r"\bdoes\s*n[o']t\s+(?:have|declare|define|specify|set))\s+"
    r"(?:an?\s+|any\s+|the\s+|declared\s+|defined\s+|explicit\s+)?(?:\w+\s+){0,2}?"
    r"(?:resource|memory)\s+requests?\b",
    re.IGNORECASE,
)
_CONCESSION = re.compile(
    r"\b(?:whether|unless|rather\s+than|instead\s+of)\b|\bnot\s+(?:true|the\s+case)\b",
    re.IGNORECASE,
)

# A probe named in an explanation of a pod that was never scheduled: probes
# only run against a started container and play no part in scheduling.
PROBE_WORDS = re.compile(
    r"\b(?:liveness|readiness|startup)\s+(?:probes?|checks?)\b", re.IGNORECASE
)
_PROBE_EXCUSE = re.compile(
    r"\b(?:never|cannot|can't|unrelated|irrelevant|rules?\s+out|ruled\s+out)\b"
    r"|\bno\s+(?:effect|role|bearing)\b"
    r"|\bnot\s+(?:a|the)\s+(?:cause|reason)\b"
    r"|\b(?:does|do|did)\s+not\s+(?:affect|influence|apply|run|execute)\b"
    r"|\bnot\s+(?:yet\s+)?(?:run|ran|executed|started)\b",
    re.IGNORECASE,
)

# A claim about what "the logs" say, with no log cited.
LOG_CLAIM = re.compile(
    r"\blogged\s+claims?\b"
    r"|\b(?:the\s+)?(?:application\s+|app\s+)?logs?\s+(?:claims?|states?|says?|"
    r"shows?|reports?|indicates?|confirms?)\b"
    r"|\bwhat\s+the\s+(?:application\s+)?logs?\s+(?:say|show|report)\b",
    re.IGNORECASE,
)


def claim_kinds(
    texts: Iterable[str],
    facts: TechnicalFacts,
    *,
    is_check: bool = False,
    cites_logs: bool = True,
) -> frozenset[str]:
    """The fixed claim types the texts make that CONTRADICT `facts`, by code.

    `is_check` skips the claim types that only make sense for an assertion of
    fact (a check asserts nothing)."""
    texts = tuple(t for t in texts if t)
    found: set[str] = set()

    if inverted_taint_toleration(texts):
        found.add(INVERTED_SCHEDULING_TERMS)

    if _asserted(
        READINESS_CAUSES_RESTART, texts, excuse=_DENIAL, excuse_inside=True
    ):
        found.add(INCORRECT_SEMANTICS)

    if _asserted(
        READINESS_PROVES_START_FAILURE,
        texts,
        excuse=_HEDGE_OR_DENIAL,
        excuse_inside=True,
    ):
        found.add(INCORRECT_SEMANTICS)

    if _asserted(NODE_REQUESTS_OR_POD_ALLOCATABLE, texts, excuse=_DENIAL):
        found.add(INCORRECT_SEMANTICS)

    if _asserted(CLUSTER_OBJECT_IN_NAMESPACE, texts, excuse=_DENIAL):
        found.add(INCORRECT_SEMANTICS)

    if facts.unschedulable and _limit_as_scheduling_basis(texts):
        found.add(INCORRECT_SEMANTICS)

    if facts.unschedulable and _selector_absence_blocks(texts):
        found.add(INCORRECT_SEMANTICS)

    if is_check:
        return frozenset(found)

    if (
        _quantity_in_wrong_role(texts, facts)
        or _request_blamed_for_oom(texts)
        or _request_in_fault_role(texts, facts.oom_recorded)
        or _asserted(
            RESOURCE_ROLE_CONFUSION, texts, excuse=_SENTENCE_DENIAL, excuse_inside=True
        )
    ):
        found.add(INCORRECT_SEMANTICS)

    if _asserted(RESTARTS_PROVE, texts, excuse=_DENIAL, excuse_inside=True):
        found.add(UNSUPPORTED_CERTAINTY)

    if _asserted(
        RESTARTS_SHOW_CAUSE, texts, excuse=_HEDGE_OR_DENIAL, excuse_inside=True
    ):
        found.add(UNSUPPORTED_CERTAINTY)

    if facts.running_and_ready and _not_ready_asserted(texts):
        found.add(CONTRADICTS_EVIDENCE)

    if facts.running_and_ready and _asserted(
        RESTARTS_SHOW_CURRENT_FAILURE, texts, excuse=_DENIAL, excuse_inside=True
    ):
        found.add(CONTRADICTS_EVIDENCE)

    if facts.requests_declared and _asserted(
        NO_REQUESTS_CLAIM, texts, excuse=_CONCESSION
    ):
        found.add(CONTRADICTS_EVIDENCE)

    if facts.unschedulable and _probe_named_as_cause(texts):
        found.add(INCORRECT_SEMANTICS)

    if facts.placement_undeclared and (
        _asserted(PLACEMENT_RULE_BLAMED, texts)
        or _asserted(PLACEMENT_RULE_AS_CAUSE, texts, excuse=_RULES_OUT)
    ):
        found.add(CONTRADICTS_EVIDENCE)

    if not cites_logs and _asserted(LOG_CLAIM, texts):
        found.add(REPORTED_WITHOUT_LOG)

    if len(facts.scheduling_signals) >= 2 and _asserted(EXCLUSIVE_CAUSE, texts):
        found.add(UNSUPPORTED_CERTAINTY)

    if _asserted(ASSERTS_MISSING_IMAGE, texts, excuse=_HEDGE_OR_DENIAL):
        found.add(UNSUPPORTED_CERTAINTY)

    if facts.running_and_ready and _asserted(
        CURRENTLY_FAILING_WITH_RESTART_HISTORY
        if facts.restart_history
        else CURRENTLY_FAILING,
        texts,
        excuse=_DENIAL,
        excuse_inside=True,
    ):
        found.add(CONTRADICTS_EVIDENCE)

    if _asserted(
        LOGS_REPORT_KUBERNETES_STATE, texts, excuse=_DENIAL, excuse_inside=True
    ):
        found.add(MISATTRIBUTED_SOURCE)

    return frozenset(found)


def _not_ready_asserted(texts: Iterable[str]) -> bool:
    """A sentence calls a container that is established READY now "not ready".
    A denial before the claim excuses it, and so does wording that places it in
    the past (an earlier restart, startup, history)."""
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if _HISTORY_WORDS.search(sentence):
                continue

            for match in NOT_READY_CLAIM.finditer(sentence):
                clause = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]
                lead = match.groupdict().get("lead") or ""

                if _DENIAL.search(clause + " " + lead) is None:
                    return True

    return False


def _request_blamed_for_oom(texts: Iterable[str]) -> bool:
    """A sentence makes a memory REQUEST the cause of an OOM kill, with no
    mention of the limit, node memory pressure or eviction, and no denial.
    ("The container may have exceeded its memory limit" and "a low request makes
    this pod an earlier victim under node memory pressure" both pass.)"""
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if (
                OOM_WORDS.search(sentence)
                and MEMORY_REQUEST.search(sentence)
                and _CAUSAL_LINK.search(sentence)
                and _REQUEST_OOM_CONTEXT.search(sentence) is None
                and _REQUEST_SENTENCE_DENIAL.search(sentence) is None
            ):
                return True

    return False


# --- a memory REQUEST in the role of the cause of an OOM kill ----------------
# Mentioning the limit does not make this statement correct. "An insufficient
# memory request led to the OOMKilled events, despite the 128Mi limit" still
# makes the request the cause. What is checked is the REQUEST's grammatical
# role (the thing that is insufficient, misconfigured or mismatched), not
# whether some other word shares the sentence:
#   * a fault word attached to the request ("an insufficient memory request");
#   * the request as subject of a fault ("the request is too low", "a request
#     that isn't enough", "a resource request mismatch").
# NOT matched: a request that is coordinated with the limit ("request and limit
# may both be too low", "misconfigured request or limit"), a value statement
# ("the request is 64Mi and the limit 128Mi"), a request in a node-pressure,
# eviction, QoS or overcommit story, a denial or a "whether".
_NOT_LIMIT_WORD = r"(?:(?!limits?\b)\w+\s+)"
_REQ_NOUN = r"(?:(?:memory|resource)\s+)?requests?\b"
_FAULT_BEFORE_REQUEST = re.compile(
    r"\b(?:insufficient|inadequate|too\s+(?:low|small)|under-?provision\w*|"
    r"misconfigured|mis-?set|incorrect(?:ly\s+\w+)?|wrong|mismatched?|low|small)\s+"
    + _NOT_LIMIT_WORD + r"{0,2}?" + _REQ_NOUN
    + r"|\bmismatch\w*\s+(?:between|of|in|with)\s+" + _NOT_LIMIT_WORD + r"{0,3}?" + _REQ_NOUN,
    re.IGNORECASE,
)
_REQUEST_IS_FAULTY = re.compile(
    # an optional value: "request of 64Mi is too low", "request is 64Mi, which ..."
    _REQ_NOUN + r"\s+(?:(?:of|at|is|=)\s+\d[\w.]*,?\s+)?(?:that\s+|which\s+)?(?:"
    r"(?:is|are|was|were|being|may\s+be|might\s+be|could\s+be)\s+(?:set\s+)?"
    r"(?:too\s+)?(?:low|small|insufficient|inadequate|misconfigured|incorrect|wrong)\b"
    r"|(?:isn't|aren't|wasn't|weren't|is\s+not|are\s+not|was\s+not|were\s+not|"
    r"may\s+not\s+be|might\s+not\s+be|may\s+not\s+have\s+been)\s+(?:\w+\s+)?"
    r"(?:sufficient|enough|adequate|large|big|high)\b"
    r"|mismatch\w*)",
    re.IGNORECASE,
)
# "request and limit", "request or the limit", "requests/limits": the limit
# carries the claim, so the sentence is not about the request alone.
_COORDINATED_WITH_LIMIT = re.compile(
    r"\A\s*(?:,\s*)?(?:and/or|and|or|/|&)\s*(?:the\s+|its\s+|a\s+|an\s+)?"
    r"(?:\w+\s+)?(?:memory\s+|resource\s+)?limits?\b",
    re.IGNORECASE,
)
_NODE_STORY = re.compile(
    r"\bpressure\b|\bevict\w*|\bqos\b|quality\s+of\s+service|"
    r"\bnode\s+(?:memory|capacity|is\s+(?:short|out))|\bovercommit\w*|"
    r"\bover-?subscri\w*|\bbest[\s-]effort\b|\bburstable\b",
    re.IGNORECASE,
)
# A sentence about the kill. With an OOMKilled recorded for the pod, "restarted
# due to ..." is about that kill even without the word OOM.
_KILL_WORDS = re.compile(
    r"\b(?:restart\w*|terminat\w*|kill\w*|crash\w*|exit\w*)\b", re.IGNORECASE
)


def _request_in_fault_role(texts: Iterable[str], oom_recorded: bool) -> bool:
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            about_the_kill = OOM_WORDS.search(sentence) is not None or (
                oom_recorded and _KILL_WORDS.search(sentence) is not None
            )

            if (
                not about_the_kill
                or _NODE_STORY.search(sentence)
                or _REQUEST_SENTENCE_DENIAL.search(sentence)
            ):
                continue

            for pattern in (_FAULT_BEFORE_REQUEST, _REQUEST_IS_FAULTY):
                for match in pattern.finditer(sentence):
                    if _COORDINATED_WITH_LIMIT.match(sentence[match.end():]) is None:
                        return True

    return False


def _probe_named_as_cause(texts: Iterable[str]) -> bool:
    """A sentence names a probe and nothing in the same sentence says it is
    irrelevant here (the whole sentence is searched: "a liveness probe cannot
    explain this pending pod" excuses itself after the probe is named)."""
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if PROBE_WORDS.search(sentence) and _PROBE_EXCUSE.search(sentence) is None:
                return True

    return False


def _selector_absence_blocks(texts: Iterable[str]) -> bool:
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if (
                SELECTOR_ABSENCE_AS_BLOCKER.search(sentence)
                and _BLOCKING_CONTEXT.search(sentence)
                and _RULES_OUT.search(sentence) is None
            ):
                return True

    return False


def _limit_as_scheduling_basis(texts: Iterable[str]) -> bool:
    for text in texts:
        for sentence in _sentences(" ".join(without_quotations(text).split())):
            if (
                RESOURCE_LIMIT.search(sentence)
                and _REQUEST_WORD.search(sentence) is None
                and _DENIAL.search(sentence) is None
            ):
                return True

    return False


# Report precedence: the most specific code first.
_PRECEDENCE = (
    INVERTED_SCHEDULING_TERMS,
    INCORRECT_SEMANTICS,
    REPORTED_WITHOUT_LOG,
    MISATTRIBUTED_SOURCE,
    CONTRADICTS_EVIDENCE,
    UNSUPPORTED_CERTAINTY,
    CONTRADICTS_STATE,
)


def technical_violation(
    texts: Iterable[str],
    facts: TechnicalFacts,
    *,
    is_check: bool = False,
    cites_logs: bool = True,
) -> str | None:
    """A fixed omission code for the first technical contradiction, else None."""
    found = claim_kinds(texts, facts, is_check=is_check, cites_logs=cites_logs)

    for code in _PRECEDENCE:
        if code in found:
            return code

    return None


# --- recommended checks ----------------------------------------------------
#
# A check is read-only diagnostic guidance. A mutating command is already
# refused by the whole-response safety check; what remains here is advice
# phrased as an action on the cluster ("Increase the memory request", "Add a
# toleration"), which is remediation, not a diagnostic, and needs a human
# decision of its own. Such a check is omitted with its hypothesis; nothing is
# rewritten into a safe-looking check.

# Verbs that are an ACTION when they open a sentence ("Increase the memory
# request"). Mid-sentence only the strictly mutating ones count, so that
# "compare labels and label selectors" is never read as an instruction.
_SUFFIX = r"(?:e|es|ed|ing|s|y|ies|ied)?"
_START_STEMS = (
    r"(?:add|increas|decreas|rais|lower|reduc|provision|upgrad|downgrad|install|"
    r"enabl|disabl|fix|resolv|remediat|rotat|revok|grant|attach|bump|allocat|"
    r"expand|resiz|uncordon|annotat|label|taint|untaint|reschedul|evict|recreat|"
    r"reappl|roll\s*back|reconfigur|adjust|tun|relax|tighten|assign|ensur|"
    r"configur|deploy|migrat|free\s+up|clean\s+up|purg|flush|force|stop|"
    r"terminat|rebuild|retry|scal|delet|remov|restart|appl|patch|drain|cordon|"
    r"reboot|redeploy|updat|chang|modif|creat)"
)
_MID_STEMS = (
    r"(?:delet|remov|restart|appl|patch|scal|increas|decreas|rais|add|drain|"
    r"cordon|reboot|redeploy|roll\s*back|evict|recreat|upgrad|resiz|provision|"
    r"reduc|fix|rotat|adjust|configur|tun|ensur|assign|relax|tighten|lower|"
    r"updat|chang|modif|enabl|disabl|grant)"
)
_OBJECT = (
    r"(?:the|a|an|more|additional|extra|any|its|your|one|that|those|these|"
    r"them|it|this|both|each|"
    r"memory|cpu|node|nodes|pod|toleration|tolerations|resource|resources|"
    r"limit|limits|request|requests|capacity|replicas?|taints?|labels?|"
    r"selector|image|tag|pvc|volume|configmap|secret)\b"
)

# A sentence that opens with the action, or a mutating action that follows
# "then", "and" or "or": "Compare the requests, then increase the memory
# request."
REMEDIATION_COMMAND = re.compile(
    r"(?:^|[.;:]\s+)(?:please\s+|then\s+)?" + _START_STEMS + _SUFFIX + r"(?![-\w])\s+"
    + _OBJECT
    + r"|(?:\bthen\s+|\band\s+|\bor\s+)(?:please\s+)?" + _MID_STEMS + _SUFFIX
    + r"(?![-\w])\s+" + _OBJECT,
    re.IGNORECASE,
)
REMEDIATION_ADVICE = re.compile(
    r"\b(?:consider|try|trying|recommend\w*|suggest\w*|advis\w+|should|must|"
    r"need(?:s)?\s+to|have\s+to)\s+(?:to\s+)?(?:the\s+|a\s+)?"
    r"(?:" + _START_STEMS + _SUFFIX + r")(?![-\w])",
    re.IGNORECASE,
)

_NAMESPACE = r"[a-z0-9](?:[-a-z0-9]*[a-z0-9])?"
_QUOTED_NAMESPACE = re.compile(
    r"\bnamespaces?\s+['\"`](" + _NAMESPACE + r")['\"`]"
    r"|['\"`](" + _NAMESPACE + r")['\"`]\s+namespace\b",
    re.IGNORECASE,
)
_BARE_NAMESPACE = re.compile(
    r"\b(?:in|within|from)\s+(?:the\s+)?(" + _NAMESPACE + r")\s+namespace\b"
    r"|\bnamespace\s+(" + _NAMESPACE + r")\b",
    re.IGNORECASE,
)
_WIDER_SCOPE = re.compile(
    r"\ball[\s-]namespaces\b|\bevery\s+namespace\b|\bother\s+namespaces\b|"
    r"\banother\s+namespace\b|\bacross\s+(?:all\s+|other\s+|different\s+)?"
    r"namespaces\b|--all-namespaces",
    re.IGNORECASE,
)
_NAMED_WORKLOAD = re.compile(
    r"\b(?:pods?|containers?)\s+(?:named\s+)?['\"`](" + _NAMESPACE + r"(?:\." + _NAMESPACE
    + r")*)['\"`]",
    re.IGNORECASE,
)
# "in the same namespace" and the like name no namespace.
_GENERIC_NAMESPACE_WORDS = frozenset(
    {
        "same", "this", "that", "pod", "pods", "investigated", "authorized",
        "target", "affected", "current", "workload", "relevant", "given", "own",
        "cluster", "node", "nodes", "correct", "right", "expected", "wrong",
        "other", "another", "the", "any", "each", "every", "its", "their",
        "specified", "named", "intended", "declared", "default",
    }
)


def remediation_in_check(check: str) -> bool:
    """True when the check advises an action on the cluster instead of an
    inspection. Quoted passages and negated phrasings are not matched."""
    for sentence in _sentences(" ".join(without_quotations(check).split())):
        for pattern in (REMEDIATION_COMMAND, REMEDIATION_ADVICE):
            for match in pattern.finditer(sentence):
                clause = _CLAUSE_BREAK.split(sentence[: match.start()])[-1]

                if _DENIAL.search(clause) is None:
                    return True

    return False


def check_scope_violation(check: str, facts: TechnicalFacts) -> bool:
    """True when the check names a namespace, pod or container other than the
    investigated one, or widens itself beyond the authorized namespace."""
    # Quoted NAMES are what is being scoped here, so quotations stay.
    text = " ".join(check.split())

    if _WIDER_SCOPE.search(text):
        return True

    own = facts.authorized_namespace.lower()

    for match in _QUOTED_NAMESPACE.finditer(text):
        name = (match.group(1) or match.group(2) or "").lower()

        if name and name != own and name not in _GENERIC_NAMESPACE_WORDS:
            return True

    for match in _BARE_NAMESPACE.finditer(text):
        name = (match.group(1) or match.group(2)).lower()

        # Bare words are only judged when they look like an identifier
        # ("team-b", "prod2"), never an ordinary word.
        if (
            name != own
            and name not in _GENERIC_NAMESPACE_WORDS
            and ("-" in name or any(c.isdigit() for c in name))
        ):
            return True

    if facts.scope_names:
        for match in _NAMED_WORKLOAD.finditer(text):
            if match.group(1).lower() not in facts.scope_names:
                return True

    return False


def check_violation(check: str, facts: TechnicalFacts) -> str | None:
    """A fixed omission code when the check is technically wrong, is not a
    read-only diagnostic, or is not scoped to the investigated resource."""
    code = technical_violation((check,), facts, is_check=True)

    if code is not None:
        return code

    if remediation_in_check(check):
        return REMEDIATION_IN_CHECK

    if check_scope_violation(check, facts):
        return CHECK_OUT_OF_SCOPE

    return None
