"""Explicit workload targets for investigations, bound by the application.

A question such as "Investigate why the payments-api workload is failing" names
a target. Without binding, the investigation followed whatever pod the
namespace listing happened to contain. Here the application:

  1. classifies the question's INTENT deterministically, before any model runs
     (`classify_question_target`):
       TARGETED           exactly one resource identity is named;
       BROAD_EXPLICIT     the question asks about the namespace as a whole;
       BROAD_UNSPECIFIED  neither a resource identity nor an explicit request
                          about the namespace as a whole was found. This is
                          an AMBIGUOUS question: investigation creation
                          refuses it (`scope_unspecified`) and asks the user
                          to name a workload or to ask about the namespace.
                          A namespace-wide run requires explicit broad intent;
     and REJECTS, with a fixed code and no guess, a question that
       names several identities       (multiple_targets),
       names one AND asks about the rest of the namespace (ambiguous_scope), or
       names something that cannot be a Kubernetes resource name
                                      (invalid_target_name);
  2. resolves a TARGETED question from Kubernetes RESOURCE IDENTITY: each
     listed pod's verified controlling owner (Pod -> ReplicaSet -> Deployment,
     or a direct StatefulSet / DaemonSet / Job owner reference), or the pod
     name itself, compared by exact name, never by substring or prefix;
  3. refuses to guess: a target that matches nothing, matches more than one
     distinct workload, or cannot be verified is a LIMITATION, and no other
     workload is investigated in its place.

What counts as a named identity (no resource-type noun is required):
  * a kind/name form ("deployment/payments-api") or a resource noun next to a
    name ("the payments-api workload", "deployment named orders-api");
  * a quoted name ("'payments-api'");
  * a name in the subject or object position of a diagnostic request
    ("Why is checkout failing?", "Investigate payments-api", "Diagnose
    memory-hog", "payments-api keeps crashing");
  * a hyphenated DNS-style identifier anywhere ("...since payments-api-7d9f8c
    restarted"), unless it is an ordinary English compound ("read-only",
    "out-of-memory").
A bare plain word that is not in such a position ("memory", "network") is NOT
treated as an identity, and neither is a word from the generic vocabulary
("pods", "cluster", "health"). Because the identity cannot be checked against
the namespace at question time, a recognised identity that matches nothing is
reported as a limitation when the namespace is listed; it never turns into a
namespace-wide investigation.

The model is untrusted for all of this. The resolution is computed from
application-minted data and every pod-scoped tool call is checked against it
at the execution boundary.
"""

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

_NAME = r"[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?"
NAME_PATTERN = re.compile(rf"^{_NAME}$")
_OWNER_NAME = re.compile(r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$")

# Candidate tokens are scanned permissively (underscores, any length) so that
# something that CANNOT be a resource name is detected and refused rather than
# silently skipped; NAME_PATTERN then decides validity.
_TOKEN = r"[a-z0-9](?:[-a-z0-9_]*[a-z0-9])?"

MAX_LISTED_PODS = 200

# Controller kinds whose pods can be resolved from an owner reference.
OWNER_KINDS = frozenset({"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "Pod"})

_NOUN_KIND: dict[str, str | None] = {
    "workload": None,
    "service": None,
    "application": None,
    "app": None,
    "deployment": "Deployment",
    "deploy": "Deployment",
    "statefulset": "StatefulSet",
    "daemonset": "DaemonSet",
    "pod": "Pod",
}
_NOUN = "|".join(sorted(_NOUN_KIND, key=len, reverse=True))

# "deployment/payments-api", "pod/web-1"
_SLASH = re.compile(rf"(?<![\w/-])(?P<noun>{_NOUN})/(?P<name>{_TOKEN})(?![\w/])")
# "deployment payments-api", "workload named payments-api". Needs a hyphen or
# digit, or an explicit "named/called", so that "deployment health" or "pod
# status" never reads as a name.
_AFTER = re.compile(
    rf"\b(?P<noun>{_NOUN})\s+(?:(?P<explicit>named|called)\s+)?(?P<name>{_TOKEN})(?![\w])"
)
# "the payments-api workload", "the checkout service"
_BEFORE = re.compile(
    rf"(?:(?P<article>\b(?:the|my|our|a|this|that)\s+)|\b)"
    rf"(?P<name>{_TOKEN})\s+(?P<noun>{_NOUN})\b"
)

# Words that sit next to a workload noun without naming a workload.
_NOT_A_TARGET = frozenset(
    """
    the a an this that these those my our your its their any all each every
    some no other another same one first last next only single whole entire
    overall general specific particular given affected failing failed broken
    unhealthy healthy crashing crashed running ready down slow unavailable
    degraded faulty problematic troubled main new old current latest
    kubernetes k8s cluster namespace namespaces platform cloud lab demo test
    production staging dev
    is are was were be been being has have had does do did will would should
    can could may might must not and or but of for in on at to from with
    without by as per why what how when where which who there here
    health status state condition conditions issue issues problem problems
    error errors failure failures logs log events event config configuration
    pods workloads deployments services apps applications
    named called using
    it they them he she we you something anything everything nothing someone
    anyone everyone system systems infrastructure environment stack
    pod container containers node nodes job jobs replica replicas replicaset
    cronjob workload deployment service app application statefulset daemonset
    deploy probe probes
    network networking dns memory cpu disk storage traffic latency performance
    connectivity security
    """.split()
)

# Ordinary English hyphenated words that are not resource names.
_COMMON_COMPOUNDS = frozenset(
    """
    out-of-memory end-to-end built-in up-to-date run-time crash-loop image-pull
    back-off e-mail time-out time-outs fail-over roll-back roll-out start-up
    set-up check-in log-in open-source day-to-day on-call well-known hands-on
    so-called one-off non-zero back-end front-end
    """.split()
)

# Hyphenated English adjectives ("cluster-wide service", "read-only service").
_ADJECTIVE_SUFFIX = re.compile(
    r"-(?:wide|only|facing|running|based|level|side|ready|critical|related|"
    r"looping|like|free|less|scoped|specific|aware|friendly|bound)$"
    r"|^(?:non|pre|post|multi|cross|self|long|short|high|low|real)-"
)

# --- intent: frames that mark a name as the subject/object of a request ------
_VERB = (
    r"(?:investigate|diagnose|debug|troubleshoot|examine|inspect|analy[sz]e|"
    r"check(?:\s+on)?|review|triage|look\s+(?:at|into)|"
    r"what(?:'s|\s+is)\s+wrong\s+with)"
)
_ARTICLE = r"(?:(?:the|my|our|this|that)\s+)?"
_AUX = r"(?:(?:is|are|keeps?|has|have|was|were|isn't|aren't|won't|not|still)\s+)*"
_PREDICATE = (
    r"(?:failing|failed|fails|crash\w*|restart\w*|down|broken|unhealthy|healthy|"
    r"ready|running|working|starting|stuck|pending|erroring|slow|unavailable|"
    r"degraded|up|ok|okay|responding|flapping|misbehaving|oomkilled|unreachable|"
    r"hanging|evicted|terminating|timing)\b"
)
# "Investigate payments-api", "Diagnose memory-hog", "Check the checkout".
_IMPERATIVE = re.compile(
    rf"\b{_VERB}\s+(?:(?:why|if|whether|how)\s+)?{_ARTICLE}(?P<name>{_TOKEN})"
    r"(?=\s*(?:[.?!,;]|$)|\s+(?:in|for|on|at|please|and|is|are|isn't|keeps?|won't|not)\b)"
)
# "Why is payments-api failing?", "Why is bad-readiness not ready?"
_INTERROGATIVE = re.compile(
    rf"\b(?:why|how\s+come|is|are|does|did|what\s+happened\s+to)\s+{_ARTICLE}"
    rf"(?P<name>{_TOKEN})\s+{_AUX}{_PREDICATE}"
)
# "payments-api keeps crashing", "the checkout is down"
_SUBJECT = re.compile(
    rf"(?:^|[.?!;,]\s*){_ARTICLE}(?P<name>{_TOKEN})\s+{_AUX}{_PREDICATE}"
)
# A hyphenated DNS-style identifier anywhere in the sentence.
_HYPHENATED = re.compile(
    r"(?<![\w/.@-])(?P<name>[a-z][a-z0-9_]*(?:-[a-z0-9_]+)+)(?![\w/-]|\.\w)"
)
# Quoted names: 'payments-api', "payments_api", `web-1`.
_QUOTED = re.compile(
    rf"(?<![\w])[\"'`](?P<name>{_TOKEN}(?:\.[a-z0-9]+)*)[\"'`](?![\w])"
)
_CONSTANT = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")  # DATABASE_URL

# Phrases that widen the question beyond one workload.
_WIDENING = re.compile(
    r"\b(?:everything(?:\s+else)?|anything\s+else|the\s+rest\s+of|"
    r"all\s+(?:the\s+)?other|other\s+(?:pods|workloads|deployments|services|apps)|"
    r"all\s+(?:of\s+)?(?:the\s+)?(?:pods|workloads|deployments|services|apps|"
    r"applications)(?!\s+(?:of|belonging|owned|from|behind|for)\b)|"
    r"every\s+(?:pod|workload|deployment|service|app)|"
    r"(?:whole|entire)\s+(?:namespace|cluster|platform|environment)|"
    r"health\s+of\s+the\s+(?:namespace|platform|cluster|environment)|"
    r"(?:namespace|platform)[-\s]wide)\b"
)
# The question is explicitly about the namespace as a whole: it names the
# namespace/platform, or refers to workloads COLLECTIVELY (plural, "everything",
# "anything"). A singular generic noun ("the pod", "this deployment", "my app")
# or a bare pronoun refers to ONE unnamed thing and is NOT explicit.
_BROAD_REFERENCE = re.compile(
    r"\b(?:namespace|platform|environment|lab|cluster|everything|anything|"
    r"anywhere|pods|workloads|deployments|services|apps|applications|containers|"
    r"statefulsets|daemonsets|jobs)\b"
)


class TargetStatus(StrEnum):
    UNRESOLVED = "unresolved"  # the namespace has not been listed yet
    RESOLVED = "resolved"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"
    UNVERIFIABLE = "unverifiable"  # some owners could not be verified


class ScopeIntent(StrEnum):
    TARGETED = "targeted"
    BROAD_EXPLICIT = "broad_explicit"
    BROAD_UNSPECIFIED = "broad_unspecified"


class TargetQuestionError(ValueError):
    """The question cannot be bound to exactly one investigation scope.

    `code` is a fixed vocabulary value (multiple_targets, ambiguous_scope,
    invalid_target_name); it never echoes the question."""

    def __init__(self, code: str = "multiple_targets") -> None:
        super().__init__(f"Question target rejected: {code}.")
        self.code = code


@dataclass(frozen=True)
class WorkloadTarget:
    """A workload the question explicitly names. `kind` is a hint only (None
    when the question says just "workload" or "service")."""

    name: str
    kind: str | None = None


@dataclass(frozen=True)
class QuestionIntent:
    scope: ScopeIntent
    target: WorkloadTarget | None = None


def classify_question_target(
    question: str, *, namespace: str | None = None
) -> QuestionIntent:
    """Decide what the question is about, deterministically.

    Raises TargetQuestionError for a question that names several identities,
    names one and also asks about the rest of the namespace, or names
    something that cannot be a Kubernetes resource name. Never guesses.
    """
    if not isinstance(question, str):
        return QuestionIntent(ScopeIntent.BROAD_UNSPECIFIED)

    # Upper-case constants such as DATABASE_URL are configuration, not names.
    text = _CONSTANT.sub(" ", question).lower()
    found: dict[str, str | None] = {}
    invalid = False

    def add(name: str, kind: str | None) -> None:
        nonlocal invalid

        if (
            len(name) < 2
            or name == namespace
            or name in _NOT_A_TARGET
            or name in _COMMON_COMPOUNDS
            or _ADJECTIVE_SUFFIX.search(name) is not None
        ):
            return

        if NAME_PATTERN.fullmatch(name) is None:
            invalid = True
            return

        found.setdefault(name, kind)

    # Quoted names are explicit; the quotes are then removed so the frames
    # below see the bare name.
    for match in _QUOTED.finditer(text):
        name = match.group("name")

        if any(ch in name for ch in "-_.") or any(ch.isdigit() for ch in name):
            add(name, None)

    text = _QUOTED.sub(lambda m: m.group("name"), text)

    for match in _SLASH.finditer(text):
        add(match.group("name"), _NOUN_KIND[match.group("noun")])

    for match in _AFTER.finditer(text):
        name = match.group("name")

        if match.group("explicit") or any(ch.isdigit() or ch in "-_" for ch in name):
            add(name, _NOUN_KIND[match.group("noun")])

    for match in _BEFORE.finditer(text):
        name = match.group("name")
        # A bare word needs an article ("the checkout service"); a hyphenated
        # or numbered name is specific enough without one.
        if match.group("article") or any(ch.isdigit() or ch in "-_" for ch in name):
            add(name, _NOUN_KIND[match.group("noun")])

    for frame in (_IMPERATIVE, _INTERROGATIVE, _SUBJECT):
        for match in frame.finditer(text):
            add(match.group("name"), None)

    for match in _HYPHENATED.finditer(text):
        add(match.group("name"), None)

    if invalid:
        raise TargetQuestionError("invalid_target_name")

    if len(found) > 1:
        raise TargetQuestionError("multiple_targets")

    widened = _WIDENING.search(text) is not None

    if found:
        if widened:
            raise TargetQuestionError("ambiguous_scope")

        name, kind = next(iter(found.items()))

        return QuestionIntent(ScopeIntent.TARGETED, WorkloadTarget(name, kind))

    if widened or _BROAD_REFERENCE.search(text) is not None:
        return QuestionIntent(ScopeIntent.BROAD_EXPLICIT)

    return QuestionIntent(ScopeIntent.BROAD_UNSPECIFIED)


def extract_workload_target(
    question: str, *, namespace: str | None = None
) -> WorkloadTarget | None:
    """The single workload the question names, or None for a broad question.

    See `classify_question_target` for the intent classification and the
    errors raised."""
    return classify_question_target(question, namespace=namespace).target


# ----------------------------------------------------------------- ownership


@dataclass(frozen=True)
class PodOwner:
    """A pod's verified controlling workload, as reported by the pod listing.

    `verified` is False when the owner chain could not be confirmed (for
    example the ReplicaSet could not be read); such a pod is never matched to
    a target and is counted as unverifiable."""

    kind: str
    name: str
    verified: bool


def pod_owners_from_listing(
    *, namespace: str, output: Any
) -> dict[str, PodOwner]:
    """Validated pod -> owner map from a get_pods result. Anything malformed
    is simply absent (and therefore unverifiable)."""
    if not isinstance(output, dict) or output.get("namespace") != namespace:
        return {}

    pods = output.get("pods")

    if not isinstance(pods, list):
        return {}

    owners: dict[str, PodOwner] = {}

    for pod in pods[:MAX_LISTED_PODS]:
        if not isinstance(pod, dict):
            continue

        name, workload = pod.get("name"), pod.get("workload")

        if (
            not isinstance(name, str)
            or not _OWNER_NAME.fullmatch(name)
            or not isinstance(workload, dict)
        ):
            continue

        kind, owner, verified = (
            workload.get("kind"),
            workload.get("name"),
            workload.get("verified"),
        )

        if (
            kind in OWNER_KINDS
            and isinstance(owner, str)
            and _OWNER_NAME.fullmatch(owner)
            and type(verified) is bool
        ):
            owners[name] = PodOwner(kind, owner, verified)

    return owners


@dataclass(frozen=True)
class TargetResolution:
    status: TargetStatus
    # Pods belonging to the resolved workload (RESOLVED only).
    pods: tuple[str, ...] = ()
    workload_kind: str | None = None
    workload_name: str | None = None
    listed: int = 0
    unverified: int = 0

    @property
    def resolved(self) -> bool:
        return self.status is TargetStatus.RESOLVED


def resolve_target(
    target: WorkloadTarget,
    listed_pods: Iterable[str],
    owners: Mapping[str, PodOwner],
) -> TargetResolution:
    """Resolve by exact identity against verified owners. Never by substring."""
    pods = list(dict.fromkeys(listed_pods))

    if not pods:
        # Either nothing was listed yet, or the namespace has no pods.
        return TargetResolution(TargetStatus.UNRESOLVED)

    matched: dict[tuple[str, str], list[str]] = {}
    unverified = 0

    for pod in pods:
        owner = owners.get(pod)

        if owner is None or not owner.verified:
            unverified += 1

        if target.kind in (None, "Pod") and pod == target.name:
            matched.setdefault(("Pod", pod), []).append(pod)

        if (
            owner is not None
            and owner.verified
            and owner.name == target.name
            and target.kind in (None, owner.kind)
            and owner.kind != "Pod"
        ):
            matched.setdefault((owner.kind, owner.name), []).append(pod)

    if len(matched) > 1:
        return TargetResolution(
            TargetStatus.AMBIGUOUS, listed=len(pods), unverified=unverified
        )

    if matched:
        (kind, name), members = next(iter(matched.items()))

        return TargetResolution(
            TargetStatus.RESOLVED,
            pods=tuple(sorted(set(members))),
            workload_kind=kind,
            workload_name=name,
            listed=len(pods),
            unverified=unverified,
        )

    return TargetResolution(
        TargetStatus.UNVERIFIABLE if unverified else TargetStatus.NOT_FOUND,
        listed=len(pods),
        unverified=unverified,
    )


# ------------------------------------------------------------- call scoping

# Tools whose `pod` argument selects a resource to inspect.
POD_SCOPED_TOOLS = frozenset(
    {
        "k8s.describe_pod",
        "k8s.get_logs",
        "k8s.get_previous_logs",
        "k8s.describe_workload_config",
    }
)


def call_outside_target(
    tool: str,
    arguments: Mapping[str, Any],
    resolution: TargetResolution,
) -> str | None:
    """A fixed reason when a call would inspect something other than the
    resolved target, else None. Pod discovery is always allowed: it is how the
    target is resolved."""
    if tool == "k8s.get_pods":
        return None

    pod = arguments.get("pod")

    if tool in POD_SCOPED_TOOLS or (tool == "k8s.get_events" and pod is not None):
        if not resolution.resolved:
            return "target_unresolved"

        if pod not in resolution.pods:
            return "outside_target"

        return None

    if tool == "k8s.get_events":
        # A namespace-wide listing covers every workload in the namespace.
        return "namespace_wide_events"

    return None


def listed_pod_names(observations: Sequence[Any]) -> list[str]:
    return [
        o.value
        for o in observations
        if o.tool == "k8s.get_pods"
        and o.field == "pods[].name"
        and isinstance(o.value, str)
    ]
