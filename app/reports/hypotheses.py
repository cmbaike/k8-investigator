"""Deterministic validation of model-generated diagnostic hypotheses.

The model is an UNTRUSTED proposer. Nothing it returns reaches a report until
it passes every check here, and nothing here can create or modify a verified
finding: hypotheses live in a separate report section with a fixed
`unverified` status.

A valid citation establishes PROVENANCE, not the truth of the explanation.

Two failure classes are handled differently:
  * Provenance/security failures (unknown or foreign citations, resource
    mismatch, smuggled fields, secret reproduction, unsafe checks) reject the
    WHOLE response: the model is not trustworthy for this investigation.
  * Wording failures (`HypothesisToneError`) OMIT only the offending
    hypothesis and are counted and disclosed. A hypothesis that cannot be made
    sufficiently cautious is dropped, never softened or rewritten.

Caution is enforced in layers, not by a banned-word list alone:
  1. structure: the model supplies what the application REPORTED, a POSSIBLE
     explanation and what is NOT YET VERIFIED as separate fields; the
     application composes the final text with fixed attribution/disclaimer;
  2. log-attribution: a hypothesis citing logs must attribute them, and one
     citing none must not claim logs say something;
  3. hedging: every sentence of the possible explanation must be hedged, and
     the hedge must come before any causal connective;
  4. certainty vocabulary, negation/hedge aware ("has not been verified" and
     "needs to be confirmed" are legitimate).
These are conservative heuristics, not guarantees. Errors carry only fixed
codes, never model or log text.
"""

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.reports.config_grounding import (
    ConfigurationContext,
    collect_configuration,
    configuration_context_for,
)
from app.reports.health_grounding import (
    collect_container_classifications,
    collect_container_values,
    collect_pod_events,
    identity_conflicts,
)
from app.reports.pod_health_grounding import classify_pods, collect_pod_facts
from app.reports.probe_declarations import readiness_declared
from app.reports.models import AIHypothesis, HypothesisResource
from app.reports.snapshot import InvestigationEvidenceSnapshot
from app.reports.stage_consistency import StageFacts, stage_violation
from app.reports.source_claims import reported_violation, unsupported_claim
from app.reports.state_consistency import (
    ContainerFacts,
    PodState,
    pod_state_violation,
    state_violation,
)
from app.reports.technical_consistency import (
    TechnicalFacts,
    check_violation,
    normalize_quantity,
    technical_violation,
)
from app.tools.container_health import HealthCategory, classify_container
from app.tools.event_signals import SCHEDULING_CONSTRAINTS
from app.tools.pod_health import PodCategory
from app.tools.event_signals import IMAGE_PULL_SIGNALS, NOT_PULL_SIGNALS
from app.tools.log_context import LogContextEntry, sanitize_log_text

MAX_HYPOTHESES = 4
MAX_RESPONSE_CHARS = 8_000
MAX_REFERENCES = 6

# Per-field text limits. Mirrors the report model; checked here first so an
# over-long field omits ONE hypothesis (a wording failure) rather than
# rejecting the whole response as malformed.
MAX_REPORTED_CHARS = 200
MAX_POSSIBLE_CHARS = 300
MAX_NOT_VERIFIED_CHARS = 400
MAX_CHECK_CHARS = 300

_REFERENCE = re.compile(r"^(?:ev|log)-[0-9]{4}$")
_CONTAINER_FIELD = re.compile(r"^containers\[([^\]]+)\]\.")
_ENV_FIELD = re.compile(r"^containers\[[^\]]+\]\.env\[([^\]]+)\]\.source$")
_LIVENESS_DECLARED = re.compile(r"^containers\[([^\]]+)\]\.liveness_probe\.declared$")

# --- certainty / hedging vocabulary ----------------------------------------

_CERTAINTY = re.compile(
    r"\b(verified|confirmed?|confirms|established|proven|proves?|"
    r"definit(?:e|ive)(?:ly)?|certain(?:ly)?|conclusive(?:ly)?|undoubtedly)\b"
    # "the root cause is X" claims a cause; "the exact cause is not yet known"
    # disclaims one and is the honest wording this layer wants.
    r"|\b(?:root\s+)?cause\s+(?:is|was)\b"
    r"(?!\s+(?:not|never|unknown|unclear|undetermined|uncertain|yet)\b)",
    re.IGNORECASE,
)

# A certainty word is legitimate when it is negated or itself hedged:
# "has not been verified", "needs to be confirmed", "to confirm whether".
_CERTAINTY_QUALIFIER = re.compile(
    # Negation/need/modality within a few words before the word...
    r"\b(?:not|no|never|nothing|none|yet|without|cannot|can't|unable|"
    r"need(?:s|ed)?\s+to\s+be|"
    r"should\s+be|must\s+be|has\s+to\s+be|have\s+to\s+be|remains?\s+to\s+be|"
    r"until|before|whether|if|unless|nor|neither)\b"
    r"(?:\s+\w+){0,3}\s*$"
    # ...or an infinitive directly attached: "to confirm whether".
    r"|\bto\s+$",
    re.IGNORECASE,
)

_HEDGE = re.compile(
    r"\b(may|might|could|possibly|possible|potentially|perhaps|conceivably|"
    r"plausibly|suggests?|appears?|seems?|would\s+explain|one\s+possibility|"
    r"cannot\s+be\s+ruled\s+out|not\s+(?:yet\s+)?(?:known|clear|established))\b",
    re.IGNORECASE,
)

# Connectives that turn a statement into a causal assertion.
_CAUSAL = re.compile(
    r"\b(due\s+to|because(?:\s+of)?|caused?\s+by|causes?|causing|"
    r"result(?:s|ed|ing)?\s+(?:in|from)|owing\s+to|the\s+reason|"
    r"responsible\s+for|as\s+a\s+result|leads?\s+to|led\s+to|root\s+cause)\b",
    re.IGNORECASE,
)

_LIMITATION = re.compile(
    r"\b(not|no|nothing|yet|unverified|unconfirmed|unknown|unclear|remains?|"
    r"without|cannot|could\s+not|unable|neither|pending|"
    r"need(?:s|ed)?\s+(?:to\s+)?(?:be\s+)?(?:confirm|verif|check|inspect|"
    r"establish|validat|determin)\w*|"
    r"(?:is|are)\s+needed)\b",
    re.IGNORECASE,
)

# Verification checks are recommendations only and must be read-only.
_UNSAFE_CHECK = re.compile(
    # Mutating kubectl subcommands (flags may precede the subcommand).
    r"\bkubectl\b[^\n]*?\b(?:delete|apply|patch|edit|exec|scale|rollout|replace|"
    r"drain|cordon|uncordon|taint|annotate|label|set|create|run|cp|attach|debug)\b"
    # Imperative mutating verbs opening a sentence ("Restart the deployment").
    r"|(?:^|[.;:]\s+)(?:please\s+)?(?:delete|remove|restart|apply|patch|edit|exec|"
    r"execute|scale|rollout|replace|drain|cordon|kill|reboot|redeploy|reset|rm|"
    r"sudo|update|change|modify|create|set)\b"
    # Shell metacharacters and privileged/destructive commands.
    r"|\bsudo\b|\brm\s+-|[;&|`]|\$\(|>\s*/",
    re.IGNORECASE,
)

# Verification checks must never advise exposing Secret material or going
# around Kubernetes authorization. A negation earlier in the same sentence
# ("without revealing Secret values") excuses the match.
_SECRET_EXPOSURE = re.compile(
    r"\bsecrets?\b[^.]{0,40}\b(?:values?|contents?|data|plaintext|base64|decoded?)\b"
    r"|\b(?:values?|contents?|data)\s+of\s+(?:the\s+|any\s+|a\s+)?(?:\w+\s+){0,2}secrets?\b"
    r"|\b(?:base64|b64)\b|\bdecode\b"
    r"|\b(?:reveal|expose|dump|print|display|show|extract|exfiltrate|copy|cat|"
    r"echo|leak)\b[^.]{0,40}\b(?:secrets?|credentials?|passwords?|tokens?|"
    r"api[ -]?keys?)\b",
    re.IGNORECASE,
)
_AUTH_BYPASS = re.compile(
    r"\b(?:bypass|circumvent|escalate|impersonate|elevate|override|disable)\b"
    r"[^.]{0,40}\b(?:rbac|authori[sz]ation|authentication|permissions?|"
    r"access\s+controls?|policy|policies|restrictions?)\b"
    r"|\bcluster-admin\b|\bsystem:masters\b"
    r"|\badmin\s+(?:kubeconfig|credentials?|token|access)\b"
    r"|\bkubectl\b[^.]*\s--as\b"
    r"|\buse\s+(?:a|another|the)\s+(?:different|admin|privileged)\s+"
    r"(?:kubeconfig|credentials?|identity|account)\b",
    re.IGNORECASE,
)
_NEGATION = re.compile(
    r"\b(?:without|never|avoid|not|no|don't|do\s+not)\b|n't", re.IGNORECASE
)


def _unsafe_verification(check: str) -> bool:
    """True if the check advises exposing Secret material or bypassing
    authorization (a SECURITY failure: rejects the whole response)."""
    for sentence in _sentences(check):
        for pattern in (_SECRET_EXPOSURE, _AUTH_BYPASS):
            for match in pattern.finditer(sentence):
                if _NEGATION.search(sentence[: match.start()]) is None:
                    return True

    return False


# Inspecting ConfigMaps/Secrets is pointless when the application established
# that the spec declares no environment sources. A check about the workload's
# INTENDED configuration mechanism (owner, manifest, deployment tooling, what
# is expected) is the right alternative and is not flagged.
_RESOURCE = r"(?:configmaps?|config\s+maps?|secrets?)"

# The check DIRECTS ATTENTION AT the resources: an inspection verb whose object
# is the resource ("inspect the ConfigMap"), or verifying that such resources
# exist or are referenced. A passing mention as an example of some other
# supply mechanism inside a check about the workload's own configuration
# ("...or supplied by another mechanism such as a ConfigMap") does not tell
# anyone to inspect a reference the spec lacks, and is accepted.
_INSPECTS_CONFIG_RESOURCE = re.compile(
    r"\b(?:inspect|review|examine|check|verify|validate|look\s+(?:at|into)|read|"
    r"view|describe|list|confirm|audit|compare|ensure|open|retrieve|get)\b"
    r"[^.;:,]{0,40}\b" + _RESOURCE + r"\b",
    re.IGNORECASE,
)
_VERIFIES_RESOURCE_EXISTS = re.compile(
    r"\b" + _RESOURCE + r"\b[^.;:]{0,60}\b(?:exists?|are\s+(?:correctly\s+)?referenced|"
    r"is\s+(?:correctly\s+)?referenced|present|defined)\b"
    r"|\b(?:those|these|the\s+referenced)\s+(?:resources?|" + _RESOURCE + r")\b",
    re.IGNORECASE,
)

# Only CONCRETE directions exempt a sentence. Hedge words such as "intended" or
# "expected" do not.
_INTENDED_MECHANISM = re.compile(
    r"\b(?:owner|owners|manifest|manifests|"
    r"deployment\s+(?:definition|tooling|pipeline)|source\s+of\s+truth|"
    r"gitops|helm|kustomize)\b",
    re.IGNORECASE,
)


def _check_verification_consistency(
    check: str, facts: "ConfigurationContext"
) -> None:
    if not facts.none_declared:
        return

    for sentence in _sentences(check):
        if _INTENDED_MECHANISM.search(sentence):
            continue

        for pattern in (_INSPECTS_CONFIG_RESOURCE, _VERIFIES_RESOURCE_EXISTS):
            for match in pattern.finditer(sentence):
                # A negated mention ("does not reference any ConfigMap")
                # agrees with the evidence.
                if _NEGATION.search(sentence[: match.start()]) is None:
                    raise HypothesisToneError("check_contradicts_evidence")


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_\-+/=.]{11,}")

# Limits copying of whole log passages. Short quotes of a message are allowed:
# secrets are handled by redaction patterns and the token-echo check, not by
# this window (a window cannot catch short credentials).
_VERBATIM_WINDOW = 60


class HypothesisValidationError(ValueError):
    """Model output failed deterministic validation. `code` is a fixed value;
    messages never include model or log content."""

    def __init__(self, code: str) -> None:
        super().__init__(f"Hypothesis validation failed: {code}.")
        self.code = code


class HypothesisToneError(HypothesisValidationError):
    """Wording is not sufficiently cautious. Omits ONE hypothesis only."""


class HypothesisLimitError(HypothesisToneError):
    """The hypothesis is otherwise valid but over a size limit (it cites too
    many references). Omits ONE hypothesis only, with a fixed reason code;
    nothing is truncated."""


_PROVENANCE_CODES = frozenset(
    {
        "cross_investigation",
        "reference_count",
        "malformed_reference",
        "duplicate_reference",
        "unknown_reference",
        "resource_mismatch",
    }
)
_SECURITY_CODES = frozenset(
    {"secret_reproduction", "unsafe_text", "unsafe_check", "empty_text"}
)


def categorize_rejection(code: str) -> str:
    """Map a fixed validation code to a coarse, non-sensitive class.

    provenance: citations/resources do not check out against this investigation
    security:   the text would reproduce secrets, or is an unsafe check
    structure:  not the agreed JSON shape
    """
    if code in _PROVENANCE_CODES:
        return "provenance"

    if code in _SECURITY_CODES:
        return "security"

    return "structure"


class HypothesisGenerationError(RuntimeError):
    """Optional AI stage unavailable. `reason` is a fixed, non-sensitive code;
    `category` (optional) is a coarse validation-failure class."""

    def __init__(self, reason: str, category: str | None = None) -> None:
        super().__init__(f"Hypothesis generation unavailable: {reason}.")
        self.reason = reason
        self.category = category


@dataclass(frozen=True)
class HypothesisBatch:
    """Validated hypotheses plus the count omitted for insufficient caution."""

    hypotheses: list[AIHypothesis] = field(default_factory=list)
    omitted: int = 0
    # Fixed wording-failure code -> count. Never contains rejected text.
    omission_reasons: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class HypothesisInput:
    """Everything the tool-less generator may see. Carries no executor."""

    snapshot: InvestigationEvidenceSnapshot
    log_entries: tuple[LogContextEntry, ...]
    omitted_log_entries: int
    authorized_namespace: str


@dataclass(frozen=True)
class ReferenceResource:
    namespace: str | None
    pod: str | None
    containers: frozenset[str]


class HypothesisEvidenceRegistry:
    """Investigation-scoped registry of every citable reference.

    Built only from this investigation's evidence snapshot and log context.
    Reference formats are positional, so scoping is by construction plus an
    explicit investigation-ID check, never by format alone.
    """

    def __init__(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
        snapshot: InvestigationEvidenceSnapshot,
        log_entries: Iterable[LogContextEntry],
    ) -> None:
        if snapshot.investigation_id != investigation_id:
            raise HypothesisValidationError("cross_investigation")

        self.investigation_id = investigation_id
        self.authorized_namespace = authorized_namespace
        self._snapshot = snapshot
        self._resources: dict[str, ReferenceResource] = {}
        self._classifications = collect_container_classifications(snapshot)
        self._container_values = collect_container_values(snapshot)
        self._events = collect_pod_events(snapshot)
        self._evidence_fields = {
            item.evidence_id: item.field for item in snapshot.evidence
        }
        self._evidence_values = {
            item.evidence_id: item.value for item in snapshot.evidence
        }
        self._configuration = collect_configuration(snapshot)[0]
        self._pod_assessments = classify_pods(snapshot)
        self._pod_facts = collect_pod_facts(snapshot)
        self._liveness_declared: dict[tuple[str, str, str], bool] = {}
        self._known_names: set[str] = {authorized_namespace.lower()}
        self._log_lines: list[str] = []
        # Events verified against a DIFFERENT pod UID than the one inspected do
        # not describe it: their references are not citable.
        conflicts = identity_conflicts(snapshot)

        for item in snapshot.evidence:
            if (
                item.tool == "k8s.get_events"
                and (item.namespace, item.pod) in conflicts
            ):
                continue

            declared = _LIVENESS_DECLARED.match(item.field)

            if declared and type(item.value) is bool and item.namespace and item.pod:
                self._liveness_declared[
                    (item.namespace, item.pod, declared.group(1))
                ] = item.value

            containers: set[str] = set()
            match = _CONTAINER_FIELD.match(item.field)

            if match:
                containers.add(match.group(1))
            elif item.field == "containers[].name" and isinstance(item.value, str):
                containers.add(item.value)

            self._resources[item.evidence_id] = ReferenceResource(
                namespace=item.namespace,
                pod=item.pod,
                containers=frozenset(containers),
            )
            self._add_names(item.namespace, item.pod, *containers)

            # Verified resource names (e.g. workload identity) may be quoted.
            if item.field.endswith(".name") and isinstance(item.value, str):
                self._add_names(item.value)

            # Environment variable NAMES and images from verified
            # configuration evidence are identifiers, not credentials.
            env_match = _ENV_FIELD.match(item.field)

            if env_match:
                self._add_names(env_match.group(1))

            if item.field.endswith(".image") and isinstance(item.value, str):
                self._add_names(item.value)

        for entry in log_entries:
            self._resources[entry.log_ref] = ReferenceResource(
                namespace=entry.namespace,
                pod=entry.pod,
                containers=frozenset({entry.container} if entry.container else ()),
            )
            self._add_names(entry.namespace, entry.pod, entry.container)
            self._log_lines.extend(entry.lines)

    def _add_names(self, *names: str | None) -> None:
        self._known_names.update(n.lower() for n in names if n)

    def resource_for(self, reference: str) -> ReferenceResource | None:
        return self._resources.get(reference)

    def configuration_context(
        self, pod: str | None, container: str | None
    ) -> ConfigurationContext | None:
        return configuration_context_for(
            self._snapshot, self.authorized_namespace, pod, container
        )

    def never_started(self, pod: str | None, container: str | None) -> bool:
        """True when Kubernetes reports the resource's container(s) failed
        before ever starting (a pre-start failure with no evidence it ran).

        With no single container named, every observed container of the pod
        must be in that state. Derived from application-minted observations
        only; a never-started container has no application behaviour to
        describe.
        """
        if pod is None:
            return False

        namespace = self.authorized_namespace
        blocked = self._pod_assessments.get((namespace, pod))

        # An unschedulable pod, or one whose volumes cannot be mounted, has had
        # no container run, whatever its (absent or transitional) statuses say.
        if blocked is not None and not any(
            a.ran_before
            for (ns, p, _), a in self._classifications.items()
            if (ns, p) == (namespace, pod)
        ):
            return True

        observed = {
            name: assessment
            for (ns, p, name), assessment in self._classifications.items()
            if ns == namespace and p == pod
        }
        targets = [container] if container else list(observed)

        return bool(targets) and all(
            name in observed
            and observed[name].category is HealthCategory.PRE_START_FAILURE
            and not observed[name].ran_before
            for name in targets
        )

    def evidence_field(self, reference: str) -> str | None:
        """The extractor field name an evidence id cites (None for log refs
        and unknown ids). Used for ordering only, never for provenance."""
        return self._evidence_fields.get(reference)

    def cited_observations(self, references: Iterable[Any]) -> dict[str, tuple[str, Any]]:
        """Evidence id -> (field, value) for the cited observations (log
        references and unknown ids are skipped). For checking that a specific
        detail in the wording is supplied by something cited."""
        return {
            ref: (self._evidence_fields[ref], self._evidence_values.get(ref))
            for ref in references
            if isinstance(ref, str) and ref in self._evidence_fields
        }

    def assessment(self, pod: str | None, container: str | None):
        """The established health classification for the resource: the most
        severe among its container(s), or None when nothing is observed."""
        if pod is None:
            return None

        namespace = self.authorized_namespace
        found = [
            assessment
            for (ns, p, name), assessment in self._classifications.items()
            if ns == namespace and p == pod and container in (None, name)
        ]
        order = {"critical": 0, "warning": 1}

        return min(
            found,
            key=lambda a: order.get(a.severity or "", 2),
            default=None,
        )

    def scheduling_signals(self, pod: str | None) -> frozenset[str]:
        """Scheduler constraint signals the application classified for the
        pod (condition or FailedScheduling events), by fixed name."""
        facts = self._pod_facts.get((self.authorized_namespace, pod)) if pod else None

        if facts is None:
            return frozenset()

        names = set(facts.scheduling_signals)

        for event in facts.events:
            if event.reason == "FailedScheduling":
                names.update(name for name, _ref in event.signals)

        return frozenset(names)

    def technical_facts(
        self, pod: str | None, container: str | None
    ) -> TechnicalFacts:
        """What the application established that the technical-consistency
        rules depend on. Application-minted observations only."""
        if pod is None:
            return TechnicalFacts(authorized_namespace=self.authorized_namespace)

        namespace = self.authorized_namespace
        assessment = self.pod_assessment(pod)
        containers = self.container_facts(pod, container)
        names = {pod.lower()} | {
            name.lower()
            for (ns, p, name) in self._container_values
            if ns == namespace and p == pod
        }

        pod_facts = self._pod_facts.get((namespace, pod))
        selector = pod_facts.node_selector[0] if pod_facts and pod_facts.node_selector else None
        affinity = pod_facts.affinity[0] if pod_facts and pod_facts.affinity else None

        return TechnicalFacts(
            placement_undeclared=selector is False and affinity is False,
            unschedulable=bool(
                assessment is not None and assessment.category is PodCategory.UNSCHEDULABLE
            ),
            requests_declared=any(
                isinstance(values.get("resources.memory_request"), str)
                for (ns, p, _name), values in self._container_values.items()
                if ns == namespace and p == pod
            ),
            restart_history=any(
                isinstance(values.get("restart_count"), int)
                and not isinstance(values.get("restart_count"), bool)
                and values["restart_count"] >= 1
                for (ns, p, _name), values in self._container_values.items()
                if ns == namespace and p == pod
            ),
            memory_requests=self._quantities(pod, "resources.memory_request"),
            memory_limits=self._quantities(pod, "resources.memory_limit"),
            oom_recorded=any(
                "OOMKilled" in (values.get("last_termination.reason"), values.get("reason"))
                for (ns, p, _name), values in self._container_values.items()
                if ns == namespace and p == pod
            ),
            scheduling_signals=self.scheduling_signals(pod) & frozenset(SCHEDULING_CONSTRAINTS),
            running_and_ready=bool(containers)
            and all(f.running and not f.not_ready for f in containers),
            authorized_namespace=namespace,
            scope_names=frozenset(names),
        )

    def _quantities(self, pod: str, field: str) -> frozenset[str]:
        found = set()

        for (ns, p, _name), values in self._container_values.items():
            value = values.get(field)

            if ns == self.authorized_namespace and p == pod and isinstance(value, str):
                normal = normalize_quantity(value)

                if normal:
                    found.add(normal)

        return frozenset(found)

    def stage_facts(self, pod: str | None, container: str | None) -> StageFacts:
        """Which lifecycle stages the application established as completed.
        Application-minted observations only."""
        if pod is None:
            return StageFacts()

        namespace = self.authorized_namespace
        pod_facts = self._pod_facts.get((namespace, pod))
        scheduled_status = pod_facts.scheduled_status if pod_facts else None
        values = [
            observed
            for (ns, p, name), observed in self._container_values.items()
            if (ns, p) == (namespace, pod) and container in (None, name)
        ]
        started = any(
            observed.get("state") in {"running", "terminated"}
            or "last_termination.reason" in observed
            for observed in values
        )
        restarted = [
            observed
            for observed in values
            if type(observed.get("restart_count")) is int
            and observed["restart_count"] >= 1
        ]

        return StageFacts(
            scheduled=(scheduled_status is not None and scheduled_status[0] == "True")
            or started,
            scheduling_history=bool(self.scheduling_signals(pod))
            or any(
                event.reason == "FailedScheduling"
                for event in self._events.get((namespace, pod), ())
            ),
            sole_restart_was_oom=bool(restarted)
            and all(
                observed["restart_count"] == 1
                and observed.get("last_termination.reason") == "OOMKilled"
                for observed in restarted
            ),
        )

    def liveness_failures_recorded(self, pod: str | None) -> bool:
        """True when an accepted event of the pod was classified as a
        liveness-probe failure or a liveness restart (pod-level, never tied to
        one container)."""
        if pod is None:
            return False

        return any(
            signal in {"liveness_probe_failed", "liveness_restart"}
            for event in self._events.get((self.authorized_namespace, pod), ())
            for signal, _ref in event.signals
        )

    def references_config_objects(self, pod: str | None) -> bool:
        """True when the pod's spec declares a ConfigMap or Secret VOLUME.

        A volume is a reference to such an object, so a check that names
        ConfigMaps or Secrets is then consistent with the evidence even when
        no ENVIRONMENT source is declared. Names and source types only; no
        object is read."""
        facts = self._pod_facts.get((self.authorized_namespace, pod)) if pod else None

        return bool(
            facts
            and any(
                source in {"config_map", "secret", "projected"}
                for source, _ref in facts.volumes.values()
            )
        )

    def pod_assessment(self, pod: str | None):
        """The established pod-level assessment (unschedulable, volume mount
        failure), or None."""
        if pod is None:
            return None

        found = self._pod_assessments.get((self.authorized_namespace, pod))

        return found[0] if found else None

    def pod_state(self, pod: str | None, container: str | None) -> PodState | None:
        """Pod-level established state for deterministic contradiction checks."""
        if pod is None:
            return None

        namespace = self.authorized_namespace
        declared = [
            value
            for (ns, p, name), value in self._liveness_declared.items()
            if (ns, p) == (namespace, pod) and container in (None, name)
        ]
        liveness = (
            True if any(declared) else False if declared and not any(declared) else None
        )

        return PodState(
            blocked_before_start=(namespace, pod) in self._pod_assessments,
            liveness_probe_declared=liveness,
        )

    def container_facts(
        self, pod: str | None, container: str | None
    ) -> list[ContainerFacts]:
        """Established structured state for the resource's container(s), for
        deterministic contradiction checks. Empty when nothing is observed.
        Application-minted observations only; never model or log text."""
        if pod is None:
            return []

        namespace = self.authorized_namespace
        values = {
            name: observed
            for (ns, p, name), observed in self._container_values.items()
            if ns == namespace and p == pod
        }
        names = [container] if container else sorted(values)
        # Image-pull evidence: the kubelet's pull-related reasons, except an
        # event whose message was classified as the crash-loop back-off
        # ("Back-off restarting failed container"), which is not about pulling.
        # An unclassified event keeps counting (reason and count alone cannot
        # rule a pull problem out).
        reasons = frozenset(
            event.reason
            for event in self._events.get((namespace, pod), ())
            if not (
                {signal for signal, _ref in event.signals} & NOT_PULL_SIGNALS
                and not {signal for signal, _ref in event.signals} & IMAGE_PULL_SIGNALS
            )
        )
        config = self._configuration.get((namespace, pod))
        facts = []

        for name in names:
            if name not in values:
                return []  # a named container that was not observed

            observed = values[name]
            assessment = classify_container(observed)
            # Declared / verified absent / unknown. The Pod's own container
            # specification is read first (it covers a standalone Pod), the
            # owning workload's template otherwise; None when neither was
            # collected, and an uncollected probe is never read as absent.
            probe = readiness_declared(
                self._snapshot,
                (namespace, pod),
                name,
                config.containers.get(name) if config is not None else None,
            )

            context = self.configuration_context(pod, name)
            facts.append(
                ContainerFacts(
                    running=observed.get("state") == "running",
                    not_ready=observed.get("ready") is False,
                    event_reasons=reasons,
                    readiness_probe_declared=probe,
                    env_none_declared=bool(context and context.none_declared),
                    ran_before=assessment.ran_before,
                    pre_start=assessment.category is HealthCategory.PRE_START_FAILURE,
                )
            )

        return facts

    def established_facts(
        self, pod: str | None, container: str | None
    ) -> tuple[str, list[str]] | None:
        """Application-authored statement of independently established facts
        about this resource, with the evidence it rests on.

        Currently: Kubernetes reported a termination exit code AND static
        analysis of the declared startup found an unconditional exit with the
        same code. Derived only from verified evidence, never from model or
        log text. Returns None when nothing is established.
        """
        if pod is None:
            return None

        pods, exit_codes = collect_configuration(self._snapshot)
        config = pods.get((self.authorized_namespace, pod))

        if config is None:
            return None

        sentences: list[str] = []
        refs: list[str] = []

        for name, cfg in sorted(config.containers.items()):
            if container is not None and name != container:
                continue

            code = cfg.attrs.get("startup.static_exit_code")
            observed = exit_codes.get((self.authorized_namespace, pod, name))

            if (
                cfg.attrs.get("startup.static_analysis") == "unconditional_exit"
                and type(code) is int
                and observed is not None
                and observed[0] == code
            ):
                sentences.append(
                    f"Container {name!r}: Kubernetes reported exit code "
                    f"{code} and static analysis of its declared startup "
                    "command found an unconditional exit with the same code, "
                    "independent of environment variables. Changing "
                    "environment variable values alone would not be expected "
                    "to change this termination."
                )
                refs.extend(
                    [
                        observed[1],
                        cfg.refs["startup.static_analysis"],
                        cfg.refs["startup.static_exit_code"],
                    ]
                )

        if not sentences:
            return None

        text = " ".join(sentences)

        if len(text) > 700 or len(set(refs)) > 3:
            return None  # bounded: omit rather than truncate or overflow

        return text, list(dict.fromkeys(refs))

    @property
    def known_names(self) -> frozenset[str]:
        return frozenset(self._known_names)

    @property
    def log_lines(self) -> tuple[str, ...]:
        return tuple(self._log_lines)


class _ModelResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    namespace: str | None = Field(default=None, max_length=253)
    pod: str | None = Field(default=None, max_length=253)
    container: str | None = Field(default=None, max_length=253)


class _ModelHypothesis(BaseModel):
    """Exactly what the model may supply. No status, severity, title, free
    explanation, or findings: unknown keys are rejected, so they cannot be
    smuggled in."""

    model_config = ConfigDict(extra="forbid")

    reported: str | None = None
    possible_explanation: str
    not_yet_verified: str
    evidence: list[Any]
    resource: _ModelResource | None = None
    verification_check: str


def _check_references(
    refs: list[Any], registry: HypothesisEvidenceRegistry
) -> list[ReferenceResource]:
    """Provenance of EVERY cited reference, however many there are.

    An unknown, malformed, duplicated or foreign reference rejects the whole
    response, even in a hypothesis that is also over the citation limit: the
    limit is a size rule and must never mask a provenance failure. The size
    rule itself (MAX_REFERENCES) is applied afterwards, per hypothesis."""
    if not refs:
        raise HypothesisValidationError("reference_count")

    seen: set[str] = set()
    resources: list[ReferenceResource] = []

    for ref in refs:
        if not isinstance(ref, str) or not _REFERENCE.fullmatch(ref):
            raise HypothesisValidationError("malformed_reference")

        if ref in seen:
            raise HypothesisValidationError("duplicate_reference")

        seen.add(ref)
        resource = registry.resource_for(ref)

        if resource is None:
            raise HypothesisValidationError("unknown_reference")

        if (
            resource.namespace is not None
            and resource.namespace != registry.authorized_namespace
        ):
            raise HypothesisValidationError("resource_mismatch")

        resources.append(resource)

    return resources


def _derive_resource(
    resources: list[ReferenceResource],
    declared: Mapping[str, str | None] | None,
    registry: HypothesisEvidenceRegistry,
) -> HypothesisResource:
    """Resource identity comes from the cited evidence, never from the model.

    Same-namespace evidence is NOT assumed to concern the same workload: all
    pod-bearing citations must name one pod. No cross-resource relationship is
    defined, so mixing pods is rejected.
    """
    pods = {r.pod for r in resources if r.pod}

    if len(pods) > 1:
        raise HypothesisValidationError("resource_mismatch")

    pod = next(iter(pods), None)
    containers = {c for r in resources for c in r.containers}
    container = next(iter(containers)) if len(containers) == 1 else None

    if declared:
        declared_namespace = declared.get("namespace")
        declared_pod = declared.get("pod")
        declared_container = declared.get("container")

        if declared_namespace not in (None, registry.authorized_namespace):
            raise HypothesisValidationError("resource_mismatch")

        if declared_pod is not None and declared_pod != pod:
            raise HypothesisValidationError("resource_mismatch")

        if declared_container is not None and declared_container != container:
            raise HypothesisValidationError("resource_mismatch")

    return HypothesisResource(
        namespace=registry.authorized_namespace,
        pod=pod,
        container=container,
    )


def _normalize(text: str) -> str:
    return " ".join(text.lower().split())


def _check_text(text: Any, registry: HypothesisEvidenceRegistry) -> str:
    """Provenance/security checks shared by every model-authored field."""
    if not isinstance(text, str) or not text.strip():
        raise HypothesisValidationError("empty_text")

    text = text.strip()

    if re.search(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]", text) or "```" in text:
        raise HypothesisValidationError("unsafe_text")

    # Anything the log sanitizer would redact must not be reproduced.
    if sanitize_log_text(text)[1] > 0:
        raise HypothesisValidationError("secret_reproduction")

    normalized = _normalize(text)

    # Bounded verbatim copying of log passages is rejected.
    for line in registry.log_lines:
        line_n = _normalize(line)

        if len(line_n) < _VERBATIM_WINDOW:
            continue

        for i in range(len(line_n) - _VERBATIM_WINDOW + 1):
            if line_n[i : i + _VERBATIM_WINDOW] in normalized:
                raise HypothesisValidationError("secret_reproduction")

    # Identifier-looking tokens echoed from logs (that are not known
    # resource names) are treated as potential credentials.
    if registry.log_lines:
        log_blob = _normalize("\n".join(registry.log_lines))

        for token in _TOKEN.findall(text):
            token_n = token.lower().strip(".,;:")

            if (
                any(c.isalpha() for c in token_n)
                and any(c.isdigit() for c in token_n)
                and token_n not in registry.known_names
                and token_n in log_blob
            ):
                raise HypothesisValidationError("secret_reproduction")

    return text


# --- tone ------------------------------------------------------------------


def _sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]


def asserts_certainty(text: str) -> bool:
    """True if `text` claims certainty. Negated or hedged uses of words such as
    'verified' ("has not been verified", "needs to be confirmed") are fine."""
    for match in _CERTAINTY.finditer(text):
        prefix = text[max(0, match.start() - 40) : match.start()]

        if not _CERTAINTY_QUALIFIER.search(prefix):
            return True

    return False


def is_cautious_explanation(text: str) -> bool:
    """Every sentence must be hedged, and the hedge must precede any causal
    connective in that sentence ("may be failing due to X" passes; "is failing
    due to X, which may ..." and "is failing due to X" do not)."""
    sentences = _sentences(text)

    if not sentences:
        return False

    for sentence in sentences:
        hedge = _HEDGE.search(sentence)

        if hedge is None:
            return False

        causal = _CAUSAL.search(sentence)

        if causal is not None and causal.start() < hedge.start():
            return False

    return True


def _check_tone(
    *,
    reported: str | None,
    possible: str,
    not_verified: str,
    evidence: list[Any],
) -> None:
    cites_logs = any(isinstance(r, str) and r.startswith("log-") for r in evidence)

    # Log claims must be attributed to the application; and a hypothesis that
    # cites no logs must not claim the logs say something.
    if cites_logs and reported is None:
        raise HypothesisToneError("unattributed_log_claim")

    # A log claim may not carry a Kubernetes state (or the claim of a source
    # that is not logs) under the application's name.
    source = reported_violation(reported, cites_logs=cites_logs)

    if source is not None:
        raise HypothesisToneError(source)

    if not cites_logs and reported is not None:
        # Typically: logs were never retrieved, yet the model claims what
        # "the application logs report". Distinct from a missing attribution.
        raise HypothesisToneError("reported_without_log_evidence")

    for text in (t for t in (reported, possible, not_verified) if t):
        if asserts_certainty(text):
            raise HypothesisToneError("verified_claim")

    if not is_cautious_explanation(possible):
        raise HypothesisToneError("insufficiently_cautious")

    if not _LIMITATION.search(not_verified):
        raise HypothesisToneError("insufficiently_cautious")


# --- consistency with independently established configuration evidence ----
#
# Model-authored uncertainty must not contradict facts the application
# established itself. These are conservative, wording-level heuristics over
# the model's own uncertainty/explanation text (never the attributed `reported`
# field, which is an application claim). A match omits that ONE hypothesis
# with a fixed code; nothing is rewritten and no text is retained.

# "not inspected / not verified / unknown" style predicates.
_NOT_ESTABLISHED = re.compile(
    r"\b(?:not|never|no)\b(?:\s+\w+){0,2}?\s+"
    r"(?:inspected|examined|checked|reviewed|retrieved|collected|"
    r"analy[sz]ed|established|verified|confirmed)\b"
    r"|\b(?:unknown|uninspected|unexamined|unverified|unconfirmed)\b",
    re.IGNORECASE,
)

# Subjects whose inspection the application's evidence DOES cover.
_CONFIG_SUBJECT = re.compile(
    r"\b(?:configuration|config|environment\s+(?:configuration|declarations?|"
    r"spec)|(?:declared|declarations?\s+of)\s+(?:environment\s+)?variables?|"
    r"environment\s+variable\s+(?:declarations?|names?|list))\b",
    re.IGNORECASE,
)
_STARTUP_SUBJECT = re.compile(
    r"\b(?:startup\s+(?:behaviou?r|command|configuration|analysis)|entrypoint)\b",
    re.IGNORECASE,
)

# A sentence scoped to things the evidence does NOT cover is legitimate.
_OUT_OF_SCOPE = re.compile(
    r"\b(?:values?|contents?|runtime|run-time|injected|injection|supplied|"
    r"provided|correct(?:ly)?|baked|image|other\s+(?:mechanisms?|sources?)|"
    r"present|actual(?:ly)?|effective|resolved|whether|configmaps?|secrets?)\b",
    re.IGNORECASE,
)

# Hedging only (negation is not an excuse for overstating absence).
_HEDGED = re.compile(
    r"\b(?:may|might|could|possibly|perhaps|whether|if|unless|appears?|seems?|"
    r"suggests?)\b",
    re.IGNORECASE,
)

_HEDGED_OR_NEGATED = re.compile(
    r"\b(?:may|might|could|possibly|perhaps|whether|if|unless|not|no|never)\b|n't",
    re.IGNORECASE,
)

# "No variables are declared" / "does not show any variables declared".
_CLAIMS_NONE_DECLARED = re.compile(
    r"\b(?:no|zero|without\s+any)\s+(?:environment\s+)?variables?\s+"
    r"(?:(?:are|is)\s+)?declared\b"
    r"|\bdeclares?\s+no\s+(?:environment|env)\b"
    r"|\b(?:does|do)\s+not\s+(?:show|list|declare|contain|define|include)"
    r"\s+any\s+(?:environment\s+)?variables?\b",
    re.IGNORECASE,
)
# "The variable is declared in the workload."
_CLAIMS_DECLARED = re.compile(
    r"\b(?:is|are)\s+declared\s+(?:in|by|for|within|on)\b", re.IGNORECASE
)

# Negation/denial words that make "...environment is empty" a disclaimer.
# ("no" is excluded: "declares no variables and the environment is empty" is
# still an overstatement.)
_DENIAL = re.compile(
    r"\b(?:not|never|cannot|neither|nor|without|unable|nothing)\b|n't",
    re.IGNORECASE,
)

# Treating absence of a declaration as proof about the runtime environment.
_OVERSTATES_ABSENCE = re.compile(
    r"\b(?:environment|container|pod|process)\s+(?:has|contains|defines)\s+no\s+"
    r"(?:env\w*\s+)?variables?\b"
    r"|\b(?:environment|env)\s+(?:is|was)\s+empty\b"
    r"|\bno\s+environment\s+variables?\s+(?:exist|are\s+(?:set|present|"
    r"available|defined))\b"
    r"|\bvariables?\s+(?:is|are)\s+(?:definitely\s+|certainly\s+)?"
    r"(?:not\s+set|missing|absent|undefined)\s+(?:at|in)\s+(?:runtime|the\s+"
    r"(?:container|environment))\b",
    re.IGNORECASE,
)


def _check_consistency(
    texts: Iterable[str], facts: ConfigurationContext
) -> None:
    """Raise HypothesisToneError when wording contradicts, or overstates,
    independently established configuration/startup evidence."""
    for text in texts:
        for sentence in _sentences(text):
            scoped_out = _OUT_OF_SCOPE.search(sentence) is not None

            if _NOT_ESTABLISHED.search(sentence) and not scoped_out:
                if facts.inspected and _CONFIG_SUBJECT.search(sentence):
                    raise HypothesisToneError("contradicts_established_evidence")

                if facts.startup_established and _STARTUP_SUBJECT.search(sentence):
                    raise HypothesisToneError("contradicts_established_evidence")

            if facts.declared_any and _CLAIMS_NONE_DECLARED.search(sentence):
                raise HypothesisToneError("contradicts_established_evidence")

            claim = _CLAIMS_DECLARED.search(sentence)

            if facts.none_declared and claim:
                # Excuse only a hedge or negation in the same clause BEFORE
                # the claim ("whether it is declared"), not elsewhere in the
                # sentence ("... declared, but its value is not verified").
                clause = re.split(r"[,;:]", sentence[: claim.start()])[-1]

                if _HEDGED_OR_NEGATED.search(clause) is None:
                    raise HypothesisToneError("contradicts_established_evidence")

            if _HEDGED.search(sentence) is None:
                for claim in _OVERSTATES_ABSENCE.finditer(sentence):
                    # Denying the inference is the CORRECT wording ("this does
                    # not confirm the environment is empty"): a negation or
                    # denial earlier in the same clause excuses the match.
                    clause = re.split(r"[,;:]", sentence[: claim.start()])[-1]

                    if _DENIAL.search(clause) is None:
                        raise HypothesisToneError("overstated_absence")


# A container that never started has no runtime behaviour: nothing crashed,
# exited, restarted or logged. Hedged speculation about any of those contradicts
# the Kubernetes state the application verified. Sentences that DENY it
# ("no application logs exist") are the correct wording and are allowed.
_RAN_VOCABULARY = re.compile(
    r"\b(?:crash\w*|exit(?:ed|s|ing)?|exit\s+codes?|terminat\w+|oom\w*|"
    r"out\s+of\s+memory|stack\s*traces?|exceptions?|panic\w*|logs?|logged|"
    r"restart(?:ed|s|ing)?|runtime\s+(?:error|failure|bug)|"
    # Probes only run against a container that is running.
    r"(?:liveness|readiness|startup)\s+(?:probes?|checks?))\b",
    re.IGNORECASE,
)
_RAN_DENIAL = re.compile(
    r"\b(?:not|no|never|cannot|without|unable|nothing|unavailable|absent|"
    r"neither|nor|zero)\b|n't",
    re.IGNORECASE,
)


def _check_never_started_consistency(texts: Iterable[str]) -> None:
    for text in texts:
        for sentence in _sentences(text):
            for match in _RAN_VOCABULARY.finditer(sentence):
                # The denial must come before the word, in the same clause:
                # "no logs exist" is fine; "it may have crashed and may not
                # start" is not.
                clause = re.split(r"[,;:]", sentence[: match.start()])[-1]

                if _RAN_DENIAL.search(clause) is None:
                    raise HypothesisToneError("contradicts_container_state")


# The application authors the attribution ("The application logs report that"),
# so a model that repeats it ("The application reported that ...") is
# normalized. This removes only a leading attribution phrase; it never
# changes the claimed content or adds certainty.
_LEADING_ATTRIBUTION = re.compile(
    r"^\s*(?:the\s+)?(?:application(?:'s)?(?:\s+logs?)?|app(?:\s+logs?)?|logs?|"
    r"program|process|container(?:\s+logs?)?)\s+"
    r"(?:has\s+|have\s+)?(?:reported|reports?|states?|stated|says?|said|"
    r"indicates?|indicated|claims?|claimed|shows?|showed|printed|prints?)\b"
    r"(?:\s+that\b)?\s*",
    re.IGNORECASE,
)


def strip_leading_attribution(text: str) -> str:
    return _LEADING_ATTRIBUTION.sub("", text, count=1).strip()


def _sentence(text: str) -> str:
    return text.strip().rstrip(".!? ") + "."


def compose_explanation(
    *, reported: str | None, possible: str, not_verified: str
) -> str:
    """Application-authored presentation with fixed attribution and
    disclaimer wording. The model supplies only the content of each part."""
    parts = []

    if reported:
        parts.append(f"The application logs report that {_sentence(reported)}")

    parts.append(f"Possible explanation (unverified): {_sentence(possible)}")
    parts.append(f"Not yet verified: {_sentence(not_verified)}")

    return " ".join(parts)


def validate_hypothesis_fields(
    *,
    reported: str | None,
    possible_explanation: str,
    not_yet_verified: str,
    evidence: list[Any],
    declared_resource: Mapping[str, str | None] | None,
    verification_check: str | None,
    registry: HypothesisEvidenceRegistry,
    stored_explanation: str | None = None,
    stored_established: str | None = None,
    stored_configuration: str | None = None,
    stored_check_withheld: str | None = None,
) -> AIHypothesis:
    """Validate one hypothesis from ANY source and return the report model.

    `status` and `explanation` are authored by the application, never read from
    the source. `stored_explanation` (re-validation of provider-built objects)
    must equal the recomposed text.

    A recommended check that is technically wrong, an action instead of an
    inspection, or aimed at something other than this resource is WITHHELD:
    the hypothesis is kept without a check and says why
    (`check_withheld_reason`). Nothing is rewritten into a different check; the
    report's own application-authored checks remain.
    """
    # Provenance and security first: these reject the whole response.
    resources = _check_references(evidence, registry)
    resource = _derive_resource(resources, declared_resource, registry)

    possible = _check_text(possible_explanation, registry)
    not_verified = _check_text(not_yet_verified, registry)
    check = (
        _check_text(verification_check, registry)
        if verification_check is not None
        else None
    )
    attributed = _check_text(reported, registry) if reported is not None else None

    if attributed is not None:
        attributed = strip_leading_attribution(attributed)

        if not attributed:
            raise HypothesisToneError("unattributed_log_claim")

    if check is not None and (_UNSAFE_CHECK.search(check) or _unsafe_verification(check)):
        raise HypothesisValidationError("unsafe_check")

    # Size and wording last: these omit only this hypothesis. Every provenance
    # and security check above has already passed, so an over-limit hypothesis
    # is dropped for size alone; its references are never truncated.
    if len(evidence) > MAX_REFERENCES:
        raise HypothesisLimitError("too_many_references")

    for text, limit in (
        (attributed, MAX_REPORTED_CHARS),
        (possible, MAX_POSSIBLE_CHARS),
        (not_verified, MAX_NOT_VERIFIED_CHARS),
        (check, MAX_CHECK_CHARS),
    ):
        if text is not None and len(text) > limit:
            raise HypothesisToneError("too_long")

    _check_tone(
        reported=attributed,
        possible=possible,
        not_verified=not_verified,
        evidence=evidence,
    )

    # A specific detail (probe path, port, status code) or an event claim must
    # be supplied by evidence of its own kind that the hypothesis cites.
    unsupported = unsupported_claim(
        (possible, not_verified), registry.cited_observations(evidence)
    )

    if unsupported is not None:
        raise HypothesisToneError(unsupported)

    # Kubernetes semantics (taints belong to nodes and tolerations to pods,
    # pods request and nodes allocate, a readiness failure restarts nothing,
    # ...) against what the application established. A wrong explanation omits
    # the hypothesis. The recommended check is held to the same semantics and
    # must also be a read-only diagnostic scoped to this resource: a wrong
    # check sends an engineer to inspect the wrong object, so it is withheld
    # (below) while a sound explanation is kept.
    technical = registry.technical_facts(resource.pod, resource.container)
    violation = technical_violation(
        (possible, not_verified),
        technical,
        cites_logs=any(_is_log_ref(ref) for ref in evidence),
    )

    if violation is not None:
        raise HypothesisToneError(violation)

    # Re-validating a hypothesis whose check was already withheld: the reason
    # is carried forward; a check can only ever become withheld, never restored.
    withheld = (
        check_violation(check, technical) if check is not None else stored_check_withheld
    )

    explanation = compose_explanation(
        reported=attributed, possible=possible, not_verified=not_verified
    )

    if stored_explanation is not None and stored_explanation != explanation:
        raise HypothesisValidationError("schema")

    configuration = registry.configuration_context(resource.pod, resource.container)

    if configuration is not None:
        _check_consistency((possible, not_verified), configuration)

        if not registry.references_config_objects(resource.pod):
            _check_verification_consistency(check, configuration)

    if registry.never_started(resource.pod, resource.container):
        _check_never_started_consistency((possible, not_verified))

        # A check that asks for logs, exit codes, restarts or probes of a
        # container that never ran is pointed at something that does not exist.
        if check is not None and withheld is None:
            try:
                _check_never_started_consistency((check,))
            except HypothesisToneError as exc:
                withheld = exc.code

    # Deterministic contradictions with structured Kubernetes state.
    violation = state_violation(
        (possible, not_verified),
        registry.container_facts(resource.pod, resource.container),
        cites_logs=any(_is_log_ref(ref) for ref in evidence),
    )

    if violation is not None:
        raise HypothesisToneError(violation)

    pod_state = registry.pod_state(resource.pod, resource.container)
    violation = pod_state_violation((possible, not_verified), pod_state)

    if violation is not None:
        raise HypothesisToneError(violation)

    # A stage Kubernetes established as completed cannot be the failure: a
    # scheduled pod "unable to schedule", the only restart blamed on a
    # non-memory mechanism after an OOMKilled termination. Only the
    # explanation itself is read, never the statement of what is unverified.
    violation = stage_violation(
        (possible,), registry.stage_facts(resource.pod, resource.container)
    )

    if violation is not None:
        raise HypothesisToneError(violation)

    if check is not None and withheld is None:
        withheld = state_violation(
            (check,),
            registry.container_facts(resource.pod, resource.container),
            cites_logs=False,
            inspection_only=True,
        ) or pod_state_violation((check,), pod_state)

    established = registry.established_facts(resource.pod, resource.container)
    established_text, established_refs = established or (None, [])

    # Application-authored: a provider-supplied value must match exactly.
    if stored_established is not None and stored_established != established_text:
        raise HypothesisValidationError("schema")

    config_text = configuration.text if configuration and configuration.text else None
    config_refs = list(configuration.refs) if config_text else []

    if stored_configuration is not None and stored_configuration != config_text:
        raise HypothesisValidationError("schema")

    try:
        return AIHypothesis(
            explanation=explanation,
            status="unverified",
            reported=attributed,
            possible_explanation=possible,
            not_yet_verified=not_verified,
            evidence_refs=list(evidence),
            resource=resource,
            verification_check=None if withheld else check,
            check_withheld_reason=withheld,
            independently_established=established_text,
            established_refs=established_refs,
            configuration_context=config_text,
            configuration_refs=config_refs,
        )
    except ValidationError:
        raise HypothesisValidationError("schema") from None


def _is_log_ref(reference: object) -> bool:
    return isinstance(reference, str) and reference.startswith("log-")


def _is_duplicate(hypothesis: AIHypothesis, seen: set[str]) -> bool:
    """Same explanation wording as one already accepted in this response."""
    key = _normalize(hypothesis.possible_explanation)

    if key in seen:
        return True

    seen.add(key)

    return False


def parse_hypothesis_response(
    content: str,
    *,
    registry: HypothesisEvidenceRegistry,
    expected_investigation_id: str,
) -> HypothesisBatch:
    """Parse and validate a raw model response.

    Provenance/security failures reject everything. Wording failures omit only
    the offending hypothesis and are counted."""
    if not isinstance(content, str) or len(content) > MAX_RESPONSE_CHARS:
        raise HypothesisValidationError("response_size")

    try:
        payload = json.loads(content)
    except (json.JSONDecodeError, RecursionError):
        raise HypothesisValidationError("malformed_json") from None

    if not isinstance(payload, dict):
        raise HypothesisValidationError("malformed_json")

    # Any extra key (findings, status, severity, ...) is rejected outright.
    if set(payload) != {"investigation_id", "hypotheses"}:
        raise HypothesisValidationError("unexpected_fields")

    if payload["investigation_id"] != expected_investigation_id:
        raise HypothesisValidationError("cross_investigation")

    items = payload["hypotheses"]

    if not isinstance(items, list) or len(items) > MAX_HYPOTHESES:
        raise HypothesisValidationError("hypothesis_count")

    hypotheses: list[AIHypothesis] = []
    omitted = 0
    reasons: dict[str, int] = {}
    seen: set[str] = set()

    for item in items:
        try:
            parsed = _ModelHypothesis.model_validate(item)
        except ValidationError:
            # Covers smuggled keys such as status/severity/findings.
            raise HypothesisValidationError("schema") from None

        try:
            validated = validate_hypothesis_fields(
                reported=parsed.reported,
                possible_explanation=parsed.possible_explanation,
                not_yet_verified=parsed.not_yet_verified,
                evidence=parsed.evidence,
                declared_resource=(
                    parsed.resource.model_dump() if parsed.resource else None
                ),
                verification_check=parsed.verification_check,
                registry=registry,
            )
        except HypothesisToneError as exc:
            omitted += 1
            reasons[exc.code] = reasons.get(exc.code, 0) + 1
            continue

        if _is_duplicate(validated, seen):
            omitted += 1
            reasons["duplicate_hypothesis"] = (
                reasons.get("duplicate_hypothesis", 0) + 1
            )
            continue

        hypotheses.append(validated)

    return HypothesisBatch(
        hypotheses=hypotheses, omitted=omitted, omission_reasons=reasons
    )


def revalidate_hypotheses(
    hypotheses: Iterable[AIHypothesis],
    *,
    registry: HypothesisEvidenceRegistry,
) -> HypothesisBatch:
    """Independently re-check hypotheses from ANY provider implementation."""
    validated: list[AIHypothesis] = []
    omitted = 0
    reasons: dict[str, int] = {}
    seen: set[str] = set()

    for h in hypotheses:
        try:
            checked = validate_hypothesis_fields(
                reported=h.reported,
                possible_explanation=h.possible_explanation,
                not_yet_verified=h.not_yet_verified,
                evidence=list(h.evidence_refs),
                declared_resource=h.resource.model_dump(),
                verification_check=h.verification_check,
                registry=registry,
                stored_explanation=h.explanation,
                stored_established=h.independently_established,
                stored_configuration=h.configuration_context,
                stored_check_withheld=h.check_withheld_reason,
            )
        except HypothesisToneError as exc:
            omitted += 1
            reasons[exc.code] = reasons.get(exc.code, 0) + 1
            continue

        if _is_duplicate(checked, seen):
            omitted += 1
            reasons["duplicate_hypothesis"] = (
                reasons.get("duplicate_hypothesis", 0) + 1
            )
            continue

        validated.append(checked)

    if len(validated) + omitted > MAX_HYPOTHESES:
        raise HypothesisValidationError("hypothesis_count")

    return HypothesisBatch(
        hypotheses=validated, omitted=omitted, omission_reasons=reasons
    )
