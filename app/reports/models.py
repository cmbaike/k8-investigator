from typing import Literal

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Fixed vocabulary for per-hypothesis omission diagnostics (wording failures).
OMISSION_REASON_CODES = frozenset(
    {
        "unattributed_log_claim",
        "reported_without_log_evidence",
        "verified_claim",
        "insufficiently_cautious",
        "too_long",
        # Wording contradicts configuration/startup evidence the application
        # established independently, or overstates what its absence proves.
        "contradicts_established_evidence",
        "overstated_absence",
        # Recommended check targets ConfigMaps/Secrets the spec never references.
        "check_contradicts_evidence",
        # Repeats another hypothesis of the same response (same explanation).
        "duplicate_hypothesis",
        # Describes a container that Kubernetes reports never started as if it
        # had run (crashed, exited, logged).
        "contradicts_container_state",
        # Cites more evidence than the per-hypothesis limit. The references
        # themselves were all valid; only this hypothesis is omitted.
        "too_many_references",
        # A "log claim" that is really a Kubernetes state or event (or any
        # claim carrying the name of a source it did not come from).
        "misattributed_source",
        # Names a specific probe path/port/status code, or asserts what
        # events show, with no cited evidence that supplies it.
        "unsupported_specific_claim",
        # Attributes a taint to a pod, or a toleration to a node (Kubernetes:
        # nodes have taints, pods have tolerations). Applies to the
        # explanation and to the recommended check.
        "inverted_scheduling_terms",
        # Other high-confidence Kubernetes-semantics errors (node requests,
        # a memory limit as the scheduling basis, a readiness failure that
        # restarts a container, a cluster-scoped object in a namespace).
        "incorrect_kubernetes_semantics",
        # Asserts a cause the evidence does not establish: the image "does not
        # exist", or one scheduler constraint as the only cause while several
        # were reported.
        "unsupported_causal_certainty",
        # The recommended check advises an action on the cluster instead of an
        # inspection (read-only diagnostics only).
        "remediation_in_check",
        # The recommended check names a namespace, pod or container other
        # than the investigated one.
        "check_out_of_scope",
    }
)


class StrictReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceReference(StrictReportModel):
    evidence_id: str = Field(pattern=r"^ev-[0-9]{4}$")


# Fixed vocabulary of scheduler constraints the application classifies from a
# scheduler status message (see app.tools.event_signals). The label is written
# here, never taken from the message, and is the only text a viewer needs.
# Display order: resources first, then taints, then the rest.
SCHEDULING_CONSTRAINT_LABELS: dict[str, str] = {
    "insufficient_cpu": "Insufficient CPU",
    "insufficient_memory": "Insufficient memory",
    "untolerated_taint": "Untolerated node taints",
    "insufficient_ephemeral_storage": "Insufficient ephemeral storage",
    "too_many_pods": "Node pod limit reached",
    "node_selector_mismatch": "Node selector or affinity mismatch",
    "pod_affinity_mismatch": "Pod affinity or topology-spread mismatch",
    "node_unschedulable": "Nodes marked unschedulable",
    "unbound_volume_claim": "Unbound or missing PersistentVolumeClaim",
    "volume_node_conflict": "Volume node-affinity conflict",
}


class SchedulingConstraint(StrictReportModel):
    """One scheduler constraint Kubernetes reported for an unschedulable pod.

    APPLICATION-authored from validated, fixed-vocabulary signals; never model
    or event-message text. `evidence_ids` are the signal observations that
    establish it, and must be among the finding's own evidence."""

    signal: str
    label: str = Field(min_length=1, max_length=80)
    evidence_ids: list[str] = Field(min_length=1, max_length=4)

    @model_validator(mode="after")
    def _fixed_vocabulary(self) -> "SchedulingConstraint":
        if SCHEDULING_CONSTRAINT_LABELS.get(self.signal) != self.label:
            raise ValueError("Unknown scheduling constraint or label.")

        if not all(re.fullmatch(r"ev-[0-9]{4}", ref) for ref in self.evidence_ids):
            raise ValueError("evidence_ids must be ev-NNNN references.")

        return self


class InvestigationFinding(StrictReportModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2000)
    severity: Literal["info", "warning", "critical", "unknown"]
    evidence: list[EvidenceReference] = Field(min_length=1)
    # Structured, validated scheduler constraints (unschedulable pods only).
    scheduling_constraints: list[SchedulingConstraint] = Field(
        default_factory=list, max_length=len(SCHEDULING_CONSTRAINT_LABELS)
    )

    @model_validator(mode="after")
    def _constraints_rest_on_the_finding_evidence(self) -> "InvestigationFinding":
        cited = {reference.evidence_id for reference in self.evidence}
        signals = [c.signal for c in self.scheduling_constraints]

        if len(set(signals)) != len(signals):
            raise ValueError("Duplicate scheduling constraint.")

        for constraint in self.scheduling_constraints:
            if not set(constraint.evidence_ids) <= cited:
                raise ValueError("Constraint cites evidence outside the finding.")

        return self


class HypothesisResource(StrictReportModel):
    """Resource identity DERIVED by the application from cited evidence."""

    namespace: str = Field(min_length=1, max_length=253)
    pod: str | None = Field(default=None, min_length=1, max_length=253)
    container: str | None = Field(default=None, min_length=1, max_length=253)


class AIHypothesis(StrictReportModel):
    """An unverified, model-generated diagnostic interpretation.

    Never a finding. A valid citation establishes provenance, not the truth of
    the explanation. There is deliberately no confidence field: confidence
    calibration has not been established.

    The epistemic parts are stored separately and `explanation` is COMPOSED by
    the application from them, with fixed attribution and disclaimer wording:
      * `reported`            - what the application's own logs say (an
                                attributed paraphrase, never a verified fact);
      * `possible_explanation`- a tentative interpretation (hedged);
      * `not_yet_verified`    - what remains uncorroborated.
    """

    explanation: str = Field(min_length=1, max_length=1200)
    status: Literal["unverified"] = "unverified"
    reported: str | None = Field(default=None, min_length=1, max_length=200)
    possible_explanation: str = Field(min_length=1, max_length=300)
    not_yet_verified: str = Field(min_length=1, max_length=400)
    # `ev-NNNN` (verified observation) or `log-NNNN` (untrusted log excerpt).
    evidence_refs: list[str] = Field(min_length=1, max_length=6)
    resource: HypothesisResource
    # A read-only check the model recommended, or None when the application
    # withheld it (it was technically wrong, an action instead of an
    # inspection, or aimed outside the investigated resource). The check is
    # never edited: it is shown as written or not at all.
    verification_check: str | None = Field(default=None, min_length=1, max_length=300)
    # Fixed code (an OMISSION_REASON_CODES value) saying why the check was
    # withheld; set exactly when `verification_check` is None.
    check_withheld_reason: str | None = Field(default=None, max_length=60)
    # APPLICATION-authored, never model text: facts independently established
    # from verified evidence (Kubernetes + static analysis) about the same
    # resource, shown beside the hypothesis so a model's explanation is never
    # the only statement about it. Cited by `established_refs` (ev-NNNN).
    independently_established: str | None = Field(
        default=None, min_length=1, max_length=700
    )
    established_refs: list[str] = Field(default_factory=list, max_length=3)
    # APPLICATION-authored statement of what the workload spec DECLARES
    # (variables and ConfigMap/Secret sources), with an explicit note that it
    # does not establish the complete runtime environment. Kept separate from
    # `reported` (application-claimed requirements) and from
    # `independently_established` (termination behaviour).
    configuration_context: str | None = Field(
        default=None, min_length=1, max_length=1000
    )
    configuration_refs: list[str] = Field(default_factory=list, max_length=6)

    @model_validator(mode="after")
    def _check_is_present_or_explained(self) -> "AIHypothesis":
        if (self.verification_check is None) != (self.check_withheld_reason is not None):
            raise ValueError("A withheld check needs a reason, and only then.")

        if (
            self.check_withheld_reason is not None
            and self.check_withheld_reason not in OMISSION_REASON_CODES
        ):
            raise ValueError("Unknown check withheld reason.")

        return self

    @field_validator("established_refs", "configuration_refs")
    @classmethod
    def _established_refs_are_evidence(cls, value: list[str]) -> list[str]:
        import re

        if not all(re.fullmatch(r"ev-[0-9]{4}", ref) for ref in value):
            raise ValueError("established_refs must be ev-NNNN references.")

        return value


class AIAnalysisStatus(StrictReportModel):
    """Bounded, non-sensitive disclosure about the optional AI stage.

    Contains only application-controlled values; never model or log text.
    """

    # generated:     attempted, at least one hypothesis accepted
    # all_omitted:   attempted, hypotheses were proposed, none passed validation
    # none_proposed: attempted, the model proposed no hypotheses
    # unavailable:   attempted, the stage failed as a whole (see `reason`)
    # not_attempted: not run
    state: Literal[
        "generated", "all_omitted", "none_proposed", "unavailable", "not_attempted"
    ]
    reason: Literal[
        "timeout",
        "provider_error",
        "malformed_response",
        "validation_failed",
        "no_evidence",
    ] | None = None
    message: str = Field(min_length=1, max_length=200)
    log_excerpts_used: int = Field(default=0, ge=0, le=100)
    log_excerpts_omitted: int = Field(default=0, ge=0, le=1000)
    # Proposed hypotheses dropped because their wording could not be validated
    # as sufficiently cautious. Never replaced by weaker wording.
    hypotheses_omitted: int = Field(default=0, ge=0, le=10)
    # Total proposed by the model (accepted + omitted). Count only.
    hypotheses_proposed: int = Field(default=0, ge=0, le=10)
    # Bounded diagnostics: fixed category -> count. Never rejected text.
    omission_reasons: dict[str, int] = Field(default_factory=dict, max_length=8)
    # Failure class when the whole response was rejected (reason ==
    # validation_failed): provenance, security or structure.
    rejection_category: Literal["provenance", "security", "structure"] | None = None

    @field_validator("omission_reasons")
    @classmethod
    def _bounded_reason_codes(cls, value: dict[str, int]) -> dict[str, int]:
        for code, count in value.items():
            if code not in OMISSION_REASON_CODES:
                raise ValueError("Unknown omission reason code.")

            if type(count) is not int or not 1 <= count <= 10:
                raise ValueError("Omission count out of range.")

        return value


class DiagnosticCheck(StrictReportModel):
    """A recommended check placed on the resource it was written for."""

    text: str = Field(min_length=1, max_length=4000)
    source: Literal["hypothesis", "report"]
    hypothesis_index: int | None = Field(default=None, ge=0, le=4)
    pod: str | None = Field(default=None, min_length=1, max_length=253)
    container: str | None = Field(default=None, min_length=1, max_length=253)


class DiagnosticFinding(StrictReportModel):
    """Index into the report's findings, plus the single pod it cites, if any."""

    index: int = Field(ge=0)
    pod: str | None = Field(default=None, min_length=1, max_length=253)


class DiagnosticResource(StrictReportModel):
    """One workload, or one pod whose owner was not verified."""

    namespace: str = Field(min_length=1, max_length=253)
    kind: Literal[
        "Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet", "Pod"
    ]
    name: str = Field(min_length=1, max_length=253)
    ownership: Literal["verified", "unresolved"]
    pods: list[str] = Field(default_factory=list, max_length=100)
    findings: list[DiagnosticFinding] = Field(default_factory=list, max_length=100)
    hypothesis_indexes: list[int] = Field(default_factory=list, max_length=5)
    checks: list[DiagnosticCheck] = Field(default_factory=list, max_length=20)
    # established: describe_pod succeeded. unknown: listed, not inspected.
    # failed: inspection was attempted and did not succeed.
    coverage: Literal["established", "unknown", "failed"] = "established"
    deeply_investigated: bool = False


class NamespaceDiagnostic(StrictReportModel):
    """Resource-grouped view of a namespace-wide investigation.

    Built from evidence identity and verified owner references. Empty when the
    investigation was about one workload.
    """

    listed_pods: int = Field(ge=0)
    inspected_pods: int = Field(ge=0)
    uninspected_pods: int = Field(default=0, ge=0)
    unsuccessful_pods: int = Field(default=0, ge=0)
    listing_truncated: bool = False
    # False when listed pods were not all health-inspected, an inspection
    # failed, or the listing stopped at one API page. None on reports stored
    # before this was recorded. Execution can still have finished.
    assessment_complete: bool | None = None
    resources: list[DiagnosticResource] = Field(default_factory=list, max_length=100)
    shared_findings: list[DiagnosticFinding] = Field(
        default_factory=list, max_length=100
    )
    shared_hypothesis_indexes: list[int] = Field(default_factory=list, max_length=5)
    shared_checks: list[DiagnosticCheck] = Field(default_factory=list, max_length=20)


class InvestigationReport(StrictReportModel):
    investigation_id: str = Field(min_length=1)
    summary: str = Field(min_length=1, max_length=3000)
    findings: list[InvestigationFinding] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list, max_length=20)
    suggested_checks: list[str] = Field(default_factory=list, max_length=20)

    # Optional AI enrichment, kept apart from deterministic `findings`.
    ai_hypotheses: list[AIHypothesis] = Field(default_factory=list, max_length=5)
    ai_analysis: AIAnalysisStatus | None = None
    # Present only for a namespace-wide investigation. Older reports omit it.
    namespace_diagnostic: NamespaceDiagnostic | None = None

    @model_validator(mode="after")
    def _diagnostic_indexes_fit(self) -> "InvestigationReport":
        diagnostic = self.namespace_diagnostic

        if diagnostic is None:
            return self

        finding_count = len(self.findings)
        hypothesis_count = len(self.ai_hypotheses)

        def check_findings(items: list[DiagnosticFinding]) -> None:
            indexes = [item.index for item in items]

            if len(indexes) != len(set(indexes)):
                raise ValueError("A diagnostic finding is listed twice.")

            if any(index >= finding_count for index in indexes):
                raise ValueError("Diagnostic finding index is outside the report.")

        def check_hypotheses(indexes: list[int]) -> None:
            if len(indexes) != len(set(indexes)):
                raise ValueError("A diagnostic hypothesis is listed twice.")

            if any(index >= hypothesis_count for index in indexes):
                raise ValueError("Diagnostic hypothesis index is outside the report.")

        seen_findings: set[int] = set()
        seen_hypotheses: set[int] = set()

        for resource in diagnostic.resources:
            check_findings(resource.findings)
            check_hypotheses(resource.hypothesis_indexes)
            resource_findings = {item.index for item in resource.findings}

            if seen_findings & resource_findings:
                raise ValueError("A finding is listed on more than one resource.")

            if seen_hypotheses & set(resource.hypothesis_indexes):
                raise ValueError("A hypothesis is listed on more than one resource.")

            seen_findings.update(resource_findings)
            seen_hypotheses.update(resource.hypothesis_indexes)

        check_findings(diagnostic.shared_findings)
        check_hypotheses(diagnostic.shared_hypothesis_indexes)

        if seen_findings & {item.index for item in diagnostic.shared_findings}:
            raise ValueError("A finding is both grouped and shared.")

        if seen_hypotheses & set(diagnostic.shared_hypothesis_indexes):
            raise ValueError("A hypothesis is both grouped and shared.")

        return self
