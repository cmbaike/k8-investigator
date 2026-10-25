from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.reports.evidence import ReportEvidence, build_report_evidence
from app.tools.investigation import InvestigationContext
from app.tools.workload_target import TargetStatus, listed_pod_names


class SnapshotScope(BaseModel):
    """What the investigation was asked to cover and what it actually covered.

    Application-derived. `mode` is "namespace" for a broad question and
    "workload" when the question named a target (bound by the application)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    mode: Literal["namespace", "workload"]
    requested: str | None = Field(default=None, max_length=63)
    requested_kind: str | None = Field(default=None, max_length=30)
    status: Literal[
        "not_applicable", "unresolved", "resolved", "not_found", "ambiguous",
        "unverifiable",
    ] = "not_applicable"
    workload_kind: str | None = Field(default=None, max_length=30)
    workload_name: str | None = Field(default=None, max_length=253)
    pods: tuple[str, ...] = Field(default=(), max_length=20)
    listed: int = Field(default=0, ge=0)
    inspected: int = Field(default=0, ge=0)
    # Listed pods with no successful describe. Not healthy.
    uninspected: int = Field(default=0, ge=0)
    # describe_pod was attempted and did not succeed. Not healthy.
    unsuccessful: int = Field(default=0, ge=0)
    uninspected_pods: tuple[str, ...] = Field(default=(), max_length=20)
    unsuccessful_pods: tuple[str, ...] = Field(default=(), max_length=20)
    listing_truncated: bool = False
    # Pods that received logs, events, or workload configuration after describe.
    deeply_investigated: int = Field(default=0, ge=0)
    unverified: int = Field(default=0, ge=0)
    # Namespace mode only: True when the question asked about the namespace as
    # a whole, False when no resource identity was recognised in it.
    broad_explicit: bool = False
    # Model proposals refused for falling outside the bound workload. They were
    # recorded in the audit trail and never executed. Fixed reason codes only.
    rejected_proposals: int = Field(default=0, ge=0, le=100)
    rejected_reasons: tuple[str, ...] = Field(default=(), max_length=5)

    @property
    def targeted(self) -> bool:
        return self.mode == "workload"

    @property
    def resolved(self) -> bool:
        return self.status == TargetStatus.RESOLVED.value


class InvestigationEvidenceSnapshot(BaseModel):
    """Application-created evidence snapshot for one investigation."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    truncated: bool = False
    scope: SnapshotScope | None = None

    investigation_id: str = Field(min_length=1)
    evidence: tuple[ReportEvidence, ...] = Field(max_length=100)

    @model_validator(mode="after")
    def validate_unique_evidence_ids(self):
        ids = [item.evidence_id for item in self.evidence]

        if len(ids) != len(set(ids)):
            raise ValueError("Evidence snapshot contains duplicate identifiers.")

        return self


def build_investigation_evidence_snapshot(
    context: InvestigationContext,
) -> InvestigationEvidenceSnapshot:
    """Capture trusted observations and disclose evidence truncation."""

    evidence = build_report_evidence(context)
    resolution = context.target_resolution
    # The listing observation carries the pod's name as its VALUE.
    listed = {
        name for name in listed_pod_names(context.observations)
        if context.in_target_scope(name)
    }
    inspected = {o.pod for o in context.observations
                 if o.tool == "k8s.describe_pod" and o.pod and context.in_target_scope(o.pod)}
    outcomes = getattr(context, "health_outcomes", {}) or {}
    unsuccessful_names = sorted(
        pod for pod in listed
        if pod not in inspected and outcomes.get(pod) == "failed"
    )
    uninspected_names = sorted(
        pod for pod in listed
        if pod not in inspected and pod not in set(unsuccessful_names)
    )
    deep_tools = {
        "k8s.get_logs", "k8s.get_previous_logs", "k8s.get_events",
        "k8s.describe_workload_config",
    }
    deep_pods = {
        o.pod for o in context.observations
        if o.tool in deep_tools and o.pod and o.pod in inspected
    }
    listing_truncated = any(
        o.tool == "k8s.get_pods" and o.field == "listing.truncated" and o.value is True
        for o in context.observations
    )
    coverage = {
        "uninspected": len(uninspected_names),
        "unsuccessful": len(unsuccessful_names),
        "uninspected_pods": tuple(uninspected_names[:20]),
        "unsuccessful_pods": tuple(unsuccessful_names[:20]),
        "listing_truncated": listing_truncated,
        "deeply_investigated": len(deep_pods),
    }

    rejections = {
        "rejected_proposals": min(context.rejected_proposal_count, 100),
        "rejected_reasons": context.rejected_proposal_reasons,
    }

    if context.target is None:
        scope = SnapshotScope(
            mode="namespace",
            listed=len(listed),
            inspected=len(inspected),
            broad_explicit=context.broad_scope_explicit,
            **coverage,
            **rejections,
        )
    else:
        scope = SnapshotScope(
            mode="workload",
            requested=context.target.name,
            requested_kind=context.target.kind,
            status=resolution.status.value,
            workload_kind=resolution.workload_kind,
            workload_name=resolution.workload_name,
            pods=resolution.pods[:20],
            listed=resolution.listed,
            inspected=len(inspected),
            unverified=resolution.unverified,
            **coverage,
            **rejections,
        )

    eligible_count = sum(
        1
        for observation in context.observations
        if context.in_target_scope(observation.pod)
        and type(observation.value) in (
            str,
            int,
            float,
            bool,
            type(None),
        )
    )

    return InvestigationEvidenceSnapshot(
        investigation_id=context.investigation_id,
        evidence=evidence,
        truncated=eligible_count > len(evidence),
        scope=scope,
    )