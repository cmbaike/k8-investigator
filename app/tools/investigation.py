"""Namespace-scoped, bounded investigation state."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import Iterator

from app.tools.investigation_authority import InvestigationKind
from app.tools.log_context import (
    MAX_LOG_CONTEXT_TOTAL_BYTES,
    MAX_LOG_EXCERPT_BYTES,
    MAX_LOG_ENTRIES,
    LogContextEntry,
    build_log_context_entry,
)
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.proposal_rejection import (
    MAX_REJECTED_PROPOSALS,
    REJECTION_REASONS,
    RejectedProposal,
    safe_proposal_arguments,
)
from app.tools.workload_target import (
    PodOwner,
    TargetResolution,
    WorkloadTarget,
    call_outside_target,
    listed_pod_names,
    pod_owners_from_listing,
    resolve_target,
)
from app.tools.observations import (
    LOG_TOOLS,
    TrustedToolObservation,
    observations_from_execution,
    validated_log_output,
)


class InvestigationStepLimitError(RuntimeError):
    pass


class InvestigationScopeError(ValueError):
    pass


class TargetScopeError(InvestigationScopeError):
    """A call would inspect something other than the bound workload.

    Distinct from a namespace violation: the namespace was authorized, the
    call is simply not about the requested workload. `reason` is one of
    proposal_rejection.REJECTION_REASONS. Such a proposal is rejected and
    audited without aborting the investigation."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Tool call is outside the requested workload ({reason}).")
        self.reason = reason


class InvestigationConcurrentExecutionError(RuntimeError):
    """Another execution already owns this investigation context."""


class InvestigationConcurrentRunError(RuntimeError):
    """Another controller already owns this investigation run."""
    
class InvestigationDuplicateRequestError(ValueError):
    """An execution request ID was already recorded."""    
    


@dataclass(frozen=True)
class InvestigationContext:
    """Authority-bearing fields are immutable; state changes through record_execution.

    Construct using trusted application code. A lease serializes orchestrated
    executions within this Python process; it is not distributed coordination.
    """

    investigation_id: str
    user_text: str
    max_steps: int = 6
    authorized_namespace: str | None = None
    # Bound by the application, before any model is invoked, from the
    # authenticated investigation request. When set, tool authority comes from
    # this field and NOT from re-reading `user_text`. Contexts built without it
    # (legacy / explicit-operation callers) keep text-derived authority.
    investigation_kind: InvestigationKind | None = None
    # The workload the question explicitly names, bound by the application
    # before any model runs. None means a broad, namespace-level investigation.
    target: WorkloadTarget | None = None
    # With no target: True when the question explicitly asked about the
    # namespace as a whole, False when no resource identity was recognised.
    # Disclosure only; it grants no authority.
    broad_scope_explicit: bool = False
    # Namespace-wide runs inspect basic pod health before the model spends
    # the step budget. Targeted runs leave this false.
    namespace_health_discovery: bool = False

    _pod_owners: dict[str, PodOwner] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _observations: list[TrustedToolObservation] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _completed_steps: int = field(default=0, init=False, repr=False, compare=False)
    # describe_pod outcomes that did not mint evidence ("failed"). Successful
    # inspections are also recorded so a later failure cannot overwrite them.
    _health_outcomes: dict[str, str] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _execution_lock: Lock = field(default_factory=Lock, init=False, repr=False, compare=False)
    _run_lock: Lock = field(default_factory=Lock, init=False, repr=False, compare=False)

    # Model proposals refused at target validation: fixed reason codes and
    # counts only. `_unaudited_rejections` holds those refused BEFORE the
    # execution boundary (by the coverage policy) until the controller has
    # written their audit events.
    _rejection_counts: dict[str, int] = field(
        default_factory=dict, init=False, repr=False, compare=False
    )
    _unaudited_rejections: list[RejectedProposal] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    
    
    _recorded_request_ids: set[str] = field(
        default_factory=set,
        init=False,
        repr=False,
        compare=False,
    )

    # Bounded, UNTRUSTED, in-memory log excerpts. Deliberately separate from
    # `_observations` so log text can never enter the evidence snapshot,
    # a persisted report, or an audit event.
    _log_entries: list[LogContextEntry] = field(
        default_factory=list, init=False, repr=False, compare=False
    )
    _log_bytes_used: int = field(default=0, init=False, repr=False, compare=False)
    _log_entries_omitted: int = field(default=0, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not self.investigation_id:
            raise ValueError("Investigation ID is required.")
        if not self.user_text:
            raise ValueError("Original user request is required.")
        if not 1 <= self.max_steps <= 10:
            raise ValueError("Investigation step budget must be between 1 and 10.")

    @contextmanager
    def run_lease(self) -> Iterator[None]:
        """Own a complete multi-step run, including provider calls.

        This lock is separate from execution_lease so each step can acquire
        the existing single-flight execution boundary without deadlocking.
        """
        if not self._run_lock.acquire(blocking=False):
            raise InvestigationConcurrentRunError(
                f"Investigation {self.investigation_id!r} already has an active run."
            )
        try:
            yield
        finally:
            self._run_lock.release()

    @contextmanager
    def execution_lease(self) -> Iterator[None]:
        """Reject overlapping orchestrated executions without waiting.

        Lease must encompass authorization, pre-dispatch audit, executor,
        recording and completion audit. Always releases on exceptions.
        """
        if not self._execution_lock.acquire(blocking=False):
            raise InvestigationConcurrentExecutionError(
                f"Investigation {self.investigation_id!r} already has an active execution."
            )
        try:
            yield
        finally:
            self._execution_lock.release()

    @property
    def completed_steps(self) -> int:
        return self._completed_steps

    @property
    def observations(self) -> tuple[TrustedToolObservation, ...]:
        return tuple(self._observations)

    @property
    def has_step_budget(self) -> bool:
        return self._completed_steps < self.max_steps

    def require_authorized_namespace(self) -> str:
        if not self.authorized_namespace:
            raise InvestigationScopeError("Investigation has no authorized namespace.")
        return self.authorized_namespace

    def validate_execution_scope(self, call: ToolCall) -> None:
        expected = self.require_authorized_namespace()
        actual = call.arguments.get("namespace")
        if not isinstance(actual, str) or actual != expected:
            raise InvestigationScopeError(
                "Executed tool namespace is outside the authorized investigation scope."
            )

    @property
    def target_resolution(self) -> TargetResolution | None:
        """Where the bound target resolves, from application-recorded data
        (the namespace listing and verified owners). None when untargeted."""
        if self.target is None:
            return None

        return resolve_target(
            self.target, listed_pod_names(self._observations), self._pod_owners
        )

    def in_target_scope(self, pod: str | None) -> bool:
        """Whether evidence about `pod` belongs in this investigation's scope.

        Untargeted: everything. Targeted: only the resolved workload's pods
        (and evidence that names no pod)."""
        resolution = self.target_resolution

        if resolution is None or pod is None:
            return True

        return resolution.resolved and pod in resolution.pods

    def validate_target_scope(self, call: ToolCall) -> None:
        """Reject a call that would inspect anything but the bound target."""
        resolution = self.target_resolution

        if resolution is None:
            return

        reason = call_outside_target(call.name, call.arguments, resolution)

        if reason is not None:
            raise TargetScopeError(reason)

    # ---------------------------------------------------- rejected proposals

    @property
    def rejected_proposal_count(self) -> int:
        return sum(self._rejection_counts.values())

    @property
    def rejected_proposal_reasons(self) -> tuple[str, ...]:
        """Distinct fixed reason codes seen, sorted."""
        return tuple(sorted(self._rejection_counts))

    @property
    def rejection_limit_reached(self) -> bool:
        return self.rejected_proposal_count >= MAX_REJECTED_PROPOSALS

    def note_rejected_proposal(
        self, call: ToolCall, reason: str, *, audited: bool
    ) -> RejectedProposal:
        """Count one refused proposal (it was NOT executed).

        `audited` is True when the execution boundary already wrote its
        proposed/rejected events; otherwise the record waits in
        `drain_unaudited_rejections` for the controller to write them."""
        if reason not in REJECTION_REASONS:
            raise ValueError("Unknown proposal rejection reason.")

        self._rejection_counts[reason] = self._rejection_counts.get(reason, 0) + 1
        rejection = RejectedProposal(
            ordinal=self.rejected_proposal_count,
            tool=call.name,
            arguments=safe_proposal_arguments(call.arguments),
            reason=reason,
        )

        if not audited:
            self._unaudited_rejections.append(rejection)

        return rejection

    def drain_unaudited_rejections(self) -> tuple[RejectedProposal, ...]:
        pending = tuple(self._unaudited_rejections)
        self._unaudited_rejections.clear()

        return pending

    @property
    def health_outcomes(self) -> dict[str, str]:
        """pod name -> 'inspected' or 'failed' for describe_pod attempts."""
        return dict(self._health_outcomes)

    def record_execution(
        self,
        *,
        request_id: str,
        call: ToolCall,
        result: ToolExecutionResult,
        consume_step: bool = True,
    ) -> tuple[TrustedToolObservation, ...]:
        """Record scoped execution. Failed executions consume budget, not trust.

        `consume_step` is false for the namespace health-discovery pass. Those
        calls are still authorized, audited and recorded; they do not spend the
        step budget the diagnostic analysis uses.

        Direct calls are retained for existing tests; production execution must
        go through the orchestrator while holding the execution lease.
        """
        if consume_step and not self.has_step_budget:
            raise InvestigationStepLimitError(
                f"Investigation {self.investigation_id!r} "
                f"has reached its {self.max_steps}-step limit."
            )
        self.validate_execution_scope(call)
        self.validate_target_scope(call)
        if request_id in self._recorded_request_ids:
           raise InvestigationDuplicateRequestError(
              f"Execution request {request_id!r} "
              f"was already recorded in investigation "
              f"{self.investigation_id!r}."
        )
        #object.__setattr__(self, "_completed_steps", self._completed_steps + 1)
        minted = observations_from_execution(request_id=request_id, call=call, result=result)
        self._recorded_request_ids.add(request_id)
        if consume_step:
            object.__setattr__(
                 self,
                 "_completed_steps",
                 self._completed_steps + 1,
            )
        if call.name == "k8s.describe_pod":
            pod = call.arguments.get("pod")
            if isinstance(pod, str) and pod and pod not in self._health_outcomes:
                self._health_outcomes[pod] = (
                    "inspected"
                    if result.status == ToolExecutionStatus.SUCCESS
                    else "failed"
                )
        self._observations.extend(minted)

        if call.name == "k8s.get_pods" and result.status == ToolExecutionStatus.SUCCESS:
            self._pod_owners.update(
                pod_owners_from_listing(
                    namespace=call.arguments.get("namespace"),
                    output=result.output,
                )
            )

        self._record_log_context(request_id=request_id, call=call, result=result)
        return tuple(minted)

    def _record_log_context(
        self, *, request_id: str, call: ToolCall, result: ToolExecutionResult
    ) -> None:
        """Capture one bounded, sanitized, identity-checked log excerpt.

        Only strictly validated log retrievals are eligible. Capacity
        exhaustion is counted so the report can disclose omitted context.
        """
        if call.name not in LOG_TOOLS:
            return

        remaining = MAX_LOG_CONTEXT_TOTAL_BYTES - self._log_bytes_used

        if len(self._log_entries) >= MAX_LOG_ENTRIES or remaining <= 0:
            if validated_log_output(call, result) is not None:
                object.__setattr__(
                    self, "_log_entries_omitted", self._log_entries_omitted + 1
                )
            return

        entry = build_log_context_entry(
            log_ref=f"log-{len(self._log_entries) + 1:04d}",
            request_id=request_id,
            call=call,
            result=result,
            byte_budget=remaining,
        )

        if entry is None:
            # Distinguish "nothing usable in the logs" from "the registry's
            # remaining byte budget was too small": the latter is disclosed.
            if remaining < MAX_LOG_EXCERPT_BYTES and build_log_context_entry(
                log_ref="log-0000",
                request_id=request_id,
                call=call,
                result=result,
                byte_budget=MAX_LOG_EXCERPT_BYTES,
            ) is not None:
                object.__setattr__(
                    self, "_log_entries_omitted", self._log_entries_omitted + 1
                )
            return

        self._log_entries.append(entry)
        object.__setattr__(
            self, "_log_bytes_used", self._log_bytes_used + entry.bytes_included
        )

    @property
    def log_entries(self) -> tuple[LogContextEntry, ...]:
        """Untrusted, in-memory excerpts. Never persist or log these."""
        return tuple(self._log_entries)

    @property
    def log_entries_omitted(self) -> int:
        return self._log_entries_omitted

    def find_log_entry(self, log_ref: str) -> LogContextEntry | None:
        return next((e for e in self._log_entries if e.log_ref == log_ref), None)

    def find_observations(
        self, *, tool: str | None = None, field: str | None = None,
        value: str | int | None = None,
    ) -> tuple[TrustedToolObservation, ...]:
        return tuple(
            observation for observation in self._observations
            if (tool is None or observation.tool == tool)
            and (field is None or observation.field == field)
            and (value is None or observation.value == value)
        )
