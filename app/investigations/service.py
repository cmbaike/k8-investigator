"""Application-owned investigation lifecycle orchestration."""

from collections.abc import Callable
from dataclasses import dataclass

from app.investigations.heartbeat import (
    InvestigationLeaseHeartbeat,
    InvestigationLeaseLostError,
)
from app.investigations.models import InvestigationRecord
from app.investigations.repository import (
    InvestigationRepository,
    InvestigationTransitionError,
)
from app.reports.enrichment import HypothesisProvider, add_ai_hypotheses
from app.reports.grounding import build_grounded_report
from app.reports.resource_groups import attach_namespace_diagnostic
from app.reports.models import InvestigationReport
from app.reports.snapshot import build_investigation_evidence_snapshot
from app.tools.executor import execute_tool_call
from app.tools.investigation import InvestigationContext
from app.tools.investigation_controller import (
    InvestigationRunResult,
    InvestigationStopReason,
    ProposalProvider,
    run_investigation,
)
from app.tools.orchestrator import AuditSink, Executor
from app.tools.investigation_scope import (
    InvestigationScopeCreationError,
    create_bound_investigation_context,
)


@dataclass(frozen=True)
class InvestigationServiceResult:
    record: InvestigationRecord
    report: InvestigationReport | None
    run: InvestigationRunResult

class InvestigationService:
    def __init__(
        self,
        *,
        repository: InvestigationRepository,
        provider: ProposalProvider,
        audit: AuditSink,
        executor: Executor = execute_tool_call,
        lease_seconds: int = 120,
        runner: Callable = run_investigation,
        heartbeat_interval_seconds: float = 30.0,
        hypothesis_provider: HypothesisProvider | None = None,
    ) -> None:
        if not 1 <= lease_seconds <= 3600:
            raise ValueError("Invalid investigation lease duration.")

        if not 0 < heartbeat_interval_seconds < lease_seconds:
            raise ValueError(
                "Heartbeat interval must be shorter than lease duration."
            )

        self.repository = repository
        self.provider = provider
        self.audit = audit
        self.executor = executor
        self.lease_seconds = lease_seconds
        self.runner = runner
        self.heartbeat_interval_seconds = heartbeat_interval_seconds
        # Optional, tool-less AI stage. Runs after execution; never required.
        self.hypothesis_provider = hypothesis_provider

    
    def execute_existing(
        self,
        *,
        investigation_id: str,
        authorized_namespace: str,
       ) -> InvestigationServiceResult:
      record = self.repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace=authorized_namespace,
      )

      if record is None:
        raise InvestigationTransitionError(
            "Investigation not found."
        )

      if record.status.value != "pending":
        raise InvestigationTransitionError(
            "Investigation is not pending."
        )

      if record.user_text is None or record.max_steps is None:
        raise InvestigationTransitionError(
            "Investigation execution inputs are unavailable."
        )

      # Revalidate the persisted request against the namespace that was
      # authorized and stored at creation. The namespace is NOT re-derived from
      # the question: the stored, authorized value is authoritative, and the
      # question must still be fulfillable within it. The investigation kind is
      # bound here, before any model is invoked.
      try:
        context = create_bound_investigation_context(
          record.user_text,
          namespace=record.authorized_namespace,
          max_steps=record.max_steps,
          investigation_id=record.investigation_id,
        )
      except InvestigationScopeCreationError as exc:
        if exc.code == "namespace_conflict":
          raise InvestigationTransitionError(
              "Persisted investigation namespace mismatch."
          ) from None

        raise InvestigationTransitionError(
            "Persisted investigation scope is no longer valid."
        ) from None

      return self._execute_pending(context=context)
  
    
    def _execute_pending(
        self,
        *,
        context: InvestigationContext,
    ) -> InvestigationServiceResult:
        namespace = context.require_authorized_namespace()
        investigation_id = context.investigation_id

        token = self.repository.start_investigation_with_lease(
           investigation_id=investigation_id,
           authorized_namespace=namespace,
           lease_seconds=self.lease_seconds,
        )
        try:
            with InvestigationLeaseHeartbeat(
                repository=self.repository,
                investigation_id=investigation_id,
                authorized_namespace=namespace,
                lease_token=token,
                lease_seconds=self.lease_seconds,
                interval_seconds=self.heartbeat_interval_seconds,
            ) as heartbeat:
                ownership_lost = False

                def guarded_provider(context, steps):
                    heartbeat.check()
                    return self.provider(context, steps)

                def guarded_executor(call):
                    nonlocal ownership_lost

                    try:
                        heartbeat.check()
                        self.repository.assert_investigation_lease(
                            investigation_id=investigation_id,
                            authorized_namespace=namespace,
                            lease_token=token,
                        )
                        heartbeat.check()
                    except (
                        InvestigationLeaseLostError,
                        InvestigationTransitionError,
                    ) as exc:
                        ownership_lost = True
                        raise InvestigationLeaseLostError(
                            "Investigation execution ownership could not be "
                            "verified."
                        ) from exc

                    return self.executor(call)

                run = self.runner(
                    context=context,
                    provider=guarded_provider,
                    audit=self.audit,
                    executor=guarded_executor,
                )

                if ownership_lost:
                    raise InvestigationLeaseLostError(
                        "Investigation execution ownership was lost during "
                        "tool dispatch."
                    )

                heartbeat.check()

                if run.investigation_id != investigation_id:
                 raise ValueError(
                    "Controller returned a mismatched investigation ID."
                )

                snapshot = build_investigation_evidence_snapshot(context)
                report = build_grounded_report(snapshot)

                if report.investigation_id != investigation_id:
                   raise ValueError("Report investigation ID mismatch.")

                # Optional enrichment: separate from execution and from the
                # deterministic findings. It cannot fail the investigation.
                if run.stop_reason != InvestigationStopReason.TOOL_FAILED:
                    report = add_ai_hypotheses(
                        report,
                        snapshot=snapshot,
                        context=context,
                        provider=self.hypothesis_provider,
                    )
                    report = attach_namespace_diagnostic(report, snapshot)
               
                heartbeat.check()

            # Tool failure is not a successful investigation.
            if run.stop_reason == InvestigationStopReason.TOOL_FAILED:
                record = self.repository.fail_investigation_with_lease(
                    investigation_id=investigation_id,
                    authorized_namespace=namespace,
                    lease_token=token,
                    stop_reason="tool_failed",
                )

                return InvestigationServiceResult(
                    record=record,
                    report=None,
                    run=run,
                )

            record = self.repository.complete_investigation_with_lease(
                investigation_id=investigation_id,
                authorized_namespace=namespace,
                lease_token=token,
                report=report,
                stop_reason=run.stop_reason.value,
            )

            return InvestigationServiceResult(
                record=record,
                report=report,
                run=run,
            )

        except Exception:
            # Do not overwrite a record after ownership has been lost.
            try:
                self.repository.fail_investigation_with_lease(
                    investigation_id=investigation_id,
                    authorized_namespace=namespace,
                    lease_token=token,
                    stop_reason="execution_failed",
                )
            except InvestigationTransitionError:
                pass

            raise        

    # Keep the remainder of the existing execute() method unchanged,
    # starting at its current `try:` block.   

    def execute(
        self,
        *,
        context: InvestigationContext,
    ) -> InvestigationServiceResult:
        namespace = context.require_authorized_namespace()
        investigation_id = context.investigation_id

        # The trusted caller must already have authorized this namespace.
        # User text alone is not an authorization credential.
        self.repository.create_investigation(
            investigation_id=investigation_id,
            authorized_namespace=namespace,
            user_text=context.user_text,
            max_steps=context.max_steps,
        )
        
        return self._execute_pending(context=context)
