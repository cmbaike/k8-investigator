import pytest
from unittest.mock import Mock
from uuid import uuid4

from app.investigations.heartbeat import InvestigationLeaseLostError
from app.investigations.models import InvestigationStatus
from app.investigations.service import InvestigationService
from app.reports.models import InvestigationReport
from app.tools.investigation import InvestigationContext
from app.tools.investigation_controller import (
    InvestigationRunResult,
    InvestigationStopReason,
)
from app.investigations.repository import InvestigationTransitionError
from app.investigations.repository import InvestigationRepository
from datetime import datetime, timezone

from app.investigations.models import InvestigationRecord


def test_service_persists_grounded_report():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock(spec=InvestigationRepository)

    repository.start_investigation_with_lease.return_value = uuid4()

    completed_record = Mock()
    completed_record.status = InvestigationStatus.COMPLETED

    repository.complete_investigation_with_lease.return_value = completed_record

    runner = Mock(
        return_value=InvestigationRunResult(
            investigation_id=investigation_id,
            stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
            steps=(),
        )
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        runner=runner,
    )

    result = service.execute(context=context)

    assert result.record.status == InvestigationStatus.COMPLETED
    assert result.report is not None
    assert result.report.investigation_id == investigation_id

    repository.create_investigation.assert_called_once_with(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        user_text="Investigate pod health in namespace ai-ops-demo.",
        max_steps=3,     
    )

    repository.complete_investigation_with_lease.assert_called_once()

    repository.fail_investigation_with_lease.assert_not_called()


def test_service_marks_investigation_failed_on_controller_exception():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock()
    repository.start_investigation_with_lease.return_value = uuid4()

    runner = Mock(side_effect=RuntimeError("Provider unavailable"))

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        runner=runner,
    )

    with pytest.raises(RuntimeError, match="Provider unavailable"):
        service.execute(context=context)

    repository.fail_investigation_with_lease.assert_called_once_with(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=repository.start_investigation_with_lease.return_value,
        stop_reason="execution_failed",
    )

    repository.complete_investigation_with_lease.assert_not_called()
    
from app.investigations.repository import InvestigationTransitionError


def test_service_does_not_overwrite_lost_lease():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock()
    repository.start_investigation_with_lease.return_value = uuid4()

    repository.complete_investigation_with_lease.side_effect = (
        InvestigationTransitionError("Lease expired")
    )

    repository.fail_investigation_with_lease.side_effect = (
        InvestigationTransitionError("Lease no longer owned")
    )

    runner = Mock(
        return_value=InvestigationRunResult(
            investigation_id=investigation_id,
            stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
            steps=(),
        )
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        runner=runner,
    )

    with pytest.raises(InvestigationTransitionError, match="Lease expired"):
        service.execute(context=context)

    repository.complete_investigation_with_lease.assert_called_once()
    repository.fail_investigation_with_lease.assert_called_once()        


def test_service_marks_tool_failure_without_persisting_report():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock()
    repository.start_investigation_with_lease.return_value = uuid4()

    failed_record = Mock()
    failed_record.status = InvestigationStatus.FAILED
    repository.fail_investigation_with_lease.return_value = failed_record

    runner = Mock(
        return_value=InvestigationRunResult(
            investigation_id=investigation_id,
            stop_reason=InvestigationStopReason.TOOL_FAILED,
            steps=(),
        )
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        runner=runner,
    )

    result = service.execute(context=context)

    assert result.record.status == InvestigationStatus.FAILED
    assert result.report is None

    repository.fail_investigation_with_lease.assert_called_once_with(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=repository.start_investigation_with_lease.return_value,
        stop_reason="tool_failed",
    )

    repository.complete_investigation_with_lease.assert_not_called()
    
    
from unittest.mock import patch


def test_service_uses_heartbeat_during_controller_execution():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock()
    repository.start_investigation_with_lease.return_value = uuid4()

    completed_record = Mock()
    completed_record.status = InvestigationStatus.COMPLETED
    repository.complete_investigation_with_lease.return_value = completed_record

    runner = Mock(
        return_value=InvestigationRunResult(
            investigation_id=investigation_id,
            stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
            steps=(),
        )
    )

    with patch(
        "app.investigations.service.InvestigationLeaseHeartbeat"
    ) as heartbeat_class:
        heartbeat = heartbeat_class.return_value.__enter__.return_value

        service = InvestigationService(
            repository=repository,
            provider=Mock(),
            audit=Mock(),
            runner=runner,
        )

        result = service.execute(context=context)

        assert result.record.status == InvestigationStatus.COMPLETED

        heartbeat_class.assert_called_once()
        assert heartbeat.check.call_count == 2

        runner.assert_called_once() 
        
def test_service_blocks_dispatch_when_database_lease_is_invalid():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock(spec=InvestigationRepository)
    repository.start_investigation_with_lease.return_value = uuid4()
    repository.assert_investigation_lease.side_effect = (
        InvestigationTransitionError("Lease expired")
    )

    executor = Mock()

    def runner(*, context, provider, audit, executor):
        executor(Mock())

        return InvestigationRunResult(
            investigation_id=context.investigation_id,
            stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
            steps=(),
        )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        executor=executor,
        runner=runner,
    )

    with pytest.raises(InvestigationLeaseLostError) as exc_info:
        service.execute(context=context)
    assert isinstance(exc_info.value.__cause__, InvestigationTransitionError)
    executor.assert_not_called()
    repository.complete_investigation_with_lease.assert_not_called()
    
    
def test_service_propagates_ownership_loss_after_orchestrator_catches_it():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock(spec=InvestigationRepository)
    repository.start_investigation_with_lease.return_value = uuid4()
    repository.assert_investigation_lease.side_effect = (
        InvestigationTransitionError("Lease expired")
    )
    repository.fail_investigation_with_lease.side_effect = (
        InvestigationTransitionError("Lease no longer owned")
    )

    executor = Mock()

    def runner(*, context, provider, audit, executor):
        try:
            executor(Mock())
        except InvestigationLeaseLostError:
            pass  # Simulate the orchestrator converting the error.

        return InvestigationRunResult(
            investigation_id=context.investigation_id,
            stop_reason=InvestigationStopReason.TOOL_FAILED,
            steps=(),
        )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        executor=executor,
        runner=runner,
    )

    with pytest.raises(InvestigationLeaseLostError):
        service.execute(context=context)

    executor.assert_not_called()
    repository.complete_investigation_with_lease.assert_not_called()
    
def test_service_builds_report_while_heartbeat_is_active():
    investigation_id = str(uuid4())

    context = InvestigationContext(
        investigation_id=investigation_id,
        user_text="Investigate pod health in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
        max_steps=3,
    )

    repository = Mock(spec=InvestigationRepository)
    repository.start_investigation_with_lease.return_value = uuid4()

    run = InvestigationRunResult(
        investigation_id=investigation_id,
        stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
        steps=(),
    )

    events = []

    class TrackingHeartbeat:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            events.append("heartbeat_started")
            return self

        def check(self):
            pass

        def __exit__(self, exc_type, exc_value, traceback):
            events.append("heartbeat_stopped")

    def build_report(snapshot):
        events.append("report_built")
        return InvestigationReport(
            investigation_id=investigation_id,
            summary="No verified findings.",
            findings=[],
            uncertainties=[],
            suggested_checks=[],
        )

    with (
        patch(
            "app.investigations.service.InvestigationLeaseHeartbeat",
            TrackingHeartbeat,
        ),
        patch(
            "app.investigations.service.build_grounded_report",
            side_effect=build_report,
        ),
    ):
        service = InvestigationService(
            repository=repository,
            provider=Mock(),
            audit=Mock(),
            runner=Mock(return_value=run),
        )

        service.execute(context=context)

    assert events == [
        "heartbeat_started",
        "report_built",
        "heartbeat_stopped",
    ]
    
    
def test_execute_existing_uses_persisted_inputs_without_creating_record():
    investigation_id = str(uuid4())
    question = (
        "Investigate the failing workload "
        "in namespace ai-ops-demo."
    )

    repository = Mock(spec=InvestigationRepository)

    repository.get_investigation.return_value = InvestigationRecord(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.PENDING,
        created_at=datetime.now(timezone.utc),
        user_text=question,
        max_steps=4,
    )

    repository.start_investigation_with_lease.return_value = uuid4()

    completed_record = Mock()
    completed_record.status = InvestigationStatus.COMPLETED

    repository.complete_investigation_with_lease.return_value = (
        completed_record
    )

    def runner(*, context, provider, audit, executor):
        assert context.investigation_id == investigation_id
        assert context.user_text == question
        assert context.authorized_namespace == "ai-ops-demo"
        assert context.max_steps == 4

        return InvestigationRunResult(
            investigation_id=investigation_id,
            stop_reason=InvestigationStopReason.PROVIDER_FINISHED,
            steps=(),
        )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
        runner=runner,
    )

    result = service.execute_existing(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert result.record.status == InvestigationStatus.COMPLETED
    assert result.report is not None

    repository.create_investigation.assert_not_called()

    repository.start_investigation_with_lease.assert_called_once_with(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_seconds=120,
    )

    repository.complete_investigation_with_lease.assert_called_once()
    
def test_execute_existing_rejects_missing_execution_inputs():
    investigation_id = str(uuid4())

    repository = Mock(spec=InvestigationRepository)

    repository.get_investigation.return_value = InvestigationRecord(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
    )

    with pytest.raises(
        InvestigationTransitionError,
        match="execution inputs are unavailable",
    ):
        service.execute_existing(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
        )

    repository.start_investigation_with_lease.assert_not_called()
    repository.create_investigation.assert_not_called()
    
def test_execute_existing_rejects_running_investigation():
    investigation_id = str(uuid4())

    repository = Mock(spec=InvestigationRepository)

    repository.get_investigation.return_value = InvestigationRecord(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.RUNNING,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
        user_text=(
            "Investigate the failing workload "
            "in namespace ai-ops-demo."
        ),
        max_steps=4,
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
    )

    with pytest.raises(
        InvestigationTransitionError,
        match="not pending",
    ):
        service.execute_existing(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
        )

    repository.start_investigation_with_lease.assert_not_called()
    repository.create_investigation.assert_not_called()
    
def test_execute_existing_rejects_missing_investigation():
    repository = Mock(spec=InvestigationRepository)
    repository.get_investigation.return_value = None

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
    )

    with pytest.raises(
        InvestigationTransitionError,
        match="not found",
    ):
        service.execute_existing(
            investigation_id=str(uuid4()),
            authorized_namespace="ai-ops-demo",
        )

    repository.start_investigation_with_lease.assert_not_called()
    repository.create_investigation.assert_not_called()

def test_execute_existing_rejects_persisted_namespace_mismatch():
    investigation_id = str(uuid4())

    repository = Mock(spec=InvestigationRepository)

    repository.get_investigation.return_value = InvestigationRecord(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.PENDING,
        created_at=datetime.now(timezone.utc),
        user_text=(
            "Investigate the failing workload "
            "in namespace production."
        ),
        max_steps=4,
    )

    service = InvestigationService(
        repository=repository,
        provider=Mock(),
        audit=Mock(),
    )

    with pytest.raises(
        InvestigationTransitionError,
        match="namespace mismatch",
    ):
        service.execute_existing(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
        )

    repository.start_investigation_with_lease.assert_not_called()
    repository.create_investigation.assert_not_called()
