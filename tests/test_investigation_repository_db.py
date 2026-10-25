"""PostgreSQL integration tests for investigation persistence."""

import os
from uuid import uuid4

import psycopg
import pytest

from app.investigations.models import InvestigationStatus
from app.investigations.repository import (
    InvestigationRepository,
    InvestigationTransitionError,
)
from app.reports.models import InvestigationReport
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from psycopg.rows import dict_row


@pytest.fixture
def repository():
    database_url = os.environ.get("TEST_DATABASE_URL")

    if not database_url:
        pytest.skip("TEST_DATABASE_URL is not configured")

    return InvestigationRepository(database_url=database_url)


@pytest.fixture
def investigation_id(repository):
    investigation_id = f"test-{uuid4()}"

    yield investigation_id

    # Cleanup is deliberately scoped to this test's record.
    with psycopg.connect(repository.database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM investigations
                WHERE investigation_id = %s
                """,
                (investigation_id,),
            )


def test_create_and_start_investigation(repository, investigation_id):
    record = repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert record.status == InvestigationStatus.PENDING
    assert record.started_at is None

    started = repository.start_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert started.status == InvestigationStatus.RUNNING
    assert started.started_at is not None
    assert started.finished_at is None


def test_complete_investigation_persists_report(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    report = InvestigationReport(
        investigation_id=investigation_id,
        summary="Verified Kubernetes observations.",
        findings=[],
        uncertainties=["Underlying cause not established."],
        suggested_checks=[],
    )

    completed = repository.complete_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        report=report,
        stop_reason="step_budget_exhausted",
    )

    assert completed.status == InvestigationStatus.COMPLETED
    assert completed.finished_at is not None
    assert completed.stop_reason == "step_budget_exhausted"

    # Read through a new database connection.
    persisted = repository.get_report(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert persisted == report


def test_failed_investigation_has_no_report(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    failed = repository.fail_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        stop_reason="tool_failed",
    )

    assert failed.status == InvestigationStatus.FAILED
    assert failed.finished_at is not None

    assert repository.get_report(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    ) is None


def test_namespace_isolation(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="other-namespace",
    ) is None

    assert repository.get_report(
        investigation_id=investigation_id,
        authorized_namespace="other-namespace",
    ) is None

    with pytest.raises(InvestigationTransitionError):
        repository.start_investigation(
            investigation_id=investigation_id,
            authorized_namespace="other-namespace",
        )


def test_terminal_state_cannot_be_restarted(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.fail_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        stop_reason="tool_failed",
    )

    with pytest.raises(InvestigationTransitionError):
        repository.start_investigation(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
        )

def test_concurrent_start_allows_only_one_worker(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    def attempt_start():
        try:
            repository.start_investigation(
                investigation_id=investigation_id,
                authorized_namespace="ai-ops-demo",
            )
            return "started"
        except InvestigationTransitionError:
            return "rejected"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt_start(), range(2)))

    assert sorted(results) == ["rejected", "started"]

    persisted = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert persisted.status == InvestigationStatus.RUNNING
    
def test_pending_investigation_can_fail(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    failed = repository.fail_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        stop_reason="initialization_failed",
    )

    assert failed.status == InvestigationStatus.FAILED
    assert failed.started_at is None
    assert failed.finished_at is not None
    assert failed.stop_reason == "initialization_failed"


def test_failed_investigation_cannot_fail_again(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.fail_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        stop_reason="initialization_failed",
    )

    with pytest.raises(InvestigationTransitionError):
        repository.fail_investigation(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            stop_reason="second_failure",
        )

def test_leased_investigation_cannot_use_legacy_completion(
    repository, investigation_id
):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    report = InvestigationReport(
        investigation_id=investigation_id,
        summary="Verified observations.",
        findings=[],
        uncertainties=[],
        suggested_checks=[],
    )

    with pytest.raises(InvestigationTransitionError):
        repository.complete_investigation(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            report=report,
            stop_reason="provider_finished",
        )

    completed = repository.complete_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=token,
        report=report,
        stop_reason="provider_finished",
    )

    assert completed.status == InvestigationStatus.COMPLETED


def test_wrong_lease_token_cannot_complete(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    report = InvestigationReport(
        investigation_id=investigation_id,
        summary="Verified observations.",
        findings=[],
        uncertainties=[],
        suggested_checks=[],
    )

    with pytest.raises(InvestigationTransitionError):
        repository.complete_investigation_with_lease(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            lease_token=uuid4(),
            report=report,
            stop_reason="provider_finished",
        )


def test_valid_lease_can_be_renewed(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.renew_investigation_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=token,
    )

    record = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert record.status == InvestigationStatus.RUNNING
    
def expire_lease(repository, investigation_id):
    """Simulate lease expiry using PostgreSQL's clock."""
    with psycopg.connect(repository.database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET lease_expires_at = NOW() - INTERVAL '1 second'
                WHERE investigation_id = %s
                """,
                (investigation_id,),
            )


def test_expired_lease_is_recovered(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    expire_lease(repository, investigation_id)

    recovered = repository.fail_expired_investigations()

    assert recovered >= 1

    record = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert record.status == InvestigationStatus.FAILED
    assert record.stop_reason == "execution_lease_expired"
    assert record.finished_at is not None

    with pytest.raises(InvestigationTransitionError):
        repository.renew_investigation_lease(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            lease_token=token,
        )


def test_stale_worker_cannot_complete_recovered_investigation(
    repository, investigation_id
):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    expire_lease(repository, investigation_id)
    repository.fail_expired_investigations()

    report = InvestigationReport(
        investigation_id=investigation_id,
        summary="Verified observations.",
        findings=[],
        uncertainties=[],
        suggested_checks=[],
    )

    with pytest.raises(InvestigationTransitionError):
        repository.complete_investigation_with_lease(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            lease_token=token,
            report=report,
            stop_reason="provider_finished",
        )

    assert repository.get_report(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    ) is None


def test_unexpired_lease_is_not_recovered(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_seconds=3600,
    )

    repository.fail_expired_investigations()

    record = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert record.status == InvestigationStatus.RUNNING
    
    
def test_leased_investigation_cannot_use_legacy_failure(
    repository, investigation_id
):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    with pytest.raises(InvestigationTransitionError):
        repository.fail_investigation(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            stop_reason="tool_failed",
        )

    record = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert record.status == InvestigationStatus.RUNNING 
    
    
def test_valid_lease_passes_authoritative_check(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    repository.assert_investigation_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=token,
    )


def test_expired_lease_fails_authoritative_check(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    expire_lease(repository, investigation_id)

    with pytest.raises(InvestigationTransitionError):
        repository.assert_investigation_lease(
            investigation_id=investigation_id,
            authorized_namespace="ai-ops-demo",
            lease_token=token,
        )

def test_wrong_namespace_cannot_validate_lease(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    with pytest.raises(InvestigationTransitionError):
        repository.assert_investigation_lease(
            investigation_id=investigation_id,
            authorized_namespace="another-namespace",
            lease_token=token,
        )
              
def test_investigation_execution_inputs_round_trip(repository):
    investigation_id = "test-" + str(uuid4())
    question = (
        "Investigate the failing workload "
        "in namespace ai-ops-demo."
    )

    created = repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        user_text=question,
        max_steps=6,
    )

    retrieved = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert created.user_text == question
    assert created.max_steps == 6

    assert retrieved is not None
    assert retrieved.user_text == question
    assert retrieved.max_steps == 6
    assert retrieved.status == InvestigationStatus.PENDING
    
def test_investigation_without_execution_inputs_remains_readable(repository,):
    investigation_id = "test-" + str(uuid4())

    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    retrieved = repository.get_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    assert retrieved is not None
    assert retrieved.user_text is None
    assert retrieved.max_steps is None                     

def test_principal_scoped_lookup_returns_authorized_investigation(
    repository,
):
    investigation_id = "test-" + str(uuid4())

    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    record = repository.get_investigation_for_namespaces(
        investigation_id=investigation_id,
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    assert record is not None
    assert record.investigation_id == investigation_id
    assert record.authorized_namespace == "ai-ops-demo"
    
def test_principal_scoped_lookup_hides_unauthorized_investigation(
    repository,
):
    investigation_id = "test-" + str(uuid4())

    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="production",
    )

    record = repository.get_investigation_for_namespaces(
        investigation_id=investigation_id,
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    assert record is None 
    
def test_principal_scoped_lookup_rejects_empty_allowlist(
    repository,
):
    record = repository.get_investigation_for_namespaces(
        investigation_id="nonexistent-investigation",
        allowed_namespaces=frozenset(),
    )

    assert record is None       

def test_lease_transitions_preserve_execution_inputs(
    repository,
    investigation_id,
):
    """Regression: terminal records must echo persisted user_text/max_steps."""
    question = "Investigate failing workload in namespace ai-ops-demo."

    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        user_text=question,
        max_steps=4,
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    completed = repository.complete_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=token,
        report=InvestigationReport(
            investigation_id=investigation_id,
            summary="Summary.",
        ),
        stop_reason="provider_finished",
    )

    assert completed.user_text == question
    assert completed.max_steps == 4


def test_lease_failure_preserves_execution_inputs(
    repository,
    investigation_id,
):
    question = "Investigate failing workload in namespace ai-ops-demo."

    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        user_text=question,
        max_steps=4,
    )

    token = repository.start_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    )

    failed = repository.fail_investigation_with_lease(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        lease_token=token,
        stop_reason="execution_failed",
    )

    assert failed.user_text == question
    assert failed.max_steps == 4
