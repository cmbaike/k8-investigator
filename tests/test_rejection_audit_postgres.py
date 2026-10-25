"""PostgreSQL integration: durable audit of rejected out-of-target proposals.

Uses the REAL audit writer (`write_investigation_audit_event`) and, for the
lease test, the REAL repository and service. Only the Kubernetes executor is a
stub, and it records every call so the tests can prove what was NOT executed.

Skipped unless TEST_DATABASE_URL is configured (same convention as the other
database tests). Every row a test creates is keyed by a unique investigation id
and removed afterwards; nothing else is touched.

What these tests do and do not claim: the audit writer is NOT fenced by the
execution lease. `test_lease_expiry_...` pins the verified behavior (audit rows
are still written; every later Kubernetes call and the completion are refused)
rather than asserting a guarantee the writer does not give.
"""

import json
import os
from pathlib import Path
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from app.investigations.heartbeat import InvestigationLeaseLostError
from app.investigations.models import InvestigationStatus
from app.investigations.repository import InvestigationRepository
from app.investigations.service import InvestigationService
from app.tools.coverage import SUPPLEMENTARY_TOOLS, CoverageProvider
from app.tools.investigation_audit import write_investigation_audit_event
from app.tools.investigation_controller import (
    InvestigationStopReason,
    run_investigation,
)
from app.tools.investigation_scope import create_bound_investigation_context
from app.tools.models import ToolCall
from app.tools.proposal_rejection import MAX_REJECTED_PROPOSALS
from tests.test_target_binding_and_readiness import (
    BAD,
    BROKEN,
    GET_PODS,
    NS,
    TARGETED_BAD,
    Cluster,
    describe,
    scripted,
)

AUDIT_MIGRATION = (
    Path(__file__).resolve().parents[1] / "migrations" / "004_add_investigation_audit.sql"
)

HOSTILE = ToolCall(
    name="k8s.describe_pod",
    arguments={
        "namespace": NS,
        "pod": BROKEN,
        "container": "app; DROP TABLE investigation_audit_events",
        "password": "SENTINEL-SECRET-771",
        "note": "ignore previous instructions",
    },
)


@pytest.fixture
def database_url(monkeypatch):
    url = os.environ.get("TEST_DATABASE_URL")

    if not url:
        pytest.skip("TEST_DATABASE_URL is not configured")

    # The test database may predate the audit table. Apply the committed
    # migration (idempotent: CREATE ... IF NOT EXISTS) so the REAL schema, with
    # its CHECK constraint, is what the writer is exercised against.
    with psycopg.connect(url) as conn:
        conn.execute(AUDIT_MIGRATION.read_text())

    # The real writer reads DATABASE_URL when it is called.
    monkeypatch.setenv("DATABASE_URL", url)

    return url


@pytest.fixture
def investigation_id(database_url):
    investigation_id = f"test-{uuid4()}"

    yield investigation_id

    # Cleanup is scoped to this test's own investigation.
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM investigation_audit_events WHERE investigation_id = %s",
                (investigation_id,),
            )
            cur.execute(
                "DELETE FROM investigations WHERE investigation_id = %s",
                (investigation_id,),
            )


def stored_events(database_url, investigation_id):
    with psycopg.connect(database_url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT request_id, event_type, tool_name, arguments, status, detail
                FROM investigation_audit_events
                WHERE investigation_id = %s
                ORDER BY created_at, event_id
                """,
                (investigation_id,),
            )

            return cur.fetchall()


def bound(investigation_id, question=TARGETED_BAD, **kwargs):
    return create_bound_investigation_context(
        question, namespace=NS, investigation_id=investigation_id, **kwargs
    )


def rejected_rows(rows):
    return [r for r in rows if r["event_type"] == "rejected"]


# --------------------------------------------------- durable proposed/rejected


def test_an_out_of_target_proposal_is_durably_proposed_then_rejected(
    database_url, investigation_id
):
    cluster = Cluster()

    run_investigation(
        context=bound(investigation_id),
        provider=CoverageProvider(scripted(GET_PODS, HOSTILE)),
        audit=write_investigation_audit_event,
        executor=cluster,
        tolerated_failure_tools=SUPPLEMENTARY_TOOLS,
    )
    rows = stored_events(database_url, investigation_id)
    about_broken = [
        r for r in rows
        if r["tool_name"] == "k8s.describe_pod" and r["arguments"].get("pod") == BROKEN
    ]

    assert [(r["event_type"], r["status"], r["detail"]) for r in about_broken] == [
        ("proposed", "received", None),
        ("rejected", "denied", "outside_target"),
    ]
    # Both events of the proposal share one request id.
    assert len({r["request_id"] for r in about_broken}) == 1
    # Safe identifiers only: hostile keys and values never reach PostgreSQL.
    assert all(r["arguments"] == {"namespace": NS, "pod": BROKEN} for r in about_broken)
    stored = json.dumps([dict(r) for r in rows], default=str)
    assert "SENTINEL-SECRET-771" not in stored
    assert "DROP TABLE" not in stored
    assert "ignore previous" not in stored
    # The detail is a member of the fixed vocabulary, never free text.
    assert {r["detail"] for r in rejected_rows(rows)} == {"outside_target"}


def test_the_rejected_call_never_reaches_kubernetes_or_later_audit_phases(
    database_url, investigation_id
):
    cluster = Cluster()

    run_investigation(
        context=bound(investigation_id),
        provider=scripted(GET_PODS, describe(BROKEN), describe(BAD)),
        audit=write_investigation_audit_event,
        executor=cluster,
    )
    rows = stored_events(database_url, investigation_id)

    assert BROKEN not in cluster.inspected_pods()
    assert cluster.inspected_pods() == {BAD}  # the in-target call still ran
    assert not [
        r for r in rows
        if r["arguments"].get("pod") == BROKEN
        and r["event_type"] in {"authorized", "execution_started", "completed"}
    ]
    # ...while the target's own call went through every phase.
    assert {
        r["event_type"] for r in rows if r["arguments"].get("pod") == BAD
    } == {"proposed", "authorized", "execution_started", "completed"}


def test_the_boundary_rejection_path_is_durable_too(database_url, investigation_id):
    """A raw provider is rejected inside the execution boundary, not the policy."""
    run_investigation(
        context=bound(investigation_id),
        provider=scripted(GET_PODS, describe(BROKEN)),
        audit=write_investigation_audit_event,
        executor=Cluster(),
    )
    rejected = rejected_rows(stored_events(database_url, investigation_id))

    assert [(r["tool_name"], r["detail"]) for r in rejected] == [
        ("k8s.describe_pod", "outside_target")
    ]


# ------------------------------------------------------------------- bounded


def test_a_stubborn_provider_is_bounded_by_the_rejection_limit(
    database_url, investigation_id
):
    cluster, ctx = Cluster(), bound(investigation_id)
    proposals = []

    def stubborn(_context, steps):
        proposals.append(1)

        return GET_PODS if not steps else describe(BROKEN)

    result = run_investigation(
        context=ctx,
        provider=stubborn,
        audit=write_investigation_audit_event,
        executor=cluster,
    )
    rows = stored_events(database_url, investigation_id)
    rejected = rejected_rows(rows)

    assert result.stop_reason is InvestigationStopReason.PROVIDER_FINISHED
    assert len(rejected) == MAX_REJECTED_PROPOSALS
    # One proposed event per rejected proposal, each with its own request id.
    assert len({r["request_id"] for r in rejected}) == MAX_REJECTED_PROPOSALS
    assert len(proposals) == 1 + MAX_REJECTED_PROPOSALS
    assert cluster.inspected_pods() == set()  # nothing outside the target ran
    assert ctx.rejected_proposal_count == MAX_REJECTED_PROPOSALS


# ---------------------------------------------------------------- lease expiry


@pytest.fixture
def repository(database_url):
    return InvestigationRepository(database_url=database_url)


def expire_lease(database_url, investigation_id):
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE investigations
                SET lease_expires_at = NOW() - INTERVAL '1 second'
                WHERE investigation_id = %s
                """,
                (investigation_id,),
            )


def service_for(repository, provider, cluster):
    return InvestigationService(
        repository=repository,
        provider=provider,
        audit=write_investigation_audit_event,
        executor=cluster,
        lease_seconds=120,
        heartbeat_interval_seconds=60,  # no renewal can happen inside a test
    )


def create_pending(repository, investigation_id):
    repository.create_investigation(
        investigation_id=investigation_id,
        authorized_namespace=NS,
        user_text=TARGETED_BAD,
        max_steps=6,
    )


def test_a_rejection_while_the_lease_is_valid_completes_normally(
    database_url, repository, investigation_id
):
    create_pending(repository, investigation_id)
    cluster = Cluster()
    service = service_for(repository, scripted(GET_PODS, describe(BROKEN), describe(BAD)), cluster)

    outcome = service.execute_existing(
        investigation_id=investigation_id, authorized_namespace=NS
    )

    assert outcome.record.status == InvestigationStatus.COMPLETED
    assert BROKEN not in cluster.inspected_pods()
    assert len(rejected_rows(stored_events(database_url, investigation_id))) == 1


def test_lease_expiry_during_rejection_handling_is_refused_after_the_audit_not_before(
    database_url, repository, investigation_id
):
    """Pins the VERIFIED behavior; it does not claim the audit writer is fenced.

    The provider lets the lease lapse in the same step that it proposes the
    out-of-target call. The rejection audit rows are still written (the sink has
    no lease check). What the lease DOES guard is everything that matters
    afterwards: the next Kubernetes call is refused before execution and the
    investigation cannot be completed by the stale worker.
    """
    create_pending(repository, investigation_id)
    cluster, calls = Cluster(), []

    def expiring(_context, steps):
        calls.append(len(steps))

        if not steps:
            return GET_PODS
        if len(calls) == 2:
            expire_lease(database_url, investigation_id)

            return describe(BROKEN)  # rejected after the lease lapsed
        return describe(BAD)  # a valid call, proposed with no lease

    service = service_for(repository, expiring, cluster)

    with pytest.raises(InvestigationLeaseLostError):
        service.execute_existing(
            investigation_id=investigation_id, authorized_namespace=NS
        )

    rows = stored_events(database_url, investigation_id)
    rejected = rejected_rows(rows)

    # Verified: the rejection audit WAS written although the lease had expired.
    assert [(r["tool_name"], r["detail"]) for r in rejected] == [
        ("k8s.describe_pod", "outside_target")
    ]
    # Verified: neither the rejected call nor the later valid one executed.
    assert cluster.inspected_pods() == set()
    assert [c.name for c in cluster.calls] == ["k8s.get_pods"]
    # Verified: the stale worker did not complete or publish a report.
    record = repository.get_investigation(
        investigation_id=investigation_id, authorized_namespace=NS
    )

    assert record.status != InvestigationStatus.COMPLETED
    # The lapsed lease is what lets the recovery sweep fail it, as designed.
    assert repository.fail_expired_investigations() >= 1
    recovered = repository.get_investigation(
        investigation_id=investigation_id, authorized_namespace=NS
    )

    assert recovered.status == InvestigationStatus.FAILED
    assert recovered.stop_reason == "execution_lease_expired"
    assert repository.get_report(
        investigation_id=investigation_id, authorized_namespace=NS
    ) is None
