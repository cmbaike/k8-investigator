from unittest.mock import Mock
from uuid import uuid4

import pytest

from app.investigations.heartbeat import (
    InvestigationLeaseHeartbeat,
    InvestigationLeaseLostError,
)

from threading import Event
from time import monotonic, sleep

from app.investigations.heartbeat import InvestigationLeaseLostError


def make_heartbeat(repository):
    return InvestigationLeaseHeartbeat(
        repository=repository,
        investigation_id="test-investigation",
        authorized_namespace="ai-ops-demo",
        lease_token=uuid4(),
        lease_seconds=120,
        interval_seconds=0.01,
    )


def test_heartbeat_renews_lease():
    repository = Mock()

    with make_heartbeat(repository) as heartbeat:
        import time

        deadline = time.monotonic() + 1

        while repository.renew_investigation_lease.call_count == 0:
            if time.monotonic() >= deadline:
                pytest.fail("Heartbeat did not renew lease.")
            time.sleep(0.005)

        heartbeat.check()

    repository.renew_investigation_lease.assert_called()


def test_heartbeat_detects_renewal_failure():
    repository = Mock()
    repository.renew_investigation_lease.side_effect = RuntimeError(
        "Database unavailable"
    )

    with pytest.raises(InvestigationLeaseLostError) as exc_info:
        with make_heartbeat(repository) as heartbeat:
            deadline = monotonic() + 1.0

            while monotonic() < deadline:
                try:
                    heartbeat.check()
                except InvestigationLeaseLostError:
                    break

                sleep(0.01)
            else:
                pytest.fail("Heartbeat did not detect renewal failure.")

    assert isinstance(
        exc_info.value.__cause__,
        RuntimeError,
    )

    assert str(exc_info.value.__cause__) == "Database unavailable"


def test_heartbeat_rejects_invalid_interval():
    with pytest.raises(ValueError):
        InvestigationLeaseHeartbeat(
            repository=Mock(),
            investigation_id="test-investigation",
            authorized_namespace="ai-ops-demo",
            lease_token=uuid4(),
            lease_seconds=10,
            interval_seconds=10,
        )
        
def test_heartbeat_shutdown_fails_closed_when_renewal_is_blocked():
    renewal_started = Event()
    release_renewal = Event()

    repository = Mock()

    def blocked_renewal(**kwargs):
        renewal_started.set()
        release_renewal.wait(timeout=2)

    repository.renew_investigation_lease.side_effect = blocked_renewal

    heartbeat = InvestigationLeaseHeartbeat(
        repository=repository,
        investigation_id="test-investigation",
        authorized_namespace="ai-ops-demo",
        lease_token=uuid4(),
        lease_seconds=2,
        interval_seconds=0.01,
        shutdown_timeout_seconds=0.02,
    )

    try:
        with pytest.raises(InvestigationLeaseLostError):
            with heartbeat:
                assert renewal_started.wait(timeout=1)
    finally:
        release_renewal.set()
        if heartbeat._thread is not None:
            heartbeat._thread.join(timeout=1)
            
def test_heartbeat_rejects_invalid_shutdown_timeout():
    with pytest.raises(ValueError):
        InvestigationLeaseHeartbeat(
            repository=Mock(),
            investigation_id="test-investigation",
            authorized_namespace="ai-ops-demo",
            lease_token=uuid4(),
            lease_seconds=2,
            interval_seconds=0.01,
            shutdown_timeout_seconds=0,
        )                    
