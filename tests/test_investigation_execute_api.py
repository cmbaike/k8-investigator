from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.investigations.models import InvestigationStatus
from app.investigations.repository import InvestigationTransitionError
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import require_api_key_principal
from datetime import datetime, timezone

from app.investigations.models import InvestigationRecord


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def authorized_principal():
    return APIKeyPrincipal(
        principal_id="test-operator",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )


@pytest.fixture
def authenticated_client(authorized_principal):
    app.dependency_overrides[require_api_key_principal] = (
        lambda: authorized_principal
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(require_api_key_principal, None)


def investigation_record(
    *,
    status=InvestigationStatus.PENDING,
    namespace="ai-ops-demo",
    user_text="Investigate the failing workload in namespace ai-ops-demo.",
    max_steps=6,
):
    return SimpleNamespace(
        investigation_id=str(uuid4()),
        authorized_namespace=namespace,
        status=status,
        user_text=user_text,
        max_steps=max_steps,
    )
    
def test_execute_returns_404_for_unknown_investigation(
    authenticated_client,
):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = None

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ):
        response = authenticated_client.post(
            "/investigations/nonexistent/execute"
        )

    assert response.status_code == 404

    repository.get_investigation_for_namespaces.assert_called_once_with(
        investigation_id="nonexistent",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )


def test_execute_returns_404_for_unauthorized_investigation(
    authenticated_client,
):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = None

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ):
        response = authenticated_client.post(
            "/investigations/other-namespace-id/execute"
        )

    assert response.status_code == 404
    
@pytest.mark.parametrize(
    "status",
    [
        InvestigationStatus.RUNNING,
        InvestigationStatus.COMPLETED,
        InvestigationStatus.FAILED,
    ],
)
def test_execute_rejects_non_pending_investigation(
    authenticated_client,
    status,
):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = (
        investigation_record(status=status)
    )

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ), patch("app.api.build_investigation_service") as factory:
        response = authenticated_client.post(
            "/investigations/test-id/execute"
        )

    assert response.status_code == 409
    factory.assert_not_called()
    
@pytest.mark.parametrize(
    "user_text,max_steps",
    [
        (None, 6),
        ("Investigate the failing workload in namespace ai-ops-demo.", None),
    ],
)
def test_execute_rejects_missing_persisted_inputs(
    authenticated_client,
    user_text,
    max_steps,
):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = (
        investigation_record(
            user_text=user_text,
            max_steps=max_steps,
        )
    )

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ), patch("app.api.build_investigation_service") as factory:
        response = authenticated_client.post(
            "/investigations/test-id/execute"
        )

    assert response.status_code == 409
    factory.assert_not_called()
    
def test_execute_maps_lease_transition_failure_to_409(
    authenticated_client,
):
    record = investigation_record()

    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = record

    service = Mock()
    service.execute_existing.side_effect = InvestigationTransitionError(
        "Investigation is no longer pending."
    )

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ), patch(
        "app.api.build_investigation_service",
        return_value=service,
    ):
        response = authenticated_client.post(
            f"/investigations/{record.investigation_id}/execute"
        )

    assert response.status_code == 409

    service.execute_existing.assert_called_once_with(
        investigation_id=record.investigation_id,
        authorized_namespace="ai-ops-demo",
    )
    
def test_execute_hides_internal_execution_errors(
    authenticated_client,
):
    record = investigation_record()

    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = record

    service = Mock()
    service.execute_existing.side_effect = RuntimeError(
        "sensitive internal execution detail"
    )

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ), patch(
        "app.api.build_investigation_service",
        return_value=service,
    ):
        response = authenticated_client.post(
            f"/investigations/{record.investigation_id}/execute"
        )

    assert response.status_code == 500
    assert "sensitive internal execution detail" not in response.text
    
def test_execute_returns_completed_investigation(
    authenticated_client,
):
    investigation_id = str(uuid4())

    pending = investigation_record()
    pending.investigation_id = investigation_id

    completed = InvestigationRecord(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
        status=InvestigationStatus.COMPLETED,
        created_at=datetime.now(timezone.utc),
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        stop_reason="provider_finished",
        user_text=(
            "Investigate the failing workload "
            "in namespace ai-ops-demo."
        ),
        max_steps=6,
    )

    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = pending

    service = Mock()
    service.execute_existing.return_value = SimpleNamespace(
        record=completed,
    )

    with patch(
        "app.api.InvestigationRepository",
        return_value=repository,
    ), patch(
        "app.api.build_investigation_service",
        return_value=service,
    ) as factory:
        response = authenticated_client.post(
            f"/investigations/{investigation_id}/execute"
        )

    assert response.status_code == 200
    assert response.json()["investigation_id"] == investigation_id
    assert response.json()["authorized_namespace"] == "ai-ops-demo"
    assert response.json()["status"] == "completed"

    factory.assert_called_once_with(repository=repository)

    service.execute_existing.assert_called_once_with(
        investigation_id=investigation_id,
        authorized_namespace="ai-ops-demo",
    ) 
    
def test_execute_does_not_require_an_api_key(client):
    with patch("app.api.InvestigationRepository") as repository_class:
        repository_class.return_value.get_investigation_for_namespaces.return_value = None
        response = client.post(
            f"/investigations/{uuid4()}/execute"
        )

    assert response.status_code == 404
    repository_class.return_value.get_investigation_for_namespaces.assert_called()
    repository_class.assert_not_called()                
