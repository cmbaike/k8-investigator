"""Authenticated, namespace-scoped investigation status and report retrieval."""

from datetime import datetime, timezone
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.investigations.models import InvestigationRecord, InvestigationStatus
from app.reports.models import InvestigationReport
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import require_api_key_principal


@pytest.fixture
def authenticated_client():
    app.dependency_overrides[require_api_key_principal] = lambda: APIKeyPrincipal(
        principal_id="test-operator",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(require_api_key_principal, None)


def record(status, investigation_id=None):
    now = datetime.now(timezone.utc)
    return InvestigationRecord(
        investigation_id=investigation_id or str(uuid4()),
        authorized_namespace="ai-ops-demo",
        status=status,
        created_at=now,
        started_at=None if status == InvestigationStatus.PENDING else now,
        finished_at=(
            now
            if status in {InvestigationStatus.COMPLETED, InvestigationStatus.FAILED}
            else None
        ),
        stop_reason=(
            "provider_finished"
            if status == InvestigationStatus.COMPLETED
            else "execution_failed"
            if status == InvestigationStatus.FAILED
            else None
        ),
        user_text="Investigate namespace ai-ops-demo.",
        max_steps=3,
    )


def repo_returning(value):
    repository = Mock()
    repository.get_investigation_for_namespaces.return_value = value
    return repository


def test_report_does_not_require_an_api_key():
    with patch("app.api.InvestigationRepository") as repository_class:
        repository_class.return_value.get_investigation_for_namespaces.return_value = None
        response = TestClient(app).get(f"/investigations/{uuid4()}/report")

    assert response.status_code == 404
    repository_class.return_value.get_investigation_for_namespaces.assert_called()


def test_status_does_not_require_an_api_key():
    with patch("app.api.InvestigationRepository") as repository_class:
        repository_class.return_value.get_investigation_for_namespaces.return_value = None
        response = TestClient(app).get(f"/investigations/{uuid4()}")

    assert response.status_code == 404
    repository_class.return_value.get_investigation_for_namespaces.assert_called()


def test_report_unknown_or_out_of_scope_is_404(authenticated_client):
    repository = repo_returning(None)

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get("/investigations/other/report")

    assert response.status_code == 404
    repository.get_investigation_for_namespaces.assert_called_once_with(
        investigation_id="other",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )
    repository.get_report.assert_not_called()


@pytest.mark.parametrize(
    "status",
    [
        InvestigationStatus.PENDING,
        InvestigationStatus.RUNNING,
        InvestigationStatus.FAILED,
    ],
)
def test_report_not_available_before_completion(authenticated_client, status):
    repository = repo_returning(record(status))

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get("/investigations/x/report")

    assert response.status_code == 409
    assert status.value in response.json()["detail"]
    repository.get_report.assert_not_called()


def test_completed_report_is_returned_from_authorized_namespace(
    authenticated_client,
):
    completed = record(InvestigationStatus.COMPLETED)
    report = InvestigationReport(
        investigation_id=completed.investigation_id,
        summary="Summary.",
    )
    repository = repo_returning(completed)
    repository.get_report.return_value = report

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get(
            f"/investigations/{completed.investigation_id}/report"
        )

    assert response.status_code == 200
    assert response.json()["investigation_id"] == completed.investigation_id
    repository.get_report.assert_called_once_with(
        investigation_id=completed.investigation_id,
        authorized_namespace="ai-ops-demo",
    )


def test_report_lookup_errors_are_hidden(authenticated_client):
    repository = Mock()
    repository.get_investigation_for_namespaces.side_effect = RuntimeError(
        "postgresql://secret@host/db"
    )

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get("/investigations/x/report")

    assert response.status_code == 500
    assert "secret" not in response.text


def test_report_retrieval_errors_are_hidden(authenticated_client):
    completed = record(InvestigationStatus.COMPLETED)
    repository = repo_returning(completed)
    repository.get_report.side_effect = RuntimeError("secret detail")

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get("/investigations/x/report")

    assert response.status_code == 500
    assert "secret" not in response.text


def test_status_is_scoped_to_principal_namespaces(authenticated_client):
    repository = repo_returning(None)

    with patch("app.api.InvestigationRepository", return_value=repository):
        response = authenticated_client.get("/investigations/other")

    assert response.status_code == 404
