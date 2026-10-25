from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.investigations.models import (
    InvestigationRecord,
    InvestigationStatus,
)
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import get_demo_principal


TEST_KEY = "unused"

PRINCIPAL = APIKeyPrincipal(
    principal_id="beta-user-1",
    allowed_namespaces=frozenset({"ai-ops-demo"}),
)


@pytest.fixture
def client():
    previous_overrides = app.dependency_overrides.copy()

    app.dependency_overrides.clear()
    app.dependency_overrides[get_demo_principal] = lambda: PRINCIPAL

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous_overrides)


def test_unauthorized_namespace_never_creates_record(
    client,
    monkeypatch,
):
    def forbidden_repository():
        raise AssertionError(
            "Unauthorized namespace reached repository."
        )

    monkeypatch.setattr(
        "app.api.InvestigationRepository",
        forbidden_repository,
    )

    response = client.post(
        "/investigations",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": (
                "Investigate the failing workload in namespace production."
            ),
        },
    )

    assert response.status_code == 403


def test_authorized_creation_persists_pending_record(
    client,
    monkeypatch,
):
    created = []

    class FakeRepository:
        def create_investigation(
            self,
            *,
            investigation_id,
            authorized_namespace,
            user_text,
            max_steps,
        ):
            created.append(
                (investigation_id, authorized_namespace, user_text, max_steps,)
            )

            return InvestigationRecord(
                investigation_id=investigation_id,
                authorized_namespace=authorized_namespace,
                status=InvestigationStatus.PENDING,
                created_at=datetime.now(timezone.utc),
                user_text=user_text,
                max_steps=max_steps,
            )

    monkeypatch.setattr(
        "app.api.InvestigationRepository",
        FakeRepository,
    )

    response = client.post(
        "/investigations",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": (
                "Investigate the failing workload in namespace ai-ops-demo."
            ),
            "max_steps": 6,
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert body["status"] == "pending"
    assert body["authorized_namespace"] == "ai-ops-demo"

    assert len(created) == 1
    assert created[0][0] == body["investigation_id"]
    assert created[0][1] == "ai-ops-demo"
    assert created[0][2] == ("Investigate the failing workload in namespace ai-ops-demo.")
    assert created[0][3] == 6
    assert body["user_text"] == created[0][2]
    assert body["max_steps"] == 6


def test_invalid_scope_never_creates_record(
    client,
    monkeypatch,
):
    def forbidden_repository():
        raise AssertionError(
            "Invalid scope reached repository."
        )

    monkeypatch.setattr(
        "app.api.InvestigationRepository",
        forbidden_repository,
    )

    response = client.post(
        "/investigations",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": "Investigate the application.",
        },
    )

    assert response.status_code == 422
