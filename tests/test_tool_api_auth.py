from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.security.api_keys import (
    APIKeyPrincipal,
    NamespaceAuthorizationError,
)
from app.security.dependencies import require_api_key_principal
from app.tools.orchestration import ToolOrchestrationResult

@pytest.fixture
def client():
    app.dependency_overrides.clear()

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


def test_missing_api_key_still_reaches_orchestration(client, monkeypatch):
    seen = []

    def record(**kwargs):
        seen.append(kwargs)
        return ToolOrchestrationResult(status="none")

    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        record,
    )

    response = client.post(
        "/tools/run",
        json={
            "question": "Inspect pods in namespace ai-ops-demo."
        },
    )

    assert response.status_code == 200
    assert seen


def test_authenticated_principal_reaches_orchestration(
    client,
    monkeypatch,
):
    principal = APIKeyPrincipal(
        principal_id="beta-user-1",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    app.dependency_overrides[
        require_api_key_principal
    ] = lambda: principal

    received = []

    def fake_orchestration(
        *,
        request_id,
        user_text,
        principal,
    ):
        received.append(
            (request_id, user_text, principal)
        )

        return ToolOrchestrationResult(
            status="none",
            call=None,
            execution=None,
            reason=None,
        )

    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        fake_orchestration,
    )

    response = client.post(
        "/tools/run",
        json={
            "question": "Inspect pods in namespace ai-ops-demo."
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "none"
    assert len(received) == 1
    assert received[0][2] == principal


def test_unauthorized_namespace_returns_403(
    client,
    monkeypatch,
):
    principal = APIKeyPrincipal(
        principal_id="beta-user-1",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    app.dependency_overrides[
        require_api_key_principal
    ] = lambda: principal

    def reject_namespace(**kwargs):
        raise NamespaceAuthorizationError(
            "Namespace access denied."
        )

    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        reject_namespace,
    )

    response = client.post(
        "/tools/run",
        json={
            "question": "Inspect pods in namespace production."
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Namespace access denied."
    )


def test_internal_exception_is_not_disclosed(
    client,
    monkeypatch,
):
    principal = APIKeyPrincipal(
        principal_id="beta-user-1",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    app.dependency_overrides[
        require_api_key_principal
    ] = lambda: principal

    def failing_orchestration(**kwargs):
        raise RuntimeError(
            "Sensitive internal connection details"
        )

    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        failing_orchestration,
    )

    response = client.post(
        "/tools/run",
        json={
            "question": "Inspect pods in namespace ai-ops-demo."
        },
    )

    assert response.status_code == 500
    assert "Sensitive internal" not in response.text

def test_api_key_header_is_ignored(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        lambda **kwargs: ToolOrchestrationResult(status="none"),
    )

    request_body = {
        "question": "Inspect pods in namespace ai-ops-demo."
    }

    missing = client.post("/tools/run", json=request_body)
    invalid = client.post(
        "/tools/run",
        headers={"X-API-Key": "incorrect"},
        json=request_body,
    )

    assert missing.status_code == 200
    assert invalid.status_code == 200