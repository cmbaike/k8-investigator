import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.security.api_keys import APIKeyPrincipal
from app.security.dependencies import get_demo_principal
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.tools.orchestration import ToolOrchestrationResult
from app.tools.proposal_gate import ProposalGateResult


TEST_KEY = "integration-test-api-key"

PRINCIPAL = APIKeyPrincipal(
    principal_id="integration-test-user",
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


def test_a_request_without_a_key_still_reaches_the_handler(client, monkeypatch):
    monkeypatch.setattr(
        "app.api.run_read_only_tool_request",
        lambda **kwargs: ToolOrchestrationResult(status="none"),
    )

    response = client.post(
        "/tools/run",
        json={"question": "List pods in namespace ai-ops-demo."},
    )

    assert response.status_code == 200


def test_unauthorized_namespace_never_executes(
    client,
    monkeypatch,
):
    bound_call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "production"},
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="bound",
            call=bound_call,
            reason=None,
        ),
    )

    def forbidden_execution(*args, **kwargs):
        raise AssertionError(
            "Unauthorized namespace reached execution."
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        forbidden_execution,
    )

    response = client.post(
        "/tools/run",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": "List pods in namespace production."
        },
    )

    assert response.status_code == 403
    assert response.json()["detail"] == (
        "Namespace access denied."
    )


def test_authorized_namespace_executes_exact_bound_call(
    client,
    monkeypatch,
):
    bound_call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    execution = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={"items": []},
        error=None,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="bound",
            call=bound_call,
            reason=None,
        ),
    )

    executed_calls = []

    def fake_execution(call, *, request_id):
        executed_calls.append((call, request_id))
        return execution

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execution,
    )

    response = client.post(
        "/tools/run",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": "List pods in namespace ai-ops-demo."
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "executed"

    assert len(executed_calls) == 1
    assert executed_calls[0][0] == bound_call

    # Audited execution must receive the same request ID
    # returned by the HTTP endpoint.
    assert executed_calls[0][1] == response.json()["request_id"]


def test_bound_call_without_namespace_never_executes(
    client,
    monkeypatch,
):
    bound_call = ToolCall(
        name="k8s.get_pods",
        arguments={},
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="bound",
            call=bound_call,
            reason=None,
        ),
    )

    def forbidden_execution(*args, **kwargs):
        raise AssertionError(
            "Namespace-less tool call reached execution."
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        forbidden_execution,
    )

    response = client.post(
        "/tools/run",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": "List pods."
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "blocked"
    assert response.json()["execution"] is None


def test_internal_error_does_not_disclose_details(
    client,
    monkeypatch,
):
    bound_call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="bound",
            call=bound_call,
            reason=None,
        ),
    )

    def failing_execution(*args, **kwargs):
        raise RuntimeError(
            "Sensitive Kubernetes connection details"
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        failing_execution,
    )

    response = client.post(
        "/tools/run",
        headers={"X-API-Key": TEST_KEY},
        json={
            "question": "List pods in namespace ai-ops-demo."
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == "Tool request failed."
    assert "Sensitive Kubernetes" not in response.text
