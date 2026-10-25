from uuid import UUID, uuid4

import pytest

from app.security.api_keys import APIKeyPrincipal, NamespaceAuthorizationError
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from app.tools.proposal import ToolProposal
from app.tools.proposal_gate import ProposalGateResult
from app.tools.orchestration import run_read_only_tool_request

from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.security.api_keys import (
    APIKeyPrincipal,
    NamespaceAuthorizationError,
)
from app.tools.models import ToolCall
from app.tools.orchestration import run_read_only_tool_request
from app.security.api_keys import APIKeyPrincipal

TEST_PRINCIPAL = APIKeyPrincipal(
    principal_id="orchestration-test",
    allowed_namespaces=frozenset({
        "ai-ops-demo",
        "orders-prod",
    }),
)


REQUEST_ID = UUID("12345678-1234-5678-1234-567812345678")


def test_none_never_executes(monkeypatch):
    proposal = ToolProposal(
        action="none",
        tool=None,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: proposal,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="none",
            call=None,
            reason=None,
        ),
    )

    executed = False

    def fake_execute(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError(
            "executor must not run for none"
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execute,
    )

    result = run_read_only_tool_request(
        request_id=REQUEST_ID,
        principal=TEST_PRINCIPAL,
        user_text="Why is my application failing?",
    )

    assert result.status == "none"
    assert result.call is None
    assert result.execution is None
    assert executed is False


def test_blocked_never_executes(monkeypatch):
    raw_call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "orders-prod",
            "pod": "guessed-pod",
        },
    )

    proposal = ToolProposal(
        action="tool",
        tool=raw_call,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: proposal,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="blocked",
            call=None,
            reason="Candidate pod is not asserted.",
        ),
    )

    executed = False

    def fake_execute(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError(
            "executor must not run for blocked proposal"
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execute,
    )

    result = run_read_only_tool_request(
        request_id=REQUEST_ID,
        principal=TEST_PRINCIPAL,
        user_text=(
            "Get logs in namespace orders-prod. "
            "Guess the pod name."
        ),
    )

    assert result.status == "blocked"
    assert result.call is None
    assert result.execution is None
    assert result.reason is not None
    assert executed is False


def test_bound_call_is_only_call_executed(monkeypatch):
    # Raw model proposal deliberately lacks application defaults.
    raw_call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    # This represents the post-gate, schema-validated ToolCall.
    bound_call = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
            "container": None,
            "tail": 200,
        },
    )

    proposal = ToolProposal(
        action="tool",
        tool=raw_call,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: proposal,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="bound",
            call=bound_call,
            reason=None,
        ),
    )

    captured = {}

    def fake_execute(call, *, request_id=None):
        captured["call"] = call
        captured["request_id"] = request_id

        return ToolExecutionResult(
            tool=call.name,
            status=ToolExecutionStatus.SUCCESS,
            output={"ok": True},
            error=None,
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execute,
    )

    result = run_read_only_tool_request(
        request_id=REQUEST_ID,
        principal=TEST_PRINCIPAL,
        user_text=(
            "Get logs for pod payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )

    assert result.status == "executed"
    assert result.call == bound_call
    assert result.execution is not None
    assert result.execution.status == ToolExecutionStatus.SUCCESS

    # Critical security invariant:
    # the audited executor receives gate.call, not proposal.tool.
    assert captured["call"] == bound_call
    assert captured["call"] != raw_call
    assert captured["request_id"] == str(REQUEST_ID)


def test_operation_substitution_never_executes(monkeypatch):
    raw_call = ToolCall(
        name="k8s.get_previous_logs",
        arguments={
            "namespace": "search-test",
            "pod": "search-api-84d2b",
            "tail": 75,
        },
    )

    proposal = ToolProposal(
        action="tool",
        tool=raw_call,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: proposal,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="blocked",
            call=None,
            reason=(
                "Proposed tool does not match the read-only "
                "operation authorized by the user."
            ),
        ),
    )

    executed = False

    def fake_execute(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError(
            "operation substitution reached executor"
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execute,
    )

    result = run_read_only_tool_request(
        request_id=REQUEST_ID,
        principal=TEST_PRINCIPAL,
        user_text=(
            "Fetch the last 75 log lines from pod "
            "search-api-84d2b in namespace search-test."
        ),
    )

    assert result.status == "blocked"
    assert executed is False


def test_read_only_substitution_never_executes(monkeypatch):
    raw_call = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "orders-prod",
        },
    )

    proposal = ToolProposal(
        action="tool",
        tool=raw_call,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: proposal,
    )

    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: ProposalGateResult(
            status="blocked",
            call=None,
            reason=(
                "Proposed tool does not match the read-only "
                "operation authorized by the user."
            ),
        ),
    )

    executed = False

    def fake_execute(*args, **kwargs):
        nonlocal executed
        executed = True
        raise AssertionError(
            "read-only substitution reached executor"
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execute,
    )

    result = run_read_only_tool_request(
        request_id=REQUEST_ID,
        principal=TEST_PRINCIPAL,
        user_text=(
            "Get logs from namespace orders-prod. "
            "Guess which pod belongs to the orders API."
        ),
    )

    assert result.status == "blocked"
    assert executed is False

def test_unauthorized_namespace_never_reaches_execution(monkeypatch):
    principal = APIKeyPrincipal(
        principal_id="beta-user-1",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "production"},
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )
    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: SimpleNamespace(
            status="bound",
            call=call,
        ),
    )

    def forbidden_execution(*args, **kwargs):
        raise AssertionError(
            "Unauthorized call reached audited execution."
        )

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        forbidden_execution,
    )

    with pytest.raises(NamespaceAuthorizationError):
        run_read_only_tool_request(
            request_id=uuid4(),
            user_text="Inspect pods in namespace production.",
            principal=principal,
        )


def test_authorized_namespace_reaches_audited_execution(monkeypatch):
    principal = APIKeyPrincipal(
        principal_id="beta-user-1",
        allowed_namespaces=frozenset({"ai-ops-demo"}),
    )

    call = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    monkeypatch.setattr(
        "app.tools.orchestration.propose_tool",
        lambda user_text: object(),
    )
    monkeypatch.setattr(
        "app.tools.orchestration.gate_tool_proposal",
        lambda proposal, user_text: SimpleNamespace(
            status="bound",
            call=call,
        ),
    )

    executions = []

    def fake_execution(bound_call, *, request_id):
        executions.append((bound_call, request_id))
        return None

    monkeypatch.setattr(
        "app.tools.orchestration.execute_audited_tool_call",
        fake_execution,
    )

    result = run_read_only_tool_request(
        request_id=uuid4(),
        user_text="Inspect pods in namespace ai-ops-demo.",
        principal=principal,
    )

    assert result.status == "executed"
    assert len(executions) == 1
    assert executions[0][0] == call    
    