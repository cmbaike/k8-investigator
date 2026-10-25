import pytest

from app.tools.investigation import (
    InvestigationContext,
    InvestigationStepLimitError,
)
from app.tools.models import (
    ToolCall,
    ToolExecutionResult,
    ToolExecutionStatus,
)

from app.tools.investigation import InvestigationDuplicateRequestError


def get_pods_call() -> ToolCall:
    return ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )


def successful_get_pods_result() -> ToolExecutionResult:
    return ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.SUCCESS,
        output={
            "namespace": "ai-ops-demo",
            "pods": [
                {
                    "name": "payments-api-abc123",
                    "status": "Running",
                }
            ],
        },
        error=None,
    )


def test_context_starts_without_observations():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    assert context.observations == ()
    assert context.completed_steps == 0
    assert context.has_step_budget is True


def test_successful_execution_mints_observation_into_context():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    minted = context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    assert len(minted) == 1
    assert minted[0].value == "payments-api-abc123"

    assert context.observations == minted
    assert context.completed_steps == 1


def test_failed_execution_consumes_step_but_mints_nothing():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.ERROR,
        output={
            "pods": [
                {"name": "must-not-be-trusted"},
            ]
        },
        error="cluster failure",
    )

    minted = context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=result,
    )

    assert minted == ()
    assert context.observations == ()
    assert context.completed_steps == 1


def test_timeout_cannot_mint_observation():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.TIMEOUT,
        output={
            "pods": [
                {"name": "must-not-be-trusted"},
            ]
        },
        error="timeout",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=result,
    )

    assert context.observations == ()


def test_observation_view_is_immutable_tuple():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    assert isinstance(context.observations, tuple)

    with pytest.raises(AttributeError):
        context.observations.append("fake")


def test_context_cannot_be_initialized_with_observations():
    with pytest.raises(TypeError):
        InvestigationContext(
            investigation_id="inv-001",
            user_text="Investigate payments.",
            _observations=[],
        )


def test_find_observation_by_value():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    matches = context.find_observations(
        field="pods[].name",
        value="payments-api-abc123",
    )

    assert len(matches) == 1
    assert matches[0].tool == "k8s.get_pods"


def test_unknown_observation_value_is_not_found():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments in namespace ai-ops-demo.",
        max_steps=1,
        authorized_namespace="ai-ops-demo",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    assert context.find_observations(
        value="invented-admin-pod",
    ) == ()


def test_step_budget_is_enforced():
    context = InvestigationContext(
        investigation_id="inv-001",
        user_text="Investigate payments.",
        max_steps=1,
        authorized_namespace="ai-ops-demo",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    assert context.completed_steps == 1
    assert context.has_step_budget is False

    with pytest.raises(InvestigationStepLimitError):
        context.record_execution(
            request_id="request-002",
            call=get_pods_call(),
            result=successful_get_pods_result(),
        )

    assert context.completed_steps == 1

def test_duplicate_request_id_is_rejected_without_consuming_step():
    context = InvestigationContext(
        investigation_id="inv-duplicate-request",
        user_text="Investigate payments.",
        max_steps=3,
        authorized_namespace="ai-ops-demo",
    )

    context.record_execution(
        request_id="request-001",
        call=get_pods_call(),
        result=successful_get_pods_result(),
    )

    original_observations = context.observations

    with pytest.raises(InvestigationDuplicateRequestError):
        context.record_execution(
            request_id="request-001",
            call=get_pods_call(),
            result=successful_get_pods_result(),
        )

    assert context.completed_steps == 1
    assert context.observations == original_observations