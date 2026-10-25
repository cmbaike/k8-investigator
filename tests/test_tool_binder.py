import pytest

from app.tools.binder import (
    CandidateNotGroundedError,
    ToolBindingError,
    bind_proposed_user_tool_call,
    bind_user_tool_call,
    ground_observed_candidate,
    ground_user_candidate,
)
from app.tools.investigation import InvestigationContext, InvestigationScopeError
from app.tools.investigation_scope import create_investigation_context
from app.tools.models import ToolCall, ToolExecutionResult, ToolExecutionStatus
from app.tools.provenance import (
    ArgumentSource,
    AssertionStatus,
    GroundedArgument,
    GroundedToolCall,
)


def _context_with_observed_pod(
    user_text: str = (
        "Investigate the failing workload "
        "in namespace ai-ops-demo."
    ),
) -> InvestigationContext:
    context = create_investigation_context(user_text)

    call = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    result = ToolExecutionResult(
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

    context.record_execution(
        request_id="request-get-pods-001",
        call=call,
        result=result,
    )

    return context

def grounded_argument(
    name: str,
    value: str | int,
    evidence: str,
) -> GroundedArgument:
    return GroundedArgument(
        name=name,
        value=value,
        source=ArgumentSource.USER,
        evidence=evidence,
        assertion=AssertionStatus.ASSERTED,
    )

def test_binds_grounded_get_pods():
    text = "List pods in namespace ai-ops-demo."
    call = GroundedToolCall(
        name="k8s.get_pods",
        arguments=[
            grounded_argument(
                "namespace",
                "ai-ops-demo",
                "namespace ai-ops-demo",
            ),
        ],
    )

    result = bind_user_tool_call(call, text)

    assert result.name == "k8s.get_pods"
    assert result.arguments == {
        "namespace": "ai-ops-demo",
    }

def test_binds_logs_and_applies_application_default():
    text = (
        "Get logs for pod payments-api-abc123 "
        "in namespace ai-ops-demo."
    )

    call = GroundedToolCall(
        name="k8s.get_logs",
        arguments=[
            grounded_argument(
                "namespace",
                "ai-ops-demo",
                "namespace ai-ops-demo",
            ),
            grounded_argument(
                "pod",
                "payments-api-abc123",
                "pod payments-api-abc123",
            ),
        ],
    )

    result = bind_user_tool_call(call, text)

    assert result.arguments["namespace"] == "ai-ops-demo"
    assert result.arguments["pod"] == "payments-api-abc123"
    assert result.arguments["container"] is None
    assert result.arguments["tail"] == 200

def test_rejects_invented_pod():
    text = (
        "The payments service in namespace ai-ops-demo is broken. "
        "Get its logs."
    )

    call = GroundedToolCall(
        name="k8s.get_logs",
        arguments=[
            grounded_argument(
                "namespace",
                "ai-ops-demo",
                "namespace ai-ops-demo",
            ),
            grounded_argument(
                "pod",
                "payments-service",
                "pod payments-service",
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="evidence is not present",
    ):
        bind_user_tool_call(call, text)

def test_rejects_untrusted_assumption():
    text = (
        "List the pods for the payments service. "
        "Assume the namespace is production."
    )

    call = GroundedToolCall(
        name="k8s.get_pods",
        arguments=[
            GroundedArgument(
                name="namespace",
                value="production",
                source=ArgumentSource.USER,
                evidence="namespace is production",
                assertion=AssertionStatus.UNTRUSTED,
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_user_tool_call(call, text)

def test_rejects_missing_required_argument():
    call = GroundedToolCall(
        name="k8s.get_logs",
        arguments=[],
    )

    with pytest.raises(
        ToolBindingError,
        match="Invalid arguments",
    ):
        bind_user_tool_call(
            call,
            "Show the logs.",
        )

def test_rejects_unknown_argument():
    text = "List pods in namespace ai-ops-demo."

    call = GroundedToolCall(
        name="k8s.get_pods",
        arguments=[
            grounded_argument(
                "namespace",
                "ai-ops-demo",
                "namespace ai-ops-demo",
            ),
            grounded_argument(
                "force",
                "true",
                "force true",
            ),
        ],
    )

    with pytest.raises(ToolBindingError):
        bind_user_tool_call(call, text)

def test_rejects_duplicate_argument():
    text = (
        "List pods in namespace ai-ops-demo "
        "and namespace production."
    )

    call = GroundedToolCall(
        name="k8s.get_pods",
        arguments=[
            grounded_argument(
                "namespace",
                "ai-ops-demo",
                "namespace ai-ops-demo",
            ),
            grounded_argument(
                "namespace",
                "production",
                "namespace production",
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="Duplicate argument",
    ):
        bind_user_tool_call(call, text)

def test_rejects_tool_observation_in_user_only_binder():
    call = GroundedToolCall(
        name="k8s.get_logs",
        arguments=[
            GroundedArgument(
                name="pod",
                value="payments-api-abc123",
                source=ArgumentSource.TOOL_OBSERVATION,
                evidence="payments-api-abc123",
                assertion=AssertionStatus.ASSERTED,
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="not user-sourced",
    ):
        bind_user_tool_call(
            call,
            "Get its logs.",
        )

def test_proposed_grounded_get_pods_is_bound():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    result = bind_proposed_user_tool_call(
        proposed,
        "List pods in namespace ai-ops-demo.",
    )

    assert result.arguments == {
        "namespace": "ai-ops-demo",
    }

def test_proposed_invented_pod_is_rejected():
    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-service",
            "container": "payments-service",
            "tail": 100,
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_proposed_user_tool_call(
            proposed,
            (
                "The payments service in namespace ai-ops-demo is broken. "
                "Get its logs. Guess the pod name if necessary."
            ),
        )

def test_proposed_unknown_placeholder_is_rejected():
    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "unknown",
            "container": "unknown",
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_proposed_user_tool_call(
            proposed,
            "Show the logs in namespace ai-ops-demo.",
        )

def test_proposed_ungrounded_optional_tail_uses_application_default():
    proposed = ToolCall(
        name="k8s.get_previous_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
            "tail": 100,
        },
    )

    result = bind_proposed_user_tool_call(
        proposed,
        (
            "Show previous logs for pod "
            "payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )

    assert result.arguments == {
        "namespace": "ai-ops-demo",
        "pod": "payments-api-abc123",
        "container": None,
        "tail": 200,
    }

def test_proposed_grounded_optional_tail_is_preserved():
    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
            "tail": 50,
        },
    )

    result = bind_proposed_user_tool_call(
        proposed,
        (
            "Get the last 50 log lines from pod "
            "payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )

    assert result.arguments["tail"] == 50

def test_proposed_ungrounded_required_pod_remains_rejected():
    proposed = ToolCall(
        name="k8s.get_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "invented-pod",
        },
    )

    with pytest.raises(
        ToolBindingError,
        match="not asserted",
    ):
        bind_proposed_user_tool_call(
            proposed,
            "Get logs in namespace ai-ops-demo.",
        )

def test_proposed_unknown_argument_remains_rejected():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
            "force": "true",
        },
    )

    with pytest.raises(ToolBindingError):
        bind_proposed_user_tool_call(
            proposed,
            "List pods in namespace ai-ops-demo.",
        )

def test_proposed_ungrounded_optional_values_use_application_defaults():
    proposed = ToolCall(
        name="k8s.get_previous_logs",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
            "container": "payments-api",
            "tail": 100,
        },
    )

    result = bind_proposed_user_tool_call(
        proposed,
        (
            "Show previous logs for pod "
            "payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )

    assert result.name == "k8s.get_previous_logs"
    assert result.arguments == {
        "namespace": "ai-ops-demo",
        "pod": "payments-api-abc123",
        "container": None,
        "tail": 200,
    }

def test_observed_pod_candidate_is_grounded():
    context = _context_with_observed_pod()

    grounded = ground_observed_candidate(
        "pod",
        "payments-api-abc123",
        context,
    )

    assert grounded.name == "pod"
    assert grounded.value == "payments-api-abc123"
    assert grounded.source == ArgumentSource.TOOL_OBSERVATION
    assert grounded.assertion == AssertionStatus.ASSERTED
    assert "request-get-pods-001" in grounded.evidence
    assert "k8s.get_pods" in grounded.evidence
    assert "pods[].name" in grounded.evidence

def test_unobserved_pod_candidate_is_rejected():
    context = _context_with_observed_pod()

    with pytest.raises(
        CandidateNotGroundedError,
        match="not present in trusted tool observations",
    ):
        ground_observed_candidate(
            "pod",
            "invented-admin-pod",
            context,
        )

def test_pod_observation_cannot_authorize_deployment_argument():
    context = _context_with_observed_pod()

    with pytest.raises(
        CandidateNotGroundedError,
        match="cannot be grounded from tool observations",
    ):
        ground_observed_candidate(
            "deployment",
            "payments-api-abc123",
            context,
        )

def test_tool_observation_cannot_authorize_tail_argument():
    context = _context_with_observed_pod()

    with pytest.raises(
        CandidateNotGroundedError,
        match="cannot be grounded from tool observations",
    ):
        ground_observed_candidate(
            "tail",
            200,
            context,
        )

def test_observed_identifier_requires_exact_value_match():
    context = _context_with_observed_pod()

    with pytest.raises(CandidateNotGroundedError):
        ground_observed_candidate(
            "pod",
            "payments-api",
            context,
        )

def test_failed_execution_cannot_authorize_pod_candidate():
    context = InvestigationContext(
        investigation_id="inv-binding-002",
        user_text="Investigate namespace ai-ops-demo.",
        authorized_namespace="ai-ops-demo",
    )

    call = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    result = ToolExecutionResult(
        tool="k8s.get_pods",
        status=ToolExecutionStatus.ERROR,
        output={
            "pods": [
                {
                    "name": "untrusted-error-pod",
                }
            ],
        },
        error="cluster error",
    )

    context.record_execution(
        request_id="request-error-001",
        call=call,
        result=result,
    )

    assert context.observations == ()

    with pytest.raises(CandidateNotGroundedError):
        ground_observed_candidate(
            "pod",
            "untrusted-error-pod",
            context,
        )

def test_proposed_binding_without_context_preserves_user_grounding():
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },

    )

    bound = bind_proposed_user_tool_call(
        proposed,
        (
            "Describe pod payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )

    assert bound.name == "k8s.describe_pod"
    assert bound.arguments["namespace"] == "ai-ops-demo"
    assert bound.arguments["pod"] == "payments-api-abc123"

def test_proposed_binding_can_use_observed_pod():
    context = _context_with_observed_pod()
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    bound = bind_proposed_user_tool_call(
        proposed,
        "Describe pod in namespace ai-ops-demo.",
        context=context,
    )

    assert bound.name == "k8s.describe_pod"
    assert bound.arguments["namespace"] == "ai-ops-demo"
    assert bound.arguments["pod"] == "payments-api-abc123"

def test_proposed_binding_rejects_unobserved_pod():
    context = _context_with_observed_pod()
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "invented-admin-pod",
        },

    )
    with pytest.raises(
        ToolBindingError,
        match="not asserted in the user input",
    ):
        bind_proposed_user_tool_call(
            proposed,
            "Describe pod in namespace ai-ops-demo.",
            context=context,
        )

def test_proposed_binding_does_not_use_observation_without_context():
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    with pytest.raises(ToolBindingError):
        bind_proposed_user_tool_call(
            proposed,
            "Describe pod in namespace ai-ops-demo.",
        )

def test_user_grounding_takes_precedence_over_observation():
    context = _context_with_observed_pod()
    grounded = ground_user_candidate(
        "pod",
        "payments-api-abc123",
        (
            "Describe pod payments-api-abc123 "
            "in namespace ai-ops-demo."
        ),
    )
    assert grounded.source == ArgumentSource.USER

def test_bind_user_tool_call_rejects_tool_observation_source():
    grounded = GroundedToolCall(
        name="k8s.describe_pod",
        arguments=[
            GroundedArgument(
                name="namespace",
                value="ai-ops-demo",
                source=ArgumentSource.USER,
                evidence="namespace ai-ops-demo",
                assertion=AssertionStatus.ASSERTED,
            ),
            GroundedArgument(
                name="pod",
                value="payments-api-abc123",
                source=ArgumentSource.TOOL_OBSERVATION,
                evidence=(
                    "request-get-pods-001:"
                    "k8s.get_pods:"
                    "pods[].name"
                ),
                assertion=AssertionStatus.ASSERTED,
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="not user-sourced",
    ):
        bind_user_tool_call(
            grounded,
            (
                "Describe the pod "
                "in namespace ai-ops-demo."
            ),
        )

def test_direct_user_binding_rejects_fabricated_tool_observation():
    call = GroundedToolCall(
        name="k8s.describe_pod",
        arguments=[
            GroundedArgument(
                name="namespace",
                value="ai-ops-demo",
                source=ArgumentSource.USER,
                evidence="namespace ai-ops-demo",
                assertion=AssertionStatus.ASSERTED,
            ),
            GroundedArgument(
                name="pod",
                value="fabricated-admin-pod",
                source=ArgumentSource.TOOL_OBSERVATION,
                evidence=(
                    "fake-request:"
                    "k8s.get_pods:"
                    "pods[].name"
                ),
                assertion=AssertionStatus.ASSERTED,
            ),
        ],
    )

    with pytest.raises(
        ToolBindingError,
        match="not user-sourced",
    ):
        bind_user_tool_call(
            call,
            "Describe pod in namespace ai-ops-demo.",
        )

def test_observation_from_another_context_is_not_available():
    context_a = _context_with_observed_pod()
    context_b = InvestigationContext(
        investigation_id="inv-other",
        user_text="Describe pod in namespace ai-ops-demo.",
    )

    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    with pytest.raises(ToolBindingError):
        bind_proposed_user_tool_call(
            proposed,
            "Describe pod in namespace ai-ops-demo.",
            context=context_b,
        )

    # Sanity check: the observation exists only in A.
    assert context_a.find_observations(
        field="pods[].name",
        value="payments-api-abc123",
    )

    assert context_b.observations == ()

def test_investigation_can_bind_initial_pod_listing():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    text = "Investigate the failing workload in namespace ai-ops-demo."
    context = create_investigation_context(text)
    bound = bind_proposed_user_tool_call(
        proposed,
        text,
        context=context,
    )

    assert bound.name == "k8s.get_pods"
    assert bound.arguments["namespace"] == "ai-ops-demo"

def test_investigation_can_describe_observed_pod():
    context = _context_with_observed_pod()
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )

    bound = bind_proposed_user_tool_call(
        proposed,
        (
            "Investigate the failing workload "
            "in namespace ai-ops-demo."
        ),
        context=context,
    )

    assert bound.name == "k8s.describe_pod"
    assert bound.arguments["pod"] == "payments-api-abc123"

def test_investigation_rejects_invented_pod():
    context = _context_with_observed_pod()
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "invented-admin-pod",
        },
    )

    with pytest.raises(ToolBindingError):
        bind_proposed_user_tool_call(
            proposed,
            (
                "Investigate the failing workload "
                "in namespace ai-ops-demo."
            ),
            context=context,
        )

def test_investigation_does_not_authorize_restart():
    proposed = ToolCall(
        name="k8s.rollout_restart",
        arguments={
            "namespace": "ai-ops-demo",
            "deployment": "payments-api",
        },
    )

    with pytest.raises(ValueError):
        bind_proposed_user_tool_call(
            proposed,
            (
                "Investigate the failing workload "
                "in namespace ai-ops-demo."
            ),
        )

def test_investigation_cannot_substitute_explicit_operation():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={
            "namespace": "ai-ops-demo",
        },
    )

    with pytest.raises(ValueError):
        bind_proposed_user_tool_call(
            proposed,
            (
                "Investigate the workload. "
                "Describe pod payments-api-abc123 "
                "in namespace ai-ops-demo."
            ),
        )

def test_trusted_pod_cannot_override_namespace_scope():
    text = (
        "Investigate the failing workload "
        "in namespace ai-ops-demo."
    )

    context = create_investigation_context(text)
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "production",
            "pod": "payments-api-abc123",
        },
    )

    with pytest.raises(InvestigationScopeError):
        bind_proposed_user_tool_call(
            proposed,
            text,
            context=context,
        )


def test_explicit_operation_does_not_require_investigation_context():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )
    bound = bind_proposed_user_tool_call(
        proposed,
        "List pods in namespace ai-ops-demo.",
    )
    assert bound.name == "k8s.get_pods"
    assert bound.arguments["namespace"] == "ai-ops-demo"


def test_investigation_rejects_context_from_different_request():
    original_text = (
        "Investigate the failing workload "
        "in namespace ai-ops-demo."
    )
    different_text = (
        "Diagnose the failing workload "
        "in namespace ai-ops-demo."
    )
    context = _context_with_observed_pod(user_text=original_text)
    proposed = ToolCall(
        name="k8s.describe_pod",
        arguments={
            "namespace": "ai-ops-demo",
            "pod": "payments-api-abc123",
        },
    )
    with pytest.raises(ToolBindingError, match="context does not match"):
        bind_proposed_user_tool_call(
            proposed,
            different_text,
            context=context,
        )

def test_explicit_operation_does_not_require_investigation_context():
    proposed = ToolCall(
        name="k8s.get_pods",
        arguments={"namespace": "ai-ops-demo"},
    )

    bound = bind_proposed_user_tool_call(
        proposed,
        "List pods in namespace ai-ops-demo.",
    )

    assert bound.name == "k8s.get_pods"
    assert bound.arguments["namespace"] == "ai-ops-demo"    